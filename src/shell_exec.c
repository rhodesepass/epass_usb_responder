#include "shell_exec.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t monotonic_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool append_limited(uint8_t **dst, size_t *dst_size, const uint8_t *src, size_t n, size_t max_size)
{
	size_t can_write = n;
	uint8_t *next = NULL;
	if (*dst_size >= max_size)
	{
		return true;
	}
	if (*dst_size + can_write > max_size)
	{
		can_write = max_size - *dst_size;
	}
	if (can_write == 0)
	{
		return true;
	}
	next = (uint8_t *)realloc(*dst, *dst_size + can_write);
	if (!next)
	{
		return false;
	}
	*dst = next;
	memcpy(*dst + *dst_size, src, can_write);
	*dst_size += can_write;
	return true;
}

static bool set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0)
	{
		return false;
	}
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

static pid_t shell_pid = -1;
static int shell_stdin_fd = -1;
static int shell_stdout_fd = -1;
static int shell_stderr_fd = -1;
static int shell_status_fd = -1;
static unsigned shell_cmd_id = 0;
static bool shell_session_active = false;

static void shell_session_cleanup(void)
{
	if (shell_status_fd >= 0)
	{
		close(shell_status_fd);
		shell_status_fd = -1;
	}
	if (shell_stdout_fd >= 0)
	{
		close(shell_stdout_fd);
		shell_stdout_fd = -1;
	}
	if (shell_stderr_fd >= 0)
	{
		close(shell_stderr_fd);
		shell_stderr_fd = -1;
	}
	if (shell_stdin_fd >= 0)
	{
		close(shell_stdin_fd);
		shell_stdin_fd = -1;
	}
	if (shell_pid > 0)
	{
		killpg(shell_pid, SIGKILL);
		while (waitpid(shell_pid, NULL, 0) < 0 && errno == EINTR)
			;
		shell_pid = -1;
	}
	shell_session_active = false;
}

static bool shell_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len > 0)
	{
		ssize_t written = write(fd, p, len);
		if (written < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return false;
		}
		p += written;
		len -= (size_t)written;
	}
	return true;
}

static bool shell_session_start(void)
{
	int stdin_pipe[2] = {-1, -1};
	int stdout_pipe[2] = {-1, -1};
	int stderr_pipe[2] = {-1, -1};
	int status_pipe[2] = {-1, -1};
	pid_t pid;

	if (pipe(stdin_pipe) != 0 || pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0 || pipe(status_pipe) != 0)
	{
		goto error;
	}

	pid = fork();
	if (pid < 0)
	{
		goto error;
	}
	if (pid == 0)
	{
		setpgid(0, 0);
		if (dup2(stdin_pipe[0], STDIN_FILENO) < 0)
			_exit(127);
		if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0)
			_exit(127);
		if (dup2(stderr_pipe[1], STDERR_FILENO) < 0)
			_exit(127);
		if (dup2(status_pipe[1], 3) < 0)
			_exit(127);

		close(stdin_pipe[0]);
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);
		close(status_pipe[0]);
		close(status_pipe[1]);

		execl("/bin/sh", "sh", "-s", (char *)NULL);
		_exit(127);
	}

	setpgid(pid, pid);

	close(stdin_pipe[0]);
	close(stdout_pipe[1]);
	close(stderr_pipe[1]);
	close(status_pipe[1]);

	shell_stdin_fd = stdin_pipe[1];
	shell_stdout_fd = stdout_pipe[0];
	shell_stderr_fd = stderr_pipe[0];
	shell_status_fd = status_pipe[0];
	shell_pid = pid;
	shell_session_active = true;

	if (!set_nonblock(shell_stdout_fd) || !set_nonblock(shell_stderr_fd) || !set_nonblock(shell_status_fd))
	{
		shell_session_cleanup();
		return false;
	}

	return true;

error:
	if (stdin_pipe[0] >= 0)
		close(stdin_pipe[0]);
	if (stdin_pipe[1] >= 0)
		close(stdin_pipe[1]);
	if (stdout_pipe[0] >= 0)
		close(stdout_pipe[0]);
	if (stdout_pipe[1] >= 0)
		close(stdout_pipe[1]);
	if (stderr_pipe[0] >= 0)
		close(stderr_pipe[0]);
	if (stderr_pipe[1] >= 0)
		close(stderr_pipe[1]);
	if (status_pipe[0] >= 0)
		close(status_pipe[0]);
	if (status_pipe[1] >= 0)
		close(status_pipe[1]);
	return false;
}

static bool shell_session_ensure(void)
{
	if (shell_session_active)
	{
		int status;
		pid_t wr = waitpid(shell_pid, &status, WNOHANG);
		if (wr == shell_pid)
		{
			shell_session_cleanup();
		}
	}
	if (!shell_session_active)
	{
		return shell_session_start();
	}
	return true;
}

bool usb_responder_exec_shell(
    const char *command,
    const usb_responder_shell_exec_options_t *options,
    usb_responder_shell_exec_result_t *out_result)
{
	bool stdout_open = true;
	bool stderr_open = true;
	bool status_open = true;
	bool status_received = false;
	bool kill_sent = false;
	uint64_t start_ms;
	uint64_t deadline_ms;
	char *command_payload = NULL;
	size_t command_payload_len = 0;
	char status_accum[256];
	size_t status_accum_len = 0;
	unsigned cmd_id;
	int command_exit_code = -1;

	if (!command || !options || !out_result)
	{
		return false;
	}
	memset(out_result, 0, sizeof(*out_result));
	out_result->exit_code = -1;

	if (!shell_session_ensure())
	{
		return false;
	}

	cmd_id = ++shell_cmd_id;
	command_payload_len = snprintf(NULL, 0, "%s\nprintf 'SHELL_STATUS_%u_%%d\\n' >&3 $?\n", command, cmd_id);
	command_payload = (char *)malloc(command_payload_len + 1);
	if (!command_payload)
	{
		return false;
	}
	snprintf(command_payload, command_payload_len + 1, "%s\nprintf 'SHELL_STATUS_%u_%%d\\n' >&3 $?\n", command, cmd_id);

	if (!shell_write_all(shell_stdin_fd, command_payload, command_payload_len))
	{
		free(command_payload);
		shell_session_cleanup();
		return false;
	}
	free(command_payload);

	start_ms = monotonic_ms();
	deadline_ms = start_ms + options->timeout_ms;
	status_accum_len = 0;

	while (!status_received || stdout_open || stderr_open)
	{
		struct pollfd pfds[3];
		nfds_t pfds_n = 0;
		int timeout_ms = 100;
		uint64_t now_ms = monotonic_ms();

		if (now_ms >= deadline_ms && !status_received)
		{
			out_result->timed_out = true;
			if (!kill_sent)
			{
				killpg(shell_pid, SIGTERM);
				kill_sent = true;
			}
			else
			{
				killpg(shell_pid, SIGKILL);
			}
		}
		else if (!status_received)
		{
			uint64_t remain = deadline_ms - now_ms;
			if (remain < (uint64_t)timeout_ms)
			{
				timeout_ms = (int)remain;
			}
		}

		if (stdout_open)
		{
			pfds[pfds_n].fd = shell_stdout_fd;
			pfds[pfds_n].events = POLLIN | POLLHUP;
			pfds_n++;
		}
		if (stderr_open)
		{
			pfds[pfds_n].fd = shell_stderr_fd;
			pfds[pfds_n].events = POLLIN | POLLHUP;
			pfds_n++;
		}
		if (status_open)
		{
			pfds[pfds_n].fd = shell_status_fd;
			pfds[pfds_n].events = POLLIN | POLLHUP;
			pfds_n++;
		}

		int pr = -1;
		if (pfds_n > 0)
		{
			pr = poll(pfds, pfds_n, timeout_ms);
			if (pr > 0)
			{
				for (nfds_t i = 0; i < pfds_n; ++i)
				{
					uint8_t tmp[4096];
					int fd = pfds[i].fd;
					if (!(pfds[i].revents & (POLLIN | POLLHUP)))
					{
						continue;
					}

					if (fd == shell_stdout_fd || fd == shell_stderr_fd)
					{
						ssize_t n = read(fd, tmp, sizeof(tmp));
						if (n > 0)
						{
							if (fd == shell_stdout_fd)
							{
								if (!append_limited(&out_result->stdout_data, &out_result->stdout_size, tmp,
										    (size_t)n, options->max_stdout))
								{
									goto cleanup;
								}
							}
							else if (!append_limited(&out_result->stderr_data, &out_result->stderr_size, tmp,
										 (size_t)n, options->max_stderr))
							{
								goto cleanup;
							}
						}
						else if (n == 0)
						{
							if (fd == shell_stdout_fd)
							{
								close(shell_stdout_fd);
								shell_stdout_fd = -1;
								stdout_open = false;
							}
							else
							{
								close(shell_stderr_fd);
								shell_stderr_fd = -1;
								stderr_open = false;
							}
						}
						else if (errno != EAGAIN && errno != EINTR)
						{
							goto cleanup;
						}
					}
					else if (fd == shell_status_fd)
					{
						ssize_t n = read(shell_status_fd, tmp, sizeof(tmp));
						if (n > 0)
						{
							if (status_accum_len + (size_t)n > sizeof(status_accum))
							{
								status_accum_len = 0;
							}
							memcpy(status_accum + status_accum_len, tmp, (size_t)n);
							status_accum_len += (size_t)n;

							char prefix[32];
							int prefix_len = snprintf(prefix, sizeof(prefix), "SHELL_STATUS_%u_", cmd_id);
							char *line = status_accum;
							char *end = status_accum + status_accum_len;
							while (line < end)
							{
								char *newline = memchr(line, '\n', (size_t)(end - line));
								if (!newline)
								{
									break;
								}
								size_t line_len = (size_t)(newline - line);
								if ((size_t)prefix_len <= line_len && memcmp(line, prefix, (size_t)prefix_len) == 0)
								{
									char numbuf[32] = {0};
									size_t num_len = line_len - (size_t)prefix_len;
									if (num_len >= sizeof(numbuf))
									{
										num_len = sizeof(numbuf) - 1;
									}
									memcpy(numbuf, line + prefix_len, num_len);
									command_exit_code = atoi(numbuf);
									status_received = true;
								}
								line = newline + 1;
							}

							if (line < end)
							{
								size_t remaining = (size_t)(end - line);
								memmove(status_accum, line, remaining);
								status_accum_len = remaining;
							}
							else
							{
								status_accum_len = 0;
							}
						}
						else if (n == 0)
						{
							close(shell_status_fd);
							shell_status_fd = -1;
							status_open = false;
						}
						else if (errno != EAGAIN && errno != EINTR)
						{
							goto cleanup;
						}
					}
				}
			}
			else if (pr < 0 && errno != EINTR)
			{
				goto cleanup;
			}
		}

		if (pr == 0 && status_received)
		{
			break;
		}
		if (pfds_n == 0)
		{
			if (status_received || out_result->timed_out)
			{
				break;
			}
			goto cleanup;
		}
	}

	if (status_received)
	{
		out_result->exit_code = command_exit_code;
	}
	else if (out_result->timed_out)
	{
		out_result->exit_code = 128 + SIGKILL;
		shell_session_cleanup();
	}

	out_result->duration_ms = (uint32_t)(monotonic_ms() - start_ms);
	return true;

cleanup:
	shell_session_cleanup();
	usb_responder_shell_exec_result_free(out_result);
	return false;
}

void usb_responder_shell_exec_result_free(usb_responder_shell_exec_result_t *result)
{
	if (!result)
	{
		return;
	}
	free(result->stdout_data);
	free(result->stderr_data);
	memset(result, 0, sizeof(*result));
}
