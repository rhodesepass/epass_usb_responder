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

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool append_limited(uint8_t** dst, size_t* dst_size, const uint8_t* src, size_t n, size_t max_size) {
    size_t can_write = n;
    uint8_t* next = NULL;
    if (*dst_size >= max_size) {
        return true;
    }
    if (*dst_size + can_write > max_size) {
        can_write = max_size - *dst_size;
    }
    if (can_write == 0) {
        return true;
    }
    next = (uint8_t*)realloc(*dst, *dst_size + can_write);
    if (!next) {
        return false;
    }
    *dst = next;
    memcpy(*dst + *dst_size, src, can_write);
    *dst_size += can_write;
    return true;
}

static bool set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return false;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

bool usb_responder_exec_shell(
    const char* command,
    const usb_responder_shell_exec_options_t* options,
    usb_responder_shell_exec_result_t* out_result) {
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    pid_t pid = -1;
    int status = 0;
    bool child_running = true;
    bool out_open = true;
    bool err_open = true;
    uint64_t start_ms = monotonic_ms();
    uint64_t deadline_ms = start_ms + options->timeout_ms;
    bool kill_sent = false;

    if (!command || !options || !out_result) {
        return false;
    }
    memset(out_result, 0, sizeof(*out_result));
    out_result->exit_code = -1;

    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        goto cleanup;
    }

    pid = fork();
    if (pid < 0) {
        goto cleanup;
    }
    if (pid == 0) {
        setpgid(0, 0);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        execl("/bin/sh", "sh", "-c", command, (char*)NULL);
        _exit(127);
    }

    setpgid(pid, pid);
    close(out_pipe[1]);
    close(err_pipe[1]);
    out_pipe[1] = -1;
    err_pipe[1] = -1;
    if (!set_nonblock(out_pipe[0]) || !set_nonblock(err_pipe[0])) {
        goto cleanup;
    }

    while (child_running || out_open || err_open) {
        struct pollfd pfds[2];
        nfds_t pfds_n = 0;
        int timeout_ms = 100;
        uint64_t now_ms = monotonic_ms();

        if (now_ms >= deadline_ms && child_running) {
            out_result->timed_out = true;
            if (!kill_sent) {
                killpg(pid, SIGTERM);
                kill_sent = true;
            } else {
                killpg(pid, SIGKILL);
            }
        } else if (child_running) {
            uint64_t remain = deadline_ms - now_ms;
            if (remain < (uint64_t)timeout_ms) {
                timeout_ms = (int)remain;
            }
        }

        if (out_open) {
            pfds[pfds_n].fd = out_pipe[0];
            pfds[pfds_n].events = POLLIN | POLLHUP;
            pfds_n++;
        }
        if (err_open) {
            pfds[pfds_n].fd = err_pipe[0];
            pfds[pfds_n].events = POLLIN | POLLHUP;
            pfds_n++;
        }
        if (pfds_n > 0) {
            int pr = poll(pfds, pfds_n, timeout_ms);
            if (pr > 0) {
                for (nfds_t i = 0; i < pfds_n; ++i) {
                    uint8_t tmp[4096];
                    bool is_out = (pfds[i].fd == out_pipe[0]);
                    if (pfds[i].revents & (POLLIN | POLLHUP)) {
                        ssize_t n = read(pfds[i].fd, tmp, sizeof(tmp));
                        if (n > 0) {
                            if (is_out) {
                                if (!append_limited(&out_result->stdout_data, &out_result->stdout_size, tmp,
                                                    (size_t)n, options->max_stdout)) {
                                    goto cleanup;
                                }
                            } else if (!append_limited(&out_result->stderr_data, &out_result->stderr_size, tmp,
                                                        (size_t)n, options->max_stderr)) {
                                goto cleanup;
                            }
                        } else if (n == 0) {
                            if (is_out) {
                                close(out_pipe[0]);
                                out_pipe[0] = -1;
                                out_open = false;
                            } else {
                                close(err_pipe[0]);
                                err_pipe[0] = -1;
                                err_open = false;
                            }
                        } else if (errno != EAGAIN && errno != EINTR) {
                            goto cleanup;
                        }
                    }
                }
            } else if (pr < 0 && errno != EINTR) {
                goto cleanup;
            }
        }

        if (child_running) {
            pid_t wr = waitpid(pid, &status, WNOHANG);
            if (wr == pid) {
                child_running = false;
                if (WIFEXITED(status)) {
                    out_result->exit_code = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    out_result->exit_code = 128 + WTERMSIG(status);
                }
            }
        }
    }

    out_result->duration_ms = (uint32_t)(monotonic_ms() - start_ms);
    return true;

cleanup:
    if (pid > 0) {
        killpg(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    if (out_pipe[0] >= 0) close(out_pipe[0]);
    if (out_pipe[1] >= 0) close(out_pipe[1]);
    if (err_pipe[0] >= 0) close(err_pipe[0]);
    if (err_pipe[1] >= 0) close(err_pipe[1]);
    usb_responder_shell_exec_result_free(out_result);
    return false;
}

void usb_responder_shell_exec_result_free(usb_responder_shell_exec_result_t* result) {
    if (!result) {
        return;
    }
    free(result->stdout_data);
    free(result->stderr_data);
    memset(result, 0, sizeof(*result));
}
