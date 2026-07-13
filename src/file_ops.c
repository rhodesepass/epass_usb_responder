#include "file_ops.h"

#include "io_utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define USB_RESPONDER_UPLOAD_DEBUG 1

#if USB_RESPONDER_UPLOAD_DEBUG
static int64_t debug_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

/* 每写入这么多字节就主动把脏页刷到 NAND。机器只有 ~57MB 内存、NAND 写很慢，
 * 若任由脏页堆到 dirty_ratio（~9MB）触发 balance_dirty_pages，内核会强制 write()
 * 同步回写，而慢 NAND 在 GC/擦除时吞吐塌到近零，单次 write 可卡几百秒，期间不读
 * USB OUT 端点导致上位机超时。主动按 1MB 节奏 fsync 把在途脏数据钳小，让每次停顿
 * 都有界，避免那种无界长停顿。 */
#define USB_RESPONDER_UPLOAD_SYNC_INTERVAL (1u << 20)

#if USB_RESPONDER_UPLOAD_DEBUG
/* 直接写入 /dev/kmsg 确保消息出现在 dmesg 中，不依赖 syslogd/journald 是否运行 */
static void debug_kmsg(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

static void debug_kmsg(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    int fd;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) {
        return;
    }

    fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    /* <6> = LOG_INFO 优先级，消息会出现在 dmesg */
    dprintf(fd, "<6>epass_upload: %s\n", buf);
    close(fd);
}
#endif

static void upload_pace_writeback(usb_responder_upload_session_t* session) {
    int fd;
#if USB_RESPONDER_UPLOAD_DEBUG
    int64_t t0 = debug_now_ms();
#endif
    if (!session->fp || fflush(session->fp) != 0) {
        return;
    }
    fd = fileno(session->fp);
    if (fd < 0 || fsync(fd) != 0) {
        return;
    }
    /* 落盘后的页已是干净页，主动让内核回收，避免页缓存在小内存机器上膨胀。
     * POSIX_FADV_DONTNEED 在部分 libc 上是 no-op，但关键的 fsync 已经达成目的。 */
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#if USB_RESPONDER_UPLOAD_DEBUG
    {
        int64_t elapsed = debug_now_ms() - t0;
        debug_kmsg("sync done path=%s bytes=%llu elapsed_ms=%lld",
                   session->relative_path,
                   (unsigned long long)session->bytes_written,
                   (long long)elapsed);
        if (elapsed > 500) {
            debug_kmsg("SLOW_SYNC path=%s elapsed_ms=%lld (>500ms!)",
                       session->relative_path, (long long)elapsed);
        }
    }
#endif
}

static void set_file_error(const char* prefix, const char* path) {
    char msg[512];
    snprintf(msg, sizeof(msg), "%s %s: %s", prefix, path ? path : "", strerror(errno));
    usb_responder_set_last_error(msg);
}

const char* usb_responder_storage_name(usb_responder_storage_t storage) {
    switch (storage) {
    case USB_RESPONDER_STORAGE_NAND:
        return "nand";
    case USB_RESPONDER_STORAGE_SD:
        return "sd";
    default:
        return "unknown";
    }
}

bool usb_responder_storage_from_name(const char* name, usb_responder_storage_t* out) {
    if (!name || !out) {
        return false;
    }
    if (strcmp(name, "nand") == 0) {
        *out = USB_RESPONDER_STORAGE_NAND;
        return true;
    }
    if (strcmp(name, "sd") == 0) {
        *out = USB_RESPONDER_STORAGE_SD;
        return true;
    }
    return false;
}

static bool path_is_storage_root(const char* abs_path) {
    return strcmp(abs_path, "/") == 0 || strcmp(abs_path, "/sd") == 0;
}

static bool path_component_is_dotdot(const char* start, size_t len) {
    return len == 2 && start[0] == '.' && start[1] == '.';
}

static bool path_component_is_dot(const char* start, size_t len) {
    return len == 1 && start[0] == '.';
}

static bool build_path(const char* relative, char* out_path, size_t out_size, usb_responder_storage_t* out_storage) {
    const char* r = relative;
    size_t used = 1;
    bool saw_component = false;
    usb_responder_storage_t storage = USB_RESPONDER_STORAGE_NAND;

    if (!relative || !out_path || out_size < 2) {
        return false;
    }

    out_path[0] = '/';
    out_path[1] = '\0';
    while (*r != '\0') {
        const char* slash = NULL;
        size_t seglen = 0;

        while (*r == '/') {
            ++r;
        }
        if (*r == '\0') {
            break;
        }
        slash = strchr(r, '/');
        seglen = slash ? (size_t)(slash - r) : strlen(r);
        if (path_component_is_dotdot(r, seglen)) {
            usb_responder_set_last_error("path traversal not allowed");
            return false;
        }
        if (!path_component_is_dot(r, seglen)) {
            if (!saw_component && seglen == 2 && r[0] == 's' && r[1] == 'd') {
                storage = USB_RESPONDER_STORAGE_SD;
            }
            if (used + (used > 1 ? 1u : 0u) + seglen >= out_size) {
                usb_responder_set_last_error("path too long");
                return false;
            }
            if (used > 1) {
                out_path[used++] = '/';
            }
            memcpy(out_path + used, r, seglen);
            used += seglen;
            out_path[used] = '\0';
            saw_component = true;
        }
        r = slash ? slash + 1 : "";
    }

    if (out_storage) {
        *out_storage = storage;
    }
    return true;
}

static bool path_storage_matches_desire(usb_responder_storage_t actual, const char* desire_storage) {
    usb_responder_storage_t desired;

    if (!desire_storage || desire_storage[0] == '\0') {
        return true;
    }
    if (!usb_responder_storage_from_name(desire_storage, &desired)) {
        usb_responder_set_last_error("invalid desire_storage");
        return false;
    }
    if (desired != actual) {
        char msg[128];
        snprintf(msg,
                 sizeof(msg),
                 "desire_storage=%s but path is on %s",
                 usb_responder_storage_name(desired),
                 usb_responder_storage_name(actual));
        usb_responder_set_last_error(msg);
        return false;
    }
    return true;
}

static bool read_mountinfo_sd(char* source, size_t source_size) {
    FILE* f = NULL;
    char line[2048];
    bool found = false;

    if (!source || source_size == 0) {
        return false;
    }
    source[0] = '\0';
    f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        return false;
    }
    while (fgets(line, sizeof(line), f)) {
        char mount_point[USB_RESPONDER_PATH_MAX_LEN];
        char fs_type[128];
        char mount_source[USB_RESPONDER_PATH_MAX_LEN];
        char* sep = strstr(line, " - ");

        mount_point[0] = '\0';
        fs_type[0] = '\0';
        mount_source[0] = '\0';
        if (sscanf(line, "%*s %*s %*s %*s %4095s %*s", mount_point) != 1) {
            continue;
        }
        if (!sep || strcmp(mount_point, "/sd") != 0) {
            continue;
        }
        if (sscanf(sep + 3, "%127s %4095s", fs_type, mount_source) != 2) {
            continue;
        }
        if (strstr(mount_source, "/dev/mmcblk") != NULL) {
            snprintf(source, source_size, "%s", mount_source);
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static bool is_sd_mounted(void) {
    char source[USB_RESPONDER_PATH_MAX_LEN];
    return read_mountinfo_sd(source, sizeof(source));
}

static bool ensure_storage_writeable(usb_responder_storage_t storage) {
    if (storage == USB_RESPONDER_STORAGE_SD && !is_sd_mounted()) {
        usb_responder_set_last_error("sd storage is not mounted on mmc");
        return false;
    }
    return true;
}

static bool parse_perm_octal(const char* perm_str, mode_t* out_mode) {
    char* end = NULL;
    unsigned long val = 0;

    if (!perm_str || perm_str[0] == '\0' || !out_mode) {
        return false;
    }
    val = strtoul(perm_str, &end, 8);
    if (end == perm_str || *end != '\0' || val > 07777u) {
        usb_responder_set_last_error("invalid perm");
        return false;
    }
    *out_mode = (mode_t)(val & 07777u);
    return true;
}

static void storage_statvfs_or_zero(const char* path, uint64_t* total_bytes, uint64_t* free_bytes) {
    struct statvfs sv;

    *total_bytes = 0;
    *free_bytes = 0;
    if (statvfs(path, &sv) != 0) {
        return;
    }
    *total_bytes = (uint64_t)sv.f_blocks * (uint64_t)sv.f_frsize;
    *free_bytes = (uint64_t)sv.f_bavail * (uint64_t)sv.f_frsize;
}

static usb_responder_upload_session_t* find_session(usb_responder_file_ops_t* ops, uint32_t transfer_id) {
    for (size_t i = 0; i < USB_RESPONDER_MAX_UPLOAD_SESSIONS; ++i) {
        if (ops->sessions[i].used && ops->sessions[i].transfer_id == transfer_id) {
            return &ops->sessions[i];
        }
    }
    return NULL;
}

static usb_responder_upload_session_t* alloc_session(usb_responder_file_ops_t* ops) {
    for (size_t i = 0; i < USB_RESPONDER_MAX_UPLOAD_SESSIONS; ++i) {
        if (!ops->sessions[i].used) {
            ops->sessions[i].used = true;
            return &ops->sessions[i];
        }
    }
    return NULL;
}

bool usb_responder_file_ops_init(usb_responder_file_ops_t* ops) {
    if (!ops) {
        usb_responder_set_last_error("invalid file ops");
        return false;
    }
    memset(ops, 0, sizeof(*ops));
    return true;
}

bool usb_responder_storage_info_read(usb_responder_storage_info_t* out) {
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    storage_statvfs_or_zero("/", &out->nand_total_bytes, &out->nand_free_bytes);
    out->sd_mounted = is_sd_mounted();
    if (out->sd_mounted) {
        storage_statvfs_or_zero("/sd", &out->sd_total_bytes, &out->sd_free_bytes);
    }
    return true;
}

void usb_responder_file_ops_shutdown(usb_responder_file_ops_t* ops) {
    if (!ops) {
        return;
    }
    for (size_t i = 0; i < USB_RESPONDER_MAX_UPLOAD_SESSIONS; ++i) {
        if (ops->sessions[i].used) {
            if (ops->sessions[i].fp) {
                fclose(ops->sessions[i].fp);
            }
            unlink(ops->sessions[i].temp_path);
        }
    }
    memset(ops->sessions, 0, sizeof(ops->sessions));
}

bool usb_responder_file_begin_upload(
    usb_responder_file_ops_t* ops,
    uint32_t transfer_id,
    const char* relative_path,
    const char* desire_storage,
    const char* perm) {
    usb_responder_upload_session_t* session = NULL;
    usb_responder_storage_t storage = USB_RESPONDER_STORAGE_NAND;

    if (!ops || !relative_path) {
        usb_responder_set_last_error("invalid upload session");
        return false;
    }
    /* 上次上传未完成时客户端常会带着同一 transfer_id 重试 BEGIN；先清理残留会话。 */
    if (find_session(ops, transfer_id)) {
        usb_responder_file_abort_upload(ops, transfer_id);
    }
    session = alloc_session(ops);
    if (!session) {
        usb_responder_set_last_error("no free upload session");
        return false;
    }
    session->apply_perm = false;
    session->file_mode = 0644;
    if (perm != NULL && perm[0] != '\0') {
        if (!parse_perm_octal(perm, &session->file_mode)) {
            session->used = false;
            return false;
        }
        session->apply_perm = true;
    }
    if (!build_path(relative_path, session->final_path, sizeof(session->final_path), &storage) ||
        !path_storage_matches_desire(storage, desire_storage) || !ensure_storage_writeable(storage)) {
        session->used = false;
        return false;
    }
    if (snprintf(session->relative_path, sizeof(session->relative_path), "%s", relative_path) >=
        (int)sizeof(session->relative_path)) {
        session->used = false;
        usb_responder_set_last_error("relative path too long");
        return false;
    }
    if (snprintf(session->temp_path, sizeof(session->temp_path), "%s.part", session->final_path) >=
        (int)sizeof(session->temp_path)) {
        session->used = false;
        usb_responder_set_last_error("temp path too long");
        return false;
    }

    session->fp = fopen(session->temp_path, "wb");
    if (!session->fp) {
        session->used = false;
        set_file_error("fopen", session->temp_path);
#if USB_RESPONDER_UPLOAD_DEBUG
        debug_kmsg("begin_upload FAIL fopen path=%s temp=%s err=%s",
                   relative_path, session->temp_path, strerror(errno));
#endif
        return false;
    }
    session->transfer_id = transfer_id;
    session->bytes_written = 0;
    session->synced_bytes = 0;
#if USB_RESPONDER_UPLOAD_DEBUG
    debug_kmsg("begin_upload OK path=%s temp=%s tid=%u storage=%s",
               relative_path, session->temp_path, transfer_id,
               usb_responder_storage_name(storage));
#endif
    return true;
}

bool usb_responder_file_append_upload_chunk(
    usb_responder_file_ops_t* ops, uint32_t transfer_id, const uint8_t* data, size_t size) {
    usb_responder_upload_session_t* session = NULL;
#if USB_RESPONDER_UPLOAD_DEBUG
    int64_t t0 = debug_now_ms();
#endif
    if (!ops || !data || size == 0) {
        usb_responder_set_last_error("invalid upload chunk");
        return false;
    }
    session = find_session(ops, transfer_id);
    if (!session || !session->fp) {
        usb_responder_set_last_error("upload session not found");
        return false;
    }
#if USB_RESPONDER_UPLOAD_DEBUG
    {
        int64_t t_fwrite = debug_now_ms();
#endif
    if (fwrite(data, 1, size, session->fp) != size) {
        set_file_error("fwrite", session->temp_path);
        return false;
    }
#if USB_RESPONDER_UPLOAD_DEBUG
        int64_t fwrite_elapsed = debug_now_ms() - t_fwrite;
        if (fwrite_elapsed > 100) {
            debug_kmsg("SLOW_FWRITE path=%s size=%zu elapsed=%lldms total=%llu",
                       session->relative_path, size, (long long)fwrite_elapsed,
                       (unsigned long long)(session->bytes_written + size));
        }
    }
#endif
    session->bytes_written += size;
    if (session->bytes_written - session->synced_bytes >= USB_RESPONDER_UPLOAD_SYNC_INTERVAL) {
        upload_pace_writeback(session);
        session->synced_bytes = session->bytes_written;
    }
#if USB_RESPONDER_UPLOAD_DEBUG
    {
        int64_t total_elapsed = debug_now_ms() - t0;
        if (total_elapsed > 200) {
            debug_kmsg("SLOW_CHUNK path=%s size=%zu total_elapsed=%lldms total_written=%llu",
                       session->relative_path, size, (long long)total_elapsed,
                       (unsigned long long)session->bytes_written);
        }
    }
#endif
    return true;
}

bool usb_responder_file_finish_upload(usb_responder_file_ops_t* ops, uint32_t transfer_id) {
    usb_responder_upload_session_t* session = NULL;
#if USB_RESPONDER_UPLOAD_DEBUG
    int64_t t0 = debug_now_ms();
#endif
    if (!ops) {
        usb_responder_set_last_error("invalid file ops");
        return false;
    }
    session = find_session(ops, transfer_id);
    if (!session) {
        usb_responder_set_last_error("upload session not found");
        return false;
    }
#if USB_RESPONDER_UPLOAD_DEBUG
    {
        char path_copy[USB_RESPONDER_PATH_MAX_LEN];
        uint64_t total_bytes;
        snprintf(path_copy, sizeof(path_copy), "%s", session->relative_path);
        total_bytes = session->bytes_written;
#endif
    if (session->fp) {
#if USB_RESPONDER_UPLOAD_DEBUG
        int64_t t_close = debug_now_ms();
#endif
        fclose(session->fp);
        session->fp = NULL;
#if USB_RESPONDER_UPLOAD_DEBUG
        {
            int64_t close_elapsed = debug_now_ms() - t_close;
            debug_kmsg("finish fclose path=%s elapsed=%lldms total_bytes=%llu",
                       path_copy, (long long)close_elapsed,
                       (unsigned long long)total_bytes);
            if (close_elapsed > 500) {
                debug_kmsg("SLOW_FCLOSE path=%s elapsed=%lldms (>500ms!)",
                           path_copy, (long long)close_elapsed);
            }
        }
#endif
    }
    if (rename(session->temp_path, session->final_path) != 0) {
        set_file_error("rename", session->final_path);
        unlink(session->temp_path);
        memset(session, 0, sizeof(*session));
        return false;
    }
    if (session->apply_perm) {
        if (chmod(session->final_path, session->file_mode) != 0) {
            set_file_error("chmod", session->final_path);
            unlink(session->final_path);
            memset(session, 0, sizeof(*session));
            return false;
        }
    }
#if USB_RESPONDER_UPLOAD_DEBUG
        debug_kmsg("finish OK path=%s final=%s total_bytes=%llu total_elapsed=%lldms",
                   path_copy, session->final_path,
                   (unsigned long long)total_bytes,
                   (long long)(debug_now_ms() - t0));
    }
#endif
    memset(session, 0, sizeof(*session));
    return true;
}

bool usb_responder_file_abort_upload(usb_responder_file_ops_t* ops, uint32_t transfer_id) {
    usb_responder_upload_session_t* session = NULL;
    if (!ops) {
        return false;
    }
    session = find_session(ops, transfer_id);
    if (!session) {
        return false;
    }
    if (session->fp) {
        fclose(session->fp);
        session->fp = NULL;
    }
    unlink(session->temp_path);
    memset(session, 0, sizeof(*session));
    return true;
}

bool usb_responder_file_read(
    const usb_responder_file_ops_t* ops, const char* relative_path, uint8_t** out_data, size_t* out_size) {
    char path[USB_RESPONDER_PATH_MAX_LEN];
    if (!ops || !relative_path || !out_data || !out_size) {
        return false;
    }
    if (!build_path(relative_path, path, sizeof(path), NULL)) {
        return false;
    }
    return usb_responder_read_file_all(path, out_data, out_size);
}

static bool list_append_line(char** text, size_t* used, size_t* cap, const char* name) {
    size_t n = strlen(name) + 1;
    if (*used + n + 1 > *cap) {
        size_t new_cap = (*cap == 0) ? 256u : *cap;
        while (new_cap < *used + n + 1) {
            new_cap *= 2u;
        }
        char* next = (char*)realloc(*text, new_cap);
        if (!next) {
            return false;
        }
        *text = next;
        *cap = new_cap;
    }
    memcpy(*text + *used, name, n - 1);
    (*text)[*used + n - 1] = '\n';
    *used += n;
    return true;
}

static char* list_finalize(char* text, size_t used) {
    if (!text) {
        return (char*)calloc(1, 1);
    }
    text[used] = '\0';
    return text;
}

bool usb_responder_file_list(
    const usb_responder_file_ops_t* ops, const char* relative_path, char** out_files, char** out_dirs) {
    DIR* dir = NULL;
    struct dirent* de = NULL;
    char dirpath[USB_RESPONDER_PATH_MAX_LEN];
    char* files = NULL;
    char* dirs = NULL;
    size_t fu = 0, fc = 0, du = 0, dc = 0;

    if (!ops || !relative_path || !out_files || !out_dirs) {
        return false;
    }
    *out_files = NULL;
    *out_dirs = NULL;
    if (!build_path(relative_path, dirpath, sizeof(dirpath), NULL)) {
        return false;
    }
    dir = opendir(dirpath);
    if (!dir) {
        return false;
    }
    while ((de = readdir(dir)) != NULL) {
        char child[USB_RESPONDER_PATH_MAX_LEN];
        struct stat st;
        int n = 0;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        n = snprintf(child, sizeof(child), "%s/%s", dirpath, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            closedir(dir);
            free(files);
            free(dirs);
            usb_responder_set_last_error("path too long");
            return false;
        }
        if (lstat(child, &st) != 0) {
            set_file_error("lstat", child);
            closedir(dir);
            free(files);
            free(dirs);
            return false;
        }
        if (S_ISDIR(st.st_mode)) {
            if (!list_append_line(&dirs, &du, &dc, de->d_name)) {
                closedir(dir);
                free(files);
                free(dirs);
                usb_responder_set_last_error("oom");
                return false;
            }
        } else {
            if (!list_append_line(&files, &fu, &fc, de->d_name)) {
                closedir(dir);
                free(files);
                free(dirs);
                usb_responder_set_last_error("oom");
                return false;
            }
        }
    }
    closedir(dir);

    *out_files = list_finalize(files, fu);
    *out_dirs = list_finalize(dirs, du);
    if (!*out_files || !*out_dirs) {
        free(*out_files);
        free(*out_dirs);
        *out_files = NULL;
        *out_dirs = NULL;
        usb_responder_set_last_error("oom");
        return false;
    }
    return true;
}

bool usb_responder_file_stat(
    const usb_responder_file_ops_t* ops, const char* relative_path, usb_responder_stat_info_t* out) {
    char path[USB_RESPONDER_PATH_MAX_LEN];
    struct stat st;
    char userbuf[128];
    char groupbuf[128];
    struct passwd pws;
    struct passwd* pw_ptr = NULL;
    char pwbuf[4096];
    struct group grs;
    struct group* gr_ptr = NULL;
    char grbuf[4096];

    if (!ops || !relative_path || !out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!build_path(relative_path, path, sizeof(path), NULL)) {
        return false;
    }
    if (lstat(path, &st) != 0) {
        set_file_error("lstat", path);
        return false;
    }

    if (getpwuid_r(st.st_uid, &pws, pwbuf, sizeof(pwbuf), &pw_ptr) != 0 || pw_ptr == NULL) {
        snprintf(userbuf, sizeof(userbuf), "%u", (unsigned)st.st_uid);
    } else {
        snprintf(userbuf, sizeof(userbuf), "%s", pw_ptr->pw_name);
    }
    if (getgrgid_r(st.st_gid, &grs, grbuf, sizeof(grbuf), &gr_ptr) != 0 || gr_ptr == NULL) {
        snprintf(groupbuf, sizeof(groupbuf), "%u", (unsigned)st.st_gid);
    } else {
        snprintf(groupbuf, sizeof(groupbuf), "%s", gr_ptr->gr_name);
    }
    snprintf(out->owner, sizeof(out->owner), "%s:%s", userbuf, groupbuf);
    snprintf(out->perm, sizeof(out->perm), "%04o", (unsigned)(st.st_mode & 07777));
    snprintf(out->size, sizeof(out->size), "%llu", (unsigned long long)st.st_size);
    if (S_ISREG(st.st_mode)) {
        snprintf(out->type, sizeof(out->type), "file");
    } else if (S_ISDIR(st.st_mode)) {
        snprintf(out->type, sizeof(out->type), "dir");
    } else if (S_ISLNK(st.st_mode)) {
        snprintf(out->type, sizeof(out->type), "link");
    } else {
        snprintf(out->type, sizeof(out->type), "other");
    }
    return true;
}

static bool remove_path_recursive(const char* abs_path) {
    struct stat st;

    if (lstat(abs_path, &st) != 0) {
        set_file_error("lstat", abs_path);
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR* d = opendir(abs_path);
        struct dirent* de = NULL;
        if (!d) {
            set_file_error("opendir", abs_path);
            return false;
        }
        while ((de = readdir(d)) != NULL) {
            char child[USB_RESPONDER_PATH_MAX_LEN];
            int n = 0;
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
            n = snprintf(child, sizeof(child), "%s/%s", abs_path, de->d_name);
            if (n <= 0 || (size_t)n >= sizeof(child)) {
                closedir(d);
                usb_responder_set_last_error("path too long");
                return false;
            }
            if (!remove_path_recursive(child)) {
                closedir(d);
                return false;
            }
        }
        closedir(d);
        if (rmdir(abs_path) != 0) {
            set_file_error("rmdir", abs_path);
            return false;
        }
        return true;
    }
    if (unlink(abs_path) != 0) {
        set_file_error("unlink", abs_path);
        return false;
    }
    return true;
}

bool usb_responder_file_delete(
    const usb_responder_file_ops_t* ops, const char* relative_path, const char* desire_storage) {
    char path[USB_RESPONDER_PATH_MAX_LEN];
    usb_responder_storage_t storage = USB_RESPONDER_STORAGE_NAND;
    if (!ops || !relative_path) {
        return false;
    }
    if (!build_path(relative_path, path, sizeof(path), &storage) ||
        !path_storage_matches_desire(storage, desire_storage) || !ensure_storage_writeable(storage)) {
        return false;
    }
    if (path_is_storage_root(path)) {
        usb_responder_set_last_error("refusing to delete storage root");
        return false;
    }
    return remove_path_recursive(path);
}

bool usb_responder_dir_mkdir(
    usb_responder_file_ops_t* ops, const char* relative_path, bool parents, const char* desire_storage) {
    char path[USB_RESPONDER_PATH_MAX_LEN];
    char work[USB_RESPONDER_PATH_MAX_LEN];
    const char* r = NULL;
    usb_responder_storage_t storage = USB_RESPONDER_STORAGE_NAND;

    if (!ops || !relative_path) {
        return false;
    }
    if (!build_path(relative_path, path, sizeof(path), &storage) ||
        !path_storage_matches_desire(storage, desire_storage) || !ensure_storage_writeable(storage)) {
        return false;
    }
    if (!parents) {
        if (mkdir(path, 0755) != 0) {
            set_file_error("mkdir", path);
            return false;
        }
        return true;
    }

    if (snprintf(work, sizeof(work), "/") >= (int)sizeof(work)) {
        usb_responder_set_last_error("path too long");
        return false;
    }
    r = path + 1;
    while (*r != '\0') {
        const char* slash = NULL;
        const char* sep = NULL;
        size_t seglen = 0;
        size_t wlen = 0;
        int n = 0;

        while (*r == '/') {
            ++r;
        }
        if (*r == '\0') {
            break;
        }
        slash = strchr(r, '/');
        seglen = slash ? (size_t)(slash - r) : strlen(r);
        if (seglen == 0) {
            break;
        }

        wlen = strlen(work);
        sep = (strcmp(work, "/") == 0) ? "" : "/";
        n = snprintf(work + wlen, sizeof(work) - wlen, "%s%.*s", sep, (int)seglen, r);
        if (n <= 0 || wlen + (size_t)n >= sizeof(work)) {
            usb_responder_set_last_error("path too long");
            return false;
        }

        if (mkdir(work, 0755) != 0) {
            if (errno != EEXIST) {
                set_file_error("mkdir", work);
                return false;
            }
            {
                struct stat st;
                if (stat(work, &st) != 0) {
                    set_file_error("stat", work);
                    return false;
                }
                if (!S_ISDIR(st.st_mode)) {
                    usb_responder_set_last_error("path exists and is not a directory");
                    return false;
                }
            }
        }
        r = slash ? slash + 1 : "";
    }
    return true;
}

bool usb_responder_file_rename(
    const usb_responder_file_ops_t* ops,
    const char* from_relative,
    const char* to_relative,
    const char* desire_storage) {
    char from_path[USB_RESPONDER_PATH_MAX_LEN];
    char to_path[USB_RESPONDER_PATH_MAX_LEN];
    usb_responder_storage_t from_storage = USB_RESPONDER_STORAGE_NAND;
    usb_responder_storage_t to_storage = USB_RESPONDER_STORAGE_NAND;
    if (!ops || !from_relative || !to_relative) {
        return false;
    }
    if (!build_path(from_relative, from_path, sizeof(from_path), &from_storage) ||
        !build_path(to_relative, to_path, sizeof(to_path), &to_storage) ||
        !path_storage_matches_desire(from_storage, desire_storage) ||
        !path_storage_matches_desire(to_storage, desire_storage) ||
        !ensure_storage_writeable(from_storage) ||
        (to_storage != from_storage && !ensure_storage_writeable(to_storage))) {
        return false;
    }
    if (path_is_storage_root(from_path) || path_is_storage_root(to_path)) {
        usb_responder_set_last_error("refusing to rename storage root");
        return false;
    }
    if (from_storage != to_storage) {
        usb_responder_set_last_error("cross-storage rename is not supported");
        return false;
    }
    if (rename(from_path, to_path) != 0) {
        set_file_error("rename", to_path);
        return false;
    }
    return true;
}
