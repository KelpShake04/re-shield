#if !defined(_WIN32)

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "file_platform.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* O_NONBLOCK keeps open() from blocking on a FIFO; non-regular files are rejected. */
int reshield_file_open_regular(const char *path, reshield_file_t *handle_out, uint64_t *size_out) {
    if (path == NULL || handle_out == NULL) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        return -1;
    }
    *handle_out = (reshield_file_t)fd;
    if (size_out != NULL) {
        *size_out = (uint64_t)st.st_size;
    }
    return 0;
}

intptr_t reshield_file_read(reshield_file_t handle, void *buf, size_t n) {
    for (;;) {
        ssize_t r = read((int)handle, buf, n);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return (intptr_t)r;
    }
}

void reshield_file_close(reshield_file_t handle) {
    close((int)handle);
}

#define WALK_PATH_MAX 4096u

typedef struct {
    char   path[WALK_PATH_MAX]; /* full path of the directory being read, then of each entry */
    size_t rel_off;             /* offset in path where the base-relative part starts */
    unsigned max_depth;
    size_t max_entries;
    size_t count;
    int  (*visit)(const char *, void *);
    void  *ctx;
} walk_t;

/* path[0..dir_len) is the directory to read. Returns 0, 1 (visitor stopped) or -1. */
static int walk_dir(walk_t *w, size_t dir_len, unsigned depth) {
    DIR *d = opendir(w->path);
    if (d == NULL) {
        return -1;
    }
    size_t sep = (dir_len > 0 && w->path[dir_len - 1] == '/') ? 0u : 1u;
    int rc = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (e == NULL) {
            rc = errno != 0 ? -1 : 0;
            break;
        }
        const char *name = e->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        size_t n = strlen(name);
        if (dir_len + sep + n + 1u > WALK_PATH_MAX || ++w->count > w->max_entries) {
            rc = -1;
            break;
        }
        if (sep) {
            w->path[dir_len] = '/';
        }
        memcpy(w->path + dir_len + sep, name, n + 1u);
        struct stat st;
        if (lstat(w->path, &st) != 0) { /* lstat: a symlink is an item, never followed */
            rc = -1;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (depth + 1u > w->max_depth) {
                rc = -1;
                break;
            }
            rc = walk_dir(w, dir_len + sep + n, depth + 1u);
        } else {
            rc = w->visit(w->path + w->rel_off, w->ctx) != 0 ? 1 : 0;
        }
        w->path[dir_len] = '\0';
        if (rc != 0) {
            break;
        }
    }
    closedir(d);
    return rc;
}

int reshield_dir_walk(const char *base_dir, unsigned max_depth, size_t max_entries,
                      int (*visit)(const char *rel_path, void *ctx), void *ctx) {
    if (visit == NULL) {
        return -1;
    }
    if (base_dir == NULL || base_dir[0] == '\0') {
        base_dir = ".";
    }
    size_t len = strlen(base_dir);
    if (len + 1u > WALK_PATH_MAX) {
        return -1;
    }
    walk_t *w = (walk_t *)malloc(sizeof(*w)); /* 4 KiB: keep it off the recursion stack */
    if (w == NULL) {
        return -1;
    }
    memcpy(w->path, base_dir, len + 1u);
    while (len > 1u && w->path[len - 1] == '/') {
        w->path[--len] = '\0';
    }
    w->rel_off = w->path[len - 1] == '/' ? len : len + 1u;
    w->max_depth = max_depth;
    w->max_entries = max_entries;
    w->count = 0;
    w->visit = visit;
    w->ctx = ctx;
    int rc = walk_dir(w, len, 0);
    free(w);
    return rc;
}

#else
typedef int reshield_file_posix_unused_t;
#endif
