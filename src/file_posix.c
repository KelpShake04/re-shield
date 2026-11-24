#if !defined(_WIN32)

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "file_platform.h"

#include <errno.h>
#include <fcntl.h>
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

#else
typedef int reshield_file_posix_unused_t;
#endif
