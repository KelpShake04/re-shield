#ifndef RESHIELD_FILE_PLATFORM_H
#define RESHIELD_FILE_PLATFORM_H

/* Internal (not installed) platform file I/O used by sha256.c and manifest.c.
 * Implemented in file_posix.c and file_windows.c. Paths are UTF-8. */

#include <stddef.h>
#include <stdint.h>

/* POSIX file descriptor or Windows HANDLE. */
typedef intptr_t reshield_file_t;

/* Opens `path` read-only. Succeeds (returns 0) only for a regular file, and never blocks
 * on FIFOs or devices. *size_out receives the current file size. Returns -1 otherwise. */
int reshield_file_open_regular(const char *path, reshield_file_t *handle_out, uint64_t *size_out);

/* Reads up to n bytes once: -1 on error, 0 at EOF, otherwise the byte count (retries EINTR). */
intptr_t reshield_file_read(reshield_file_t handle, void *buf, size_t n);

void reshield_file_close(reshield_file_t handle);

/* Reads until n bytes or EOF. Returns the byte count (< n only at EOF) or -1 on error. */
static inline intptr_t reshield_file_read_full(reshield_file_t handle, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        intptr_t r = reshield_file_read(handle, (uint8_t *)buf + got, n - got);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            break;
        }
        got += (size_t)r;
    }
    return (intptr_t)got;
}

#endif /* RESHIELD_FILE_PLATFORM_H */
