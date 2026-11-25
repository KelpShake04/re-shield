#ifndef RESHIELD_FILE_PLATFORM_H
#define RESHIELD_FILE_PLATFORM_H

/* Internal (not installed) platform file I/O used by sha256.c and manifest.c.
 * Implemented in file_posix.c and file_windows.c. Paths are UTF-8. */

#include <stddef.h>
#include <stdint.h>

/* POSIX file descriptor or Windows HANDLE. */
typedef intptr_t reshield_file_t;

/* Return values of the open and read calls below when the failure is environmental, not a
 * statement about the file: access denied, sharing/lock violation, antivirus block, I/O error.
 * Every other failure (missing file, directory, special file, bad path, unknown cause) stays -1,
 * which callers treat as a tamper verdict (fail closed). */
#define RESHIELD_FILE_UNREADABLE (-2)

/* Opens `path` read-only. Succeeds (returns 0) only for a regular file, and never blocks
 * on FIFOs or devices. *size_out receives the current file size. Returns -1 otherwise, or
 * RESHIELD_FILE_UNREADABLE when the file could not be opened for the reason above. */
int reshield_file_open_regular(const char *path, reshield_file_t *handle_out, uint64_t *size_out);

/* Reads up to n bytes once: -1 on error, RESHIELD_FILE_UNREADABLE on an I/O, lock or access
 * error, 0 at EOF, otherwise the byte count (retries EINTR). */
intptr_t reshield_file_read(reshield_file_t handle, void *buf, size_t n);

void reshield_file_close(reshield_file_t handle);

/* Recursively lists `base_dir` (UTF-8; NULL or "" means ".") for the strict manifest scan.
 * Symlinks and Windows reparse points are NOT followed: they are reported like files.
 * visit(rel_path, ctx) is called for every entry that is not a real directory (regular
 * files, symlinks, reparse points, FIFOs, devices, ...). rel_path is UTF-8 with '/'
 * separators, relative to base_dir. Names are compared as bytes, never normalized.
 * visit returns 0 to continue, non-zero to stop.
 * Returns 0 when the walk finished, 1 when visit stopped it, -1 on any error or limit:
 * unreadable directory, nesting deeper than max_depth, more than max_entries entries
 * (directories count), a path that does not fit the internal 4096-char buffer, or (Windows)
 * a name that is not valid UTF-16. The caller must treat -1 as "cannot verify". */
int reshield_dir_walk(const char *base_dir, unsigned max_depth, size_t max_entries,
                      int (*visit)(const char *rel_path, void *ctx), void *ctx);

/* Reads until n bytes or EOF. Returns the byte count (< n only at EOF), or the negative
 * error value of reshield_file_read(). */
static inline intptr_t reshield_file_read_full(reshield_file_t handle, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        intptr_t r = reshield_file_read(handle, (uint8_t *)buf + got, n - got);
        if (r < 0) {
            return r;
        }
        if (r == 0) {
            break;
        }
        got += (size_t)r;
    }
    return (intptr_t)got;
}

#endif /* RESHIELD_FILE_PLATFORM_H */
