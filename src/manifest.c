#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "reshield/manifest.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef RESHIELD_DISABLE
/* Internal helper in sha256.c: hashes at most max_read bytes of a regular file. */
extern int reshield_sha256_file_limited(const char *path,
                                        uint8_t out_hash[RESHIELD_SHA256_SIZE],
                                        uint64_t *out_size,
                                        uint64_t max_read);

#define RESHIELD_MANIFEST_MAX_BYTES (4u * 1024u * 1024u)
#define RESHIELD_MANIFEST_MAX_LINE  1023u

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_sha256_hex(const char *hex, uint8_t out[RESHIELD_SHA256_SIZE]) {
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        int hi = hex_nibble(hex[i * 2 + 0]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Component-wise check: rejects absolute paths, empty components, ".." components,
 * and CR/LF. Names that merely contain ".." (e.g. "v1..2.cfg") are allowed. */
static int is_safe_relative_path(const char *rel) {
    if (rel == NULL || rel[0] == '\0' || rel[0] == '/') {
        return 0;
    }
    const char *p = rel;
    for (;;) {
        const char *q = p;
        while (*q != '\0' && *q != '/') {
            if (*q == '\n' || *q == '\r') {
                return 0;
            }
            q++;
        }
        size_t n = (size_t)(q - p);
        if (n == 0 || (n == 2 && p[0] == '.' && p[1] == '.')) {
            return 0;
        }
        if (*q == '\0') {
            return 1;
        }
        p = q + 1;
    }
}

static void copy_failed_path(char *dst, size_t cap, const char *src) {
    if (dst == NULL || cap == 0 || src == NULL) {
        return;
    }
    size_t len = strlen(src);
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int parse_manifest_line(const char *line,
                               uint8_t out_hash[RESHIELD_SHA256_SIZE],
                               uint64_t *out_size,
                               const char **out_rel_path) {
    /* Format: <64-hex-sha256> <byte-size> <relative-path> */
    if (strlen(line) < 68) {
        return -1;
    }
    if (parse_sha256_hex(line, out_hash) != 0) {
        return -1;
    }
    if (line[64] != ' ') {
        return -1;
    }
    const char *p = line + 65;
    if (!isdigit((unsigned char)*p)) {
        return -1;
    }
    char *endptr = NULL;
    unsigned long long sz = strtoull(p, &endptr, 10);
    if (endptr == p || *endptr != ' ') {
        return -1;
    }
    const char *rel = endptr + 1;
    if (!is_safe_relative_path(rel)) {
        return -1;
    }
    *out_size = (uint64_t)sz;
    *out_rel_path = rel;
    return 0;
}

/* Reads the whole manifest once (single open, regular files only, size-capped) so the
 * root hash and the parsed entries come from the same bytes. *out_buf is NUL-terminated
 * and owned by the caller. */
static int read_manifest_file(const char *path, char **out_buf, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || (uint64_t)st.st_size > RESHIELD_MANIFEST_MAX_BYTES) {
        close(fd);
        return -1;
    }

    size_t want = (size_t)st.st_size;
    char *buf = (char *)malloc(want + 2);
    if (buf == NULL) {
        close(fd);
        return -1;
    }
    size_t got = 0;
    while (got < want + 1) {
        ssize_t n = read(fd, buf + got, want + 1 - got);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            if (n < 0) {
                got = want + 1;
            }
            break;
        }
        got += (size_t)n;
    }
    close(fd);

    /* Grew while reading, read error, embedded NUL, or CRLF: reject. */
    if (got > want || memchr(buf, '\0', got) != NULL || memchr(buf, '\r', got) != NULL) {
        free(buf);
        return -1;
    }
    buf[got] = '\0';
    *out_buf = buf;
    *out_len = got;
    return 0;
}

static reshield_manifest_status_t load_verified_manifest(
    const char *manifest_path,
    const uint8_t *expected_root_sha256,
    char **out_buf,
    size_t *out_len) {
    uint8_t root_expected[RESHIELD_SHA256_SIZE];
    if (expected_root_sha256 != NULL) {
        memcpy(root_expected, expected_root_sha256, RESHIELD_SHA256_SIZE);
    } else if (reshield_get_sealed_manifest_root(root_expected) != 0) {
        return RESHIELD_MANIFEST_UNSEALED;
    }

    char *buf = NULL;
    size_t len = 0;
    if (read_manifest_file(manifest_path, &buf, &len) != 0) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    uint8_t root_actual[RESHIELD_SHA256_SIZE];
    reshield_sha256(buf, len, root_actual);
    if (!reshield_digest_equal(root_actual, root_expected)) {
        free(buf);
        return RESHIELD_MANIFEST_ROOT_MISMATCH;
    }
    *out_buf = buf;
    *out_len = len;
    return RESHIELD_MANIFEST_OK;
}

/* Returns 1 and fills the outputs for the next entry, 0 at end of buffer, -1 on a
 * malformed or over-long line. Blank lines and '#' comments are skipped. Modifies buf. */
static int next_manifest_entry(char **cursor,
                               char *end,
                               uint8_t out_hash[RESHIELD_SHA256_SIZE],
                               uint64_t *out_size,
                               const char **out_rel_path) {
    while (*cursor < end) {
        char *line = *cursor;
        char *nl = (char *)memchr(line, '\n', (size_t)(end - line));
        size_t len = nl != NULL ? (size_t)(nl - line) : (size_t)(end - line);
        *cursor = nl != NULL ? nl + 1 : end;
        if (len > RESHIELD_MANIFEST_MAX_LINE) {
            return -1;
        }
        line[len] = '\0';
        if (len == 0 || line[0] == '#') {
            continue;
        }
        return parse_manifest_line(line, out_hash, out_size, out_rel_path) == 0 ? 1 : -1;
    }
    return 0;
}

static int verify_one_asset_entry(const char *asset_base_dir,
                                  const char *rel_path,
                                  uint64_t expected_size,
                                  const uint8_t expected_hash[RESHIELD_SHA256_SIZE]) {
    char full_path[1024];
    int n = 0;
    if (asset_base_dir != NULL && asset_base_dir[0] != '\0') {
        n = snprintf(full_path, sizeof(full_path), "%s/%s", asset_base_dir, rel_path);
    } else {
        n = snprintf(full_path, sizeof(full_path), "%s", rel_path);
    }
    if (n <= 0 || (size_t)n >= sizeof(full_path)) {
        return 0;
    }

    uint8_t actual_hash[RESHIELD_SHA256_SIZE];
    uint64_t actual_size = 0;
    /* Read at most expected_size+1 bytes so a FIFO/huge file cannot hang or exhaust us. */
    uint64_t max_read = expected_size < UINT64_MAX ? expected_size + 1u : UINT64_MAX;
    if (reshield_sha256_file_limited(full_path, actual_hash, &actual_size, max_read) != 0) {
        return 0;
    }
    if (actual_size != expected_size) {
        return 0;
    }
    return reshield_digest_equal(actual_hash, expected_hash);
}
#endif

reshield_manifest_status_t reshield_verify_manifest_files(
    const char *manifest_path,
    const char *asset_base_dir,
    const uint8_t *expected_root_sha256,
    char *failed_path_buf,
    size_t failed_path_cap) {
#ifdef RESHIELD_DISABLE
    (void)manifest_path;
    (void)asset_base_dir;
    (void)expected_root_sha256;
    (void)failed_path_buf;
    (void)failed_path_cap;
    return RESHIELD_MANIFEST_OK;
#else
    if (manifest_path == NULL) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    char *buf = NULL;
    size_t len = 0;
    reshield_manifest_status_t st = load_verified_manifest(manifest_path, expected_root_sha256,
                                                           &buf, &len);
    if (st != RESHIELD_MANIFEST_OK) {
        return st;
    }

    char *cursor = buf;
    int entries = 0;
    for (;;) {
        uint8_t exp_hash[RESHIELD_SHA256_SIZE];
        uint64_t exp_size = 0;
        const char *rel_path = NULL;
        int r = next_manifest_entry(&cursor, buf + len, exp_hash, &exp_size, &rel_path);
        if (r < 0) {
            st = RESHIELD_MANIFEST_IO_ERROR;
            break;
        }
        if (r == 0) {
            st = entries > 0 ? RESHIELD_MANIFEST_OK : RESHIELD_MANIFEST_IO_ERROR;
            break;
        }
        entries++;

        if (!verify_one_asset_entry(asset_base_dir, rel_path, exp_size, exp_hash)) {
            copy_failed_path(failed_path_buf, failed_path_cap, rel_path);
            st = RESHIELD_MANIFEST_ASSET_MISMATCH;
            break;
        }
    }

    free(buf);
    return st;
#endif
}

reshield_manifest_status_t reshield_verify_single_asset(
    const char *manifest_path,
    const char *asset_base_dir,
    const char *asset_rel_path,
    const uint8_t *expected_root_sha256) {
#ifdef RESHIELD_DISABLE
    (void)manifest_path;
    (void)asset_base_dir;
    (void)asset_rel_path;
    (void)expected_root_sha256;
    return RESHIELD_MANIFEST_OK;
#else
    if (manifest_path == NULL || !is_safe_relative_path(asset_rel_path)) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    char *buf = NULL;
    size_t len = 0;
    reshield_manifest_status_t st = load_verified_manifest(manifest_path, expected_root_sha256,
                                                           &buf, &len);
    if (st != RESHIELD_MANIFEST_OK) {
        return st;
    }

    char *cursor = buf;
    st = RESHIELD_MANIFEST_ASSET_MISMATCH;
    for (;;) {
        uint8_t exp_hash[RESHIELD_SHA256_SIZE];
        uint64_t exp_size = 0;
        const char *rel_path = NULL;
        int r = next_manifest_entry(&cursor, buf + len, exp_hash, &exp_size, &rel_path);
        if (r < 0) {
            st = RESHIELD_MANIFEST_IO_ERROR;
            break;
        }
        if (r == 0) {
            break;
        }
        if (strcmp(rel_path, asset_rel_path) == 0) {
            st = verify_one_asset_entry(asset_base_dir, rel_path, exp_size, exp_hash)
                     ? RESHIELD_MANIFEST_OK
                     : RESHIELD_MANIFEST_ASSET_MISMATCH;
            break;
        }
    }

    free(buf);
    return st;
#endif
}
