#include "reshield/manifest.h"

#include "file_platform.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RESHIELD_DISABLE
/* Internal helper in sha256.c: hashes at most max_read bytes of a regular file. */
extern int reshield_sha256_file_limited(const char *path,
                                        uint8_t out_hash[RESHIELD_SHA256_SIZE],
                                        uint64_t *out_size,
                                        uint64_t max_read);

#define RESHIELD_MANIFEST_MAX_BYTES (4u * 1024u * 1024u)
#define RESHIELD_MANIFEST_MAX_LINE  1023u

/* Manifest v2 header (see docs/integrity-verification.md, section 8). */
#define RESHIELD_MANIFEST_MAX_ALLOW 64u
#define RESHIELD_ALLOW_MAX_GLOB     255u
#define RESHIELD_STRICT_MAX_DEPTH   32u
#define RESHIELD_STRICT_MAX_ENTRIES 100000u
#define RESHIELD_GLOB_BUDGET        (1u << 28) /* total matcher steps per strict scan */

typedef struct {
    int         strict;
    int         seen_version;
    size_t      n_allow;
    const char *allow[RESHIELD_MANIFEST_MAX_ALLOW]; /* point into the manifest buffer */
} manifest_policy_t;

typedef struct {
    char             *cursor;
    char             *end;
    int               in_header; /* '#' lines are only valid before the first entry line */
    manifest_policy_t policy;
} manifest_iter_t;

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

static char ascii_upper(char c) {
    return (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
}

static int ascii_equal_nocase(const char *p, size_t n, const char *upper_name) {
    if (strlen(upper_name) != n) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (ascii_upper(p[i]) != upper_name[i]) {
            return 0;
        }
    }
    return 1;
}

/* Windows reserved device names. The part before the first '.' (trailing spaces
 * stripped) is compared, so "nul.txt" is reserved too. */
static int is_reserved_device_name(const char *p, size_t n) {
    static const char *const names[] = { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" };
    size_t base = 0;
    while (base < n && p[base] != '.') {
        base++;
    }
    while (base > 0 && p[base - 1] == ' ') {
        base--;
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (ascii_equal_nocase(p, base, names[i])) {
            return 1;
        }
    }
    if (base == 4 && p[3] >= '0' && p[3] <= '9') {
        return ascii_equal_nocase(p, 3, "COM") || ascii_equal_nocase(p, 3, "LPT");
    }
    return 0;
}

/* Component-wise check, identical on every platform (mirrored by tools/manifest_path.py):
 * '/' is the only separator. Rejects absolute paths, empty components, '\\', ':',
 * control characters (0x01-0x1F, so CR/LF too), '< > " | ? *', components ending in '.'
 * or ' ' (which also rules out ".", ".." and "..."), and Windows reserved device names.
 * Names that merely contain ".." (e.g. "v1..2.cfg") are allowed. */
static int is_safe_relative_path(const char *rel) {
    if (rel == NULL || rel[0] == '\0' || rel[0] == '/') {
        return 0;
    }
    const char *p = rel;
    for (;;) {
        const char *q = p;
        while (*q != '\0' && *q != '/') {
            unsigned char c = (unsigned char)*q;
            if (c < 0x20 || strchr("\\:<>\"|?*", c) != NULL) {
                return 0;
            }
            q++;
        }
        size_t n = (size_t)(q - p);
        if (n == 0 || q[-1] == '.' || q[-1] == ' ' || is_reserved_device_name(p, n)) {
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
    reshield_file_t file;
    uint64_t size = 0;
    if (reshield_file_open_regular(path, &file, &size) != 0) {
        return -1;
    }
    if (size > RESHIELD_MANIFEST_MAX_BYTES) {
        reshield_file_close(file);
        return -1;
    }

    size_t want = (size_t)size;
    char *buf = (char *)malloc(want + 2);
    if (buf == NULL) {
        reshield_file_close(file);
        return -1;
    }
    intptr_t n = reshield_file_read_full(file, buf, want + 1);
    reshield_file_close(file);
    size_t got = n < 0 ? 0 : (size_t)n;

    /* Grew while reading, read error, embedded NUL, or CRLF: reject. */
    if (n < 0 || got > want || memchr(buf, '\0', got) != NULL || memchr(buf, '\r', got) != NULL) {
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
    } else {
        int rc = reshield_get_sealed_manifest_root(root_expected);
        if (rc == -1) {
            return RESHIELD_MANIFEST_UNSEALED;
        }
        if (rc != 0) {
            /* Invalid record or sealed without a manifest root: never "unsealed" (no allow_unsealed bypass). */
            return RESHIELD_MANIFEST_ROOT_MISMATCH;
        }
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

/* An #allow glob is a relative POSIX path pattern: no leading '/', no control characters or
 * '\', no ".." component, 1..255 bytes. '*' and '?' are the only wildcards. */
static int is_valid_glob(const char *g, size_t len) {
    if (len == 0 || len > RESHIELD_ALLOW_MAX_GLOB || g[0] == '/') {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)g[i];
        if (c < 0x20 || c == 0x7f || c == '\\') {
            return 0;
        }
        if ((i == 0 || g[i - 1] == '/') && c == '.' && i + 1 < len && g[i + 1] == '.' &&
            (i + 2 == len || g[i + 2] == '/')) {
            return 0;
        }
    }
    return 1;
}

/* '#' line inside the header block (line[0] == '#', NUL-terminated, length len).
 * "# ..." and a bare "#" are comments; "#reshield-manifest v2[ strict]" and "#allow <glob>"
 * are directives; anything else (unknown directive, bad version, bad glob, too many
 * #allow lines, #allow before the version line) is an error: fail closed. */
static int parse_header_line(const char *line, size_t len, manifest_policy_t *p) {
    if (len == 1 || line[1] == ' ') {
        return 0;
    }
    if (strncmp(line, "#reshield-manifest ", 19) == 0) {
        if (p->seen_version) {
            return -1;
        }
        if (strcmp(line + 19, "v2") == 0) {
            p->strict = 0;
        } else if (strcmp(line + 19, "v2 strict") == 0) {
            p->strict = 1;
        } else {
            return -1;
        }
        p->seen_version = 1;
        return 0;
    }
    if (strncmp(line, "#allow ", 7) == 0) {
        if (!p->seen_version || p->n_allow >= RESHIELD_MANIFEST_MAX_ALLOW ||
            !is_valid_glob(line + 7, len - 7u)) {
            return -1;
        }
        p->allow[p->n_allow++] = line + 7;
        return 0;
    }
    return -1;
}

static void iter_init(manifest_iter_t *it, char *buf, size_t len) {
    memset(it, 0, sizeof(*it));
    it->cursor = buf;
    it->end = buf + len;
    it->in_header = 1;
}

/* Returns 1 and fills the outputs for the next entry, 0 at end of buffer, -1 on a
 * malformed or over-long line. Blank lines are skipped; '#' lines are header lines (v2
 * directives or comments) before the first entry and an error after it. Modifies buf. */
static int next_manifest_entry(manifest_iter_t *it,
                               uint8_t out_hash[RESHIELD_SHA256_SIZE],
                               uint64_t *out_size,
                               const char **out_rel_path) {
    while (it->cursor < it->end) {
        char *line = it->cursor;
        char *nl = (char *)memchr(line, '\n', (size_t)(it->end - line));
        size_t len = nl != NULL ? (size_t)(nl - line) : (size_t)(it->end - line);
        it->cursor = nl != NULL ? nl + 1 : it->end;
        if (len > RESHIELD_MANIFEST_MAX_LINE) {
            return -1;
        }
        line[len] = '\0';
        if (len == 0) {
            continue;
        }
        if (line[0] == '#') {
            if (!it->in_header || parse_header_line(line, len, &it->policy) != 0) {
                return -1;
            }
            continue;
        }
        it->in_header = 0;
        return parse_manifest_line(line, out_hash, out_size, out_rel_path) == 0 ? 1 : -1;
    }
    return 0;
}

/* Iterative '*' / '?' matcher (no recursion). '*' matches any byte string including '/',
 * '?' any single byte, everything else byte for byte (case-sensitive). Returns 1 on a
 * match, 0 on none, -1 when the shared step budget ran out (callers treat it as no match). */
static int glob_match(const char *g, const char *s, uint32_t *budget) {
    const char *star = NULL;
    const char *mark = NULL;
    while (*s != '\0') {
        if (*budget == 0) {
            return -1;
        }
        (*budget)--;
        if (*g == '*') {
            star = g++;
            mark = s;
        } else if (*g == '?' || *g == *s) {
            g++;
            s++;
        } else if (star != NULL) {
            g = star + 1;
            s = ++mark;
        } else {
            return 0;
        }
    }
    while (*g == '*') {
        g++;
    }
    return *g == '\0';
}

static int cmp_name_ptr(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

typedef struct {
    const char *const       *names; /* sorted manifest entry paths */
    size_t                   n;
    const manifest_policy_t *policy;
    uint32_t                 budget;
    char                    *failed;
    size_t                   failed_cap;
} strict_scan_t;

/* Visitor for reshield_dir_walk: returns 1 (stop) for an entry that is neither listed in the
 * manifest nor matched by an #allow glob. */
static int strict_visit(const char *rel, void *vctx) {
    strict_scan_t *sc = (strict_scan_t *)vctx;
    size_t lo = 0, hi = sc->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(sc->names[mid], rel);
        if (c == 0) {
            return 0;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    for (size_t i = 0; i < sc->policy->n_allow; i++) {
        if (glob_match(sc->policy->allow[i], rel, &sc->budget) == 1) {
            return 0;
        }
    }
    copy_failed_path(sc->failed, sc->failed_cap, rel);
    return 1;
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

    manifest_iter_t it;
    iter_init(&it, buf, len);
    const char **names = NULL; /* entry paths, only collected when the manifest is strict */
    size_t n_names = 0;
    int entries = 0;
    for (;;) {
        uint8_t exp_hash[RESHIELD_SHA256_SIZE];
        uint64_t exp_size = 0;
        const char *rel_path = NULL;
        int r = next_manifest_entry(&it, exp_hash, &exp_size, &rel_path);
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
        if (it.policy.strict) {
            if (names == NULL) {
                /* An entry line needs >= 68 bytes, so len / 68 + 1 slots always suffice. */
                names = (const char **)malloc((len / 68u + 1u) * sizeof(*names));
                if (names == NULL) {
                    st = RESHIELD_MANIFEST_IO_ERROR;
                    break;
                }
            }
            names[n_names++] = rel_path;
        }
    }

    /* Strict scan runs only after every listed asset verified, so ROOT_MISMATCH, IO_ERROR and
     * ASSET_MISMATCH take precedence over ASSET_EXTRA. */
    if (st == RESHIELD_MANIFEST_OK && it.policy.strict) {
        qsort((void *)names, n_names, sizeof(*names), cmp_name_ptr);
        strict_scan_t sc = { (const char *const *)names, n_names, &it.policy, RESHIELD_GLOB_BUDGET,
                             failed_path_buf, failed_path_cap };
        copy_failed_path(failed_path_buf, failed_path_cap, "");
        if (reshield_dir_walk(asset_base_dir, RESHIELD_STRICT_MAX_DEPTH,
                              RESHIELD_STRICT_MAX_ENTRIES, strict_visit, &sc) != 0) {
            st = RESHIELD_MANIFEST_ASSET_EXTRA; /* extra file found, or the scan could not finish */
        }
    }

    free((void *)names);
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

    manifest_iter_t it;
    iter_init(&it, buf, len);
    st = RESHIELD_MANIFEST_ASSET_MISMATCH;
    for (;;) {
        uint8_t exp_hash[RESHIELD_SHA256_SIZE];
        uint64_t exp_size = 0;
        const char *rel_path = NULL;
        int r = next_manifest_entry(&it, exp_hash, &exp_size, &rel_path);
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
