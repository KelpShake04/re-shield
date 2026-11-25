#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "reshield/manifest.h"

#include "../src/file_platform.h" /* reshield_dir_walk() is internal; unit-tested here directly */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

static int g_failures = 0;

#define ASSERT_TRUE(cond, msg)                                                 \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);          \
            g_failures++;                                                      \
        } else {                                                               \
            printf("PASS: %s\n", (msg));                                       \
        }                                                                      \
    } while (0)

static void hash_to_hex(const uint8_t hash[RESHIELD_SHA256_SIZE], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        out[i * 2 + 0] = hex[(hash[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = hex[hash[i] & 0x0fu];
    }
    out[64] = '\0';
}

#ifndef RESHIELD_DISABLE
#define ADIR "build/mt_assets"
#define MPATH "build/mt_manifest.txt"

#ifdef _WIN32
/* The library treats paths as UTF-8; narrow fopen()/remove() would use the ANSI code page. */
static int utf8_to_wide(const char *s, wchar_t *w, int cap) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, cap) > 0;
}
static FILE *fopen_utf8(const char *path, const char *mode) {
    wchar_t wp[512], wm[8];
    return (utf8_to_wide(path, wp, 512) && utf8_to_wide(mode, wm, 8)) ? _wfopen(wp, wm) : NULL;
}
static int remove_utf8(const char *path) {
    wchar_t wp[512];
    return utf8_to_wide(path, wp, 512) ? _wremove(wp) : -1;
}
#else
#define fopen_utf8 fopen
#define remove_utf8 remove
#endif

static void write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen_utf8(path, "wb");
    if (f != NULL) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

/* Writes `content` as the manifest, uses its own SHA-256 as the root, and verifies. */
static reshield_manifest_status_t verify_content(const char *content, size_t len,
                                                 char *failed, size_t failed_cap) {
    write_file(MPATH, content, len);
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256_file(MPATH, root, NULL);
    return reshield_verify_manifest_files(MPATH, ADIR, root, failed, failed_cap);
}

static reshield_manifest_status_t verify_str(const char *content) {
    return verify_content(content, strlen(content), NULL, 0);
}

static void sha_hex(const char *data, size_t len, char out[65]) {
    uint8_t h[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, len, h);
    hash_to_hex(h, out);
}

/* Decodes \xNN escapes (the only escape in tests/path_rules.txt); returns 0 on a bad escape. */
static int unescape_path(const char *src, char *dst, size_t cap) {
    size_t n = 0;
    while (*src != '\0') {
        if (n + 1 >= cap) {
            return 0;
        }
        if (src[0] == '\\') {
            unsigned v = 0;
            if (src[1] != 'x' || sscanf(src + 2, "%2x", &v) != 1 ||
                !isxdigit((unsigned char)src[2]) || !isxdigit((unsigned char)src[3])) {
                return 0;
            }
            dst[n++] = (char)v;
            src += 4;
        } else {
            dst[n++] = *src++;
        }
    }
    dst[n] = '\0';
    return n > 0;
}

/* Runs every case of tests/path_rules.txt (the Python tools check the same file) through
 * reshield_verify_single_asset() and, where possible, through a manifest line. A path the
 * rule accepts is never IO_ERROR (the asset is just not listed / not on disk). */
static void test_shared_path_rules(const uint8_t root[RESHIELD_SHA256_SIZE], const char *hex) {
    FILE *f = fopen("tests/path_rules.txt", "r");
    ASSERT_TRUE(f != NULL, "path rules: open tests/path_rules.txt");
    if (f == NULL) {
        return;
    }
    int cases = 0, bad_single = 0, bad_line = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#') {
            continue;
        }
        char path[512];
        if ((line[0] != '+' && line[0] != '-') || line[1] != ' ' ||
            !unescape_path(line + 2, path, sizeof(path))) {
            fprintf(stderr, "FAIL: bad path_rules.txt line: %s\n", line);
            g_failures++;
            continue;
        }
        int want_ok = line[0] == '+';
        cases++;
        int single_ok = reshield_verify_single_asset(MPATH, ADIR, path, root) != RESHIELD_MANIFEST_IO_ERROR;
        if (single_ok != want_ok) {
            fprintf(stderr, "FAIL: single_asset path rule mismatch: %s\n", line);
            bad_single++;
        }
        if (strchr(path, '\n') == NULL && strchr(path, '\r') == NULL) {
            char entry[1024];
            snprintf(entry, sizeof(entry), "%s 3 %s\n", hex, path);
            int line_ok = verify_str(entry) != RESHIELD_MANIFEST_IO_ERROR;
            if (line_ok != want_ok) {
                fprintf(stderr, "FAIL: manifest line path rule mismatch: %s\n", line);
                bad_line++;
            }
        }
    }
    fclose(f);
    ASSERT_TRUE(cases > 40, "path rules: table loaded");
    ASSERT_TRUE(bad_single == 0, "path rules: reshield_verify_single_asset matches the shared table");
    ASSERT_TRUE(bad_line == 0, "path rules: manifest lines match the shared table");
    ASSERT_TRUE(reshield_verify_single_asset(MPATH, ADIR, "", root) == RESHIELD_MANIFEST_IO_ERROR,
                "path rules: empty path rejected");
}

/* Accepted names that need real files: nested directories and non-ASCII names. */
static void test_path_rules_real_files(void) {
    char hex[65];
    char buf[512];
    sha_hex("abc", 3, hex);
    mkdir(ADIR "/sub", 0755);
    mkdir(ADIR "/sub/dir", 0755);
    write_file(ADIR "/sub/dir/ok.cfg", "abc", 3);
    write_file(ADIR "/\xed\x95\x9c\xea\xb8\x80.cfg", "abc", 3); /* UTF-8 for hangul "han-geul" */
    snprintf(buf, sizeof(buf), "%s 3 sub/dir/ok.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_OK, "path rules: 'sub/dir/ok.cfg' verifies");
    snprintf(buf, sizeof(buf), "%s 3 \xed\x95\x9c\xea\xb8\x80.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_OK, "path rules: non-ASCII (hangul) name verifies");
    remove(ADIR "/sub/dir/ok.cfg");
    remove_utf8(ADIR "/\xed\x95\x9c\xea\xb8\x80.cfg");
    rmdir(ADIR "/sub/dir");
    rmdir(ADIR "/sub");
}

#ifndef _WIN32
/* Runs fn in a child with an alarm so a regression that blocks cannot hang the suite. */
static int run_with_timeout(int (*fn)(void), unsigned secs) {
    pid_t pid = fork();
    if (pid < 0) {
        return 0;
    }
    if (pid == 0) {
        alarm(secs);
        _exit(fn() ? 0 : 1);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        return 0;
    }
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static int child_fifo_asset(void) {
    char hex[65];
    sha_hex("x", 1, hex);
    char line[256];
    snprintf(line, sizeof(line), "%s 1 fifo.bin\n", hex);
    return verify_str(line) == RESHIELD_MANIFEST_ASSET_MISMATCH;
}

static int child_zero_symlink_asset(void) {
    char hex[65];
    sha_hex("x", 1, hex);
    char line[256];
    snprintf(line, sizeof(line), "%s 1 zero.bin\n", hex);
    return verify_str(line) == RESHIELD_MANIFEST_ASSET_MISMATCH;
}

static int child_fifo_manifest(void) {
    uint8_t root[RESHIELD_SHA256_SIZE] = { 0 };
    return reshield_verify_manifest_files(ADIR "/fifo.bin", ADIR, root, NULL, 0) ==
           RESHIELD_MANIFEST_IO_ERROR;
}

#endif /* !_WIN32 */

static void test_manifest_edge_cases(void) {
    char hex[65];
    char buf[2048];
    char failed[128];

    mkdir("build", 0755);
    mkdir(ADIR, 0755);
    write_file(ADIR "/a.cfg", "abc", 3);
    write_file(ADIR "/v1..2.cfg", "abc", 3);
    sha_hex("abc", 3, hex);

    snprintf(buf, sizeof(buf), "%s 3 a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_OK, "edge: baseline valid manifest passes");
    snprintf(buf, sizeof(buf), "%s 3 a.cfg", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_OK, "edge: last line without newline passes");

    snprintf(buf, sizeof(buf), "%s 3 v1..2.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_OK, "edge: 'v1..2.cfg' is an allowed name");

    snprintf(buf, sizeof(buf), "%s 3 ../x\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: '../x' entry rejected");
    snprintf(buf, sizeof(buf), "%s 3 sub/../a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: 'sub/../a.cfg' entry rejected");
    snprintf(buf, sizeof(buf), "%s 3 /abs\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: '/abs' entry rejected");
    snprintf(buf, sizeof(buf), "%s 3 sub//a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: empty path component rejected");

    snprintf(buf, sizeof(buf), "%.63sZ 3 a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: bad hex digit rejected");
    snprintf(buf, sizeof(buf), "%s a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: missing size field rejected");
    snprintf(buf, sizeof(buf), "%s abc a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: non-numeric size rejected");

    ASSERT_TRUE(verify_str("# only a comment\n") == RESHIELD_MANIFEST_IO_ERROR,
                "edge: comment-only manifest is IO_ERROR");
    ASSERT_TRUE(verify_str("") == RESHIELD_MANIFEST_IO_ERROR, "edge: empty manifest is IO_ERROR");

    snprintf(buf, sizeof(buf), "%s 3 missing.cfg\n", hex);
    ASSERT_TRUE(verify_content(buf, strlen(buf), failed, sizeof(failed)) ==
                    RESHIELD_MANIFEST_ASSET_MISMATCH && strcmp(failed, "missing.cfg") == 0,
                "edge: missing asset is ASSET_MISMATCH and reported");

    snprintf(buf, sizeof(buf), "%s 4 a.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_ASSET_MISMATCH,
                "edge: wrong size (asset shorter) is ASSET_MISMATCH");
    write_file(ADIR "/big.cfg", "abcd", 4);
    snprintf(buf, sizeof(buf), "%s 3 big.cfg\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_ASSET_MISMATCH,
                "edge: wrong size (asset longer) is ASSET_MISMATCH");

    snprintf(buf, sizeof(buf), "%s 3 a.cfg\r\n", hex);
    ASSERT_TRUE(verify_str(buf) == RESHIELD_MANIFEST_IO_ERROR, "edge: CRLF manifest rejected");

    {
        size_t n = (size_t)snprintf(buf, sizeof(buf), "%s 3 ", hex);
        memset(buf + n, 'a', 1100);
        buf[n + 1100] = '\n';
        ASSERT_TRUE(verify_content(buf, n + 1101, NULL, 0) == RESHIELD_MANIFEST_IO_ERROR,
                    "edge: line longer than 1023 chars is IO_ERROR (no truncation)");
    }

    {
        size_t cap = 4u * 1024u * 1024u + 1u;
        char *huge = (char *)malloc(cap);
        if (huge != NULL) {
            memset(huge, '#', cap);
            huge[cap - 1] = '\n';
            ASSERT_TRUE(verify_content(huge, cap, NULL, 0) == RESHIELD_MANIFEST_IO_ERROR,
                        "edge: manifest over 4 MiB is IO_ERROR");
            free(huge);
        }
    }

    /* Sealed-root lookups: the test binary is unsealed, so expected_root=NULL must not pass. */
    snprintf(buf, sizeof(buf), "%s 3 a.cfg\n", hex);
    write_file(MPATH, buf, strlen(buf));
    ASSERT_TRUE(reshield_verify_manifest_files(MPATH, ADIR, NULL, NULL, 0) == RESHIELD_MANIFEST_UNSEALED,
                "edge: expected_root=NULL on unsealed binary is UNSEALED");
    ASSERT_TRUE(reshield_verify_single_asset(MPATH, ADIR, "a.cfg", NULL) == RESHIELD_MANIFEST_UNSEALED,
                "edge: single_asset expected_root=NULL on unsealed binary is UNSEALED");

    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256_file(MPATH, root, NULL);
    ASSERT_TRUE(reshield_verify_single_asset(MPATH, ADIR, "other.cfg", root) == RESHIELD_MANIFEST_ASSET_MISMATCH,
                "edge: single_asset not listed in manifest is ASSET_MISMATCH");
    ASSERT_TRUE(reshield_verify_single_asset(MPATH, ADIR, "../a.cfg", root) == RESHIELD_MANIFEST_IO_ERROR,
                "edge: single_asset with '../' path is IO_ERROR");
    ASSERT_TRUE(reshield_verify_single_asset(MPATH, ADIR, "a.cfg", root) == RESHIELD_MANIFEST_OK,
                "edge: single_asset listed asset passes");
    ASSERT_TRUE(reshield_verify_manifest_files(NULL, ADIR, root, NULL, 0) == RESHIELD_MANIFEST_IO_ERROR,
                "edge: manifest_path=NULL is IO_ERROR (verify_manifest_files)");
    ASSERT_TRUE(reshield_verify_single_asset(NULL, ADIR, "a.cfg", root) == RESHIELD_MANIFEST_IO_ERROR,
                "edge: manifest_path=NULL is IO_ERROR (verify_single_asset)");
    ASSERT_TRUE(reshield_verify_manifest_files("build/does_not_exist.manifest", ADIR, root, NULL, 0) ==
                    RESHIELD_MANIFEST_IO_ERROR,
                "edge: nonexistent manifest is IO_ERROR");

    test_shared_path_rules(root, hex);
    test_path_rules_real_files();

#ifndef _WIN32
    /* Non-regular assets must not block the verifier. */
    ASSERT_TRUE(mkfifo(ADIR "/fifo.bin", 0600) == 0, "edge: create FIFO");
    ASSERT_TRUE(run_with_timeout(child_fifo_asset, 3), "edge: FIFO asset is ASSET_MISMATCH within 3s");
    ASSERT_TRUE(run_with_timeout(child_fifo_manifest, 3), "edge: FIFO manifest is IO_ERROR within 3s");
    ASSERT_TRUE(symlink("/dev/zero", ADIR "/zero.bin") == 0, "edge: create /dev/zero symlink");
    ASSERT_TRUE(run_with_timeout(child_zero_symlink_asset, 3),
                "edge: /dev/zero symlink asset is ASSET_MISMATCH within 3s");
#endif

    remove(ADIR "/a.cfg");
    remove(ADIR "/v1..2.cfg");
    remove(ADIR "/big.cfg");
    remove(ADIR "/fifo.bin");
    remove(ADIR "/zero.bin");
    rmdir(ADIR);
    remove(MPATH);
}

/* ---- ASSET_UNREADABLE: an asset that cannot be opened is not a tamper verdict ---- */
#define UDIR "build/mt_unread"
#define UMPATH "build/mt_unread_manifest.txt"

static int refused(reshield_manifest_status_t st, void **pbuf, size_t *plen, reshield_manifest_status_t want);

#ifdef _WIN32
static HANDLE g_lock = INVALID_HANDLE_VALUE;

/* Holds the file open with no sharing: every other open fails with ERROR_SHARING_VIOLATION. */
static int make_unreadable(const char *path) {
    wchar_t wp[512];
    if (!utf8_to_wide(path, wp, 512)) {
        return 0;
    }
    g_lock = CreateFileW(wp, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_lock != INVALID_HANDLE_VALUE;
}

static void make_readable(const char *path) {
    (void)path;
    if (g_lock != INVALID_HANDLE_VALUE) {
        CloseHandle(g_lock);
        g_lock = INVALID_HANDLE_VALUE;
    }
}
#else
static int make_unreadable(const char *path) {
    if (chmod(path, 0) != 0) {
        return 0;
    }
    FILE *f = fopen(path, "rb"); /* still readable: running as root, the scenario cannot be made */
    if (f != NULL) {
        fclose(f);
        chmod(path, 0644);
        return 0;
    }
    return 1;
}

static void make_readable(const char *path) {
    chmod(path, 0644);
}
#endif

/* Manifest = a.cfg, b.cfg (both "abc") plus `extra`; own SHA-256 as the root. */
static reshield_manifest_status_t uverify(const char *header, const char *extra, char *failed, size_t cap) {
    char hex[65], buf[1024];
    sha_hex("abc", 3, hex);
    int n = snprintf(buf, sizeof(buf), "%s%s 3 a.cfg\n%s 3 b.cfg\n%s", header, hex, hex, extra);
    write_file(UMPATH, buf, (size_t)n);
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256_file(UMPATH, root, NULL);
    return reshield_verify_manifest_files(UMPATH, UDIR, root, failed, cap);
}

static void test_asset_unreadable(void) {
    char failed[128];
    char hex[65];
    mkdir("build", 0755);
    mkdir(UDIR, 0755);
    write_file(UDIR "/a.cfg", "abc", 3);
    write_file(UDIR "/b.cfg", "abc", 3);
    sha_hex("abc", 3, hex);
    ASSERT_TRUE(uverify("", "", NULL, 0) == RESHIELD_MANIFEST_OK, "unreadable: baseline passes");

    if (!make_unreadable(UDIR "/a.cfg")) {
        printf("SKIP: unreadable-asset tests (cannot make a file unreadable, running as root?)\n");
    } else {
        failed[0] = 'X';
        ASSERT_TRUE(uverify("", "", failed, sizeof(failed)) == RESHIELD_MANIFEST_ASSET_UNREADABLE &&
                        strcmp(failed, "a.cfg") == 0,
                    "unreadable: locked/chmod 0 asset is ASSET_UNREADABLE and named");

        char text[512];
        snprintf(text, sizeof(text), "%s 3 a.cfg\n%s 3 b.cfg\n", hex, hex);
        write_file(UMPATH, text, strlen(text));
        uint8_t root[RESHIELD_SHA256_SIZE];
        reshield_sha256_file(UMPATH, root, NULL);
        ASSERT_TRUE(reshield_verify_single_asset(UMPATH, UDIR, "a.cfg", root) == RESHIELD_MANIFEST_ASSET_UNREADABLE,
                    "unreadable: single_asset is ASSET_UNREADABLE");
        ASSERT_TRUE(reshield_verify_single_asset(UMPATH, UDIR, "b.cfg", root) == RESHIELD_MANIFEST_OK,
                    "unreadable: single_asset of a readable sibling still passes");
        void *buf = (void *)1;
        size_t len = 99;
        ASSERT_TRUE(refused(reshield_load_verified_asset(UMPATH, UDIR, "a.cfg", root, 16, &buf, &len), &buf, &len,
                            RESHIELD_MANIFEST_ASSET_UNREADABLE),
                    "unreadable: load_verified_asset is ASSET_UNREADABLE, no buffer");
        ASSERT_TRUE(reshield_sha256_file(UDIR "/a.cfg", root, NULL) == -1,
                    "unreadable: public reshield_sha256_file() still returns -1");

        /* A tampered asset anywhere in the manifest wins over an unreadable one. */
        write_file(UDIR "/b.cfg", "abd", 3);
        failed[0] = 'X';
        ASSERT_TRUE(uverify("", "", failed, sizeof(failed)) == RESHIELD_MANIFEST_ASSET_MISMATCH &&
                        strcmp(failed, "b.cfg") == 0,
                    "unreadable: a later tampered asset is ASSET_MISMATCH, not hidden by the unreadable one");
        write_file(UDIR "/b.cfg", "abc", 3);

        /* Strict manifest: an unlisted file wins; otherwise the unreadable asset is reported. */
        failed[0] = 'X';
        ASSERT_TRUE(uverify("#reshield-manifest v2 strict\n", "", failed, sizeof(failed)) ==
                            RESHIELD_MANIFEST_ASSET_UNREADABLE && strcmp(failed, "a.cfg") == 0,
                    "unreadable: strict manifest with nothing extra is ASSET_UNREADABLE and named");
        write_file(UDIR "/evil.dll", "x", 1);
        failed[0] = 'X';
        ASSERT_TRUE(uverify("#reshield-manifest v2 strict\n", "", failed, sizeof(failed)) ==
                            RESHIELD_MANIFEST_ASSET_EXTRA && strcmp(failed, "evil.dll") == 0,
                    "unreadable: strict ASSET_EXTRA takes precedence over ASSET_UNREADABLE");
        remove_utf8(UDIR "/evil.dll");

        make_readable(UDIR "/a.cfg");
        ASSERT_TRUE(uverify("", "", NULL, 0) == RESHIELD_MANIFEST_OK, "unreadable: passes again once readable");
    }

    /* Rule violations and absence stay tamper verdicts. */
    char text[512];
    mkdir(UDIR "/dir.cfg", 0755);
    snprintf(text, sizeof(text), "%s 3 a.cfg\n%s 3 dir.cfg\n", hex, hex);
    write_file(UMPATH, text, strlen(text));
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256_file(UMPATH, root, NULL);
    failed[0] = 'X';
    ASSERT_TRUE(reshield_verify_manifest_files(UMPATH, UDIR, root, failed, sizeof(failed)) ==
                        RESHIELD_MANIFEST_ASSET_MISMATCH && strcmp(failed, "dir.cfg") == 0,
                "unreadable: a directory listed as an asset is ASSET_MISMATCH");
    void *buf = (void *)1;
    size_t len = 99;
    ASSERT_TRUE(refused(reshield_load_verified_asset(UMPATH, UDIR, "dir.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH),
                "unreadable: load of a directory is ASSET_MISMATCH");
    rmdir(UDIR "/dir.cfg");
    remove_utf8(UDIR "/b.cfg");
    failed[0] = 'X';
    ASSERT_TRUE(uverify("", "", failed, sizeof(failed)) == RESHIELD_MANIFEST_ASSET_MISMATCH &&
                    strcmp(failed, "b.cfg") == 0,
                "unreadable: a missing asset is still ASSET_MISMATCH");
    write_file(UDIR "/b.cfg", "abd", 3);
    ASSERT_TRUE(uverify("", "", NULL, 0) == RESHIELD_MANIFEST_ASSET_MISMATCH,
                "unreadable: a hash mismatch is still ASSET_MISMATCH");

    remove_utf8(UDIR "/a.cfg");
    remove_utf8(UDIR "/b.cfg");
    rmdir(UDIR);
    remove_utf8(UMPATH);
}

/* ---- Strict (allowlist) manifest v2: tests for the "#reshield-manifest v2 strict" header ---- */
#define SDIR "build/mt_strict"
#define SMPATH "build/mt_strict_manifest.txt"
#define STRICT_HDR "#reshield-manifest v2 strict\n"

/* Manifest = header + the two entries a.cfg and sub/b.cfg (both "abc"). */
static reshield_manifest_status_t sverify(const char *header, char *failed, size_t cap) {
    char hex[65];
    char buf[8192];
    sha_hex("abc", 3, hex);
    int n = snprintf(buf, sizeof(buf), "%s%s 3 a.cfg\n%s 3 sub/b.cfg\n", header, hex, hex);
    write_file(SMPATH, buf, (size_t)n);
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256_file(SMPATH, root, NULL);
    return reshield_verify_manifest_files(SMPATH, SDIR, root, failed, cap);
}

static int strict_ok(const char *header) {
    return sverify(header, NULL, 0) == RESHIELD_MANIFEST_OK;
}

static int strict_extra(const char *header, const char *want_path) {
    char failed[128] = { 'X', 0 };
    reshield_manifest_status_t st = sverify(header, failed, sizeof(failed));
    return st == RESHIELD_MANIFEST_ASSET_EXTRA && strcmp(failed, want_path) == 0;
}

static int strict_io(const char *header) {
    return sverify(header, NULL, 0) == RESHIELD_MANIFEST_IO_ERROR;
}

/* Verifies an arbitrary manifest text against SDIR with its own SHA-256 as the root. */
static reshield_manifest_status_t sverify_text(const char *text, char *failed, size_t cap) {
    write_file(SMPATH, text, strlen(text));
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256_file(SMPATH, root, NULL);
    return reshield_verify_manifest_files(SMPATH, SDIR, root, failed, cap);
}

typedef struct {
    int n, found_a, found_b, absolute;
} walk_seen_t;

static int walk_record(const char *rel, void *ctx) {
    walk_seen_t *w = (walk_seen_t *)ctx;
    w->n++;
    w->found_a += strcmp(rel, "a.cfg") == 0;
    w->found_b += strcmp(rel, "sub/b.cfg") == 0;
    w->absolute += rel[0] == '/' || rel[0] == '\\';
    return 0;
}

static int walk_stop(const char *rel, void *ctx) {
    (void)rel;
    (void)ctx;
    return 1;
}

static void test_dir_walk(void) {
    walk_seen_t w;
    memset(&w, 0, sizeof(w));
    ASSERT_TRUE(reshield_dir_walk(SDIR, 32, 100, walk_record, &w) == 0 && w.n == 2 &&
                    w.found_a == 1 && w.found_b == 1,
                "dir_walk: lists files with '/' relative paths, directories are not reported");
    memset(&w, 0, sizeof(w));
    ASSERT_TRUE(reshield_dir_walk(SDIR "/", 32, 100, walk_record, &w) == 0 && w.n == 2 && !w.absolute,
                "dir_walk: trailing '/' on the base does not leak into relative paths");
    ASSERT_TRUE(reshield_dir_walk(SDIR, 32, 3, walk_record, &w) == 0,
                "dir_walk: exactly max_entries entries (a.cfg, sub, sub/b.cfg) is fine");
    ASSERT_TRUE(reshield_dir_walk(SDIR, 32, 2, walk_record, &w) == -1,
                "dir_walk: more than max_entries entries (directories count) fails closed");
    ASSERT_TRUE(reshield_dir_walk(SDIR, 1, 100, walk_record, &w) == 0 &&
                    reshield_dir_walk(SDIR, 0, 100, walk_record, &w) == -1,
                "dir_walk: nesting deeper than max_depth fails closed");
    ASSERT_TRUE(reshield_dir_walk(SDIR, 32, 100, walk_stop, NULL) == 1,
                "dir_walk: a non-zero visitor result stops the walk (returns 1)");
    ASSERT_TRUE(reshield_dir_walk("build/mt_strict_nonexistent", 32, 100, walk_record, &w) == -1,
                "dir_walk: missing base directory fails closed");
    ASSERT_TRUE(reshield_dir_walk(SDIR "/a.cfg", 32, 100, walk_record, &w) == -1,
                "dir_walk: a file as base fails closed");
}

/* Chain of n nested directories d/d/.../d below SDIR. */
static void make_chain(int n) {
    char p[512] = SDIR;
    for (int i = 0; i < n; i++) {
        strcat(p, "/d");
        mkdir(p, 0755);
    }
}

static void remove_chain(int n) {
    for (int i = n; i > 0; i--) {
        char p[512] = SDIR;
        for (int j = 0; j < i; j++) {
            strcat(p, "/d");
        }
        rmdir(p);
    }
}

static void test_strict_manifest(void) {
    char hdr[8192];
    char failed[128];
    char hex[65];
    char buf[1024];
    sha_hex("abc", 3, hex);

    mkdir("build", 0755);
    mkdir(SDIR, 0755);
    mkdir(SDIR "/sub", 0755);
    write_file(SDIR "/a.cfg", "abc", 3);
    write_file(SDIR "/sub/b.cfg", "abc", 3);

    ASSERT_TRUE(strict_ok(STRICT_HDR), "strict: exactly the listed files passes");
    test_dir_walk();

    /* Extra files. */
    write_file(SDIR "/evil.dll", "MZ", 2);
    ASSERT_TRUE(strict_extra(STRICT_HDR, "evil.dll"), "strict: dropped-in evil.dll is ASSET_EXTRA and named");
    remove(SDIR "/evil.dll");
    write_file(SDIR "/sub/proxy.dll", "MZ", 2);
    ASSERT_TRUE(strict_extra(STRICT_HDR, "sub/proxy.dll"), "strict: new file in a subfolder is ASSET_EXTRA");
    remove(SDIR "/sub/proxy.dll");
    write_file(SDIR "/.hidden.dll", "MZ", 2);
    ASSERT_TRUE(strict_extra(STRICT_HDR, ".hidden.dll"), "strict: dotfiles are extra too");
    remove(SDIR "/.hidden.dll");
    write_file(SDIR "/\xed\x95\x9c.dll", "MZ", 2); /* UTF-8 hangul */
    ASSERT_TRUE(strict_extra(STRICT_HDR, "\xed\x95\x9c.dll"), "strict: non-ASCII extra name is reported as UTF-8");
    remove_utf8(SDIR "/\xed\x95\x9c.dll");
    ASSERT_TRUE(strict_ok(STRICT_HDR), "strict: passes again once the extra files are gone");

    /* Empty directories are ignored. */
    mkdir(SDIR "/emptydir", 0755);
    ASSERT_TRUE(strict_ok(STRICT_HDR), "strict: an empty directory is ignored");
    rmdir(SDIR "/emptydir");

    /* Priority: a tampered listed asset beats an extra file; its path is the one reported. */
    write_file(SDIR "/evil.dll", "MZ", 2);
    write_file(SDIR "/a.cfg", "abd", 3);
    ASSERT_TRUE(sverify(STRICT_HDR, failed, sizeof(failed)) == RESHIELD_MANIFEST_ASSET_MISMATCH &&
                    strcmp(failed, "a.cfg") == 0,
                "strict: ASSET_MISMATCH takes precedence over ASSET_EXTRA");
    write_file(SDIR "/a.cfg", "abc", 3);
    remove(SDIR "/evil.dll");

    /* Allow globs. */
    write_file(SDIR "/x.log", "l", 1);
    ASSERT_TRUE(strict_extra(STRICT_HDR, "x.log"), "strict: unlisted x.log is extra without #allow");
    ASSERT_TRUE(strict_ok(STRICT_HDR "#allow *.log\n"), "strict: '#allow *.log' admits x.log");
    ASSERT_TRUE(strict_extra(STRICT_HDR "#allow *.LOG\n", "x.log"), "strict: globs are case-sensitive");
    ASSERT_TRUE(strict_ok(STRICT_HDR "# a comment\n#allow nomatch\n#allow x.log\n"),
                "strict: comments and several #allow lines mix");
    remove(SDIR "/x.log");
    mkdir(SDIR "/saves", 0755);
    mkdir(SDIR "/saves/deep", 0755);
    write_file(SDIR "/saves/deep/slot1.sav", "s", 1);
    ASSERT_TRUE(strict_extra(STRICT_HDR, "saves/deep/slot1.sav"), "strict: nested unlisted file is extra");
    ASSERT_TRUE(strict_ok(STRICT_HDR "#allow saves/*\n"),
                "strict: '*' crosses '/' ('saves/*' admits saves/deep/slot1.sav)");
    ASSERT_TRUE(strict_extra(STRICT_HDR "#allow saves/?\n", "saves/deep/slot1.sav"),
                "strict: '?' is exactly one byte");
    ASSERT_TRUE(strict_ok(STRICT_HDR "#allow saves/d?ep/slot?.sav\n"), "strict: '?' matches one byte");
    ASSERT_TRUE(strict_extra(STRICT_HDR "#allow saves\n", "saves/deep/slot1.sav"),
                "strict: a directory name alone does not admit its contents");
    remove(SDIR "/saves/deep/slot1.sav");
    rmdir(SDIR "/saves/deep");
    rmdir(SDIR "/saves");
    write_file(SDIR "/sub/.DS_Store", "d", 1);
    ASSERT_TRUE(strict_ok(STRICT_HDR "#allow */.DS_Store\n"), "strict: '*/.DS_Store' admits a nested .DS_Store");
    ASSERT_TRUE(strict_extra(STRICT_HDR "#allow .DS_Store\n", "sub/.DS_Store"),
                "strict: '.DS_Store' alone does not admit a nested one");
    remove(SDIR "/sub/.DS_Store");

    /* 64 allow lines are fine, 65 are not; a 255-byte glob is fine, 256 is not. */
    snprintf(hdr, sizeof(hdr), "%s", STRICT_HDR);
    for (int i = 0; i < 64; i++) {
        char l[32];
        snprintf(l, sizeof(l), "#allow g%d\n", i);
        strcat(hdr, l);
    }
    ASSERT_TRUE(strict_ok(hdr), "strict: 64 #allow lines accepted");
    strcat(hdr, "#allow g64\n");
    ASSERT_TRUE(strict_io(hdr), "strict: 65 #allow lines is IO_ERROR");
    {
        char glob[300];
        memset(glob, 'g', sizeof(glob));
        glob[255] = '\0';
        snprintf(hdr, sizeof(hdr), "%s#allow %s\n", STRICT_HDR, glob);
        ASSERT_TRUE(strict_ok(hdr), "strict: 255-byte glob accepted");
        glob[255] = 'g';
        glob[256] = '\0';
        snprintf(hdr, sizeof(hdr), "%s#allow %s\n", STRICT_HDR, glob);
        ASSERT_TRUE(strict_io(hdr), "strict: 256-byte glob is IO_ERROR");
    }

    /* Header errors fail closed. */
    ASSERT_TRUE(strict_io("#reshield-manifest v3 strict\n"), "header: unknown version is IO_ERROR");
    ASSERT_TRUE(strict_io("#reshield-manifest v2 loose\n"), "header: unknown mode is IO_ERROR");
    ASSERT_TRUE(strict_io("#reshield-manifest v2 strict \n"), "header: trailing space is IO_ERROR");
    ASSERT_TRUE(strict_io("#reshield-manifest v2\n#reshield-manifest v2 strict\n"),
                "header: duplicate version directive is IO_ERROR");
    ASSERT_TRUE(strict_io("#reshield-manifest\n"), "header: bare '#reshield-manifest' is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#frobnicate yes\n"), "header: unknown directive is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#Allow x\n"), "header: directive names are case-sensitive");
    ASSERT_TRUE(strict_io("#allow *.log\n" STRICT_HDR), "header: #allow before the version line is IO_ERROR");
    ASSERT_TRUE(strict_io("#allow *.log\n"), "header: #allow without a version line is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#allow \n"), "header: empty glob is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#allow /abs\n"), "header: absolute glob is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#allow ../x\n"), "header: '..' glob is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#allow a/../x\n"), "header: glob with '..' component is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#allow a\\b\n"), "header: backslash glob is IO_ERROR");
    ASSERT_TRUE(strict_io(STRICT_HDR "#allow a\tb\n"), "header: control character in glob is IO_ERROR");
    ASSERT_TRUE(strict_ok(STRICT_HDR "#allow v1..2*\n"), "header: '..' inside a name is fine");
    ASSERT_TRUE(strict_ok("#reshield-manifest v2\n"), "header: v2 without strict passes");
    ASSERT_TRUE(strict_ok("#reshield-manifest v2\n#allow x\n"), "header: #allow in a non-strict v2 manifest is accepted");
    ASSERT_TRUE(strict_ok("# plain comment\n#\n" STRICT_HDR), "header: comments before the directive are fine");
    ASSERT_TRUE(strict_ok("\n" STRICT_HDR "\n"), "header: blank lines are skipped");
    snprintf(buf, sizeof(buf), "%s 3 a.cfg\n%s 3 sub/b.cfg\n#reshield-manifest v2 strict\n", hex, hex);
    ASSERT_TRUE(sverify_text(buf, NULL, 0) == RESHIELD_MANIFEST_IO_ERROR,
                "header: a directive after the first entry is IO_ERROR");
    snprintf(buf, sizeof(buf), "%s 3 a.cfg\n%s 3 sub/b.cfg\n# late comment\n", hex, hex);
    ASSERT_TRUE(sverify_text(buf, NULL, 0) == RESHIELD_MANIFEST_IO_ERROR,
                "header: even a plain comment after the first entry is IO_ERROR");

    /* Non-strict manifests do not scan: v1 (no header) and v2 without 'strict' ignore extra files. */
    write_file(SDIR "/evil.dll", "MZ", 2);
    ASSERT_TRUE(strict_ok(""), "v1 manifest (no header): extra file is not detected (unchanged)");
    ASSERT_TRUE(strict_ok("# just a comment\n"), "v1 manifest with a leading comment still works");
    ASSERT_TRUE(strict_ok("#reshield-manifest v2\n"), "v2 non-strict: extra file is not detected");
    snprintf(buf, sizeof(buf), "%s%s 3 a.cfg\n", STRICT_HDR, hex);
    write_file(SMPATH, buf, strlen(buf));
    {
        uint8_t root[RESHIELD_SHA256_SIZE];
        reshield_sha256_file(SMPATH, root, NULL);
        ASSERT_TRUE(reshield_verify_single_asset(SMPATH, SDIR, "a.cfg", root) == RESHIELD_MANIFEST_OK,
                    "strict: reshield_verify_single_asset does not scan (per-asset call)");
        ASSERT_TRUE(reshield_verify_manifest_files(SMPATH, SDIR, root, failed, sizeof(failed)) ==
                            RESHIELD_MANIFEST_ASSET_EXTRA && failed[0] != '\0',
                    "strict: manifest listing only a.cfg reports an unlisted file (sub/b.cfg or evil.dll)");
        root[0] ^= 1u;
        ASSERT_TRUE(reshield_verify_manifest_files(SMPATH, SDIR, root, NULL, 0) == RESHIELD_MANIFEST_ROOT_MISMATCH,
                    "strict: ROOT_MISMATCH takes precedence over ASSET_EXTRA");
    }
    remove(SDIR "/evil.dll");

    /* Depth limit: 32 nested directories pass, 33 cannot be verified (ASSET_EXTRA, empty path). */
    make_chain(32);
    ASSERT_TRUE(strict_ok(STRICT_HDR), "strict: 32 nested (empty) directories pass");
    remove_chain(32);
    make_chain(33);
    {
        char f2[16] = { 'X', 0 };
        ASSERT_TRUE(sverify(STRICT_HDR, f2, sizeof(f2)) == RESHIELD_MANIFEST_ASSET_EXTRA && f2[0] == '\0',
                    "strict: 33 nested directories is ASSET_EXTRA with an empty path (scan incomplete)");
    }
    remove_chain(33);
    ASSERT_TRUE(strict_ok(STRICT_HDR), "strict: passes again after the limit tests");

#ifndef _WIN32
    ASSERT_TRUE(symlink("a.cfg", SDIR "/link.cfg") == 0, "strict: create symlink to a listed file");
    ASSERT_TRUE(strict_extra(STRICT_HDR, "link.cfg"), "strict: an unlisted symlink is ASSET_EXTRA (not followed)");
    ASSERT_TRUE(strict_ok(STRICT_HDR "#allow link.cfg\n"), "strict: an #allow'ed symlink passes");
    remove(SDIR "/link.cfg");
    ASSERT_TRUE(symlink("does_not_exist", SDIR "/dangling") == 0, "strict: create dangling symlink");
    ASSERT_TRUE(strict_extra(STRICT_HDR, "dangling"), "strict: a dangling symlink is ASSET_EXTRA");
    remove(SDIR "/dangling");
    ASSERT_TRUE(symlink("sub", SDIR "/sublink") == 0, "strict: create symlink to a directory");
    ASSERT_TRUE(strict_extra(STRICT_HDR, "sublink"),
                "strict: a symlinked directory is one item, not traversed");
    remove(SDIR "/sublink");
    ASSERT_TRUE(symlink("..", SDIR "/sub/loop") == 0, "strict: create symlink loop");
    ASSERT_TRUE(strict_extra(STRICT_HDR, "sub/loop"), "strict: a symlink loop does not hang the scan");
    remove(SDIR "/sub/loop");
    ASSERT_TRUE(mkfifo(SDIR "/pipe", 0600) == 0, "strict: create FIFO");
    ASSERT_TRUE(strict_extra(STRICT_HDR, "pipe"), "strict: a FIFO is ASSET_EXTRA (never opened)");
    remove(SDIR "/pipe");
    /* A listed path that is a symlink to a listed target verifies by content, as before. */
    ASSERT_TRUE(symlink("../a.cfg", SDIR "/sub/via_link.cfg") == 0, "strict: create listed symlink");
    snprintf(buf, sizeof(buf), "%s%s 3 a.cfg\n%s 3 sub/b.cfg\n%s 3 sub/via_link.cfg\n",
             STRICT_HDR, hex, hex, hex);
    ASSERT_TRUE(sverify_text(buf, NULL, 0) == RESHIELD_MANIFEST_OK,
                "strict: a listed symlink whose target hashes right passes");
    remove(SDIR "/sub/via_link.cfg");

    /* Entry limit: a.cfg, sub, sub/b.cfg, many/ and N files = 100000 entries is the maximum. */
    {
        enum { LIMIT_FILES = 100000 - 4 };
        char p[64];
        mkdir(SDIR "/many", 0755);
        for (int i = 0; i < LIMIT_FILES; i++) {
            snprintf(p, sizeof(p), SDIR "/many/f%06d", i);
            write_file(p, "", 0);
        }
        ASSERT_TRUE(strict_ok(STRICT_HDR "#allow many/*\n"), "strict: exactly 100000 entries passes");
        write_file(SDIR "/many/one_more", "", 0);
        char f2[16] = { 'X', 0 };
        ASSERT_TRUE(sverify(STRICT_HDR "#allow many/*\n", f2, sizeof(f2)) == RESHIELD_MANIFEST_ASSET_EXTRA &&
                        f2[0] == '\0',
                    "strict: 100001 entries is ASSET_EXTRA with an empty path (scan incomplete)");
        remove(SDIR "/many/one_more");
        for (int i = 0; i < LIMIT_FILES; i++) {
            snprintf(p, sizeof(p), SDIR "/many/f%06d", i);
            remove(p);
        }
        rmdir(SDIR "/many");
    }
#endif

    remove(SDIR "/a.cfg");
    remove(SDIR "/sub/b.cfg");
    rmdir(SDIR "/sub");
    rmdir(SDIR);
    remove(SMPATH);
}
#endif

/* reshield_load_verified_asset(): the verified bytes are the returned bytes. Runs in the
 * RESHIELD_DISABLE build too (there it only reads: no manifest, same path and size rules). */
#define LDIR "build/mt_load"
#define LMPATH "build/mt_load_manifest.txt"

static void put_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f != NULL) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

static void lhex(const char *data, size_t len, char out[65]) {
    uint8_t h[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, len, h);
    hash_to_hex(h, out);
}

/* The outputs are passed by address: C leaves the evaluation order of the call that fills them
 * and of these arguments unspecified, so they are only read here, after the call returned. */
static int loaded(reshield_manifest_status_t st, void **pbuf, size_t *plen, const char *want, size_t want_len) {
    int ok = st == RESHIELD_MANIFEST_OK && *pbuf != NULL && *plen == want_len &&
             (want_len == 0 || memcmp(*pbuf, want, want_len) == 0);
    reshield_free_asset(*pbuf);
    return ok;
}

static int refused(reshield_manifest_status_t st, void **pbuf, size_t *plen, reshield_manifest_status_t want) {
    int ok = st == want && *pbuf == NULL && *plen == 0;
    reshield_free_asset(*pbuf);
    return ok;
}

static void test_load_verified_asset(void) {
    void *buf = (void *)1;
    size_t len = 99;
    mkdir("build", 0755);
    mkdir(LDIR, 0755);
    mkdir(LDIR "/sub", 0755);
    put_file(LDIR "/a.cfg", "abc", 3);
    put_file(LDIR "/sub/b.cfg", "hello", 5);
    put_file(LDIR "/empty.cfg", "", 0);
    put_file("build/mt_load_outside.txt", "abc", 3);

    char ha[65], hb[65], he[65], text[512];
    lhex("abc", 3, ha);
    lhex("hello", 5, hb);
    lhex("", 0, he);
    snprintf(text, sizeof(text), "%s 3 a.cfg\n%s 5 sub/b.cfg\n%s 0 empty.cfg\n", ha, hb, he);
    put_file(LMPATH, text, strlen(text));
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256(text, strlen(text), root);

#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(loaded(reshield_load_verified_asset(NULL, LDIR, "a.cfg", NULL, 16, &buf, &len), &buf, &len, "abc", 3),
                "load (disabled): reads the file without a manifest");
    put_file(LDIR "/a.cfg", "xyz", 3);
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, &len), &buf, &len, "xyz", 3),
                "load (disabled): a modified file is not verified");
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "../mt_load_outside.txt", root, 16, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_IO_ERROR), "load (disabled): '..' path rejected");
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 2, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_IO_ERROR), "load (disabled): over max_size is IO_ERROR");
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "nope.cfg", root, 16, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_IO_ERROR), "load (disabled): missing file is IO_ERROR");
    ASSERT_TRUE(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, NULL, &len) ==
                    RESHIELD_MANIFEST_IO_ERROR, "load (disabled): NULL out_buf is IO_ERROR");
#else
    ASSERT_TRUE(loaded(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, &len), &buf, &len, "abc", 3),
                "load: valid asset returns its bytes");
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset(LMPATH, LDIR, "sub/b.cfg", root, 5, &buf, &len), &buf, &len, "hello", 5),
                "load: nested asset, size exactly max_size, passes");
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset(LMPATH, LDIR, "empty.cfg", root, 0, &buf, &len), &buf, &len, "", 0),
                "load: empty asset returns a non-NULL empty buffer");

    /* The buffer is a copy: changing the file afterwards does not change it. */
    buf = (void *)1;
    reshield_manifest_status_t st = reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, &len);
    put_file(LDIR "/a.cfg", "xyz", 3);
    ASSERT_TRUE(st == RESHIELD_MANIFEST_OK && buf != NULL && len == 3 && memcmp(buf, "abc", 3) == 0,
                "load: bytes stay the verified ones after the file is replaced");
    reshield_free_asset(buf);

    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "load: 1-byte change (same size) is ASSET_MISMATCH, no buffer");
    put_file(LDIR "/a.cfg", "abcd", 4);
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "load: longer file is ASSET_MISMATCH");
    put_file(LDIR "/a.cfg", "ab", 2);
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "load: shorter file is ASSET_MISMATCH");
    put_file(LDIR "/a.cfg", "abc", 3);
    remove(LDIR "/sub/b.cfg");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "sub/b.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "load: missing file is ASSET_MISMATCH");
    put_file(LDIR "/sub/b.cfg", "hello", 5);
    put_file(LDIR "/unlisted.cfg", "abc", 3);
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "unlisted.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "load: a file the manifest does not list is ASSET_MISMATCH");

    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 2, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_IO_ERROR), "load: asset larger than max_size is IO_ERROR");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 0, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_IO_ERROR), "load: max_size 0 only admits an empty asset");

    static const char *const bad_paths[] = { "../mt_load_outside.txt", "sub/../a.cfg", "/etc/passwd",
                                             "sub//b.cfg", "sub\\b.cfg", "a.cfg/", "", "." };
    for (size_t i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); i++) {
        buf = (void *)1;
        len = 99;
        char msg[96];
        snprintf(msg, sizeof(msg), "load: unsafe path '%s' is IO_ERROR", bad_paths[i]);
        ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, bad_paths[i], root, 16, &buf, &len), &buf, &len,
                            RESHIELD_MANIFEST_IO_ERROR), msg);
    }
    /* A manifest cannot list a '..' entry either, so even a file that exists outside is unreachable. */
    snprintf(text, sizeof(text), "%s 3 ../mt_load_outside.txt\n", ha);
    put_file("build/mt_load_m2.txt", text, strlen(text));
    uint8_t root2[RESHIELD_SHA256_SIZE];
    reshield_sha256(text, strlen(text), root2);
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset("build/mt_load_m2.txt", LDIR, "../mt_load_outside.txt", root2, 16,
                                                     &buf, &len), &buf, &len, RESHIELD_MANIFEST_IO_ERROR),
                "load: manifest listing a '..' entry does not reach the outside file");
    remove("build/mt_load_m2.txt");

    char longbase[1100];
    memset(longbase, 'd', sizeof(longbase) - 1);
    longbase[sizeof(longbase) - 1] = '\0';
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, longbase, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "load: a path that does not fit fails closed");

    uint8_t bad_root[RESHIELD_SHA256_SIZE];
    memcpy(bad_root, root, sizeof(bad_root));
    bad_root[0] ^= 1u;
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", bad_root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ROOT_MISMATCH), "load: wrong root is ROOT_MISMATCH, no buffer");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", NULL, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_UNSEALED), "load: unsealed test binary with no root is UNSEALED");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset("build/does_not_exist.txt", LDIR, "a.cfg", root, 16, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_IO_ERROR), "load: missing manifest is IO_ERROR");
    ASSERT_TRUE(reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, NULL, &len) ==
                        RESHIELD_MANIFEST_IO_ERROR &&
                    reshield_load_verified_asset(LMPATH, LDIR, "a.cfg", root, 16, &buf, NULL) ==
                        RESHIELD_MANIFEST_IO_ERROR &&
                    reshield_load_verified_asset(NULL, LDIR, "a.cfg", root, 16, &buf, &len) ==
                        RESHIELD_MANIFEST_IO_ERROR,
                "load: NULL output or NULL manifest path is IO_ERROR");
    reshield_free_asset(NULL);

#ifndef _WIN32
    /* A symlink to a regular file is read through (content stays bound to the hash); a link to a
     * device, a dangling link and a link to different bytes are not accepted. */
    ASSERT_TRUE(symlink("a.cfg", LDIR "/link.cfg") == 0, "load: create symlink to a regular file");
    ASSERT_TRUE(symlink("/dev/zero", LDIR "/zero.bin") == 0, "load: create /dev/zero symlink");
    ASSERT_TRUE(symlink("nowhere", LDIR "/dangling.cfg") == 0, "load: create dangling symlink");
    ASSERT_TRUE(symlink("sub/b.cfg", LDIR "/bytes.cfg") == 0, "load: create symlink to other bytes");
    snprintf(text, sizeof(text), "%s 3 link.cfg\n%s 3 zero.bin\n%s 3 dangling.cfg\n%s 3 bytes.cfg\n", ha, ha, ha, ha);
    put_file("build/mt_load_m3.txt", text, strlen(text));
    uint8_t root3[RESHIELD_SHA256_SIZE];
    reshield_sha256(text, strlen(text), root3);
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset("build/mt_load_m3.txt", LDIR, "link.cfg", root3, 16, &buf, &len),
                       &buf, &len, "abc", 3), "load: symlink to a matching regular file passes");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset("build/mt_load_m3.txt", LDIR, "zero.bin", root3, 16, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_ASSET_MISMATCH), "load: symlink to /dev/zero is ASSET_MISMATCH");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset("build/mt_load_m3.txt", LDIR, "dangling.cfg", root3, 16, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_ASSET_MISMATCH), "load: dangling symlink is ASSET_MISMATCH");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset("build/mt_load_m3.txt", LDIR, "bytes.cfg", root3, 16, &buf, &len),
                        &buf, &len, RESHIELD_MANIFEST_ASSET_MISMATCH), "load: symlink to other bytes is ASSET_MISMATCH");
    remove(LDIR "/link.cfg");
    remove(LDIR "/zero.bin");
    remove(LDIR "/dangling.cfg");
    remove(LDIR "/bytes.cfg");
    remove("build/mt_load_m3.txt");
#endif
#endif

    remove(LDIR "/a.cfg");
    remove(LDIR "/sub/b.cfg");
    remove(LDIR "/empty.cfg");
    remove(LDIR "/unlisted.cfg");
    rmdir(LDIR "/sub");
    rmdir(LDIR);
    remove(LMPATH);
    remove("build/mt_load_outside.txt");
}

int main(void) {
    const char *asset_path = "build/test_asset_tmp.txt";
    const char *manifest_path = "build/test_manifest_tmp.txt";
    const char *payload = "level=1\nscore_cap=9999\n";

    FILE *af = fopen(asset_path, "wb");
    ASSERT_TRUE(af != NULL, "create temp asset file");
    fwrite(payload, 1, strlen(payload), af);
    fclose(af);

    uint8_t asset_hash[RESHIELD_SHA256_SIZE];
    uint64_t asset_size = 0;
    ASSERT_TRUE(reshield_sha256_file(asset_path, asset_hash, &asset_size) == 0 &&
                asset_size == strlen(payload),
                "reshield_sha256_file() hashes asset and reports exact size");

    char asset_hex[65];
    hash_to_hex(asset_hash, asset_hex);

    FILE *mf = fopen(manifest_path, "wb");
    ASSERT_TRUE(mf != NULL, "create temp manifest file");
    fprintf(mf, "%s %llu test_asset_tmp.txt\n", asset_hex, (unsigned long long)asset_size);
    fclose(mf);

    uint8_t root_hash[RESHIELD_SHA256_SIZE];
    ASSERT_TRUE(reshield_sha256_file(manifest_path, root_hash, NULL) == 0,
                "compute manifest root SHA-256");

    char failed_path[128] = { 0 };
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               failed_path, sizeof(failed_path)) == RESHIELD_MANIFEST_OK,
                "valid manifest and asset pass verification");

    ASSERT_TRUE(reshield_verify_single_asset(manifest_path, "build",
                                             "test_asset_tmp.txt", root_hash) == RESHIELD_MANIFEST_OK,
                "single-asset verification passes for valid asset");

    /* Modify asset by 1 byte */
    af = fopen(asset_path, "wb");
    fputs("level=2\nscore_cap=9999\n", af);
    fclose(af);

#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               failed_path, sizeof(failed_path)) == RESHIELD_MANIFEST_OK,
                "disabled build skips asset mismatch");
#else
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               failed_path, sizeof(failed_path)) == RESHIELD_MANIFEST_ASSET_MISMATCH,
                "modified asset triggers RESHIELD_MANIFEST_ASSET_MISMATCH");
    ASSERT_TRUE(strcmp(failed_path, "test_asset_tmp.txt") == 0,
                "failed_path reports exact modified asset relative path");

    /* Wrong root hash */
    root_hash[0] ^= 0xffu;
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               NULL, 0) == RESHIELD_MANIFEST_ROOT_MISMATCH,
                "wrong manifest root triggers RESHIELD_MANIFEST_ROOT_MISMATCH");
#endif

    remove(asset_path);
    remove(manifest_path);

#ifndef RESHIELD_DISABLE
    test_manifest_edge_cases();
    test_asset_unreadable();
    test_strict_manifest();
#endif
    test_load_verified_asset();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All manifest unit tests passed.\n");
    return 0;
}
