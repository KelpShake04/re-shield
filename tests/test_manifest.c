#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "reshield/manifest.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <direct.h>
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

static void write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
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
    remove(ADIR "/\xed\x95\x9c\xea\xb8\x80.cfg");
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
#endif

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
#endif

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All manifest unit tests passed.\n");
    return 0;
}
