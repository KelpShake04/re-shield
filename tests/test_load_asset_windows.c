/* Windows-only tests for reshield_load_verified_asset(): path rules that only matter on Windows
 * (backslash, drive letters, UNC and \\?\ prefixes, device names, ADS), the MAX_PATH limit (the
 * file layer opens paths as given, with no \\?\ prefix), replacing a file under the loader, and a
 * file that another handle keeps open. Test files are created with \\?\ paths so that fixtures
 * longer than MAX_PATH can exist. On other platforms main() only prints SKIP (the portable cases
 * are in tests/test_manifest.c). */
#ifndef _WIN32
#include <stdio.h>

int main(void) {
    printf("SKIP: Windows-only test\n");
    return 0;
}
#else

#include "reshield/manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

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

#define ROOT "build/mt_lw"
#define MANIFEST "build/mt_lw_manifest.txt"
#define LONG_OK ROOT "_ok"
#define LONG_BAD ROOT "_long"

/* ASCII relative path with '/' -> "\\?\<cwd>\<rel with backslashes>". 0 on overflow. */
static int long_path(const char *rel, wchar_t *out, size_t cap) {
    wchar_t cwd[MAX_PATH];
    DWORD n = GetCurrentDirectoryW(MAX_PATH, cwd);
    size_t rl = strlen(rel);
    if (n == 0 || n >= MAX_PATH || 4u + n + 1u + rl + 1u > cap) {
        return 0;
    }
    wcscpy(out, L"\\\\?\\");
    wcscat(out, cwd);
    wcscat(out, L"\\");
    wchar_t *p = out + wcslen(out);
    for (size_t i = 0; i <= rl; i++) {
        p[i] = rel[i] == '/' ? L'\\' : (wchar_t)(unsigned char)rel[i];
    }
    return 1;
}

static void mkdirs(const char *rel) {
    char tmp[2048];
    wchar_t w[2048];
    size_t n = strlen(rel);
    if (n >= sizeof(tmp)) {
        return;
    }
    for (size_t i = 1; i <= n; i++) {
        if (rel[i] == '/' || rel[i] == '\0') {
            memcpy(tmp, rel, i);
            tmp[i] = '\0';
            if (long_path(tmp, w, 2048)) {
                CreateDirectoryW(w, NULL); /* "already exists" is fine */
            }
        }
    }
}

static int put(const char *rel, const char *data, size_t len) {
    wchar_t w[2048];
    if (!long_path(rel, w, 2048)) {
        return 0;
    }
    HANDLE h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD wr = 0;
    int ok = len == 0 || (WriteFile(h, data, (DWORD)len, &wr, NULL) && wr == len);
    CloseHandle(h);
    return ok;
}

static int exists(const char *rel) {
    wchar_t w[2048];
    return long_path(rel, w, 2048) && GetFileAttributesW(w) != INVALID_FILE_ATTRIBUTES;
}

static void rm(const char *rel, int dir) {
    wchar_t w[2048];
    if (long_path(rel, w, 2048)) {
        if (dir) {
            RemoveDirectoryW(w);
        } else {
            DeleteFileW(w);
        }
    }
}

/* Removes the file `rel` and then its directories up to (and including) `top`. */
static void rm_tree(const char *rel, const char *top) {
    char tmp[2048];
    size_t tl = strlen(top);
    if (strlen(rel) >= sizeof(tmp)) {
        return;
    }
    strcpy(tmp, rel);
    rm(tmp, 0);
    while (strlen(tmp) > tl) {
        char *slash = strrchr(tmp, '/');
        if (slash == NULL) {
            break;
        }
        *slash = '\0';
        rm(tmp, 1);
    }
}

static void hash_hex(const char *data, size_t len, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t h[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, len, h);
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        out[i * 2] = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 0x0f];
    }
    out[64] = '\0';
}

/* Outputs are read only after the call returned (unspecified evaluation order otherwise). */
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

/* Builds "<prefix>/<n components of `width` chars>"; the file a.cfg goes in the last one. */
static void deep_dir(char *out, size_t cap, const char *prefix, int n, int width) {
    size_t pos = (size_t)snprintf(out, cap, "%s", prefix);
    for (int i = 0; i < n && pos + (size_t)width + 2u < cap; i++) {
        out[pos++] = '/';
        memset(out + pos, 'd', (size_t)width);
        pos += (size_t)width;
    }
    out[pos] = '\0';
}

/* Manifest "<hash of abc> 3 a.cfg\n" at MANIFEST; returns its SHA-256 in root. */
static void write_manifest_a(uint8_t root[RESHIELD_SHA256_SIZE]) {
    char ha[65], text[128];
    hash_hex("abc", 3, ha);
    snprintf(text, sizeof(text), "%s 3 a.cfg\n", ha);
    put(MANIFEST, text, strlen(text));
    reshield_sha256(text, strlen(text), root);
}

static void test_basic_and_paths(void) {
    void *buf = (void *)1;
    size_t len = 99;
    char ha[65], hb[65], text[256];
    mkdirs(ROOT "/sub");
    put(ROOT "/a.cfg", "abc", 3);
    put(ROOT "/sub/b.cfg", "hello", 5);
    hash_hex("abc", 3, ha);
    hash_hex("hello", 5, hb);
    snprintf(text, sizeof(text), "%s 3 a.cfg\n%s 5 sub/b.cfg\n", ha, hb);
    put(MANIFEST, text, strlen(text));
    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256(text, strlen(text), root);

    ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len, "abc", 3),
                "win load: valid asset");
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, ROOT, "sub/b.cfg", root, 16, &buf, &len), &buf, &len,
                        "hello", 5), "win load: nested asset (forward slash)");
    buf = (void *)1;
    /* Windows opens "build\mt_lw" as well as "build/mt_lw": a backslash base directory is the caller's. */
    ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, "build\\mt_lw", "a.cfg", root, 16, &buf, &len), &buf, &len,
                        "abc", 3), "win load: base directory with a backslash works");

    /* 1-byte change, same size. */
    put(ROOT "/a.cfg", "abd", 3);
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "win load: 1-byte change is ASSET_MISMATCH");
    put(ROOT "/a.cfg", "abc", 3);

    /* The manifest lookup is byte-exact although the file system is case-insensitive. */
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, ROOT, "A.CFG", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "win load: other letter case is not a listed entry");

    static const char *const bad_paths[] = {
        "sub\\b.cfg", "..\\a.cfg", "sub\\..\\a.cfg", "\\a.cfg", "/a.cfg",
        "C:\\Windows\\win.ini", "C:/Windows/win.ini", "c:a.cfg", "C:", "\\\\server\\share\\a.cfg",
        "\\\\?\\C:\\Windows\\win.ini", "\\\\.\\C:\\Windows\\win.ini",
        "..", "../a.cfg", "sub/../a.cfg", "sub/./b.cfg",
        "CON", "con", "NUL.txt", "sub/AUX", "sub/prn.cfg", "COM1", "lpt9.dat", "CONIN$", "CONOUT$",
        "a.cfg.", "a.cfg ", "sub /b.cfg", "a.cfg:stream", "a.cfg::$DATA", "a?.cfg", "a*.cfg", "a|b", "a<b", "a>b",
        "a\"b", "a\tb", "a\nb",
    };
    for (size_t i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); i++) {
        buf = (void *)1;
        len = 99;
        char msg[160];
        snprintf(msg, sizeof(msg), "win load: unsafe path #%u is IO_ERROR", (unsigned)i);
        ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, ROOT, bad_paths[i], root, 16, &buf, &len), &buf, &len,
                            RESHIELD_MANIFEST_IO_ERROR), msg);
    }
}

static void test_replace_and_open_handles(void) {
    void *buf = (void *)1;
    size_t len = 99;
    uint8_t root[RESHIELD_SHA256_SIZE];
    write_manifest_a(root);
    put(ROOT "/a.cfg", "abc", 3);

    /* Rename-over replacement with same-size different bytes: refused; the original bytes: accepted. */
    put(ROOT "/a.new", "xyz", 3);
    wchar_t from[2048], to[2048];
    ASSERT_TRUE(long_path(ROOT "/a.new", from, 2048) && long_path(ROOT "/a.cfg", to, 2048) &&
                    MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING),
                "win load: replace a.cfg by rename");
    ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "win load: replaced file is ASSET_MISMATCH");
    put(ROOT "/a.new", "abc", 3);
    ASSERT_TRUE(MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING), "win load: replace a.cfg by rename (original bytes)");
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len, "abc", 3),
                "win load: file replaced back to the listed bytes loads");

    /* A holder that shares reading keeps the file open: the load still works, and sees its later write. */
    HANDLE h = CreateFileW(to, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    ASSERT_TRUE(h != INVALID_HANDLE_VALUE, "win load: open a.cfg for writing, sharing read");
    if (h != INVALID_HANDLE_VALUE) {
        buf = (void *)1;
        ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len,
                            "abc", 3), "win load: file held open by another handle loads");
        DWORD wr = 0;
        ASSERT_TRUE(WriteFile(h, "abd", 3, &wr, NULL) && wr == 3, "win load: write through the held handle");
        buf = (void *)1;
        ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len,
                            RESHIELD_MANIFEST_ASSET_MISMATCH), "win load: write through a held handle is detected");
        CloseHandle(h);
    }
    put(ROOT "/a.cfg", "abc", 3);

    /* A directory in place of the file is not a regular file. */
    rm(ROOT "/a.cfg", 0);
    mkdirs(ROOT "/a.cfg");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "win load: a directory is ASSET_MISMATCH");
    rm(ROOT "/a.cfg", 1);
    put(ROOT "/a.cfg", "abc", 3);
    buf = (void *)1;
    ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, ROOT, "a.cfg", root, 16, &buf, &len), &buf, &len, "abc", 3),
                "win load: file back in place loads again");
}

static void test_max_path(void) {
    void *buf = (void *)1;
    size_t len = 99;
    uint8_t root[RESHIELD_SHA256_SIZE];
    write_manifest_a(root);
    char dir[1024], file[1100];
    wchar_t cwd[MAX_PATH];
    DWORD cwd_len = GetCurrentDirectoryW(MAX_PATH, cwd);
    printf("cwd length %lu\n", (unsigned long)cwd_len);

    /* Control: a deep path that still fits MAX_PATH loads (two 40-char components, short cwd). */
    deep_dir(dir, sizeof(dir), LONG_OK, 2, 40);
    snprintf(file, sizeof(file), "%s/a.cfg", dir);
    mkdirs(dir);
    ASSERT_TRUE(put(file, "abc", 3) && cwd_len > 0 && cwd_len + 1u + strlen(file) < MAX_PATH,
                "win load: fixture under MAX_PATH created");
    ASSERT_TRUE(loaded(reshield_load_verified_asset(MANIFEST, dir, "a.cfg", root, 16, &buf, &len), &buf, &len, "abc", 3),
                "win load: path under MAX_PATH loads");
    rm_tree(file, LONG_OK);

    /* Over MAX_PATH but inside the library's 1024-byte buffer: the file exists (created with \\?\),
     * yet the open without prefix fails, so the load fails closed. */
    deep_dir(dir, sizeof(dir), LONG_BAD, 7, 50);
    snprintf(file, sizeof(file), "%s/a.cfg", dir);
    mkdirs(dir);
    ASSERT_TRUE(put(file, "abc", 3) && exists(file) && cwd_len + 1u + strlen(file) > MAX_PATH &&
                    strlen(dir) + 8u < 1024u,
                "win load: fixture over MAX_PATH (and under 1024 bytes) created");
    buf = (void *)1;
    ASSERT_TRUE(refused(reshield_load_verified_asset(MANIFEST, dir, "a.cfg", root, 16, &buf, &len), &buf, &len,
                        RESHIELD_MANIFEST_ASSET_MISMATCH), "win load: path over MAX_PATH fails closed (ASSET_MISMATCH)");
    rm_tree(file, LONG_BAD);
}

int main(void) {
    mkdirs("build");
    test_basic_and_paths();
    test_replace_and_open_handles();
    test_max_path();

    rm(ROOT "/a.cfg", 0);
    rm(ROOT "/a.new", 0);
    rm(ROOT "/sub/b.cfg", 0);
    rm(ROOT "/sub", 1);
    rm(ROOT, 1);
    rm(MANIFEST, 0);

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All Windows load_verified_asset tests passed.\n");
    return 0;
}
#endif
