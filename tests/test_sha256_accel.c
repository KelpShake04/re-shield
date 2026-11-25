/* SHA-256 hardware-instruction path vs the portable C path.
 *
 * Includes sha256.c directly to reach the streaming update (the public API has only the
 * one-shot call); the library's own sha256.o is not pulled from libreshield.a in that case,
 * sha256_accel.o is. Which backend runs is printed first: on a CPU/compiler without a
 * supported hardware path (or with -DRESHIELD_NO_HW_SHA) both sides of every comparison are the
 * portable code and only that path is checked. */
#include "../src/sha256.c"

#include <stdlib.h>

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

static void hex(const uint8_t h[32], char out[65]) {
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = d[h[i] >> 4];
        out[i * 2 + 1] = d[h[i] & 15];
    }
    out[64] = '\0';
}

/* Hash data in pieces of `chunk` bytes (0 = one piece) with whatever backend is active. */
static void hash_chunked(const uint8_t *data, size_t len, size_t chunk, uint8_t out[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (chunk == 0) {
        chunk = len > 0 ? len : 1;
    }
    for (size_t off = 0; off < len;) {
        size_t n = len - off < chunk ? len - off : chunk;
        sha256_update(&ctx, data + off, n);
        off += n;
    }
    sha256_final(&ctx, out);
}

static void hash_portable(const uint8_t *data, size_t len, size_t chunk, uint8_t out[32]) {
    reshield_sha256_force_portable(1);
    hash_chunked(data, len, chunk, out);
    reshield_sha256_force_portable(0);
}

static uint32_t g_rng = 0x12345678u;
static void fill_random(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        g_rng ^= g_rng << 13;
        g_rng ^= g_rng >> 17;
        g_rng ^= g_rng << 5;
        p[i] = (uint8_t)(g_rng >> 11);
    }
}

static void test_vectors(void) {
    uint8_t d[32];
    char h[65];

    hash_chunked((const uint8_t *)"abc", 3, 0, d);
    hex(d, h);
    ASSERT_TRUE(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
                "NIST \"abc\"");

    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hash_chunked((const uint8_t *)m, strlen(m), 0, d);
    hex(d, h);
    ASSERT_TRUE(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
                "NIST 448-bit message");

    uint8_t *a = malloc(1000000);
    ASSERT_TRUE(a != NULL, "alloc 1e6 bytes");
    if (a == NULL) {
        return;
    }
    memset(a, 'a', 1000000);
    hash_chunked(a, 1000000, 0, d);
    hex(d, h);
    ASSERT_TRUE(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
                "NIST one million 'a'");
    hash_chunked(a, 1000000, 1000, d);
    hex(d, h);
    ASSERT_TRUE(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
                "NIST one million 'a' in 1000-byte pieces");
    free(a);
}

static void test_all_lengths(void) {
    uint8_t buf[300];
    fill_random(buf, sizeof(buf));
    int bad = 0;
    for (size_t len = 0; len <= sizeof(buf); len++) {
        uint8_t hw[32], sw[32];
        hash_chunked(buf, len, 0, hw);
        hash_portable(buf, len, 0, sw);
        if (memcmp(hw, sw, 32) != 0) {
            fprintf(stderr, "mismatch at length %zu\n", len);
            bad++;
        }
    }
    ASSERT_TRUE(bad == 0, "lengths 0..300 match the portable path");
}

static void test_alignment(void) {
    static const size_t lens[] = { 0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 4096, 4099 };
    uint8_t *raw = malloc(4099 + 64);
    ASSERT_TRUE(raw != NULL, "alloc alignment buffer");
    if (raw == NULL) {
        return;
    }
    fill_random(raw, 4099 + 64);
    int bad = 0;
    for (size_t off = 0; off < 64; off++) {
        for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            uint8_t hw[32], sw[32];
            hash_chunked(raw + off, lens[i], 0, hw);
            hash_portable(raw + off, lens[i], 0, sw);
            if (memcmp(hw, sw, 32) != 0) {
                fprintf(stderr, "mismatch at offset %zu length %zu\n", off, lens[i]);
                bad++;
            }
        }
    }
    ASSERT_TRUE(bad == 0, "input alignment offsets 0..63 match the portable path");
    free(raw);
}

static void test_split_updates(void) {
    static const size_t chunks[] = { 1, 2, 3, 7, 55, 56, 63, 64, 65, 100, 127, 128, 129, 191, 4096 };
    enum { LEN = 5000 };
    uint8_t buf[LEN];
    fill_random(buf, LEN);
    uint8_t want[32];
    hash_portable(buf, LEN, 0, want);
    int bad = 0;
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        uint8_t hw[32], sw[32];
        hash_chunked(buf, LEN, chunks[i], hw);
        hash_portable(buf, LEN, chunks[i], sw);
        if (memcmp(hw, want, 32) != 0 || memcmp(sw, want, 32) != 0) {
            fprintf(stderr, "mismatch with %zu-byte updates\n", chunks[i]);
            bad++;
        }
    }
    ASSERT_TRUE(bad == 0, "split updates (1,63,64,65,... bytes) give the one-shot digest");

    /* a short piece first, so the next update starts from a partly filled buffer */
    int bad2 = 0;
    for (size_t first = 0; first <= 130; first++) {
        sha256_ctx_t c1;
        sha256_ctx_t c2;
        uint8_t a[32], b[32];
        sha256_init(&c1);
        sha256_update(&c1, buf, first);
        sha256_update(&c1, buf + first, LEN - first);
        sha256_final(&c1, a);
        reshield_sha256_force_portable(1);
        sha256_init(&c2);
        sha256_update(&c2, buf, first);
        sha256_update(&c2, buf + first, LEN - first);
        sha256_final(&c2, b);
        reshield_sha256_force_portable(0);
        if (memcmp(a, want, 32) != 0 || memcmp(b, want, 32) != 0) {
            bad2++;
        }
    }
    ASSERT_TRUE(bad2 == 0, "two-piece updates, first piece 0..130 bytes");
}

static void test_large_buffer(void) {
    size_t len = (size_t)64 * 1024 * 1024;
    uint8_t *big = malloc(len);
    ASSERT_TRUE(big != NULL, "alloc 64 MiB");
    if (big == NULL) {
        return;
    }
    fill_random(big, len);
    uint8_t hw[32], sw[32];
    reshield_sha256(big, len, hw);
    reshield_sha256_force_portable(1);
    reshield_sha256(big, len, sw);
    reshield_sha256_force_portable(0);
    ASSERT_TRUE(memcmp(hw, sw, 32) == 0, "64 MiB buffer matches the portable path");
    /* odd length and odd start: exercises the tail and an unaligned bulk run */
    reshield_sha256(big + 3, len - 3 - 17, hw);
    reshield_sha256_force_portable(1);
    reshield_sha256(big + 3, len - 3 - 17, sw);
    reshield_sha256_force_portable(0);
    ASSERT_TRUE(memcmp(hw, sw, 32) == 0, "64 MiB - 20 bytes at offset 3 matches the portable path");
    free(big);
}

int main(void) {
    static const char *const names[] = { "portable", "armv8", "shani" };
    int b = reshield_sha256_backend();
    printf("sha256 backend: %s\n", names[b >= 0 && b <= 2 ? b : 0]);
    if (b == 0) {
        printf("note: no hardware SHA path here; only the portable path is checked\n");
    }

    test_vectors();
    test_all_lengths();
    test_alignment();
    test_split_updates();
    test_large_buffer();

    if (g_failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", g_failures);
        return 1;
    }
    printf("All SHA-256 accel tests passed\n");
    return 0;
}
