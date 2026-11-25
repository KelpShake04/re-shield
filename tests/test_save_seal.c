/* HMAC-SHA256 against RFC 4231 (cases 1,2,3,4,6,7) and Python hmac vectors, plus the save-seal
 * tag/verify contract: round trip, single-bit tamper, wrong key, empty data, bad arguments. */
#include "reshield/save_seal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static void to_hex(const uint8_t *in, size_t n, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2 + 0] = hex[(in[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = hex[in[i] & 0x0fu];
    }
    out[n * 2] = '\0';
}

static void fill(uint8_t *p, size_t n, uint8_t v) {
    memset(p, v, n);
}

/* Expected tag hex vs actual bytes. */
static int tag_is(const uint8_t tag[32], const char *want_hex) {
    char got[65];
    to_hex(tag, 32, got);
    return strcmp(got, want_hex) == 0;
}

static void check_hmac(const char *name, const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, const char *want_hex) {
    uint8_t out[32];
    int rc = reshield_hmac_sha256(key, key_len, msg, msg_len, out);
    ASSERT_TRUE(rc == 0 && tag_is(out, want_hex), name);
}

static void test_rfc4231(void) {
    uint8_t key[131];
    uint8_t msg[50];

    fill(key, 20, 0x0b);
    check_hmac("RFC 4231 case 1", key, 20, (const uint8_t *)"Hi There", 8,
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    check_hmac("RFC 4231 case 2", (const uint8_t *)"Jefe", 4,
               (const uint8_t *)"what do ya want for nothing?", 28,
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    fill(key, 20, 0xaa);
    fill(msg, 50, 0xdd);
    check_hmac("RFC 4231 case 3", key, 20, msg, 50,
               "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    for (uint8_t i = 0; i < 25; i++) {
        key[i] = (uint8_t)(i + 1);
    }
    fill(msg, 50, 0xcd);
    check_hmac("RFC 4231 case 4", key, 25, msg, 50,
               "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

    fill(key, 131, 0xaa);
    check_hmac("RFC 4231 case 6 (131-byte key, hashed first)", key, 131,
               (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54,
               "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    const char *m7 = "This is a test using a larger than block-size key and a larger than "
                     "block-size data. The key needs to be hashed before being used by the "
                     "HMAC algorithm.";
    check_hmac("RFC 4231 case 7 (large key and data)", key, 131, (const uint8_t *)m7, strlen(m7),
               "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

static void test_extra_vectors(void) {
    uint8_t key[100];
    uint8_t data[1000];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i & 0xffu);
    }

    /* Key at the block size (no hashing) and one byte over (hashed). */
    fill(key, 64, 'K');
    check_hmac("64-byte key", key, 64, (const uint8_t *)"abc", 3,
               "42fcb78c5fd7e14932bf6f88a2d7adb9aad4a4a0dfaa79ba4a03493b28aec3db");
    fill(key, 65, 'K');
    check_hmac("65-byte key", key, 65, (const uint8_t *)"abc", 3,
               "a3e2dc7c2d115c8b6de4695a8d0de8c80383269c1ec52e3d34d7a05cbbb6b267");

    check_hmac("empty message (non-NULL)", (const uint8_t *)"key", 3, (const uint8_t *)"", 0,
               "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
    check_hmac("empty message (NULL)", (const uint8_t *)"key", 3, NULL, 0,
               "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
    check_hmac("1000-byte message", (const uint8_t *)"key", 3, data, sizeof(data),
               "388444776de1b9f1d4f280bc508e4e2eb543b0fc3e69c811edbcd1b098a23838");

    uint8_t tag[32];
    const uint8_t skey[] = "save-key"; /* the vectors use the 8 text bytes, not the NUL */
    ASSERT_TRUE(reshield_save_tag(skey, 8, "hello save", 10, tag) == 0 &&
                    tag_is(tag, "02b492224807713a186edac75174612e39be50d47c6055b8bccf9f544dcdfd65"),
                "save tag vector (domain prefix included)");
    ASSERT_TRUE(reshield_save_tag(skey, 8, "", 0, tag) == 0 &&
                    tag_is(tag, "95646c8b306e068f9cd310995cfe9ff8e0f185512431883ba66a9bfc4af04da1"),
                "save tag vector, empty data");
    fill(key, 100, 'S');
    ASSERT_TRUE(reshield_save_tag(key, 100, data, sizeof(data), tag) == 0 &&
                    tag_is(tag, "5076e9ab027d8f68acdc9a2935b8a7f078ac035db579cbe3d7564a6a17f31975"),
                "save tag vector, 100-byte key, 1000-byte data");

    /* Domain separation: the save tag is not the plain HMAC of the data. */
    uint8_t plain[32];
    ASSERT_TRUE(reshield_hmac_sha256(skey, 8, (const uint8_t *)"hello save", 10, plain) == 0 &&
                    reshield_save_tag(skey, 8, "hello save", 10, tag) == 0 &&
                    memcmp(plain, tag, 32) != 0,
                "save tag differs from plain HMAC of the same data");
}

static void test_roundtrip_and_tamper(void) {
    const uint8_t key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t data[40];
    uint8_t tag[32];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 7u + 3u);
    }

    ASSERT_TRUE(reshield_save_tag(key, sizeof(key), data, sizeof(data), tag) == 0, "tag computes");
    ASSERT_TRUE(reshield_save_verify(key, sizeof(key), data, sizeof(data), tag) == 1,
                "verify round trip returns 1");

    int all_data_bits = 1;
    for (size_t i = 0; i < sizeof(data); i++) {
        for (unsigned b = 0; b < 8; b++) {
            data[i] ^= (uint8_t)(1u << b);
            if (reshield_save_verify(key, sizeof(key), data, sizeof(data), tag) != 0) {
                all_data_bits = 0;
            }
            data[i] ^= (uint8_t)(1u << b);
        }
    }
    ASSERT_TRUE(all_data_bits, "every single-bit data flip is detected");

    int all_tag_bits = 1;
    for (size_t i = 0; i < sizeof(tag); i++) {
        for (unsigned b = 0; b < 8; b++) {
            tag[i] ^= (uint8_t)(1u << b);
            if (reshield_save_verify(key, sizeof(key), data, sizeof(data), tag) != 0) {
                all_tag_bits = 0;
            }
            tag[i] ^= (uint8_t)(1u << b);
        }
    }
    ASSERT_TRUE(all_tag_bits, "every single-bit tag flip is detected");

    ASSERT_TRUE(reshield_save_verify(key, sizeof(key), data, sizeof(data) - 1, tag) == 0,
                "truncated data is detected");

    uint8_t key2[16];
    memcpy(key2, key, sizeof(key));
    key2[15] ^= 1u;
    ASSERT_TRUE(reshield_save_verify(key2, sizeof(key2), data, sizeof(data), tag) == 0,
                "wrong key (one bit) is detected");
    ASSERT_TRUE(reshield_save_verify(key, sizeof(key) - 1, data, sizeof(data), tag) == 0,
                "shorter key is detected");

    /* Empty save: valid, and NULL/non-NULL pointers agree. */
    uint8_t t_null[32], t_ptr[32];
    ASSERT_TRUE(reshield_save_tag(key, sizeof(key), NULL, 0, t_null) == 0 &&
                    reshield_save_tag(key, sizeof(key), data, 0, t_ptr) == 0 &&
                    memcmp(t_null, t_ptr, 32) == 0,
                "len 0 data: NULL and non-NULL give the same tag");
    ASSERT_TRUE(reshield_save_verify(key, sizeof(key), NULL, 0, t_null) == 1,
                "len 0 data verifies");
    ASSERT_TRUE(reshield_save_verify(key, sizeof(key), data, 1, t_null) == 0,
                "one byte of data does not verify against the empty tag");
}

static void test_bad_arguments(void) {
    const uint8_t key[] = {9, 8, 7, 6};
    uint8_t data[8] = {0};
    uint8_t tag[32];
    uint8_t out[32];
    uint8_t untouched[32];
    fill(out, 32, 0xa5);
    fill(untouched, 32, 0xa5);
    memset(tag, 0, sizeof(tag));

    ASSERT_TRUE(reshield_save_tag(NULL, 4, data, 8, out) == -1, "tag: NULL key");
    ASSERT_TRUE(reshield_save_tag(key, 0, data, 8, out) == -1, "tag: key_len 0");
    ASSERT_TRUE(reshield_save_tag(key, 4, NULL, 8, out) == -1, "tag: NULL data with len > 0");
    ASSERT_TRUE(reshield_save_tag(key, 4, data, 8, NULL) == -1, "tag: NULL out");
    ASSERT_TRUE(memcmp(out, untouched, 32) == 0, "tag: out untouched after failures");

    ASSERT_TRUE(reshield_hmac_sha256(NULL, 4, data, 8, out) == -1, "hmac: NULL key");
    ASSERT_TRUE(reshield_hmac_sha256(key, 0, data, 8, out) == -1, "hmac: key_len 0");
    ASSERT_TRUE(reshield_hmac_sha256(key, 4, NULL, 8, out) == -1, "hmac: NULL msg with len > 0");
    ASSERT_TRUE(reshield_hmac_sha256(key, 4, data, 8, NULL) == -1, "hmac: NULL out");
    ASSERT_TRUE(memcmp(out, untouched, 32) == 0, "hmac: out untouched after failures");

    ASSERT_TRUE(reshield_save_verify(NULL, 4, data, 8, tag) == -1, "verify: NULL key");
    ASSERT_TRUE(reshield_save_verify(key, 0, data, 8, tag) == -1, "verify: key_len 0");
    ASSERT_TRUE(reshield_save_verify(key, 4, NULL, 8, tag) == -1, "verify: NULL data with len > 0");
    ASSERT_TRUE(reshield_save_verify(key, 4, data, 8, NULL) == -1, "verify: NULL tag");

#if SIZE_MAX > 0xffffffffu
    /* Lengths the 64-bit SHA-256 bit counter cannot hold are refused before any byte is read
     * (the pointers below are valid but far smaller than the claimed length). */
    ASSERT_TRUE(reshield_save_tag(key, 4, data, SIZE_MAX, out) == -1, "tag: len SIZE_MAX");
    ASSERT_TRUE(reshield_hmac_sha256(key, 4, data, SIZE_MAX - 1, out) == -1,
                "hmac: len SIZE_MAX - 1");
    ASSERT_TRUE(reshield_save_verify(key, 4, data, SIZE_MAX, tag) == -1, "verify: len SIZE_MAX");
    ASSERT_TRUE(memcmp(out, untouched, 32) == 0, "overflow lengths leave out untouched");
#endif
}

int main(void) {
    test_rfc4231();
    test_extra_vectors();
    test_roundtrip_and_tamper();
    test_bad_arguments();
    if (g_failures != 0) {
        fprintf(stderr, "%d failure(s)\n", g_failures);
        return 1;
    }
    printf("all save_seal tests passed\n");
    return 0;
}
