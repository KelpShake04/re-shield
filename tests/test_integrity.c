#include "reshield/integrity.h"

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

static void hash_to_hex(const uint8_t hash[RESHIELD_SHA256_SIZE], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        out[i * 2 + 0] = hex[(hash[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = hex[hash[i] & 0x0fu];
    }
    out[64] = '\0';
}

static void test_sha256_vectors(void) {
    uint8_t digest[RESHIELD_SHA256_SIZE];
    char hex[65];

    /* NIST FIPS 180-4 test vector: "" */
    reshield_sha256("", 0, digest);
    hash_to_hex(digest, hex);
    ASSERT_TRUE(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
                "SHA-256(\"\") matches NIST vector");

    /* NIST test vector: "abc" */
    reshield_sha256("abc", 3, digest);
    hash_to_hex(digest, hex);
    ASSERT_TRUE(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
                "SHA-256(\"abc\") matches NIST vector");

    /* Multi-block NIST test vector */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    reshield_sha256(msg, strlen(msg), digest);
    hash_to_hex(digest, hex);
    ASSERT_TRUE(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
                "SHA-256(448-bit message) matches NIST vector");
}

static void test_verify_buffer(void) {
    uint8_t buf[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t expected[RESHIELD_SHA256_SIZE];
    reshield_sha256(buf, sizeof(buf), expected);

    ASSERT_TRUE(reshield_verify_buffer(buf, sizeof(buf), expected) == 1,
                "reshield_verify_buffer() returns 1 on matching buffer");

    buf[7] ^= 0x01u;
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_verify_buffer(buf, sizeof(buf), expected) == 1,
                "reshield_verify_buffer() returns 1 when RESHIELD_DISABLE is set");
#else
    ASSERT_TRUE(reshield_verify_buffer(buf, sizeof(buf), expected) == 0,
                "reshield_verify_buffer() returns 0 on 1-bit tamper");
#endif
}

#ifndef RESHIELD_DISABLE
typedef struct {
    int called;
    reshield_integrity_status_t status;
} integrity_cb_state_t;

static void record_cb(const reshield_integrity_result_t *res, void *user_data) {
    integrity_cb_state_t *st = (integrity_cb_state_t *)user_data;
    st->called++;
    st->status = res->status;
}
#endif

static void test_unsealed_code_section(void) {
    reshield_integrity_result_t res;
    reshield_integrity_status_t st = reshield_verify_code_section(&res);

#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(st == RESHIELD_INTEGRITY_OK,
                "disabled build returns OK for unsealed binary");
#else
    ASSERT_TRUE(st == RESHIELD_INTEGRITY_UNSEALED,
                "unsealed test binary reports RESHIELD_INTEGRITY_UNSEALED");
    ASSERT_TRUE(res.actual_size > 0,
                "runtime code section discovery reports non-zero size");

    integrity_cb_state_t cb = { 0, RESHIELD_INTEGRITY_OK };
    reshield_integrity_config_t cfg_strict = {
        .policy = RESHIELD_INTEGRITY_POLICY_CALLBACK,
        .allow_unsealed = 0,
        .callback = record_cb,
        .user_data = &cb
    };
    (void)reshield_integrity_guard(&cfg_strict);
    ASSERT_TRUE(cb.called == 1 && cb.status == RESHIELD_INTEGRITY_UNSEALED,
                "guard(CALLBACK, allow_unsealed=0) invokes callback on unsealed binary");

    cb.called = 0;
    reshield_integrity_config_t cfg_allow = {
        .policy = RESHIELD_INTEGRITY_POLICY_CALLBACK,
        .allow_unsealed = 1,
        .callback = record_cb,
        .user_data = &cb
    };
    (void)reshield_integrity_guard(&cfg_allow);
    ASSERT_TRUE(cb.called == 0,
                "guard(CALLBACK, allow_unsealed=1) does not trigger callback on unsealed binary");
#endif
}

int main(void) {
    test_sha256_vectors();
    test_verify_buffer();
    test_unsealed_code_section();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All integrity unit tests passed.\n");
    return 0;
}
