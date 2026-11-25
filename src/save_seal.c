#include "reshield/save_seal.h"

#include "reshield/reshield.h"
#include "sha256_internal.h"

#define HMAC_BLOCK 64u

/* "reshield-save-v1" plus its NUL terminator. */
static const uint8_t SAVE_DOMAIN[] = {
    'r', 'e', 's', 'h', 'i', 'e', 'l', 'd', '-', 's', 'a', 'v', 'e', '-', 'v', '1', 0
};

/* HMAC over the concatenation of up to two message parts (the second may be empty). */
static int hmac_parts(const uint8_t *key, size_t key_len,
                      const void *a, size_t a_len,
                      const void *b, size_t b_len,
                      uint8_t out[32]) {
    if (key == NULL || key_len == 0 || out == NULL) {
        return -1;
    }
    uint8_t k0[HMAC_BLOCK] = {0};
    uint8_t pad[HMAC_BLOCK];
    uint8_t inner[RESHIELD_SAVE_TAG_SIZE];
    uint8_t result[RESHIELD_SAVE_TAG_SIZE];
    int rc = -1;

    if (key_len > HMAC_BLOCK) {
        reshield_sha256_part_t kp = {key, key_len};
        if (reshield_sha256_parts(&kp, 1, k0) != 0) { /* 32 bytes, the rest of k0 stays zero */
            goto done;
        }
    } else {
        for (size_t i = 0; i < key_len; i++) {
            k0[i] = key[i];
        }
    }

    for (size_t i = 0; i < HMAC_BLOCK; i++) {
        pad[i] = (uint8_t)(k0[i] ^ 0x36u);
    }
    { /* own scope: C++ refuses a goto that jumps past an initialized variable */
        reshield_sha256_part_t in_parts[3] = {{pad, HMAC_BLOCK}, {a, a_len}, {b, b_len}};
        if (reshield_sha256_parts(in_parts, 3, inner) != 0) {
            goto done;
        }
    }

    for (size_t i = 0; i < HMAC_BLOCK; i++) {
        pad[i] = (uint8_t)(k0[i] ^ 0x5cu);
    }
    {
        reshield_sha256_part_t out_parts[2] = {{pad, HMAC_BLOCK}, {inner, sizeof(inner)}};
        if (reshield_sha256_parts(out_parts, 2, result) != 0) {
            goto done;
        }
    }

    for (size_t i = 0; i < sizeof(result); i++) {
        out[i] = result[i];
    }
    rc = 0;
done:
    /* Best effort: SHA-256's own message-schedule scratch is not reachable from here. */
    reshield_secure_zero(k0, sizeof(k0));
    reshield_secure_zero(pad, sizeof(pad));
    reshield_secure_zero(inner, sizeof(inner));
    reshield_secure_zero(result, sizeof(result));
    return rc;
}

int reshield_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t out[32]) {
    return hmac_parts(key, key_len, msg, msg_len, NULL, 0, out);
}

int reshield_save_tag(const uint8_t *key, size_t key_len,
                      const void *data, size_t len,
                      uint8_t out_tag[32]) {
    return hmac_parts(key, key_len, SAVE_DOMAIN, sizeof(SAVE_DOMAIN), data, len, out_tag);
}

int reshield_save_verify(const uint8_t *key, size_t key_len,
                         const void *data, size_t len,
                         const uint8_t tag[32]) {
    if (tag == NULL) {
        return -1;
    }
    uint8_t expect[RESHIELD_SAVE_TAG_SIZE];
    if (reshield_save_tag(key, key_len, data, len, expect) != 0) {
        return -1;
    }
    /* No early exit and no branch on the bytes: all 32 iterations always run. */
    uint8_t diff = 0;
    for (size_t i = 0; i < sizeof(expect); i++) {
        diff |= (uint8_t)(expect[i] ^ tag[i]);
    }
    reshield_secure_zero(expect, sizeof(expect));
    return diff == 0 ? 1 : 0;
}
