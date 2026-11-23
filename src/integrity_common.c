#include "reshield/integrity.h"

#include <string.h>
#include <unistd.h>

/* Platform backend hook implemented in integrity_macos.c / integrity_linux.c */
extern int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size);

#if !defined(__APPLE__) && !defined(__linux__)
int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    (void)out_ptr;
    (void)out_size;
    return -1;
}
#endif

/**
 * Embedded integrity record patched at build time by tools/seal_binary.py.
 * Marked volatile + used so the compiler never constant-folds fields or drops the symbol.
 * Placed in writable/initialized data (outside __TEXT,__text / .text) to avoid circular hashing.
 */
typedef struct reshield_integrity_record {
    uint8_t  magic[RESHIELD_INTEGRITY_MAGIC_LEN]; /* "RSHLDCHK" */
    uint32_t version;
    uint32_t sealed;
    uint64_t expected_size;
    uint8_t  expected_sha256[RESHIELD_SHA256_SIZE];
} reshield_integrity_record_t;

#if defined(__GNUC__) || defined(__clang__)
#define RESHIELD_USED __attribute__((used))
#else
#define RESHIELD_USED
#endif

static volatile reshield_integrity_record_t RESHIELD_USED g_reshield_integrity_record = {
    .magic = { 'R', 'S', 'H', 'L', 'D', 'C', 'H', 'K' },
    .version = RESHIELD_INTEGRITY_RECORD_VERSION,
    .sealed = 0u,
    .expected_size = 0u,
    .expected_sha256 = { 0 }
};

#ifndef RESHIELD_DISABLE
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 0 : 1;
}

static void read_record(reshield_integrity_record_t *dst) {
    const volatile uint8_t *src = (const volatile uint8_t *)&g_reshield_integrity_record;
    uint8_t *out = (uint8_t *)dst;
    for (size_t i = 0; i < sizeof(*dst); i++) {
        out[i] = src[i];
    }
}
#endif

int reshield_verify_buffer(const void *data, size_t len,
                           const uint8_t expected_sha256[RESHIELD_SHA256_SIZE]) {
#ifdef RESHIELD_DISABLE
    (void)data;
    (void)len;
    (void)expected_sha256;
    return 1;
#else
    if (expected_sha256 == NULL) {
        return 0;
    }
    uint8_t actual[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, len, actual);
    return ct_memcmp(actual, expected_sha256, RESHIELD_SHA256_SIZE) == 0 ? 1 : 0;
#endif
}

reshield_integrity_status_t reshield_verify_code_section(reshield_integrity_result_t *out_result) {
    reshield_integrity_result_t res;
    memset(&res, 0, sizeof(res));

#ifdef RESHIELD_DISABLE
    res.status = RESHIELD_INTEGRITY_OK;
    if (out_result != NULL) {
        *out_result = res;
    }
    return res.status;
#else
    reshield_integrity_record_t rec;
    read_record(&rec);

    const uint8_t *code_ptr = NULL;
    uint64_t code_size = 0;
    if (reshield_platform_get_code_section(&code_ptr, &code_size) != 0 ||
        code_ptr == NULL || code_size == 0) {
        res.status = RESHIELD_INTEGRITY_ERROR;
        if (out_result != NULL) {
            *out_result = res;
        }
        return res.status;
    }

    res.actual_size = code_size;
    res.expected_size = rec.expected_size;
    memcpy(res.expected_sha256, rec.expected_sha256, RESHIELD_SHA256_SIZE);
    reshield_sha256(code_ptr, (size_t)code_size, res.actual_sha256);

    if (rec.version != RESHIELD_INTEGRITY_RECORD_VERSION || rec.sealed == 0u) {
        res.status = RESHIELD_INTEGRITY_UNSEALED;
    } else if (rec.expected_size != code_size ||
               ct_memcmp(res.actual_sha256, rec.expected_sha256, RESHIELD_SHA256_SIZE) != 0) {
        res.status = RESHIELD_INTEGRITY_TAMPERED;
    } else {
        res.status = RESHIELD_INTEGRITY_OK;
    }

    if (out_result != NULL) {
        *out_result = res;
    }
    return res.status;
#endif
}

reshield_integrity_status_t reshield_integrity_guard(const reshield_integrity_config_t *config) {
#ifdef RESHIELD_DISABLE
    (void)config;
    return RESHIELD_INTEGRITY_OK;
#else
    reshield_integrity_config_t effective = {
        .policy = RESHIELD_INTEGRITY_POLICY_REPORT,
        .allow_unsealed = 0,
        .callback = NULL,
        .user_data = NULL
    };

    if (config != NULL) {
        effective = *config;
    }

    reshield_integrity_result_t res;
    reshield_integrity_status_t status = reshield_verify_code_section(&res);

    int is_failure = (status != RESHIELD_INTEGRITY_OK) &&
                     !(status == RESHIELD_INTEGRITY_UNSEALED && effective.allow_unsealed);

    if (is_failure) {
        switch (effective.policy) {
            case RESHIELD_INTEGRITY_POLICY_CALLBACK:
                if (effective.callback != NULL) {
                    effective.callback(&res, effective.user_data);
                }
                break;
            case RESHIELD_INTEGRITY_POLICY_TERMINATE:
                /* Terminate process according to configured policy */
                _exit(1);
                break;
            case RESHIELD_INTEGRITY_POLICY_REPORT:
            default:
                break;
        }
    }

    return status;
#endif
}
