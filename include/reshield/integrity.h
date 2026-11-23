#ifndef RESHIELD_INTEGRITY_H
#define RESHIELD_INTEGRITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RESHIELD_SHA256_SIZE 32u
#define RESHIELD_INTEGRITY_MAGIC_LEN 8u
#define RESHIELD_INTEGRITY_RECORD_VERSION 1u

/**
 * Result status of a code-section integrity verification.
 */
typedef enum reshield_integrity_status {
    RESHIELD_INTEGRITY_OK       = 0, /* Hash and section size match sealed record (or RESHIELD_DISABLE) */
    RESHIELD_INTEGRITY_UNSEALED = 1, /* Binary has not been sealed at build time (sealed == 0) */
    RESHIELD_INTEGRITY_TAMPERED = 2, /* Code section size or SHA-256 mismatch */
    RESHIELD_INTEGRITY_ERROR    = 3  /* Could not locate runtime code section or unsupported platform */
} reshield_integrity_status_t;

/**
 * Enforcement policy for reshield_integrity_guard().
 */
typedef enum reshield_integrity_policy {
    RESHIELD_INTEGRITY_POLICY_REPORT    = 0, /* Return status only; caller decides */
    RESHIELD_INTEGRITY_POLICY_CALLBACK  = 1, /* Invoke user callback on non-OK status */
    RESHIELD_INTEGRITY_POLICY_TERMINATE = 2  /* Terminate process via _exit(1) */
} reshield_integrity_policy_t;

/**
 * Detailed verification output.
 */
typedef struct reshield_integrity_result {
    reshield_integrity_status_t status;
    uint64_t expected_size;
    uint64_t actual_size;
    uint8_t  expected_sha256[RESHIELD_SHA256_SIZE];
    uint8_t  actual_sha256[RESHIELD_SHA256_SIZE];
} reshield_integrity_result_t;

typedef void (*reshield_integrity_cb_t)(const reshield_integrity_result_t *result, void *user_data);

typedef struct reshield_integrity_config {
    reshield_integrity_policy_t policy;
    int                         allow_unsealed; /* Non-zero treats UNSEALED as non-fatal */
    reshield_integrity_cb_t     callback;       /* Used when policy == RESHIELD_INTEGRITY_POLICY_CALLBACK */
    void                       *user_data;
} reshield_integrity_config_t;

/**
 * Computes SHA-256 over [data, data + len) into out_hash (32 bytes).
 */
void reshield_sha256(const void *data, size_t len, uint8_t out_hash[RESHIELD_SHA256_SIZE]);

/**
 * Verifies that SHA-256(data, len) matches expected_sha256 in constant time.
 * Returns 1 on match (or when compiled with -DRESHIELD_DISABLE), 0 on mismatch.
 */
int reshield_verify_buffer(const void *data, size_t len,
                           const uint8_t expected_sha256[RESHIELD_SHA256_SIZE]);

/**
 * Hashes the main executable's in-memory code section (__TEXT,__text on macOS;
 * .text on Linux) and compares it against the build-time sealed record.
 * out_result may be NULL.
 */
reshield_integrity_status_t reshield_verify_code_section(reshield_integrity_result_t *out_result);

/**
 * Runs reshield_verify_code_section() and applies config->policy on failure.
 * If config is NULL, defaults to RESHIELD_INTEGRITY_POLICY_REPORT with allow_unsealed = 0.
 */
reshield_integrity_status_t reshield_integrity_guard(const reshield_integrity_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_INTEGRITY_H */
