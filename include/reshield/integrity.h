#ifndef RESHIELD_INTEGRITY_H
#define RESHIELD_INTEGRITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RESHIELD_SHA256_SIZE 32u
#define RESHIELD_INTEGRITY_MAGIC_LEN 8u
#define RESHIELD_INTEGRITY_RECORD_VERSION 2u

/**
 * Result status of a code-section integrity verification.
 */
typedef enum reshield_integrity_status {
    RESHIELD_INTEGRITY_OK       = 0, /* Hash and section size match sealed record (or RESHIELD_DISABLE) */
    RESHIELD_INTEGRITY_UNSEALED = 1, /* Valid record (magic+version) with sealed == 0; nothing else maps here */
    RESHIELD_INTEGRITY_TAMPERED = 2, /* Code section size/SHA-256 mismatch, or an invalid record (bad magic/version/flags) */
    RESHIELD_INTEGRITY_ERROR    = 3  /* Could not locate runtime code section or unsupported platform */
} reshield_integrity_status_t;

/**
 * Detailed code-section verification output.
 */
typedef struct reshield_integrity_result {
    reshield_integrity_status_t status;
    uint32_t build_id;
    int      has_manifest;
    uint64_t expected_size;
    uint64_t actual_size;
    uint8_t  expected_sha256[RESHIELD_SHA256_SIZE];
    uint8_t  actual_sha256[RESHIELD_SHA256_SIZE];
    uint8_t  manifest_root_sha256[RESHIELD_SHA256_SIZE];
} reshield_integrity_result_t;

/**
 * Computes SHA-256 over [data, data + len) into out_hash (32 bytes).
 */
void reshield_sha256(const void *data, size_t len, uint8_t out_hash[RESHIELD_SHA256_SIZE]);

/**
 * Computes SHA-256 of a file on disk into out_hash (32 bytes) and optionally writes file size.
 * Returns 0 on success, -1 on I/O error.
 */
int reshield_sha256_file(const char *path,
                         uint8_t out_hash[RESHIELD_SHA256_SIZE],
                         uint64_t *out_size);

/**
 * Constant-time comparison of two 32-byte SHA-256 digests.
 * Returns 1 if equal, 0 otherwise.
 */
int reshield_digest_equal(const uint8_t a[RESHIELD_SHA256_SIZE],
                          const uint8_t b[RESHIELD_SHA256_SIZE]);

/**
 * Verifies that SHA-256(data, len) matches expected_sha256 in constant time.
 * Returns 1 on match, 0 on mismatch. The comparison is performed even when compiled
 * with -DRESHIELD_DISABLE: it is application logic (e.g. key commitments), not an
 * integrity check.
 */
int reshield_verify_buffer(const void *data, size_t len,
                           const uint8_t expected_sha256[RESHIELD_SHA256_SIZE]);

/**
 * Hashes the in-memory code section (__TEXT,__text on macOS; .text on Linux and Windows
 * PE32+ x64) of the image that holds the sealed record and compares it against that record.
 * The record lives in the module that linked re-shield: the main executable for a statically
 * linked program, or a shared library (.so/.dylib/.dll) when re-shield is linked into one.
 * Seal that same file with tools/seal_binary.py. The host process need not be sealed.
 * On Linux a library opened by a relative path (dlopen("./x.so")) works too: its absolute path
 * is taken from /proc/self/maps (the mapping that holds the record). If /proc is unavailable or
 * the file was deleted or replaced after loading, it fails closed with RESHIELD_INTEGRITY_ERROR.
 * out_result may be NULL.
 */
reshield_integrity_status_t reshield_verify_code_section(reshield_integrity_result_t *out_result);

/**
 * Reads the sealed manifest root SHA-256 embedded in this binary.
 * Returns 0 if a manifest root is sealed, -1 if the binary is unsealed (valid record,
 * sealed == 0), and -2 if the record is invalid or the binary was sealed without a
 * manifest (not "unsealed": callers must not let allow_unsealed bypass it).
 */
int reshield_get_sealed_manifest_root(uint8_t out_root[RESHIELD_SHA256_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_INTEGRITY_H */
