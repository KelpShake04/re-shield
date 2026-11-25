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
 * State of an incremental code-section scan. The caller owns it (stack, struct member, global);
 * the library never allocates. The contents are private: do not read or write them, and do not
 * copy a scan that is in progress and then advance both copies. 192 bytes, 8-byte aligned.
 * Zero it or pass it to reshield_code_scan_begin() before first use; a never-initialized
 * object is not reliably detected by reshield_code_scan_step().
 */
typedef struct reshield_code_scan {
    uint64_t opaque_[24];
} reshield_code_scan_t;

/**
 * Starts (or restarts) an incremental scan of the same code section that
 * reshield_verify_code_section() hashes. The section is located once, here: on Linux that
 * opens and parses the image file, so call begin at start-up, not every frame. Hashes nothing yet.
 * Returns RESHIELD_INTEGRITY_OK when the scan is ready, RESHIELD_INTEGRITY_ERROR when the
 * section cannot be found (scan is then unusable and reshield_code_scan_step() returns -1).
 * With -DRESHIELD_DISABLE it returns OK and the first step reports a finished pass with OK.
 */
reshield_integrity_status_t reshield_code_scan_begin(reshield_code_scan_t *scan);

/**
 * Hashes the next max_bytes (or fewer, at the end of the section) with the SHA-256 state kept
 * in scan. Returns:
 *   0   the pass is not finished; call again (out_result is not touched).
 *   1   the pass finished; out_result (may be NULL) holds exactly what
 *       reshield_verify_code_section() would report for the bytes this pass read, and the
 *       sealed record is read now, not at begin. The next call starts a new pass over the same
 *       section automatically; there is no need to call begin again.
 *  -1   bad argument: scan NULL, max_bytes == 0, or scan never initialized by begin.
 * The budget is in bytes, not time. Rough guide: 64 KiB per call with the portable C SHA-256,
 * 256 KiB to 1 MiB with a hardware backend (see docs/incremental-scan.md for measured speed).
 * reshield_verify_code_section() is implemented as begin plus one step with max_bytes = SIZE_MAX,
 * so any chunking gives the same verdict for unchanged memory.
 *
 * Threading: a scan belongs to its caller. Call step on one scan from one thread at a time; there
 * is no lock. Separate scan objects may be stepped from separate threads. There is no other
 * mutable library state besides the one-time CPU feature detection of the SHA-256 backend.
 * Do not step a scan after the module that holds the code section was unloaded (dlclose/FreeLibrary):
 * the cached section pointer would dangle.
 *
 * Limits of this design. It has no key, so it adds no secrecy over the one-shot check:
 *  - An attacker who can write the code can patch this verifier, its caller, or the sealed record
 *    (it sits in writable data) and the scan will still say OK.
 *  - Bytes behind the cursor are not looked at again until the next pass. A patch applied to a
 *    chunk after it was hashed is reported at the end of the next pass, i.e. after up to about two
 *    pass lengths. A patch that is applied and undone between two visits of its chunk is never seen.
 *  - Remapping the page (shadow copies, EPT/hypervisor views) or hardware breakpoints change what
 *    runs without changing the bytes read here.
 * It is meant to catch inline hooks, software breakpoints and trainer patches that appear after the
 * start-up check, not a determined attacker.
 */
int reshield_code_scan_step(reshield_code_scan_t *scan, size_t max_bytes,
                            reshield_integrity_result_t *out_result);

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
