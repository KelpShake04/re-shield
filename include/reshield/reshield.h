#ifndef RESHIELD_H
#define RESHIELD_H

#include "reshield/attestation.h"
#include "reshield/integrity.h"
#include "reshield/manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum reshield_status {
    RESHIELD_OK                    = 0,
    RESHIELD_ERR_UNSEALED          = 1, /* Binary was not sealed at build time */
    RESHIELD_ERR_CODE_TAMPERED     = 2, /* Code section SHA-256 / size mismatch */
    RESHIELD_ERR_PAGE_PERMISSIONS  = 3, /* Code section violates W^X (writable) */
    RESHIELD_ERR_CODESIGN_INVALID  = 4, /* OS code signature verification failed */
    RESHIELD_ERR_MANIFEST_MISMATCH = 5, /* Manifest file SHA-256 does not match sealed root */
    RESHIELD_ERR_ASSET_TAMPERED    = 6, /* Asset file missing, resized, or hash mismatch */
    RESHIELD_ERR_INTERNAL          = 7  /* Internal section/file lookup error */
} reshield_status_t;

typedef enum reshield_check_flags {
    RESHIELD_CHECK_CODE_SECTION     = 1u << 0, /* __TEXT,__text / .text SHA-256 */
    RESHIELD_CHECK_PAGE_PERMISSIONS = 1u << 1, /* Code segment W^X (r-x, no W) */
    RESHIELD_CHECK_CODESIGN         = 1u << 2, /* OS code signature validity (macOS) */
    RESHIELD_CHECK_MANIFEST         = 1u << 3, /* Sealed manifest + asset verification */
    RESHIELD_CHECK_DEFAULT          = (RESHIELD_CHECK_CODE_SECTION |
                                       RESHIELD_CHECK_PAGE_PERMISSIONS)
} reshield_check_flags_t;

typedef struct reshield_report {
    reshield_status_t           status;
    uint32_t                    failed_checks;
    uint32_t                    build_id;
    reshield_integrity_result_t code_result;
    char                        failed_asset_path[256];
} reshield_report_t;

typedef void (*reshield_violation_cb_t)(const reshield_report_t *report, void *user_data);

typedef struct reshield_config {
    uint32_t                enabled_checks;
    int                     allow_unsealed; /* Non-zero: treat UNSEALED as OK during dev. DEV ONLY:
                                             * enabling it in a release build lets an attacker bypass
                                             * the code and manifest checks by flipping the sealed
                                             * byte of the record. Never ship with it set. */
    const char             *manifest_path;  /* Required when RESHIELD_CHECK_MANIFEST is set */
    const char             *asset_base_dir; /* Base directory for manifest relative paths */
    reshield_violation_cb_t on_violation;   /* Optional diagnostic callback on failure */
    void                   *user_data;
} reshield_config_t;

/**
 * Returns 1 if checks are active, or 0 when compiled with -DRESHIELD_DISABLE.
 */
int reshield_is_enabled(void);

/**
 * Returns the active platform backend name ("macos", "linux", "unsupported").
 */
const char *reshield_platform_name(void);

/**
 * Returns default configuration:
 *   enabled_checks = RESHIELD_CHECK_DEFAULT, allow_unsealed = 0, no callback.
 */
reshield_config_t reshield_default_config(void);

/**
 * Runs all configured integrity and attestation checks and returns a structured
 * status + optional detailed report. Never forcibly exits the process; the host
 * application decides how to report or handle violations.
 */
reshield_status_t reshield_verify(const reshield_config_t *config,
                                  reshield_report_t *out_report);

/**
 * Returns a human-readable static string for a reshield_status_t value.
 */
const char *reshield_status_name(reshield_status_t status);

/**
 * Overwrites [ptr, ptr + len) with zeroes using a volatile pointer so the
 * compiler does not optimize away the wipe.
 */
void reshield_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_H */
