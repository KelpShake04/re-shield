#ifndef RESHIELD_MANIFEST_H
#define RESHIELD_MANIFEST_H

#include "reshield/integrity.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum reshield_manifest_status {
    RESHIELD_MANIFEST_OK             = 0,
    RESHIELD_MANIFEST_UNSEALED       = 1, /* Binary has no sealed manifest root */
    RESHIELD_MANIFEST_ROOT_MISMATCH  = 2, /* Manifest file SHA-256 does not match sealed root */
    RESHIELD_MANIFEST_ASSET_MISMATCH = 3, /* An asset file is missing, resized, or hash-mismatched */
    RESHIELD_MANIFEST_IO_ERROR       = 4  /* Could not open or parse manifest file */
} reshield_manifest_status_t;

/**
 * Verifies the manifest file against expected_root_sha256 (or against the binary's
 * sealed manifest root if expected_root_sha256 is NULL), then verifies every asset
 * listed in the manifest under asset_base_dir.
 *
 * Manifest format (UTF-8 text, sorted lines):
 *   <64-hex-sha256> <byte-size> <relative-path>
 *
 * If an asset fails and failed_path_buf is non-NULL, writes its relative path into
 * failed_path_buf (up to failed_path_cap bytes, NUL-terminated).
 */
reshield_manifest_status_t reshield_verify_manifest_files(
    const char *manifest_path,
    const char *asset_base_dir,
    const uint8_t *expected_root_sha256,
    char *failed_path_buf,
    size_t failed_path_cap
);

/**
 * Verifies a single asset (asset_rel_path under asset_base_dir) against the manifest
 * after first verifying the manifest's own SHA-256 against expected_root_sha256
 * (or the binary's sealed manifest root if NULL).
 */
reshield_manifest_status_t reshield_verify_single_asset(
    const char *manifest_path,
    const char *asset_base_dir,
    const char *asset_rel_path,
    const uint8_t *expected_root_sha256
);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_MANIFEST_H */
