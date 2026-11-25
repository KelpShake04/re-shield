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
    RESHIELD_MANIFEST_IO_ERROR       = 4, /* Could not open or parse manifest file */
    RESHIELD_MANIFEST_ASSET_EXTRA    = 5  /* Strict manifest: a file under asset_base_dir is neither
                                           * listed nor allowed, or the scan could not complete */
} reshield_manifest_status_t;

/**
 * Verifies the manifest file against expected_root_sha256 (or against the binary's
 * sealed manifest root if expected_root_sha256 is NULL), then verifies every asset
 * listed in the manifest under asset_base_dir.
 *
 * Manifest format (UTF-8 text, sorted lines):
 *   <64-hex-sha256> <byte-size> <relative-path>
 *
 * Manifest v2 (optional, backward compatible): leading '#' lines may hold directives,
 *   #reshield-manifest v2 strict   enable the strict (allowlist) scan
 *   #allow <glob>                  (max 64) paths exempt from the strict scan
 * In a strict manifest, after all listed assets verified, asset_base_dir (NULL or "" = ".")
 * is walked recursively; any entry (file, symlink, special file; symlinks are not followed)
 * that is neither listed nor matched by an #allow glob gives RESHIELD_MANIFEST_ASSET_EXTRA.
 * A scan that cannot finish (unreadable directory, nesting > 32, > 100000 entries, path too
 * long) also gives ASSET_EXTRA, with an empty failed path. Names are compared as bytes.
 * Unknown directives or a malformed header are IO_ERROR. See docs/integrity-verification.md.
 *
 * If an asset fails (or, for ASSET_EXTRA, an extra entry is found) and failed_path_buf is
 * non-NULL, writes its relative path into failed_path_buf (up to failed_path_cap bytes,
 * NUL-terminated).
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
 * (or the binary's sealed manifest root if NULL). The strict scan is not part of this call.
 */
reshield_manifest_status_t reshield_verify_single_asset(
    const char *manifest_path,
    const char *asset_base_dir,
    const char *asset_rel_path,
    const uint8_t *expected_root_sha256
);

/**
 * Loads one asset and returns the exact bytes that were verified. Verification is the same as
 * reshield_verify_single_asset() (manifest root first, then the manifest entry for
 * asset_rel_path, then size and SHA-256), but the file is opened and read once and the hash is
 * taken over the returned buffer, so the file cannot be swapped between check and use.
 *
 * On RESHIELD_MANIFEST_OK, *out_buf (malloc'd, never NULL, even for an empty asset) and *out_len
 * are set; release the buffer with reshield_free_asset(), not free() (a DLL may use another C
 * runtime). On any other status *out_buf is NULL and *out_len is 0. Both outputs are required
 * (NULL gives IO_ERROR). The call is stateless and thread-safe; it re-checks the manifest root
 * every time and holds the whole asset in memory.
 *
 * max_size is a hard cap in bytes with no default: an asset (per the file's size) larger than
 * max_size is never read and gives RESHIELD_MANIFEST_IO_ERROR (not a tamper verdict). Statuses
 * as in reshield_verify_single_asset(): an unsafe asset_rel_path (same path rules as manifest
 * entries) is IO_ERROR; an asset that is not listed, missing, not a regular file, resized or
 * hash-mismatched is ASSET_MISMATCH. A symlink to a regular file is read through (the bytes are
 * still bound to the manifest hash). The strict scan is not part of this call. Under
 * -DRESHIELD_DISABLE nothing is verified: the file is only read, with the same path and
 * max_size rules. See docs/asset-loading.md.
 */
reshield_manifest_status_t reshield_load_verified_asset(
    const char *manifest_path,
    const char *asset_base_dir,
    const char *asset_rel_path,
    const uint8_t *expected_root_sha256,
    size_t max_size,
    void **out_buf,
    size_t *out_len
);

/** Releases a buffer returned by reshield_load_verified_asset() or
 * reshield_load_verified_app_asset(). NULL is allowed. */
void reshield_free_asset(void *buf);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_MANIFEST_H */
