#ifndef RESHIELD_ATTESTATION_H
#define RESHIELD_ATTESTATION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum reshield_attestation_status {
    RESHIELD_ATTEST_OK          = 0,
    RESHIELD_ATTEST_FAILED      = 1,
    RESHIELD_ATTEST_UNSUPPORTED = 2
} reshield_attestation_status_t;

/**
 * Verifies that the in-memory code section obeys W^X (readable + executable, NOT writable).
 * Same image as reshield_verify_code_section(): the one that holds the integrity record.
 * - macOS: mach_vm_region() walked over the whole __TEXT,__text range (gaps fail).
 * - Linux: /proc/self/maps; the whole .text range must be covered by r-x mappings.
 * - Windows: VirtualQuery over the whole .text range; every region must be committed,
 *   executable and not writable (gaps fail).
 */
reshield_attestation_status_t reshield_verify_code_page_wx(void);

/**
 * Verifies OS-level code signature validity for the running executable (the process EXE,
 * also when re-shield is linked into a shared library: the module itself is not checked).
 * - macOS: Security.framework SecCodeCopySelf + SecCodeCheckValidity.
 * - Windows: WinVerifyTrust (Authenticode, no UI, no revocation check) on the EXE file.
 *   An UNSIGNED executable returns RESHIELD_ATTEST_FAILED.
 *   The file checked is the one backing the mapped image (not the module path).
 * - Linux: returns RESHIELD_ATTEST_UNSUPPORTED.
 */
reshield_attestation_status_t reshield_verify_os_codesign(void);

/**
 * Same, but the signature must also satisfy `requirement` (code requirement language,
 * e.g. a Team ID pin). NULL behaves like reshield_verify_os_codesign(). A requirement
 * that does not parse returns RESHIELD_ATTEST_FAILED. Linux: UNSUPPORTED (ignored).
 * Windows: `requirement` must be exactly "leaf-sha256:" followed by 64 hex chars
 * (case-insensitive) = SHA-256 of the DER-encoded signing (leaf) certificate of the first
 * Authenticode signer; the signature must also pass WinVerifyTrust. Any other string (wrong
 * prefix, length or non-hex) returns FAILED (fail closed). The macOS and Windows requirement
 * syntaxes differ: set the value per platform under #ifdef.
 */
reshield_attestation_status_t reshield_verify_os_codesign_req(const char *requirement);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_ATTESTATION_H */
