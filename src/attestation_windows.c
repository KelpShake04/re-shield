#ifdef _WIN32

#include "reshield/attestation.h"
#include "reshield/integrity.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <psapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#endif

extern int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size);

#define RESHIELD_PAGE_EXEC  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define RESHIELD_PAGE_WRITE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

reshield_attestation_status_t reshield_verify_code_page_wx(void) {
#ifdef RESHIELD_DISABLE
    return RESHIELD_ATTEST_OK;
#else
    const uint8_t *code_ptr = NULL;
    uint64_t code_size = 0;
    if (reshield_platform_get_code_section(&code_ptr, &code_size) != 0 ||
        code_ptr == NULL || code_size == 0) {
        return RESHIELD_ATTEST_FAILED;
    }

    /* The whole [start, end) range must be covered by contiguous committed regions that
     * are all executable and NOT writable; a gap or reserved/free range is a failure. */
    uintptr_t start = (uintptr_t)code_ptr;
    if (code_size > UINTPTR_MAX - start) {
        return RESHIELD_ATTEST_FAILED;
    }
    uintptr_t end = start + (uintptr_t)code_size;

    uintptr_t cur = start;
    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)cur, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            return RESHIELD_ATTEST_FAILED;
        }
        uintptr_t lo = (uintptr_t)mbi.BaseAddress;
        if (lo > cur || mbi.RegionSize == 0 || mbi.RegionSize > UINTPTR_MAX - lo ||
            lo + mbi.RegionSize <= cur) {
            return RESHIELD_ATTEST_FAILED;
        }
        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_GUARD) != 0u ||
            (mbi.Protect & RESHIELD_PAGE_EXEC) == 0u ||
            (mbi.Protect & RESHIELD_PAGE_WRITE) != 0u) {
            return RESHIELD_ATTEST_FAILED;
        }
        cur = lo + mbi.RegionSize;
    }
    return RESHIELD_ATTEST_OK;
#endif
}

#ifndef RESHIELD_DISABLE
/* Windows requirement format: "leaf-sha256:" + 64 hex chars (case-insensitive) = SHA-256 of
 * the DER-encoded signing (leaf) certificate of the first Authenticode signer. Any other
 * non-NULL string fails closed: silently ignoring it would turn a configured pin into
 * "any trusted publisher is fine".
 * Authenticode validity of the EXE file on disk is checked with WinVerifyTrust
 * (no UI, no revocation check, no network). An unsigned EXE returns FAILED, so enabling
 * RESHIELD_CHECK_CODESIGN on an unsigned dev build makes reshield_verify() fail.
 * The file verified is the one backing the mapped main image: its NT path comes from
 * GetMappedFileNameW, is converted to a DOS path (GetLogicalDriveStringsW + QueryDosDeviceW)
 * and opened once; that handle is passed to WinVerifyTrust, so renaming the running EXE and
 * putting another file at the old path does not change what is verified. Fail closed when the
 * conversion fails (e.g. EXE on a UNC share). */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_leaf_pin(const char *req, uint8_t out[RESHIELD_SHA256_SIZE]) {
    static const char prefix[] = "leaf-sha256:";
    size_t plen = sizeof(prefix) - 1u;
    if (strncmp(req, prefix, plen) != 0 || strlen(req + plen) != 2u * RESHIELD_SHA256_SIZE) {
        return -1;
    }
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        int hi = hex_nibble(req[plen + 2u * i]);
        int lo = hex_nibble(req[plen + 2u * i + 1u]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Hashes the leaf certificate of the first signer found in the open WinVerifyTrust state. */
static int leaf_cert_matches(HANDLE state, const uint8_t pin[RESHIELD_SHA256_SIZE]) {
    CRYPT_PROVIDER_DATA *pd = WTHelperProvDataFromStateData(state);
    if (pd == NULL) return 0;
    CRYPT_PROVIDER_SGNR *sgnr = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
    if (sgnr == NULL) return 0;
    CRYPT_PROVIDER_CERT *pc = WTHelperGetProvCertFromChain(sgnr, 0);
    if (pc == NULL || pc->pCert == NULL || pc->pCert->pbCertEncoded == NULL ||
        pc->pCert->cbCertEncoded == 0) {
        return 0;
    }
    uint8_t h[RESHIELD_SHA256_SIZE];
    reshield_sha256(pc->pCert->pbCertEncoded, pc->pCert->cbCertEncoded, h);
    unsigned diff = 0;
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        diff |= (unsigned)(h[i] ^ pin[i]);
    }
    return diff == 0;
}

/* Opens (read-only, share read+delete) the file that backs the main image mapping.
 * Returns the handle and the DOS path in `path`, or INVALID_HANDLE_VALUE. */
static HANDLE open_mapped_image(wchar_t *path, size_t cap) {
    wchar_t nt[MAX_PATH * 4];
    DWORD nlen = GetMappedFileNameW(GetCurrentProcess(), (LPVOID)GetModuleHandleW(NULL),
                                    nt, (DWORD)(sizeof(nt) / sizeof(nt[0])));
    if (nlen == 0 || nlen >= sizeof(nt) / sizeof(nt[0])) {
        return INVALID_HANDLE_VALUE;
    }
    wchar_t drives[512];
    DWORD dl = GetLogicalDriveStringsW((DWORD)(sizeof(drives) / sizeof(drives[0])) - 1u, drives);
    if (dl == 0 || dl >= sizeof(drives) / sizeof(drives[0])) {
        return INVALID_HANDLE_VALUE;
    }
    for (const wchar_t *d = drives; *d != L'\0'; d += wcslen(d) + 1) {
        wchar_t name[3] = { d[0], L':', L'\0' };
        wchar_t dev[MAX_PATH * 2];
        DWORD dn = QueryDosDeviceW(name, dev, (DWORD)(sizeof(dev) / sizeof(dev[0])));
        if (dn == 0) {
            continue;
        }
        size_t dlen = wcslen(dev); /* first entry of the multi-string */
        if (dlen == 0 || dlen >= nlen || _wcsnicmp(nt, dev, dlen) != 0 || nt[dlen] != L'\\') {
            continue;
        }
        size_t rest = wcslen(nt + dlen);
        if (2u + rest + 1u > cap) {
            return INVALID_HANDLE_VALUE;
        }
        path[0] = name[0];
        path[1] = L':';
        memcpy(path + 2, nt + dlen, (rest + 1u) * sizeof(wchar_t));
        return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    return INVALID_HANDLE_VALUE;
}

#endif /* !RESHIELD_DISABLE */

reshield_attestation_status_t reshield_verify_os_codesign_req(const char *requirement) {
#ifdef RESHIELD_DISABLE
    (void)requirement;
    return RESHIELD_ATTEST_OK;
#else
    uint8_t pin[RESHIELD_SHA256_SIZE] = {0};
    if (requirement != NULL && parse_leaf_pin(requirement, pin) != 0) {
        return RESHIELD_ATTEST_FAILED;
    }
    enum { PATH_CAP = 32768 };
    wchar_t *path = (wchar_t *)malloc(PATH_CAP * sizeof(wchar_t));
    if (path == NULL) {
        return RESHIELD_ATTEST_FAILED;
    }
    HANDLE hfile = open_mapped_image(path, PATH_CAP);
    if (hfile == INVALID_HANDLE_VALUE) {
        free(path);
        return RESHIELD_ATTEST_FAILED;
    }

    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;
    fi.hFile = hfile;

    WINTRUST_DATA wd;
    ZeroMemory(&wd, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG rc = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    int ok = (rc == ERROR_SUCCESS);
    if (ok && requirement != NULL) {
        ok = leaf_cert_matches(wd.hWVTStateData, pin);
    }

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    CloseHandle(hfile);
    free(path);
    return ok ? RESHIELD_ATTEST_OK : RESHIELD_ATTEST_FAILED;
#endif
}

#else
typedef int reshield_attestation_windows_unused_t;
#endif
