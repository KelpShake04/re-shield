#ifdef _WIN32

/* Rename-and-replace regression test for the Authenticode check.
 *
 * Run as: test_codesign_toctou_windows.exe <path to a validly signed EXE>
 * The test EXE is itself unsigned. It renames its own running image away and copies the
 * validly signed EXE to the old path. A check that verifies the file at the module path would
 * now report OK; a check that verifies the file backing the mapped image must still FAIL.
 */

#include "reshield/attestation.h"

#include <stdio.h>
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>

#ifdef _MSC_VER
#pragma comment(lib, "wintrust.lib")
#endif

static int path_verifies(const wchar_t *path) {
    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;
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
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    return rc == ERROR_SUCCESS;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: test_codesign_toctou_windows <signed.exe>\n");
        return 2;
    }
    static wchar_t self[32768];
    static wchar_t moved[32768 + 8];
    DWORD n = GetModuleFileNameW(NULL, self, 32768);
    if (n == 0 || n >= 32768) {
        fprintf(stderr, "GetModuleFileNameW failed\n");
        return 2;
    }
    swprintf(moved, sizeof(moved) / sizeof(moved[0]), L"%ls.moved", self);

    if (reshield_verify_os_codesign_req(NULL) != RESHIELD_ATTEST_FAILED) {
        fprintf(stderr, "FAIL: the unsigned test EXE must fail before the swap\n");
        return 1;
    }
    if (!MoveFileW(self, moved)) {
        fprintf(stderr, "FAIL: could not rename the running EXE (error %lu)\n", GetLastError());
        return 2;
    }
    if (!CopyFileW(argv[1], self, TRUE)) {
        fprintf(stderr, "FAIL: could not place the signed EXE at the old path (error %lu)\n", GetLastError());
        return 2;
    }

    static wchar_t after[32768];
    DWORD an = GetModuleFileNameW(NULL, after, 32768);
    int precondition = (an != 0 && an < 32768) && path_verifies(after);
    printf("precondition: file at the module path now verifies as signed = %d\n", precondition);
    if (!precondition) {
        fprintf(stderr, "FAIL: attack precondition not met (swap had no effect on the module path)\n");
        return 2;
    }

    reshield_attestation_status_t st = reshield_verify_os_codesign_req(NULL);
    printf("after swap: reshield_verify_os_codesign_req(NULL) = %d (1 = FAILED expected)\n", (int)st);
    if (st != RESHIELD_ATTEST_FAILED) {
        fprintf(stderr, "FAIL: rename-and-replace was not detected\n");
        return 1;
    }
    printf("PASS: the mapped image (unsigned) is verified, not the swapped file at the module path\n");
    return 0;
}

#else
int main(void) { return 0; }
#endif
