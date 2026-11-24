/*
 * Module-mode test host: links NO re-shield code and has no integrity record of its own. It loads
 * the shared library given as argv[1] and calls the library's reshield_verify_code_section() and
 * reshield_verify_code_page_wx(). The library must verify its own image, not this host.
 *
 * With argv[2] and argv[3] (manifest and assets, relative to THIS executable's directory) it also
 * calls the library's reshield_check_json() with them: the manifest-bound check of module mode.
 *
 * Output: module_host: status=<NAME> wx=<0|1|2> actual_size=<n> expected_size=<n>
 *         check_json: status=<reshield_status_t> json=<report>   (the library's flat reshield_check_json)
 *         check_json_manifest: status=<reshield_status_t> json=<report>   (only with argv[2], argv[3])
 * Exit code: reshield_integrity_status_t (OK=0 UNSEALED=1 TAMPERED=2 ERROR=3),
 *            10 = library did not load, 11 = symbol missing.
 */
#include "reshield/attestation.h"
#include "reshield/integrity.h"

#include <inttypes.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

typedef reshield_integrity_status_t (*verify_code_fn)(reshield_integrity_result_t *);
typedef reshield_attestation_status_t (*verify_wx_fn)(void);
typedef int (*check_json_fn)(const char *, const char *, char *, size_t);

static const char *status_name(reshield_integrity_status_t st) {
    switch (st) {
    case RESHIELD_INTEGRITY_OK:       return "OK";
    case RESHIELD_INTEGRITY_UNSEALED: return "UNSEALED";
    case RESHIELD_INTEGRITY_TAMPERED: return "TAMPERED";
    case RESHIELD_INTEGRITY_ERROR:    return "ERROR";
    }
    return "?";
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 4) {
        fprintf(stderr, "usage: %s <shared-library> [<manifest_rel> <assets_rel>]\n", argv[0]);
        return 2;
    }

    verify_code_fn verify_code;
    verify_wx_fn verify_wx;
    check_json_fn check_json;
#ifdef _WIN32
    wchar_t wpath[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wpath, MAX_PATH) == 0) {
        return 10;
    }
    HMODULE lib = LoadLibraryW(wpath);
    if (lib == NULL) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 10;
    }
    verify_code = (verify_code_fn)(void *)GetProcAddress(lib, "reshield_verify_code_section");
    verify_wx = (verify_wx_fn)(void *)GetProcAddress(lib, "reshield_verify_code_page_wx");
    check_json = (check_json_fn)(void *)GetProcAddress(lib, "reshield_check_json");
#else
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (lib == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 10;
    }
    /* POSIX-blessed object->function pointer conversion (a plain cast trips -Wpedantic) */
    *(void **)(&verify_code) = dlsym(lib, "reshield_verify_code_section");
    *(void **)(&verify_wx) = dlsym(lib, "reshield_verify_code_page_wx");
    *(void **)(&check_json) = dlsym(lib, "reshield_check_json");
#endif
    if (verify_code == NULL || verify_wx == NULL || check_json == NULL) {
        fprintf(stderr, "symbol not found in %s\n", argv[1]);
        return 11;
    }

    reshield_integrity_result_t res;
    reshield_integrity_status_t st = verify_code(&res);
    reshield_attestation_status_t wx = verify_wx();
    printf("module_host: status=%s wx=%d actual_size=%" PRIu64 " expected_size=%" PRIu64 "\n",
           status_name(st), (int)wx, res.actual_size, res.expected_size);

    /* The flat binding entry point, no manifest: code section + W^X of the library. */
    char json[1024];
    int cj = check_json(NULL, NULL, json, sizeof(json));
    printf("check_json: status=%d json=%s\n", cj, json);
    if (argc == 4) {
        cj = check_json(argv[2], argv[3], json, sizeof(json));
        printf("check_json_manifest: status=%d json=%s\n", cj, json);
    }
    return (int)st;
}
