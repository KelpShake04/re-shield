/* reshield_verify_app(): verify code + manifest with paths relative to the executable. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "reshield/reshield.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <stdlib.h>
#else
#include <unistd.h>
#endif

#define APP_PATH_MAX 4096u

/* Writes the directory of the running executable (UTF-8, no trailing separator) into out.
 * Returns 0 on success; any truncation or lookup failure returns -1 (fail closed). */
static int exe_dir(char *out, size_t cap) {
#if defined(_WIN32)
    wchar_t w[APP_PATH_MAX];
    DWORD n = GetModuleFileNameW(NULL, w, APP_PATH_MAX);
    if (n == 0 || n >= APP_PATH_MAX) {
        return -1;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) <= 0) {
        return -1;
    }
    char *sep = strrchr(out, '\\');
#elif defined(__APPLE__)
    char raw[APP_PATH_MAX];
    uint32_t sz = (uint32_t)sizeof(raw);
    if (_NSGetExecutablePath(raw, &sz) != 0) {
        return -1;
    }
    char *real = realpath(raw, NULL);
    if (real == NULL) {
        return -1;
    }
    int n = snprintf(out, cap, "%s", real);
    free(real);
    if (n < 0 || (size_t)n >= cap) {
        return -1;
    }
    char *sep = strrchr(out, '/');
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1u);
    if (n <= 0 || (size_t)n >= cap - 1u) {
        return -1;
    }
    out[n] = '\0';
    char *sep = strrchr(out, '/');
#endif
    if (sep == NULL) {
        return -1;
    }
    *sep = '\0';
    return 0;
}

static int join(char *out, size_t cap, const char *dir, const char *rel) {
    int n = snprintf(out, cap, "%s/%s", dir, rel);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

reshield_status_t reshield_verify_app(const char *manifest_rel, const char *assets_rel,
                                      reshield_violation_cb_t on_violation, void *user_data,
                                      reshield_report_t *out_report) {
    reshield_config_t cfg = reshield_default_config();
    cfg.on_violation = on_violation;
    cfg.user_data = user_data;
#ifdef RESHIELD_ALLOW_UNSEALED
    cfg.allow_unsealed = 1; /* this library is a development build: unsealed local builds pass */
#endif

    char dir[APP_PATH_MAX], manifest[APP_PATH_MAX], assets[APP_PATH_MAX];
    if (reshield_is_enabled() && manifest_rel != NULL) {
        if (exe_dir(dir, sizeof(dir)) != 0 ||
            join(manifest, sizeof(manifest), dir, manifest_rel) != 0 ||
            join(assets, sizeof(assets), dir, assets_rel != NULL ? assets_rel : ".") != 0) {
            reshield_report_t r;
            memset(&r, 0, sizeof(r));
            r.status = RESHIELD_ERR_INTERNAL;
            r.failed_checks = RESHIELD_CHECK_MANIFEST;
            if (out_report != NULL) {
                *out_report = r;
            }
            if (on_violation != NULL) {
                on_violation(&r, user_data);
            }
            return r.status;
        }
        cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
        cfg.manifest_path = manifest;
        cfg.asset_base_dir = assets;
    }
    return reshield_verify(&cfg, out_report);
}
