#include "reshield/reshield.h"

#include <string.h>

int reshield_is_enabled(void) {
#ifdef RESHIELD_DISABLE
    return 0;
#else
    return 1;
#endif
}

const char *reshield_platform_name(void) {
#if defined(__APPLE__) && defined(__MACH__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unsupported";
#endif
}

reshield_config_t reshield_default_config(void) {
    reshield_config_t cfg = {
        .enabled_checks = RESHIELD_CHECK_DEFAULT,
        .allow_unsealed = 0,
        .manifest_path = NULL,
        .asset_base_dir = NULL,
        .on_violation = NULL,
        .user_data = NULL
    };
    return cfg;
}

const char *reshield_status_name(reshield_status_t status) {
    switch (status) {
        case RESHIELD_OK:                    return "OK";
        case RESHIELD_ERR_UNSEALED:          return "UNSEALED";
        case RESHIELD_ERR_CODE_TAMPERED:     return "CODE_TAMPERED";
        case RESHIELD_ERR_PAGE_PERMISSIONS:  return "PAGE_PERMISSIONS_VIOLATION";
        case RESHIELD_ERR_CODESIGN_INVALID:  return "CODESIGN_INVALID";
        case RESHIELD_ERR_MANIFEST_MISMATCH: return "MANIFEST_MISMATCH";
        case RESHIELD_ERR_ASSET_TAMPERED:    return "ASSET_TAMPERED";
        case RESHIELD_ERR_INTERNAL:          return "INTERNAL_ERROR";
        default:                             return "UNKNOWN";
    }
}

reshield_status_t reshield_verify(const reshield_config_t *config,
                                  reshield_report_t *out_report) {
    reshield_report_t report;
    memset(&report, 0, sizeof(report));
    report.status = RESHIELD_OK;

#ifdef RESHIELD_DISABLE
    (void)config;
    if (out_report != NULL) {
        *out_report = report;
    }
    return RESHIELD_OK;
#else
    reshield_config_t cfg = (config != NULL) ? *config : reshield_default_config();

    if ((cfg.enabled_checks & RESHIELD_CHECK_CODE_SECTION) != 0u) {
        reshield_integrity_status_t ist = reshield_verify_code_section(&report.code_result);
        report.build_id = report.code_result.build_id;
        if (ist == RESHIELD_INTEGRITY_TAMPERED) {
            report.failed_checks |= RESHIELD_CHECK_CODE_SECTION;
            report.status = RESHIELD_ERR_CODE_TAMPERED;
        } else if (ist == RESHIELD_INTEGRITY_UNSEALED && !cfg.allow_unsealed) {
            report.failed_checks |= RESHIELD_CHECK_CODE_SECTION;
            report.status = RESHIELD_ERR_UNSEALED;
        } else if (ist == RESHIELD_INTEGRITY_ERROR) {
            report.failed_checks |= RESHIELD_CHECK_CODE_SECTION;
            report.status = RESHIELD_ERR_INTERNAL;
        }
    }

    if ((cfg.enabled_checks & RESHIELD_CHECK_PAGE_PERMISSIONS) != 0u) {
        if (reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED) {
            report.failed_checks |= RESHIELD_CHECK_PAGE_PERMISSIONS;
            if (report.status == RESHIELD_OK) {
                report.status = RESHIELD_ERR_PAGE_PERMISSIONS;
            }
        }
    }

    if ((cfg.enabled_checks & RESHIELD_CHECK_CODESIGN) != 0u) {
        reshield_attestation_status_t cs = reshield_verify_os_codesign();
        if (cs == RESHIELD_ATTEST_FAILED) {
            report.failed_checks |= RESHIELD_CHECK_CODESIGN;
            if (report.status == RESHIELD_OK) {
                report.status = RESHIELD_ERR_CODESIGN_INVALID;
            }
        }
    }

    if ((cfg.enabled_checks & RESHIELD_CHECK_MANIFEST) != 0u) {
        reshield_manifest_status_t ms = reshield_verify_manifest_files(
            cfg.manifest_path,
            cfg.asset_base_dir,
            NULL,
            report.failed_asset_path,
            sizeof(report.failed_asset_path)
        );
        if (ms == RESHIELD_MANIFEST_UNSEALED && cfg.allow_unsealed) {
            /* Allowed in unsealed development builds */
        } else if (ms != RESHIELD_MANIFEST_OK) {
            report.failed_checks |= RESHIELD_CHECK_MANIFEST;
            if (report.status == RESHIELD_OK) {
                switch (ms) {
                    case RESHIELD_MANIFEST_UNSEALED:
                        report.status = RESHIELD_ERR_UNSEALED;
                        break;
                    case RESHIELD_MANIFEST_ROOT_MISMATCH:
                        report.status = RESHIELD_ERR_MANIFEST_MISMATCH;
                        break;
                    case RESHIELD_MANIFEST_ASSET_MISMATCH:
                        report.status = RESHIELD_ERR_ASSET_TAMPERED;
                        break;
                    default:
                        report.status = RESHIELD_ERR_INTERNAL;
                        break;
                }
            }
        }
    }

    if (out_report != NULL) {
        *out_report = report;
    }

    if (report.status != RESHIELD_OK && cfg.on_violation != NULL) {
        cfg.on_violation(&report, cfg.user_data);
    }

    return report.status;
#endif
}

void reshield_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0u;
    }
}
