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
#elif defined(_WIN32)
    return "windows";
#else
    return "unsupported";
#endif
}

/* Fallback for platforms with no attestation_*.c backend: without these definitions the
 * library does not link. Windows has its own backend (attestation_windows.c). UNSUPPORTED
 * is silently accepted by reshield_verify(), like the Linux codesign check. */
#if !defined(__APPLE__) && !defined(__linux__) && !defined(_WIN32)
reshield_attestation_status_t reshield_verify_code_page_wx(void) {
    return RESHIELD_ATTEST_UNSUPPORTED;
}

reshield_attestation_status_t reshield_verify_os_codesign_req(const char *requirement) {
    (void)requirement;
    return RESHIELD_ATTEST_UNSUPPORTED;
}
#endif

reshield_attestation_status_t reshield_verify_os_codesign(void) {
    return reshield_verify_os_codesign_req(NULL);
}

reshield_config_t reshield_default_config(void) {
    reshield_config_t cfg = {
        .enabled_checks = RESHIELD_CHECK_DEFAULT,
        .allow_unsealed = 0,
        .manifest_path = NULL,
        .asset_base_dir = NULL,
        .on_violation = NULL,
        .user_data = NULL,
        .codesign_requirement = NULL
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
        case RESHIELD_ERR_MANIFEST_IO:       return "MANIFEST_IO_ERROR";
        case RESHIELD_ERR_ASSET_EXTRA:       return "ASSET_EXTRA";
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

    /* allow_unsealed only works in a build compiled with -DRESHIELD_ALLOW_UNSEALED. Elsewhere a
     * set field is a configuration error, not a silent no-op: it would otherwise look like the
     * dev bypass is active (or was safely ignored) when neither is clear to the caller. */
#ifdef RESHIELD_ALLOW_UNSEALED
    const int allow_unsealed = cfg.allow_unsealed != 0;
#else
    const int allow_unsealed = 0;
#endif

    if ((cfg.enabled_checks & RESHIELD_CHECK_CODE_SECTION) != 0u) {
        reshield_integrity_status_t ist = reshield_verify_code_section(&report.code_result);
        report.build_id = report.code_result.build_id;
        if (ist == RESHIELD_INTEGRITY_TAMPERED) {
            report.failed_checks |= RESHIELD_CHECK_CODE_SECTION;
            report.status = RESHIELD_ERR_CODE_TAMPERED;
        } else if (ist == RESHIELD_INTEGRITY_UNSEALED && !allow_unsealed) {
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
        reshield_attestation_status_t cs = reshield_verify_os_codesign_req(cfg.codesign_requirement);
        /* A pin the platform cannot enforce must not pass silently. */
        if (cs == RESHIELD_ATTEST_FAILED ||
            (cs == RESHIELD_ATTEST_UNSUPPORTED && cfg.codesign_requirement != NULL)) {
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
        if (ms == RESHIELD_MANIFEST_UNSEALED && allow_unsealed) {
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
                    case RESHIELD_MANIFEST_IO_ERROR:
                        report.status = RESHIELD_ERR_MANIFEST_IO;
                        break;
                    case RESHIELD_MANIFEST_ASSET_EXTRA:
                        report.status = RESHIELD_ERR_ASSET_EXTRA;
                        break;
                    default:
                        report.status = RESHIELD_ERR_INTERNAL;
                        break;
                }
            }
        }
    }

#ifndef RESHIELD_ALLOW_UNSEALED
    if (cfg.allow_unsealed != 0) {
        report.status = RESHIELD_ERR_INTERNAL; /* configuration error wins over any other result */
    }
#endif

    if (out_report != NULL) {
        *out_report = report;
    }

    if (report.status != RESHIELD_OK && cfg.on_violation != NULL) {
        cfg.on_violation(&report, cfg.user_data);
    }

    return report.status;
#endif
}

typedef struct {
    char  *buf;
    size_t cap;
    size_t len; /* length the full output needs, may exceed cap */
} json_out_t;

static void json_ch(json_out_t *o, char c) {
    if (o->len + 1u < o->cap) {
        o->buf[o->len] = c;
    }
    o->len++;
}

static void json_raw(json_out_t *o, const char *s) {
    while (*s != '\0') {
        json_ch(o, *s++);
    }
}

static void json_str(json_out_t *o, const char *s) {
    static const char hex[] = "0123456789abcdef";
    json_ch(o, '"');
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            json_ch(o, '\\');
            json_ch(o, (char)c);
        } else if (c < 0x20u || c >= 0x7fu) {
            /* Asset paths come from the manifest and may not be valid UTF-8; escape
             * every non-printable-ASCII byte so the output is always valid JSON. */
            json_raw(o, "\\u00");
            json_ch(o, hex[c >> 4]);
            json_ch(o, hex[c & 0xfu]);
        } else {
            json_ch(o, (char)c);
        }
    }
    json_ch(o, '"');
}

static void json_hex(json_out_t *o, const uint8_t *p, size_t n) {
    static const char hex[] = "0123456789abcdef";
    json_ch(o, '"');
    for (size_t i = 0; i < n; i++) {
        json_ch(o, hex[p[i] >> 4]);
        json_ch(o, hex[p[i] & 0xfu]);
    }
    json_ch(o, '"');
}

static void json_u64(json_out_t *o, uint64_t v) {
    char tmp[21];
    size_t i = sizeof(tmp);
    tmp[--i] = '\0';
    do {
        tmp[--i] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    } while (v != 0u);
    json_raw(o, &tmp[i]);
}

size_t reshield_report_to_json(const reshield_report_t *report, char *buf, size_t cap) {
    json_out_t o = { buf, (buf != NULL) ? cap : 0u, 0u };
    if (report == NULL) {
        return 0u;
    }
    const reshield_integrity_result_t *c = &report->code_result;

    json_raw(&o, "{\"v\":1,\"status\":");
    json_str(&o, reshield_status_name(report->status));
    json_raw(&o, ",\"status_code\":");
    json_u64(&o, (uint64_t)report->status);
    json_raw(&o, ",\"failed_checks\":");
    json_u64(&o, report->failed_checks);
    json_raw(&o, ",\"build_id\":");
    json_u64(&o, report->build_id);
    json_raw(&o, ",\"failed_asset_path\":");
    /* failed_asset_path is a fixed buffer: bound the read in case it is not terminated. */
    char path[sizeof(report->failed_asset_path)];
    memcpy(path, report->failed_asset_path, sizeof(path));
    path[sizeof(path) - 1u] = '\0';
    json_str(&o, path);
    json_raw(&o, ",\"code\":{\"expected_size\":");
    json_u64(&o, c->expected_size);
    json_raw(&o, ",\"actual_size\":");
    json_u64(&o, c->actual_size);
    json_raw(&o, ",\"expected_sha256\":");
    json_hex(&o, c->expected_sha256, sizeof(c->expected_sha256));
    json_raw(&o, ",\"actual_sha256\":");
    json_hex(&o, c->actual_sha256, sizeof(c->actual_sha256));
    json_raw(&o, "}}");

    if (o.cap > 0u) {
        o.buf[(o.len < o.cap) ? o.len : o.cap - 1u] = '\0';
    }
    return o.len;
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
