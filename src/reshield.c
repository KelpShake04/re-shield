#include "reshield/reshield.h"

#include <unistd.h>

reshield_runtime_config_t reshield_default_config(void) {
    reshield_runtime_config_t cfg = {
        .action = RESHIELD_ACTION_TERMINATE,
        .check_debugger = 1,
        .deny_attach = 1,
        .check_integrity = 1,
        .allow_unsealed = 0,
        .callback = NULL,
        .user_data = NULL
    };
    return cfg;
}

#ifndef RESHIELD_DISABLE
static void enforce_action(const reshield_runtime_config_t *cfg, uint32_t threats) {
    if (threats == RESHIELD_THREAT_NONE) {
        return;
    }
    switch (cfg->action) {
        case RESHIELD_ACTION_CALLBACK:
            if (cfg->callback != NULL) {
                cfg->callback(threats, cfg->user_data);
            }
            break;
        case RESHIELD_ACTION_TERMINATE:
            _exit(1);
            break;
        case RESHIELD_ACTION_REPORT:
        default:
            break;
    }
}
#endif

uint32_t reshield_init(const reshield_runtime_config_t *config) {
#ifdef RESHIELD_DISABLE
    (void)config;
    return RESHIELD_THREAT_NONE;
#else
    reshield_runtime_config_t cfg = (config != NULL) ? *config : reshield_default_config();
    uint32_t threats = RESHIELD_THREAT_NONE;

    if (cfg.check_debugger) {
        if (reshield_check_debugger() != RESHIELD_DETECT_NONE) {
            threats |= RESHIELD_THREAT_DEBUGGER;
        }
    }

    if (cfg.deny_attach && (threats & RESHIELD_THREAT_DEBUGGER) == 0u) {
        if (reshield_deny_attach() != 0) {
            threats |= RESHIELD_THREAT_DEBUGGER;
        }
    }

    if (cfg.check_integrity) {
        reshield_integrity_status_t st = reshield_verify_code_section(NULL);
        if (st == RESHIELD_INTEGRITY_TAMPERED) {
            threats |= RESHIELD_THREAT_TAMPERED;
        } else if (st == RESHIELD_INTEGRITY_UNSEALED && !cfg.allow_unsealed) {
            threats |= RESHIELD_THREAT_UNSEALED;
        } else if (st == RESHIELD_INTEGRITY_ERROR) {
            threats |= RESHIELD_THREAT_INTEGRITY_ERROR;
        }
    }

    enforce_action(&cfg, threats);
    return threats;
#endif
}

uint32_t reshield_periodic_check(const reshield_runtime_config_t *config,
                                 const reshield_timer_t *timer,
                                 uint64_t max_ms) {
#ifdef RESHIELD_DISABLE
    (void)config;
    (void)timer;
    (void)max_ms;
    return RESHIELD_THREAT_NONE;
#else
    reshield_runtime_config_t cfg = (config != NULL) ? *config : reshield_default_config();
    uint32_t threats = RESHIELD_THREAT_NONE;

    if (cfg.check_debugger) {
        if (reshield_check_debugger() != RESHIELD_DETECT_NONE) {
            threats |= RESHIELD_THREAT_DEBUGGER;
        }
    }

    if (cfg.check_integrity) {
        reshield_integrity_status_t st = reshield_verify_code_section(NULL);
        if (st == RESHIELD_INTEGRITY_TAMPERED) {
            threats |= RESHIELD_THREAT_TAMPERED;
        } else if (st == RESHIELD_INTEGRITY_UNSEALED && !cfg.allow_unsealed) {
            threats |= RESHIELD_THREAT_UNSEALED;
        } else if (st == RESHIELD_INTEGRITY_ERROR) {
            threats |= RESHIELD_THREAT_INTEGRITY_ERROR;
        }
    }

    if (timer != NULL && max_ms > 0 && reshield_timer_exceeded_ms(timer, max_ms)) {
        threats |= RESHIELD_THREAT_TIMING;
    }

    enforce_action(&cfg, threats);
    return threats;
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

void reshield_xor_transform(uint8_t *dst, const uint8_t *src, size_t len, uint8_t key) {
    if (dst == NULL || src == NULL) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(src[i] ^ key);
    }
}
