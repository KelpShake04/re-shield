#ifndef RESHIELD_H
#define RESHIELD_H

#include "reshield/anti_debug.h"
#include "reshield/integrity.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Unified threat bitmask returned by reshield_init() and reshield_periodic_check().
 */
typedef enum reshield_threat_flags {
    RESHIELD_THREAT_NONE            = 0u,
    RESHIELD_THREAT_DEBUGGER        = 1u << 0, /* OS traced or ptrace deny failed */
    RESHIELD_THREAT_TAMPERED        = 1u << 1, /* Code section SHA-256 / size mismatch */
    RESHIELD_THREAT_UNSEALED        = 1u << 2, /* Binary was not sealed at build time */
    RESHIELD_THREAT_INTEGRITY_ERROR = 1u << 3, /* Runtime code section lookup failed */
    RESHIELD_THREAT_TIMING          = 1u << 4  /* Timing threshold exceeded */
} reshield_threat_flags_t;

/**
 * Unified enforcement action when a threat is detected.
 */
typedef enum reshield_action {
    RESHIELD_ACTION_REPORT    = 0, /* Return threat bitmask only */
    RESHIELD_ACTION_CALLBACK  = 1, /* Invoke callback with threat bitmask */
    RESHIELD_ACTION_TERMINATE = 2  /* Quietly exit via _exit(1) without diagnostics */
} reshield_action_t;

typedef void (*reshield_threat_cb_t)(uint32_t threats, void *user_data);

typedef struct reshield_runtime_config {
    reshield_action_t    action;
    int                  check_debugger;  /* Non-zero: run OS debugger detection */
    int                  deny_attach;     /* Non-zero: request PT_DENY_ATTACH / PTRACE_TRACEME */
    int                  check_integrity; /* Non-zero: verify code section SHA-256 */
    int                  allow_unsealed;  /* Non-zero: treat UNSEALED as non-fatal */
    reshield_threat_cb_t callback;        /* Used when action == RESHIELD_ACTION_CALLBACK */
    void                *user_data;
} reshield_runtime_config_t;

/**
 * Returns default strict runtime config:
 *   action = RESHIELD_ACTION_TERMINATE,
 *   check_debugger = 1, deny_attach = 1, check_integrity = 1, allow_unsealed = 0.
 */
reshield_runtime_config_t reshield_default_config(void);

/**
 * One-line startup initialization: runs enabled debugger and integrity checks
 * and enforces config->action. If config is NULL, uses reshield_default_config().
 * Returns a bitmask of reshield_threat_flags_t (0 when clean or RESHIELD_DISABLE).
 */
uint32_t reshield_init(const reshield_runtime_config_t *config);

/**
 * Periodic runtime re-check intended for critical loops (e.g. game tick or
 * validation routines). Runs non-destructive debugger check, code-section
 * integrity check, and optional timing check if timer != NULL and max_ms > 0.
 */
uint32_t reshield_periodic_check(const reshield_runtime_config_t *config,
                                 const reshield_timer_t *timer,
                                 uint64_t max_ms);

/**
 * Overwrites [ptr, ptr + len) with zeroes using a volatile pointer so the
 * compiler does not optimize away the wipe.
 */
void reshield_secure_zero(void *ptr, size_t len);

/**
 * Simple XOR transform for PoC runtime string/constant deobfuscation.
 * Note: XOR is NOT encryption; it only prevents trivial plaintext `strings` grep
 * and should be paired with reshield_secure_zero() immediately after use.
 */
void reshield_xor_transform(uint8_t *dst, const uint8_t *src, size_t len, uint8_t key);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_H */
