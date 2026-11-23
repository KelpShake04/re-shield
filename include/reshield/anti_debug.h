#ifndef RESHIELD_ANTI_DEBUG_H
#define RESHIELD_ANTI_DEBUG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detection signal bitmask returned by reshield_check_debugger() and reshield_guard().
 */
typedef enum reshield_detect_flags {
    RESHIELD_DETECT_NONE      = 0u,
    RESHIELD_DETECT_OS_TRACED = 1u << 0, /* macOS sysctl(P_TRACED) / Linux TracerPid */
    RESHIELD_DETECT_PTRACE    = 1u << 1, /* ptrace deny/self-trace failed */
    RESHIELD_DETECT_TIMING    = 1u << 2  /* monotonic clock threshold exceeded */
} reshield_detect_flags_t;

/**
 * Policy applied by reshield_guard() when a debugger signal is detected.
 */
typedef enum reshield_policy {
    RESHIELD_POLICY_REPORT    = 0, /* Return flags only; caller decides */
    RESHIELD_POLICY_CALLBACK  = 1, /* Invoke user callback with detected flags */
    RESHIELD_POLICY_TERMINATE = 2  /* Exit quietly via _exit(1) without diagnostics */
} reshield_policy_t;

typedef void (*reshield_detect_cb_t)(uint32_t flags, void *user_data);

typedef struct reshield_config {
    reshield_policy_t    policy;
    int                  enable_deny_attach; /* 0 = check only, non-zero = also call reshield_deny_attach() */
    reshield_detect_cb_t callback;           /* Used when policy == RESHIELD_POLICY_CALLBACK */
    void                *user_data;
} reshield_config_t;

typedef struct reshield_timer {
    uint64_t start_ns;
} reshield_timer_t;

/**
 * Returns 1 if re-shield checks are compiled in, or 0 if compiled with -DRESHIELD_DISABLE.
 */
int reshield_is_enabled(void);

/**
 * Returns a short static string identifying the active backend ("macos", "linux", "unsupported").
 */
const char *reshield_platform_name(void);

/**
 * Non-destructive check for an attached debugger.
 * - macOS: sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID) P_TRACED flag.
 * - Linux: /proc/self/status TracerPid != 0.
 * Returns a bitmask of reshield_detect_flags_t (0 if no debugger detected or disabled).
 */
uint32_t reshield_check_debugger(void);

/**
 * Requests OS-level debugger attach denial / self-trace.
 * - macOS: ptrace(PT_DENY_ATTACH, 0, 0, 0). Note: terminates the process with
 *   exit status 45 (ENOTSUP) if a debugger is already attached.
 * - Linux: ptrace(PTRACE_TRACEME, 0, 0, 0) once per process.
 * Returns 0 on success (or when disabled), -1 if already traced or unsupported.
 */
int reshield_deny_attach(void);

/**
 * Runs debugger detection (and optionally deny_attach) and enforces config->policy.
 * If config is NULL, defaults to RESHIELD_POLICY_REPORT with enable_deny_attach = 0.
 */
uint32_t reshield_guard(const reshield_config_t *config);

/**
 * Monotonic timer helpers for coarse timing-based anomaly checks (e.g., breakpoint pauses).
 * Note: Timing checks are heuristic and can false-positive under heavy CPU load or VM pauses.
 */
void     reshield_timer_start(reshield_timer_t *timer);
uint64_t reshield_timer_elapsed_ns(const reshield_timer_t *timer);
int      reshield_timer_exceeded_ms(const reshield_timer_t *timer, uint64_t threshold_ms);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_ANTI_DEBUG_H */
