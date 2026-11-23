#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "reshield/anti_debug.h"

#include <stddef.h>
#include <time.h>
#include <unistd.h>

/* Platform backend hooks implemented in anti_debug_macos.c / anti_debug_linux.c */
extern const char *reshield_platform_backend_name(void);
extern uint32_t    reshield_platform_check_debugger(void);
extern int         reshield_platform_deny_attach(void);

#if !defined(__APPLE__) && !defined(__linux__)
const char *reshield_platform_backend_name(void) {
    return "unsupported";
}

uint32_t reshield_platform_check_debugger(void) {
    return RESHIELD_DETECT_NONE;
}

int reshield_platform_deny_attach(void) {
    return -1;
}
#endif

static uint64_t monotonic_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int reshield_is_enabled(void) {
#ifdef RESHIELD_DISABLE
    return 0;
#else
    return 1;
#endif
}

const char *reshield_platform_name(void) {
    return reshield_platform_backend_name();
}

uint32_t reshield_check_debugger(void) {
#ifdef RESHIELD_DISABLE
    return RESHIELD_DETECT_NONE;
#else
    return reshield_platform_check_debugger();
#endif
}

int reshield_deny_attach(void) {
#ifdef RESHIELD_DISABLE
    return 0;
#else
    return reshield_platform_deny_attach();
#endif
}

uint32_t reshield_guard(const reshield_config_t *config) {
#ifdef RESHIELD_DISABLE
    (void)config;
    return RESHIELD_DETECT_NONE;
#else
    reshield_config_t effective = {
        .policy = RESHIELD_POLICY_REPORT,
        .enable_deny_attach = 0,
        .callback = NULL,
        .user_data = NULL
    };

    if (config != NULL) {
        effective = *config;
    }

    uint32_t flags = reshield_platform_check_debugger();

    if (effective.enable_deny_attach && flags == RESHIELD_DETECT_NONE) {
        if (reshield_platform_deny_attach() != 0) {
            flags |= RESHIELD_DETECT_PTRACE;
        }
    }

    if (flags != RESHIELD_DETECT_NONE) {
        switch (effective.policy) {
            case RESHIELD_POLICY_CALLBACK:
                if (effective.callback != NULL) {
                    effective.callback(flags, effective.user_data);
                }
                break;
            case RESHIELD_POLICY_TERMINATE:
                /* Terminate process according to configured policy */
                _exit(1);
                break;
            case RESHIELD_POLICY_REPORT:
            default:
                break;
        }
    }

    return flags;
#endif
}

void reshield_timer_start(reshield_timer_t *timer) {
    if (timer == NULL) {
        return;
    }
    timer->start_ns = monotonic_now_ns();
}

uint64_t reshield_timer_elapsed_ns(const reshield_timer_t *timer) {
    if (timer == NULL || timer->start_ns == 0) {
        return 0;
    }
    uint64_t now = monotonic_now_ns();
    if (now < timer->start_ns) {
        return 0;
    }
    return now - timer->start_ns;
}

int reshield_timer_exceeded_ms(const reshield_timer_t *timer, uint64_t threshold_ms) {
#ifdef RESHIELD_DISABLE
    (void)timer;
    (void)threshold_ms;
    return 0;
#else
    if (timer == NULL) {
        return 0;
    }
    uint64_t elapsed_ms = reshield_timer_elapsed_ns(timer) / 1000000ULL;
    return elapsed_ms > threshold_ms ? 1 : 0;
#endif
}
