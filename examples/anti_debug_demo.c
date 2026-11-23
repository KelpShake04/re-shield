#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "reshield/anti_debug.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void sleep_for_ms(uint64_t ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000ULL);
    ts.tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);
    (void)nanosleep(&ts, NULL);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--mode=check|deny|guard-quiet|timing] [--threshold-ms=N] [--sleep-ms=N]\n"
            "\n"
            "Modes:\n"
            "  check        Non-destructive debugger detection (sysctl P_TRACED / TracerPid).\n"
            "  deny         Calls reshield_deny_attach() (PT_DENY_ATTACH on macOS / PTRACE_TRACEME on Linux).\n"
            "  guard-quiet  Runs reshield_guard() with RESHIELD_POLICY_TERMINATE (exits 1 silently if traced).\n"
            "  timing       Measures a short loop with reshield_timer_* (use --sleep-ms to simulate breakpoint pause).\n",
            prog);
}

static uint64_t sample_work(void) {
    volatile uint64_t acc = 0;
    for (uint64_t i = 0; i < 100000; i++) {
        acc += (i * 2654435761ULL) ^ (acc >> 3);
    }
    return acc;
}

int main(int argc, char **argv) {
    const char *mode = "check";
    uint64_t threshold_ms = 200;
    uint64_t sleep_ms = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            mode = argv[i] + 7;
        } else if (strncmp(argv[i], "--threshold-ms=", 15) == 0) {
            threshold_ms = strtoull(argv[i] + 15, NULL, 10);
        } else if (strncmp(argv[i], "--sleep-ms=", 11) == 0) {
            sleep_ms = strtoull(argv[i] + 11, NULL, 10);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (strcmp(mode, "guard-quiet") == 0) {
        reshield_config_t cfg = {
            .policy = RESHIELD_POLICY_TERMINATE,
            .enable_deny_attach = 0,
            .callback = NULL,
            .user_data = NULL
        };
        (void)reshield_guard(&cfg);
        printf("ok (pid=%d, platform=%s, enabled=%d)\n",
               (int)getpid(), reshield_platform_name(), reshield_is_enabled());
        return 0;
    }

    printf("[re-shield demo] pid=%d platform=%s enabled=%d mode=%s\n",
           (int)getpid(), reshield_platform_name(), reshield_is_enabled(), mode);

    if (strcmp(mode, "check") == 0) {
        uint32_t flags = reshield_check_debugger();
        printf("check_debugger flags=0x%x (%s)\n",
               flags, flags != RESHIELD_DETECT_NONE ? "DEBUGGER DETECTED" : "clean");
        return flags != RESHIELD_DETECT_NONE ? 10 : 0;
    }

    if (strcmp(mode, "deny") == 0) {
        printf("calling reshield_deny_attach()...\n");
        fflush(stdout);
        int rc = reshield_deny_attach();
        printf("reshield_deny_attach rc=%d\n", rc);
        return rc == 0 ? 0 : 11;
    }

    if (strcmp(mode, "timing") == 0) {
        reshield_timer_t timer;
        reshield_timer_start(&timer);
        uint64_t sink = sample_work();
        if (sleep_ms > 0) {
            sleep_for_ms(sleep_ms);
        }
        uint64_t elapsed_ns = reshield_timer_elapsed_ns(&timer);
        int exceeded = reshield_timer_exceeded_ms(&timer, threshold_ms);
        printf("work=%" PRIu64 " elapsed_ms=%" PRIu64 " threshold_ms=%" PRIu64 " exceeded=%d\n",
               sink, elapsed_ns / 1000000ULL, threshold_ms, exceeded);
        return exceeded ? 12 : 0;
    }

    fprintf(stderr, "Unknown mode: %s\n", mode);
    print_usage(argv[0]);
    return 2;
}
