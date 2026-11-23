#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "reshield/anti_debug.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int g_failures = 0;

#define ASSERT_TRUE(cond, msg)                                                 \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);          \
            g_failures++;                                                      \
        } else {                                                               \
            printf("PASS: %s\n", (msg));                                       \
        }                                                                      \
    } while (0)

static void sleep_for_ms(uint64_t ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000ULL);
    ts.tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);
    (void)nanosleep(&ts, NULL);
}

static int trace_me_portable(void) {
#if defined(__APPLE__) && defined(__MACH__)
    return ptrace(PT_TRACE_ME, 0, 0, 0);
#elif defined(__linux__)
    return (int)ptrace(PTRACE_TRACEME, 0, NULL, NULL);
#else
    return -1;
#endif
}

static void test_platform_and_enabled(void) {
    const char *plat = reshield_platform_name();
    ASSERT_TRUE(plat != NULL && strlen(plat) > 0, "platform name is non-empty");
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_is_enabled() == 0, "reshield_is_enabled() == 0 when RESHIELD_DISABLE is set");
#else
    ASSERT_TRUE(reshield_is_enabled() == 1, "reshield_is_enabled() == 1 in normal build");
#endif
}

static void test_clean_check(void) {
    uint32_t flags = reshield_check_debugger();
    ASSERT_TRUE(flags == RESHIELD_DETECT_NONE,
                "reshield_check_debugger() returns NONE when run without debugger");
}

static void test_guard_report_clean(void) {
    reshield_config_t cfg = {
        .policy = RESHIELD_POLICY_REPORT,
        .enable_deny_attach = 0,
        .callback = NULL,
        .user_data = NULL
    };
    uint32_t flags = reshield_guard(&cfg);
    ASSERT_TRUE(flags == RESHIELD_DETECT_NONE,
                "reshield_guard(REPORT) returns NONE when clean");
}

static void test_timing_helpers(void) {
    reshield_timer_t t;
    reshield_timer_start(&t);
    ASSERT_TRUE(reshield_timer_exceeded_ms(&t, 500) == 0,
                "immediate timer check does not exceed 500ms threshold");

    sleep_for_ms(60);
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_timer_exceeded_ms(&t, 20) == 0,
                "disabled build ignores timing threshold");
#else
    ASSERT_TRUE(reshield_timer_exceeded_ms(&t, 20) == 1,
                "60ms delay exceeds 20ms timing threshold");
#endif
}

typedef struct {
    int called;
    uint32_t flags;
} cb_state_t;

static void record_cb(uint32_t flags, void *user_data) {
    cb_state_t *st = (cb_state_t *)user_data;
    st->called++;
    st->flags = flags;
}

static int run_traced_child(int (*child_fn)(void), int *out_exit_code) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        if (trace_me_portable() != 0) {
            _exit(99);
        }
        int rc = child_fn();
        _exit(rc);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) > 0) {
        if (WIFEXITED(status)) {
            *out_exit_code = WEXITSTATUS(status);
            return 0;
        }
        if (WIFSIGNALED(status)) {
            *out_exit_code = 128 + WTERMSIG(status);
            return 0;
        }
        if (WIFSTOPPED(status)) {
            /* Continue stopped child so it can finish executing */
#if defined(__APPLE__) && defined(__MACH__)
            (void)ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
#elif defined(__linux__)
            (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
#endif
        }
    }
    return -1;
}

static int child_check_and_callback(void) {
    uint32_t flags = reshield_check_debugger();
    cb_state_t st = { 0, 0 };
    reshield_config_t cfg = {
        .policy = RESHIELD_POLICY_CALLBACK,
        .enable_deny_attach = 0,
        .callback = record_cb,
        .user_data = &st
    };
    uint32_t guard_flags = reshield_guard(&cfg);

#ifdef RESHIELD_DISABLE
    if (flags == RESHIELD_DETECT_NONE && guard_flags == RESHIELD_DETECT_NONE && st.called == 0) {
        return 0;
    }
    return 10;
#else
    if ((flags & RESHIELD_DETECT_OS_TRACED) != 0 &&
        (guard_flags & RESHIELD_DETECT_OS_TRACED) != 0 &&
        st.called == 1 &&
        (st.flags & RESHIELD_DETECT_OS_TRACED) != 0) {
        return 0;
    }
    return 10;
#endif
}

static int child_guard_terminate(void) {
    reshield_config_t cfg = {
        .policy = RESHIELD_POLICY_TERMINATE,
        .enable_deny_attach = 0,
        .callback = NULL,
        .user_data = NULL
    };
    (void)reshield_guard(&cfg);
    return 0;
}

static int child_deny_attach(void) {
    int rc = reshield_deny_attach();
    return rc == 0 ? 0 : 11;
}

static void test_traced_child_scenarios(void) {
    int exit_code = -1;

    if (run_traced_child(child_check_and_callback, &exit_code) != 0) {
        ASSERT_TRUE(0, "traced child: waitpid succeeded");
        return;
    }
    if (exit_code == 99) {
        printf("SKIP: traced child scenarios (ptrace PT_TRACE_ME/PTRACE_TRACEME restricted by environment)\n");
        return;
    }
    ASSERT_TRUE(exit_code == 0,
                "traced child: reshield_check_debugger() & CALLBACK policy behave as expected");

    exit_code = -1;
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(run_traced_child(child_guard_terminate, &exit_code) == 0 && exit_code == 0,
                "traced child (disabled): TERMINATE policy is a no-op (exit 0)");
#else
    ASSERT_TRUE(run_traced_child(child_guard_terminate, &exit_code) == 0 && exit_code == 1,
                "traced child: TERMINATE policy exits quietly with status 1");
#endif

    exit_code = -1;
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(run_traced_child(child_deny_attach, &exit_code) == 0 && exit_code == 0,
                "traced child (disabled): reshield_deny_attach() is a no-op (exit 0)");
#elif defined(__APPLE__) && defined(__MACH__)
    /* XNU terminates traced process calling PT_DENY_ATTACH with exit status 45 (ENOTSUP) */
    ASSERT_TRUE(run_traced_child(child_deny_attach, &exit_code) == 0 && exit_code == 45,
                "traced child (macOS): PT_DENY_ATTACH terminates traced process with ENOTSUP (45)");
#elif defined(__linux__)
    ASSERT_TRUE(run_traced_child(child_deny_attach, &exit_code) == 0 && exit_code == 11,
                "traced child (Linux): PTRACE_TRACEME fails when already traced (exit 11)");
#endif
}

static void test_deny_attach_clean(void) {
    int rc = reshield_deny_attach();
    ASSERT_TRUE(rc == 0, "reshield_deny_attach() succeeds when not attached");
}

int main(void) {
    test_platform_and_enabled();
    test_clean_check();
    test_guard_report_clean();
    test_timing_helpers();
    test_traced_child_scenarios();
    test_deny_attach_clean();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All unit tests passed.\n");
    return 0;
}
