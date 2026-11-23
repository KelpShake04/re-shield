#if defined(__linux__)

#include "reshield/anti_debug.h"

#include <ctype.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

static atomic_int  g_traceme_claimed = 0;
static atomic_long g_self_traceme_ppid = 0;

const char *reshield_platform_backend_name(void) {
    return "linux";
}

uint32_t reshield_platform_check_debugger(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        return RESHIELD_DETECT_NONE;
    }

    uint32_t result = RESHIELD_DETECT_NONE;
    char line[256];
    const char *prefix = "TracerPid:";
    const size_t prefix_len = 10;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, prefix, prefix_len) == 0) {
            const char *p = line + prefix_len;
            while (*p != '\0' && isspace((unsigned char)*p)) {
                p++;
            }
            long tracer_pid = strtol(p, NULL, 10);
            if (tracer_pid > 0) {
                long self_ppid = atomic_load(&g_self_traceme_ppid);
                if (!(self_ppid > 0 && tracer_pid == self_ppid)) {
                    result = RESHIELD_DETECT_OS_TRACED;
                }
            }
            break;
        }
    }

    fclose(fp);
    return result;
}

int reshield_platform_deny_attach(void) {
    /*
     * Calling PTRACE_TRACEME twice in the same process fails with EPERM even
     * without an external debugger, so only claim the trace slot once.
     */
    if (atomic_exchange(&g_traceme_claimed, 1) != 0) {
        return reshield_platform_check_debugger() == RESHIELD_DETECT_NONE ? 0 : -1;
    }

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return -1;
    }

    /*
     * On Linux, PTRACE_TRACEME attaches this process to its parent (real_parent),
     * setting TracerPid = getppid(). Record it so subsequent TracerPid checks do
     * not false-positive against our own self-trace claim.
     */
    atomic_store(&g_self_traceme_ppid, (long)getppid());
    return 0;
}

#else
/* Empty translation unit guard for non-Linux builds */
typedef int reshield_linux_unused_t;
#endif
