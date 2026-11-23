#if defined(__APPLE__) && defined(__MACH__)

#include "reshield/debug_policy.h"

#include <string.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

const char *reshield_platform_backend_name(void) {
    return "macos";
}

uint32_t reshield_platform_check_debugger(void) {
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));

    int mib[4] = {
        CTL_KERN,
        KERN_PROC,
        KERN_PROC_PID,
        getpid()
    };

    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) {
        return RESHIELD_DETECT_NONE;
    }

    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        return RESHIELD_DETECT_OS_TRACED;
    }

    return RESHIELD_DETECT_NONE;
}

int reshield_platform_deny_attach(void) {
    /*
     * PT_DENY_ATTACH prevents future debugger attachment (sets P_LNOATTACH).
     * If a debugger is already attached, XNU terminates the process with status 45 (ENOTSUP).
     */
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0) {
        return -1;
    }
    return 0;
}

#else
/* Empty translation unit guard for non-macOS builds */
typedef int reshield_macos_unused_t;
#endif
