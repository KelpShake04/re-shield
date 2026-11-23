#if defined(__linux__)

#include "reshield/attestation.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size);

reshield_attestation_status_t reshield_verify_code_page_wx(void) {
#ifdef RESHIELD_DISABLE
    return RESHIELD_ATTEST_OK;
#else
    const uint8_t *code_ptr = NULL;
    uint64_t code_size = 0;
    if (reshield_platform_get_code_section(&code_ptr, &code_size) != 0 ||
        code_ptr == NULL || code_size == 0) {
        return RESHIELD_ATTEST_FAILED;
    }

    uintptr_t target = (uintptr_t)code_ptr;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return RESHIELD_ATTEST_FAILED;
    }

    char line[512];
    reshield_attestation_status_t status = RESHIELD_ATTEST_FAILED;
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = { 0 };
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) == 3) {
            if (target >= (uintptr_t)start && target < (uintptr_t)end) {
                /* Must be r-x (no 'w') */
                if (perms[0] == 'r' && perms[1] == '-' && perms[2] == 'x') {
                    status = RESHIELD_ATTEST_OK;
                }
                break;
            }
        }
    }

    fclose(fp);
    return status;
#endif
}

reshield_attestation_status_t reshield_verify_os_codesign(void) {
    return RESHIELD_ATTEST_UNSUPPORTED;
}

#else
typedef int reshield_attestation_linux_unused_t;
#endif
