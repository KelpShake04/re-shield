#if defined(__linux__)

#include "reshield/attestation.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    /* [start, end) must be covered by contiguous r-x mappings (maps lines are address-sorted). */
    uintptr_t start = (uintptr_t)code_ptr;
    if (code_size > UINTPTR_MAX - start) {
        return RESHIELD_ATTEST_FAILED;
    }
    uintptr_t end = start + (uintptr_t)code_size;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return RESHIELD_ATTEST_FAILED;
    }

    char line[512];
    uintptr_t cur = start;
    reshield_attestation_status_t status = RESHIELD_ATTEST_FAILED;
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Skip the tail of over-long lines (long paths) so fragments are never parsed. */
        if (strchr(line, '\n') == NULL) {
            int ch;
            while ((ch = fgetc(fp)) != EOF && ch != '\n') {
            }
        }
        unsigned long long lo = 0;
        unsigned long long hi = 0;
        char perms[8] = { 0 };
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, perms) != 3) {
            continue;
        }
        if ((uintptr_t)hi <= cur) {
            continue;
        }
        if ((uintptr_t)lo > cur) {
            break; /* gap: nothing maps [cur, lo) */
        }
        /* Must be r-x (no 'w') */
        if (!(perms[0] == 'r' && perms[1] == '-' && perms[2] == 'x')) {
            break;
        }
        cur = (uintptr_t)hi;
        if (cur >= end) {
            status = RESHIELD_ATTEST_OK;
            break;
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
