#ifdef _WIN32

#include "reshield/attestation.h"
#include "reshield/integrity.h"

#include <stdio.h>
#include <windows.h>

/* Same idea as the POSIX branch: the platform hook is overridden so the VirtualQuery walk
 * inspects a synthetic range of VirtualAlloc'd pages. The real .text passing the check is
 * covered by the sealed-EXE runs in CI (integrity_demo runs W^X as part of reshield_verify). */
static const uint8_t *g_code_ptr;
static uint64_t g_code_size;

int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    *out_ptr = g_code_ptr;
    *out_size = g_code_size;
    return 0;
}

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

int main(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t pg = (size_t)si.dwPageSize;
    DWORD old;
    uint8_t *m = (uint8_t *)VirtualAlloc(NULL, pg * 3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (m == NULL) {
        fprintf(stderr, "VirtualAlloc failed\n");
        return 1;
    }
    g_code_ptr = m;
    g_code_size = pg * 3;

    ASSERT_TRUE(VirtualProtect(m, pg, PAGE_EXECUTE_READ, &old) &&
                VirtualProtect(m + 2 * pg, pg, PAGE_EXECUTE_READ, &old),
                "setup: outer pages r-x");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "writable middle page makes W^X check FAIL");

    ASSERT_TRUE(VirtualProtect(m + pg, pg, PAGE_EXECUTE_READ, &old), "setup: middle page r-x");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_OK,
                "all pages r-x passes W^X check");

    g_code_ptr = m + pg / 2;
    g_code_size = pg * 2;
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_OK,
                "unaligned range spanning pages passes when all r-x");

    ASSERT_TRUE(VirtualProtect(m + 2 * pg, pg, PAGE_EXECUTE_READWRITE, &old), "setup: last page rwx");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "writable+executable page at the end of the range is detected");

    ASSERT_TRUE(VirtualProtect(m + 2 * pg, pg, PAGE_READONLY, &old), "setup: last page r--");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "non-executable page at the end of the range is detected");

    ASSERT_TRUE(VirtualProtect(m + 2 * pg, pg, PAGE_EXECUTE_READ, &old), "setup: last page r-x again");
    ASSERT_TRUE(VirtualFree(m + pg, pg, MEM_DECOMMIT), "setup: decommit middle page");
    g_code_ptr = m;
    g_code_size = pg * 3;
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "gap (decommitted page) inside the range makes W^X check FAIL");

    g_code_ptr = m;
    g_code_size = UINT64_MAX;
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "overflowing range fails");

    VirtualFree(m, 0, MEM_RELEASE);
    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All W^X unit tests passed.\n");
    return 0;
}

#else

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "reshield/attestation.h"
#include "reshield/integrity.h"

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Exercises the W^X region walk against a synthetic "code section" built from anonymous
 * pages. The platform hook is overridden here (the archive member that normally defines
 * it is then not linked), so reshield_verify_code_page_wx() inspects our mapping.
 * Real __TEXT cannot be made writable in-process (its maximum protection is r-x).
 */
static const uint8_t *g_code_ptr;
static uint64_t g_code_size;

int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    *out_ptr = g_code_ptr;
    *out_size = g_code_size;
    return 0;
}

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

int main(void) {
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *m = (uint8_t *)mmap(NULL, pg * 3, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }
    g_code_ptr = m;
    g_code_size = pg * 3;

    ASSERT_TRUE(mprotect(m, pg, PROT_READ | PROT_EXEC) == 0 &&
                mprotect(m + 2 * pg, pg, PROT_READ | PROT_EXEC) == 0,
                "setup: outer pages r-x");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "writable middle page makes W^X check FAIL");

    ASSERT_TRUE(mprotect(m + pg, pg, PROT_READ | PROT_EXEC) == 0, "setup: middle page r-x");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_OK,
                "all pages r-x passes W^X check");

    g_code_ptr = m + pg / 2;
    g_code_size = pg * 2;
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_OK,
                "unaligned range spanning pages passes when all r-x");

    ASSERT_TRUE(mprotect(m + 2 * pg, pg, PROT_READ | PROT_WRITE) == 0, "setup: last page rw-");
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "writable page at the end of the range is detected");

    ASSERT_TRUE(mprotect(m + 2 * pg, pg, PROT_READ | PROT_EXEC) == 0, "setup: last page r-x again");
    ASSERT_TRUE(munmap(m + pg, pg) == 0, "setup: unmap middle page");
    g_code_ptr = m;
    g_code_size = pg * 3;
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "gap (unmapped page) inside the range makes W^X check FAIL");

    g_code_ptr = m;
    g_code_size = UINT64_MAX;
    ASSERT_TRUE(reshield_verify_code_page_wx() == RESHIELD_ATTEST_FAILED,
                "overflowing range fails");

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All W^X unit tests passed.\n");
    return 0;
}

#endif /* _WIN32 */
