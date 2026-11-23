#ifdef _WIN32

#include <stdio.h>

/* The Windows W^X backend is not implemented yet; nothing to exercise here. */
int main(void) {
    printf("SKIP: W^X tests are not implemented on Windows\n");
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
