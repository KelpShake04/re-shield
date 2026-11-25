/* Incremental code scan against this binary's real code section and sealed record.
 *
 * Works the same sealed or not: every chunk size must give the same result as
 * reshield_verify_code_section(), and (outside -DRESHIELD_DISABLE) the digest must equal an
 * independent SHA-256 of the section. The status is printed as "status=NAME"; `make test` runs it
 * unsealed (UNSEALED) and tests/test_seal_workflow.py seals a copy (OK) and then flips a byte of
 * reshield_incr_sentinel (TAMPERED). On Linux, when sealed and OK, it also patches the section
 * in memory in the middle of a scan (see test_mid_scan_patch). */
#ifdef __linux__
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "reshield/integrity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size);

/* Never called; a place in .text whose bytes the sealed workflow and the mid-scan test may change. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline, used))
#endif
uint32_t reshield_incr_sentinel(uint32_t x) {
    volatile uint32_t acc = x ^ 0x1234A5A5u;
    acc = (acc << 7) | (acc >> 25);
    return acc + 0x2468ACEu;
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

static const char *status_name(reshield_integrity_status_t s) {
    switch (s) {
    case RESHIELD_INTEGRITY_OK: return "OK";
    case RESHIELD_INTEGRITY_UNSEALED: return "UNSEALED";
    case RESHIELD_INTEGRITY_TAMPERED: return "TAMPERED";
    default: return "ERROR";
    }
}

static int same_result(const reshield_integrity_result_t *a, const reshield_integrity_result_t *b) {
    return a->status == b->status && a->build_id == b->build_id && a->has_manifest == b->has_manifest &&
           a->expected_size == b->expected_size && a->actual_size == b->actual_size &&
           memcmp(a->expected_sha256, b->expected_sha256, RESHIELD_SHA256_SIZE) == 0 &&
           memcmp(a->actual_sha256, b->actual_sha256, RESHIELD_SHA256_SIZE) == 0 &&
           memcmp(a->manifest_root_sha256, b->manifest_root_sha256, RESHIELD_SHA256_SIZE) == 0;
}

/* One full pass with a fixed budget; returns the final step's result in *out, or 0 on a protocol error. */
static int run_pass(reshield_code_scan_t *scan, size_t budget, reshield_integrity_result_t *out) {
    for (uint64_t i = 0;; i++) {
        int rc = reshield_code_scan_step(scan, budget, out);
        if (rc == 1) {
            return 1;
        }
        if (rc != 0 || i > (1u << 28)) {
            return 0;
        }
    }
}

#if defined(__linux__) && !defined(RESHIELD_DISABLE)
/* Patch the section in memory while a scan is running. Needs a sealed, untampered binary (OK):
 * the verdict then flips between OK and TAMPERED on exactly the pass that read the changed byte. */
static void test_mid_scan_patch(const uint8_t *code, uint64_t size) {
    uintptr_t taddr = (uintptr_t)&reshield_incr_sentinel;
    volatile uint8_t *target = (volatile uint8_t *)taddr;
    uint64_t off = (uint64_t)(taddr - (uintptr_t)code);
    long pg = sysconf(_SC_PAGESIZE);
    if (taddr < (uintptr_t)code || off == 0 || off + 1u >= size || pg <= 0) {
        printf("SKIP: mid-scan patch (sentinel not inside the section)\n");
        return;
    }
    uintptr_t lo = (uintptr_t)target & ~((uintptr_t)pg - 1u);
    if (mprotect((void *)lo, (size_t)pg, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("SKIP: mid-scan patch (mprotect refused)\n");
        return;
    }

    reshield_code_scan_t scan;
    reshield_integrity_result_t r;
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_OK, "mid-scan: begin");

    /* Byte not reached yet: this pass already sees it. */
    ASSERT_TRUE(reshield_code_scan_step(&scan, 1, &r) == (size > 1 ? 0 : 1), "mid-scan: first byte");
    *target ^= 0x01u;
    ASSERT_TRUE(run_pass(&scan, (size_t)off, &r) == 1 && r.status == RESHIELD_INTEGRITY_TAMPERED,
                "patch ahead of the cursor: TAMPERED at the end of this pass");
    *target ^= 0x01u;

    /* Byte already behind the cursor: missed by this pass, found by the next. */
    ASSERT_TRUE(reshield_code_scan_step(&scan, (size_t)off + 1u, &r) == 0, "mid-scan: cursor past the sentinel");
    *target ^= 0x01u;
    ASSERT_TRUE(run_pass(&scan, 4096, &r) == 1 && r.status == RESHIELD_INTEGRITY_OK,
                "patch behind the cursor: this pass still OK (documented gap)");
    ASSERT_TRUE(run_pass(&scan, 4096, &r) == 1 && r.status == RESHIELD_INTEGRITY_TAMPERED,
                "patch behind the cursor: TAMPERED in the next pass");
    *target ^= 0x01u;
    ASSERT_TRUE(run_pass(&scan, 4096, &r) == 1 && r.status == RESHIELD_INTEGRITY_OK,
                "restored byte: OK again on the following pass");
    (void)mprotect((void *)lo, (size_t)pg, PROT_READ | PROT_EXEC);
}
#endif

int main(void) {
    static const size_t budgets[] = { 1, 63, 64, 65, 4096, (size_t)1 << 20, SIZE_MAX };

    reshield_integrity_result_t whole;
    reshield_verify_code_section(&whole);
    printf("status=%s\n", status_name(whole.status));
    printf("section_size=%llu\n", (unsigned long long)whole.actual_size);
    ASSERT_TRUE(whole.status != RESHIELD_INTEGRITY_ERROR, "one-shot verify finds the code section");

#ifndef RESHIELD_DISABLE
    const uint8_t *code = NULL;
    uint64_t size = 0;
    uint8_t want[RESHIELD_SHA256_SIZE];
    ASSERT_TRUE(reshield_platform_get_code_section(&code, &size) == 0 && size == whole.actual_size,
                "platform hook agrees on the section size");
    reshield_sha256(code, (size_t)size, want);
    ASSERT_TRUE(memcmp(want, whole.actual_sha256, sizeof(want)) == 0, "one-shot digest equals independent SHA-256");
#endif

    char msg[96];
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); i++) {
        reshield_code_scan_t scan;
        reshield_integrity_result_t r;
        memset(&r, 0, sizeof(r));
        int ok = reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_OK && run_pass(&scan, budgets[i], &r);
        snprintf(msg, sizeof(msg), "budget %lu: same result as one-shot (status=%s)", (unsigned long)budgets[i],
                 status_name(whole.status));
        ASSERT_TRUE(ok && same_result(&r, &whole), msg);
        ok = run_pass(&scan, budgets[i], &r);
        snprintf(msg, sizeof(msg), "budget %lu: second pass same result", (unsigned long)budgets[i]);
        ASSERT_TRUE(ok && same_result(&r, &whole), msg);
    }

#if defined(__linux__) && !defined(RESHIELD_DISABLE)
    if (whole.status == RESHIELD_INTEGRITY_OK) {
        test_mid_scan_patch(code, size);
    }
#endif

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All incremental scan (real section) tests passed.\n");
    return 0;
}
