/* Incremental code scan (reshield_code_scan_begin/step) on a synthetic "code section".
 *
 * The platform hook is overridden (the archive member that normally defines it is then not
 * linked), so the scan hashes a buffer this test owns and can change mid-scan. The sealed
 * record of this binary is empty, so the status is UNSEALED; the digest is what is compared.
 * Real sections, sealed records and TAMPERED are covered by tests/test_incremental_real.c. */
#include "reshield/integrity.h"

#include "../src/sha256_accel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 10000u

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

#ifdef RESHIELD_DISABLE

int main(void) {
    reshield_code_scan_t scan;
    reshield_integrity_result_t r;
    memset(&r, 0xAB, sizeof(r));
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_OK, "disabled: begin returns OK");
    ASSERT_TRUE(reshield_code_scan_step(&scan, 1, &r) == 1 && r.status == RESHIELD_INTEGRITY_OK,
                "disabled: first step finishes with OK");
    ASSERT_TRUE(reshield_code_scan_step(&scan, 1, NULL) == 1, "disabled: step stays finished, NULL result ok");
    ASSERT_TRUE(reshield_code_scan_step(&scan, 0, &r) == -1, "disabled: max_bytes == 0 is -1");
    ASSERT_TRUE(reshield_code_scan_step(NULL, 1, &r) == -1, "disabled: NULL scan is -1");
    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All incremental scan tests passed (disabled build).\n");
    return 0;
}

#else

static uint8_t g_buf[BUF_SIZE];
static const uint8_t *g_code_ptr = g_buf;
static uint64_t g_code_size = BUF_SIZE;
static int g_hook_rc = 0;

/* Not defined in the disabled build, which links every source file including the real hook. */
int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    if (g_hook_rc != 0) {
        return g_hook_rc;
    }
    *out_ptr = g_code_ptr;
    *out_size = g_code_size;
    return 0;
}

/* Runs one pass with a fixed budget. Returns the number of step calls, or 0 on a protocol
 * error (a return other than 0 before 1, or a call count that is not ceil(size / budget)). */
static size_t run_pass(reshield_code_scan_t *scan, size_t budget, uint64_t size,
                       reshield_integrity_result_t *out) {
    size_t calls = 0;
    for (;;) {
        int rc = reshield_code_scan_step(scan, budget, out);
        calls++;
        if (rc == 1) {
            break;
        }
        if (rc != 0 || calls > size) {
            return 0;
        }
    }
    uint64_t want = (uint64_t)budget >= size ? 1u : (size + budget - 1u) / budget;
    return calls == want ? calls : 0;
}

static int same_result(const reshield_integrity_result_t *a, const reshield_integrity_result_t *b) {
    return a->status == b->status && a->build_id == b->build_id && a->has_manifest == b->has_manifest &&
           a->expected_size == b->expected_size && a->actual_size == b->actual_size &&
           memcmp(a->expected_sha256, b->expected_sha256, RESHIELD_SHA256_SIZE) == 0 &&
           memcmp(a->actual_sha256, b->actual_sha256, RESHIELD_SHA256_SIZE) == 0 &&
           memcmp(a->manifest_root_sha256, b->manifest_root_sha256, RESHIELD_SHA256_SIZE) == 0;
}

static void test_budgets(const char *backend) {
    static const size_t budgets[] = { 1, 63, 64, 65, 4096, BUF_SIZE - 1u, BUF_SIZE, BUF_SIZE + 1u,
                                      (size_t)1 << 20, SIZE_MAX };
    uint8_t want[RESHIELD_SHA256_SIZE];
    reshield_sha256(g_buf, BUF_SIZE, want);

    reshield_integrity_result_t whole;
    reshield_verify_code_section(&whole);
    ASSERT_TRUE(whole.status == RESHIELD_INTEGRITY_UNSEALED &&
                memcmp(whole.actual_sha256, want, sizeof(want)) == 0 && whole.actual_size == BUF_SIZE,
                "one-shot verify_code_section hashes the synthetic section (UNSEALED)");

    char msg[96];
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); i++) {
        reshield_code_scan_t scan;
        reshield_integrity_result_t r;
        memset(&r, 0, sizeof(r));
        int ok = reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_OK;
        size_t calls = ok ? run_pass(&scan, budgets[i], BUF_SIZE, &r) : 0;
        snprintf(msg, sizeof(msg), "[%s] budget %lu: step protocol ok, same result as one-shot", backend,
                 (unsigned long)budgets[i]);
        ASSERT_TRUE(calls != 0 && same_result(&r, &whole), msg);

        /* The next pass restarts by itself and gives the same answer. */
        calls = ok ? run_pass(&scan, budgets[i], BUF_SIZE, &r) : 0;
        snprintf(msg, sizeof(msg), "[%s] budget %lu: second pass without begin is identical", backend,
                 (unsigned long)budgets[i]);
        ASSERT_TRUE(calls != 0 && same_result(&r, &whole), msg);
    }
}

static void test_mutation(const char *backend) {
    uint8_t orig[RESHIELD_SHA256_SIZE];
    uint8_t flipped[RESHIELD_SHA256_SIZE];
    reshield_sha256(g_buf, BUF_SIZE, orig);

    reshield_code_scan_t scan;
    reshield_integrity_result_t r;
    printf("-- mutation, %s backend\n", backend);
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_OK, "mutation: begin");

    /* A byte the cursor has not reached yet changes the result of this pass. */
    ASSERT_TRUE(reshield_code_scan_step(&scan, 4096, &r) == 0, "mutation: first chunk, pass not finished");
    g_buf[9000] ^= 0x01u;
    reshield_sha256(g_buf, BUF_SIZE, flipped);
    ASSERT_TRUE(reshield_code_scan_step(&scan, SIZE_MAX, &r) == 1 &&
                memcmp(r.actual_sha256, flipped, sizeof(flipped)) == 0 &&
                memcmp(r.actual_sha256, orig, sizeof(orig)) != 0,
                "unvisited byte changed mid-pass: this pass reports the new digest");
    g_buf[9000] ^= 0x01u;

    /* A byte behind the cursor is missed by this pass and found by the next one. */
    ASSERT_TRUE(reshield_code_scan_step(&scan, 5000, &r) == 0, "mutation: next pass, first 5000 bytes");
    g_buf[10] ^= 0x01u;
    reshield_sha256(g_buf, BUF_SIZE, flipped);
    ASSERT_TRUE(reshield_code_scan_step(&scan, SIZE_MAX, &r) == 1 &&
                memcmp(r.actual_sha256, orig, sizeof(orig)) == 0,
                "visited byte changed mid-pass: this pass still reports the old digest (documented gap)");
    ASSERT_TRUE(reshield_code_scan_step(&scan, SIZE_MAX, &r) == 1 &&
                memcmp(r.actual_sha256, flipped, sizeof(flipped)) == 0,
                "visited byte change is reported by the next pass");
    g_buf[10] ^= 0x01u;

    /* Patch and undo behind the cursor before the next visit: never seen. */
    ASSERT_TRUE(reshield_code_scan_step(&scan, 5000, &r) == 0, "mutation: next pass, first 5000 bytes");
    g_buf[20] ^= 0x01u;
    g_buf[20] ^= 0x01u;
    ASSERT_TRUE(reshield_code_scan_step(&scan, SIZE_MAX, &r) == 1 &&
                memcmp(r.actual_sha256, orig, sizeof(orig)) == 0,
                "patch undone before the next visit is not detected (documented gap)");
}

static void test_errors_and_state(void) {
    reshield_code_scan_t scan;
    reshield_integrity_result_t r;
    reshield_integrity_result_t marker;
    uint8_t want[RESHIELD_SHA256_SIZE];
    memset(&marker, 0x5A, sizeof(marker));
    reshield_sha256(g_buf, BUF_SIZE, want);

    ASSERT_TRUE(sizeof(reshield_code_scan_t) == 192 && sizeof(((reshield_code_scan_t *)0)->opaque_[0]) == 8,
                "reshield_code_scan_t is 192 bytes of uint64_t");
    ASSERT_TRUE(reshield_code_scan_begin(NULL) == RESHIELD_INTEGRITY_ERROR, "begin(NULL) returns ERROR");
    ASSERT_TRUE(reshield_code_scan_step(NULL, 1, &r) == -1, "step(NULL scan) returns -1");

    memset(&scan, 0, sizeof(scan));
    ASSERT_TRUE(reshield_code_scan_step(&scan, 1, &r) == -1, "step on a zeroed scan returns -1");
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_OK, "begin ok");
    ASSERT_TRUE(reshield_code_scan_step(&scan, 0, &r) == -1, "step(max_bytes == 0) returns -1");

    r = marker;
    ASSERT_TRUE(reshield_code_scan_step(&scan, 64, &r) == 0 && memcmp(&r, &marker, sizeof(r)) == 0,
                "unfinished step leaves out_result untouched");
    ASSERT_TRUE(reshield_code_scan_step(&scan, SIZE_MAX, NULL) == 1, "finishing with out_result == NULL works");

    /* begin in the middle of a pass starts over: the one-shot digest comes out. */
    reshield_code_scan_step(&scan, 777, NULL);
    reshield_code_scan_begin(&scan);
    ASSERT_TRUE(reshield_code_scan_step(&scan, SIZE_MAX, &r) == 1 && memcmp(r.actual_sha256, want, sizeof(want)) == 0,
                "begin during a pass restarts it");

    /* Two scans are independent. */
    reshield_code_scan_t a;
    reshield_code_scan_t b;
    reshield_code_scan_begin(&a);
    reshield_code_scan_begin(&b);
    reshield_code_scan_step(&a, 3000, NULL);
    ASSERT_TRUE(reshield_code_scan_step(&b, SIZE_MAX, &r) == 1 && memcmp(r.actual_sha256, want, sizeof(want)) == 0 &&
                reshield_code_scan_step(&a, SIZE_MAX, &r) == 1 && memcmp(r.actual_sha256, want, sizeof(want)) == 0,
                "two interleaved scans do not disturb each other");

    /* Section lookup failures fail closed, and a failed begin leaves an unusable scan. */
    reshield_code_scan_begin(&scan);
    g_hook_rc = -1;
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_ERROR, "begin: hook failure returns ERROR");
    ASSERT_TRUE(reshield_code_scan_step(&scan, 1, &r) == -1, "step after a failed begin returns -1");
    r = marker;
    ASSERT_TRUE(reshield_verify_code_section(&r) == RESHIELD_INTEGRITY_ERROR && r.status == RESHIELD_INTEGRITY_ERROR &&
                r.actual_size == 0,
                "verify_code_section: hook failure gives ERROR with a zeroed result");
    g_hook_rc = 0;
    g_code_size = 0;
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_ERROR, "begin: empty section returns ERROR");
    g_code_size = BUF_SIZE;
    g_code_ptr = NULL;
    ASSERT_TRUE(reshield_code_scan_begin(&scan) == RESHIELD_INTEGRITY_ERROR, "begin: NULL section returns ERROR");
    g_code_ptr = g_buf;
}

int main(void) {
    uint32_t x = 0x12345678u;
    for (size_t i = 0; i < BUF_SIZE; i++) {
        x = x * 1664525u + 1013904223u;
        g_buf[i] = (uint8_t)(x >> 24);
    }

    printf("SHA-256 backend: %d\n", reshield_sha256_backend());
    test_budgets("detected");
    test_mutation("detected");
    reshield_sha256_force_portable(1);
    test_budgets("portable");
    test_mutation("portable");
    reshield_sha256_force_portable(0);
    test_errors_and_state();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All incremental scan tests passed.\n");
    return 0;
}

#endif
