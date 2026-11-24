#include "reshield/reshield.h"

#include <stdio.h>
#include <string.h>

/*
 * Crackme lab target (see docs/crackme-lab.md). Own binary only, for learning what re-shield
 * does and does not stop. Two functions are the attack surface, on purpose:
 *   crackme_startup_check()  runs reshield_verify_app() and returns 0 (OK) or 10 + status
 *   crackme_check_license()  returns 1 when the key hashes to the committed digest
 * Both are external and noinline so each keeps its own symbol and entry point in .text; the lab
 * script finds them by symbol name instead of a hardcoded offset.
 */

/* SHA-256("CRACKME-LAB-2026") */
static const uint8_t KEY_COMMITMENT[RESHIELD_SHA256_SIZE] = {
    0xe4u, 0x6eu, 0x20u, 0x1cu, 0xd8u, 0x5au, 0x98u, 0xb6u,
    0x1au, 0x41u, 0xceu, 0x9fu, 0xebu, 0x80u, 0x1au, 0x84u,
    0xafu, 0x40u, 0x2eu, 0x0eu, 0x9du, 0xa4u, 0x95u, 0xc9u,
    0xcdu, 0xe1u, 0x54u, 0x10u, 0xc6u, 0x7cu, 0x35u, 0xb0u
};

static void on_violation(const reshield_report_t *report, void *user_data) {
    (void)user_data;
    fprintf(stderr, "INTEGRITY VIOLATION: %s (checks=0x%x)\n",
            reshield_status_name(report->status), report->failed_checks);
}

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

int crackme_startup_check(void);
int crackme_check_license(const char *key);

/* The library never exits: this app decides what a violation means. */
NOINLINE int crackme_startup_check(void) {
    reshield_report_t report;
    reshield_status_t status = reshield_verify_app(NULL, NULL, on_violation, NULL, &report);
    return status == RESHIELD_OK ? 0 : 10 + (int)status;
}

NOINLINE int crackme_check_license(const char *key) {
    return reshield_verify_buffer(key, strlen(key), KEY_COMMITMENT);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <license-key>\n", argv[0]);
        return 2;
    }

    int rc = crackme_startup_check();
    if (rc != 0) {
        return rc;
    }

    if (!crackme_check_license(argv[1])) {
        printf("ACCESS DENIED\n");
        return 1;
    }
    printf("UNLOCKED\n");
    return 0;
}
