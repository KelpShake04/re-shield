#include "reshield/reshield.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/**
 * Uncalled sentinel function in __TEXT,__text / .text used by automated
 * corruption-detection tests to verify SHA-256 integrity checks.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline, used))
#endif
uint32_t reshield_checksum_sentinel(uint32_t x) {
    volatile uint32_t acc = x ^ 0x5A5A1234u;
    acc = (acc << 5) | (acc >> 27);
    return acc + 0x13572468u;
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

static void log_violation(const reshield_report_t *report, void *user_data) {
    (void)user_data;
    fprintf(stderr, "[integrity-violation] status=%s failed_checks=0x%x build_id=%u",
            reshield_status_name(report->status),
            report->failed_checks,
            report->build_id);
    if (report->failed_asset_path[0] != '\0') {
        fprintf(stderr, " asset=%s", report->failed_asset_path);
    }
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    reshield_config_t cfg = reshield_default_config();
    cfg.on_violation = log_violation;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--manifest=", 11) == 0) {
            cfg.manifest_path = argv[i] + 11;
            cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
        } else if (strncmp(argv[i], "--assets=", 9) == 0) {
            cfg.asset_base_dir = argv[i] + 9;
        } else if (strcmp(argv[i], "--check-codesign") == 0) {
            cfg.enabled_checks |= RESHIELD_CHECK_CODESIGN;
        } else if (strcmp(argv[i], "--allow-unsealed") == 0) {
            cfg.allow_unsealed = 1;
        }
    }

    reshield_report_t report;
    reshield_status_t st = reshield_verify(&cfg, &report);

    printf("[re-shield integrity] platform=%s enabled=%d status=%s build_id=%u\n",
           reshield_platform_name(), reshield_is_enabled(),
           reshield_status_name(st), report.build_id);
    printf("code_size: actual=%" PRIu64 " expected=%" PRIu64 "\n",
           report.code_result.actual_size, report.code_result.expected_size);
    printf("actual_sha256:   ");
    print_hex(report.code_result.actual_sha256, RESHIELD_SHA256_SIZE);
    printf("\nexpected_sha256: ");
    print_hex(report.code_result.expected_sha256, RESHIELD_SHA256_SIZE);
    printf("\n");

    return (int)st;
}
