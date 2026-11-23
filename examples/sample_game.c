#include "reshield/reshield.h"

#include <stdio.h>
#include <string.h>

/*
 * Sample native game stage loader demonstrating:
 * 1. Code-section SHA-256 + W^X page permission verification at startup.
 * 2. Sealed asset manifest verification before loading external stage config.
 * 3. SHA-256 commitment verification for stage unlock key (no plaintext key in binary).
 */

/* SHA-256("STAGE-1-CLEAR-2026") */
static const uint8_t STAGE_KEY_COMMITMENT[RESHIELD_SHA256_SIZE] = {
    0xa1u, 0x18u, 0xd2u, 0xefu, 0xb3u, 0x55u, 0xbdu, 0x0fu,
    0x7bu, 0x16u, 0x69u, 0x9fu, 0x7fu, 0xa4u, 0x64u, 0x61u,
    0xe3u, 0x9cu, 0x11u, 0xb7u, 0x86u, 0x4bu, 0x31u, 0xf0u,
    0x89u, 0x17u, 0xefu, 0x11u, 0xd7u, 0x5eu, 0x16u, 0x98u
};

static void on_integrity_error(const reshield_report_t *report, void *user_data) {
    (void)user_data;
    fprintf(stderr, "Integrity check failed (%s, checks=0x%x, build_id=%u)",
            reshield_status_name(report->status),
            report->failed_checks,
            report->build_id);
    if (report->failed_asset_path[0] != '\0') {
        fprintf(stderr, " asset=%s", report->failed_asset_path);
    }
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <manifest-path> <asset-dir> <stage-key>\n", argv[0]);
        return 2;
    }

    const char *manifest_path = argv[1];
    const char *asset_dir = argv[2];
    const char *stage_key = argv[3];

    reshield_config_t cfg = reshield_default_config();
    cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
    cfg.manifest_path = manifest_path;
    cfg.asset_base_dir = asset_dir;
    cfg.on_violation = on_integrity_error;

    reshield_report_t report;
    if (reshield_verify(&cfg, &report) != RESHIELD_OK) {
        return 10 + (int)report.status;
    }

    /* Verify stage key against SHA-256 commitment in constant time */
    if (!reshield_verify_buffer(stage_key, strlen(stage_key), STAGE_KEY_COMMITMENT)) {
        printf("ACCESS DENIED\n");
        return 1;
    }

    /* Load verified asset */
    char cfg_path[1024];
    snprintf(cfg_path, sizeof(cfg_path), "%s/stage1.cfg", asset_dir);
    FILE *fp = fopen(cfg_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open stage config: %s\n", cfg_path);
        return 3;
    }

    char line[256];
    printf("STAGE UNLOCKED (build_id=%u)\n", report.build_id);
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
    }
    fclose(fp);
    return 0;
}
