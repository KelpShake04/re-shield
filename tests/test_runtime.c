#include "reshield/reshield.h"

#include <stdio.h>
#include <string.h>

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

typedef struct {
    int calls;
    reshield_status_t last_status;
} cb_ctx_t;

static void record_violation(const reshield_report_t *report, void *user_data) {
    cb_ctx_t *ctx = (cb_ctx_t *)user_data;
    ctx->calls++;
    ctx->last_status = report->status;
}

static void test_verify_unsealed_and_callback(void) {
    cb_ctx_t ctx = { 0, RESHIELD_OK };
    reshield_config_t cfg = reshield_default_config();
    cfg.on_violation = record_violation;
    cfg.user_data = &ctx;

    reshield_report_t report;
    reshield_status_t st = reshield_verify(&cfg, &report);

#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(st == RESHIELD_OK && ctx.calls == 0,
                "disabled reshield_verify() returns OK without callback");
#else
    ASSERT_TRUE(st == RESHIELD_ERR_UNSEALED && ctx.calls == 1 &&
                ctx.last_status == RESHIELD_ERR_UNSEALED,
                "strict reshield_verify() reports UNSEALED and invokes callback");

    ctx.calls = 0;
    cfg.allow_unsealed = 1;
    st = reshield_verify(&cfg, &report);
    ASSERT_TRUE(st == RESHIELD_OK && ctx.calls == 0,
                "allow_unsealed=1 permits unsealed dev binary while W^X passes");
#endif
}

static void test_null_config_and_report(void) {
    reshield_report_t report;
    memset(&report, 0xAB, sizeof(report));
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_verify(NULL, NULL) == RESHIELD_OK, "disabled: config=NULL, out_report=NULL returns OK");
    ASSERT_TRUE(reshield_verify(NULL, &report) == RESHIELD_OK && report.failed_checks == 0u,
                "disabled: config=NULL yields a zeroed OK report");
#else
    ASSERT_TRUE(reshield_verify(NULL, NULL) == RESHIELD_ERR_UNSEALED,
                "config=NULL and out_report=NULL: default (strict) config reports UNSEALED");
    ASSERT_TRUE(reshield_verify(NULL, &report) == RESHIELD_ERR_UNSEALED &&
                report.status == RESHIELD_ERR_UNSEALED &&
                report.failed_checks == RESHIELD_CHECK_CODE_SECTION,
                "config=NULL fills report: UNSEALED with only the code-section bit set");

    reshield_config_t cfg = reshield_default_config();
    cfg.allow_unsealed = 1;
    ASSERT_TRUE(reshield_verify(&cfg, NULL) == RESHIELD_OK, "out_report=NULL with allow_unsealed returns OK");
#endif
}

static void test_manifest_flag_with_unsealed_binary(void) {
    reshield_report_t report;
    reshield_config_t cfg = reshield_default_config();
    cfg.enabled_checks = RESHIELD_CHECK_MANIFEST;
    cfg.manifest_path = "build/does_not_exist.manifest";

#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_OK, "disabled: MANIFEST check is skipped");
#else
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_ERR_UNSEALED &&
                report.failed_checks == RESHIELD_CHECK_MANIFEST,
                "MANIFEST on unsealed binary: UNSEALED, only the manifest bit set");

    cfg.allow_unsealed = 1;
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_OK && report.failed_checks == 0u,
                "allow_unsealed + MANIFEST on unsealed binary passes (dev only)");

    cfg.enabled_checks = RESHIELD_CHECK_CODE_SECTION | RESHIELD_CHECK_MANIFEST;
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_OK && report.failed_checks == 0u,
                "allow_unsealed + CODE_SECTION|MANIFEST passes on unsealed binary");

    cfg.allow_unsealed = 0;
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_ERR_UNSEALED &&
                report.failed_checks == (RESHIELD_CHECK_CODE_SECTION | RESHIELD_CHECK_MANIFEST),
                "strict CODE_SECTION|MANIFEST: both failed_checks bits set, status UNSEALED");

    cfg.enabled_checks = 0u;
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_OK && report.failed_checks == 0u,
                "no enabled checks returns OK");
#endif
}

static void test_status_names(void) {
    ASSERT_TRUE(strcmp(reshield_status_name(RESHIELD_ERR_MANIFEST_MISMATCH), "MANIFEST_MISMATCH") == 0 &&
                strcmp(reshield_status_name(RESHIELD_ERR_ASSET_TAMPERED), "ASSET_TAMPERED") == 0 &&
                strcmp(reshield_status_name(RESHIELD_ERR_INTERNAL), "INTERNAL_ERROR") == 0 &&
                strcmp(reshield_status_name((reshield_status_t)99), "UNKNOWN") == 0,
                "reshield_status_name() names manifest/asset/internal/unknown statuses");
}

static void test_secure_zero(void) {
    uint8_t buf[16];
    memset(buf, 0xAB, sizeof(buf));
    reshield_secure_zero(buf, sizeof(buf));
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0u) {
            all_zero = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zero == 1, "reshield_secure_zero() wipes buffer to zero");
}

int main(void) {
    ASSERT_TRUE(strlen(reshield_platform_name()) > 0, "platform name is non-empty");
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_is_enabled() == 0, "reshield_is_enabled() == 0 when disabled");
#else
    ASSERT_TRUE(reshield_is_enabled() == 1, "reshield_is_enabled() == 1 when enabled");
#endif

    test_verify_unsealed_and_callback();
    test_null_config_and_report();
    test_manifest_flag_with_unsealed_binary();
    test_status_names();
    test_secure_zero();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All runtime unit tests passed.\n");
    return 0;
}
