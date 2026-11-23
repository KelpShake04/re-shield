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

static void test_codesign_requirement(void) {
    reshield_config_t cfg = reshield_default_config();
    cfg.enabled_checks = RESHIELD_CHECK_CODESIGN;
    reshield_report_t report;
#if defined(RESHIELD_DISABLE)
    (void)cfg;
    (void)report;
    ASSERT_TRUE(reshield_verify_os_codesign_req("anchor apple") != RESHIELD_ATTEST_FAILED,
                "disabled: codesign requirement is not enforced");
#elif defined(__APPLE__)
    /* The test binary is ad-hoc signed by the linker: valid, but not Apple-anchored. */
    ASSERT_TRUE(reshield_verify_os_codesign_req(NULL) == RESHIELD_ATTEST_OK,
                "codesign: NULL requirement checks validity only");
    ASSERT_TRUE(reshield_verify_os_codesign_req("!anchor apple") == RESHIELD_ATTEST_OK,
                "codesign: satisfied requirement passes");
    ASSERT_TRUE(reshield_verify_os_codesign_req("anchor apple") == RESHIELD_ATTEST_FAILED,
                "codesign: unsatisfied requirement (anchor apple) fails");
    ASSERT_TRUE(reshield_verify_os_codesign_req("identifier \"no.such.identifier\"") == RESHIELD_ATTEST_FAILED,
                "codesign: wrong identifier fails");
    ASSERT_TRUE(reshield_verify_os_codesign_req("this is ((( not a requirement") == RESHIELD_ATTEST_FAILED,
                "codesign: unparsable requirement fails closed");
    cfg.codesign_requirement = "anchor apple";
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_ERR_CODESIGN_INVALID &&
                report.failed_checks == RESHIELD_CHECK_CODESIGN,
                "reshield_verify() passes cfg.codesign_requirement through");
#elif defined(_WIN32)
    /* This test EXE is unsigned (no Authenticode), so even NULL fails; a requirement fails
     * closed regardless because Windows has no signer pin. A signed EXE is not covered here. */
    ASSERT_TRUE(reshield_verify_os_codesign_req(NULL) == RESHIELD_ATTEST_FAILED,
                "codesign: unsigned EXE fails WinVerifyTrust");
    ASSERT_TRUE(reshield_verify_os_codesign_req("anchor apple") == RESHIELD_ATTEST_FAILED,
                "codesign: a requirement fails closed on Windows (no signer pin)");
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_ERR_CODESIGN_INVALID &&
                report.failed_checks == RESHIELD_CHECK_CODESIGN,
                "reshield_verify() reports CODESIGN_INVALID for an unsigned EXE");
#else
    ASSERT_TRUE(reshield_verify_os_codesign_req("anchor apple") == RESHIELD_ATTEST_UNSUPPORTED,
                "codesign requirement is UNSUPPORTED off macOS");
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_OK,
                "off macOS: CODESIGN check without a requirement is skipped as UNSUPPORTED");
    cfg.codesign_requirement = "anchor apple";
    ASSERT_TRUE(reshield_verify(&cfg, &report) == RESHIELD_ERR_CODESIGN_INVALID &&
                report.failed_checks == RESHIELD_CHECK_CODESIGN,
                "off macOS: a requirement that cannot be enforced fails closed");
#endif
}

#define ZEROS64 "0000000000000000000000000000000000000000000000000000000000000000"

static void test_report_json(void) {
    reshield_report_t r;
    memset(&r, 0, sizeof(r));
    r.status = RESHIELD_ERR_ASSET_TAMPERED;
    r.failed_checks = RESHIELD_CHECK_MANIFEST;
    r.build_id = 7u;
    r.code_result.expected_size = 100u;
    strcpy(r.failed_asset_path, "a\"b\\c\n\xc3");

    const char *want =
        "{\"v\":1,\"status\":\"ASSET_TAMPERED\",\"status_code\":6,\"failed_checks\":8,"
        "\"build_id\":7,\"failed_asset_path\":\"a\\\"b\\\\c\\u000a\\u00c3\","
        "\"code\":{\"expected_size\":100,\"actual_size\":0,"
        "\"expected_sha256\":\"" ZEROS64 "\",\"actual_sha256\":\"" ZEROS64 "\"}}";

    char buf[1024];
    size_t n = reshield_report_to_json(&r, buf, sizeof(buf));
    ASSERT_TRUE(n == strlen(want) && strcmp(buf, want) == 0,
                "report_to_json: exact output, path escaped (quote, backslash, control, non-ASCII)");
    ASSERT_TRUE(reshield_report_to_json(&r, NULL, 0) == n,
                "report_to_json: NULL buf sizes the output");

    char small[10];
    memset(small, 'X', sizeof(small));
    n = reshield_report_to_json(&r, small, sizeof(small));
    ASSERT_TRUE(n == strlen(want) && strlen(small) == sizeof(small) - 1u &&
                strncmp(small, want, sizeof(small) - 1u) == 0,
                "report_to_json: truncates safely, NUL-terminated, returns full length");

    char untouched[4] = { 'X', 'X', 'X', 'X' };
    n = reshield_report_to_json(&r, untouched, 0);
    ASSERT_TRUE(n == strlen(want) && untouched[0] == 'X', "report_to_json: cap 0 writes nothing");

    ASSERT_TRUE(reshield_report_to_json(NULL, buf, sizeof(buf)) == 0u, "report_to_json: NULL report returns 0");

    r.code_result.expected_size = UINT64_MAX;
    reshield_report_to_json(&r, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"expected_size\":18446744073709551615,") != NULL,
                "report_to_json: uint64 max formats correctly");

    memset(r.failed_asset_path, 'a', sizeof(r.failed_asset_path));
    n = reshield_report_to_json(&r, buf, sizeof(buf));
    ASSERT_TRUE(n < sizeof(buf), "report_to_json: unterminated asset path is bounded");
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
    test_codesign_requirement();
    test_report_json();
    test_status_names();
    test_secure_zero();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All runtime unit tests passed.\n");
    return 0;
}
