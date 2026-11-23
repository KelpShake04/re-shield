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
    test_secure_zero();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All runtime unit tests passed.\n");
    return 0;
}
