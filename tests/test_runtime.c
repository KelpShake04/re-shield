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

static void test_default_config(void) {
    reshield_runtime_config_t cfg = reshield_default_config();
    ASSERT_TRUE(cfg.action == RESHIELD_ACTION_TERMINATE, "default action is TERMINATE");
    ASSERT_TRUE(cfg.check_debugger == 1 && cfg.deny_attach == 1 && cfg.check_integrity == 1,
                "default config enables debugger, deny_attach, and integrity checks");
    ASSERT_TRUE(cfg.allow_unsealed == 0, "default config rejects unsealed binaries");
}

static void test_init_and_periodic_unsealed(void) {
    reshield_runtime_config_t cfg = {
        .action = RESHIELD_ACTION_REPORT,
        .check_debugger = 1,
        .deny_attach = 0,
        .check_integrity = 1,
        .allow_unsealed = 0,
        .callback = NULL,
        .user_data = NULL
    };

    uint32_t threats = reshield_init(&cfg);
#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(threats == RESHIELD_THREAT_NONE, "disabled reshield_init() returns NONE");
#else
    ASSERT_TRUE((threats & RESHIELD_THREAT_UNSEALED) != 0 &&
                (threats & RESHIELD_THREAT_DEBUGGER) == 0,
                "unsealed reshield_init() flags UNSEALED without false debugger flag");
#endif

    cfg.allow_unsealed = 1;
    reshield_timer_t timer;
    reshield_timer_start(&timer);
    threats = reshield_periodic_check(&cfg, &timer, 500);
    ASSERT_TRUE(threats == RESHIELD_THREAT_NONE,
                "reshield_periodic_check(allow_unsealed=1) returns NONE when clean");
}

static void test_xor_and_secure_zero(void) {
    const char *plain = "re-shield-secret";
    const size_t len = strlen(plain);
    uint8_t obf[32];
    uint8_t dec[32];

    reshield_xor_transform(obf, (const uint8_t *)plain, len, 0x5Au);
    ASSERT_TRUE(memcmp(obf, plain, len) != 0, "XOR transform hides plaintext bytes");

    reshield_xor_transform(dec, obf, len, 0x5Au);
    ASSERT_TRUE(memcmp(dec, plain, len) == 0, "XOR transform round-trips cleanly");

    reshield_secure_zero(dec, len);
    int all_zero = 1;
    for (size_t i = 0; i < len; i++) {
        if (dec[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zero == 1, "reshield_secure_zero() wipes buffer to zero");
}

int main(void) {
    test_default_config();
    test_init_and_periodic_unsealed();
    test_xor_and_secure_zero();

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All unified runtime tests passed.\n");
    return 0;
}
