/* Built WITHOUT -DRESHIELD_ALLOW_UNSEALED (a release-style library): cfg.allow_unsealed must not
 * bypass anything and must not be silently ignored either. */
#include "reshield/reshield.h"

#include <stdio.h>

#ifdef RESHIELD_ALLOW_UNSEALED
#error "this test must be compiled without RESHIELD_ALLOW_UNSEALED"
#endif

int main(void) {
#ifdef RESHIELD_DISABLE
    return 0;
#else
    int failures = 0;
    reshield_report_t report;
    reshield_config_t cfg = reshield_default_config();

    /* This test binary is never sealed, so strict mode reports UNSEALED. */
    if (reshield_verify(&cfg, &report) != RESHIELD_ERR_UNSEALED) {
        fprintf(stderr, "FAIL: strict config on an unsealed binary must report UNSEALED\n");
        failures++;
    }

    cfg.allow_unsealed = 1;
    if (reshield_verify(&cfg, &report) != RESHIELD_ERR_INTERNAL) {
        fprintf(stderr, "FAIL: allow_unsealed without RESHIELD_ALLOW_UNSEALED must be INTERNAL_ERROR\n");
        failures++;
    }
    if (reshield_verify(&cfg, NULL) == RESHIELD_OK) {
        fprintf(stderr, "FAIL: allow_unsealed must not turn an unsealed binary into OK\n");
        failures++;
    }

    if (failures == 0) {
        printf("PASS: allow_unsealed is a configuration error in a build without RESHIELD_ALLOW_UNSEALED\n");
    }
    return failures == 0 ? 0 : 1;
#endif
}
