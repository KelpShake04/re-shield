#include "reshield/reshield.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Sample native mini-game stage validator used to compare reversing friction
 * BEFORE (-DRESHIELD_UNPROTECTED) and AFTER (libreshield + strip + seal).
 */

#if defined(__GNUC__) || defined(__clang__)
#define SAMPLE_NOINLINE __attribute__((noinline))
#else
#define SAMPLE_NOINLINE
#endif

#ifdef RESHIELD_UNPROTECTED

static const char *PLAIN_STAGE_KEY = "SECRET_STAGE_KEY_2026";

static SAMPLE_NOINLINE int validate_stage_key(const char *input) {
    return strcmp(input, PLAIN_STAGE_KEY) == 0;
}

#else

/* "SECRET_STAGE_KEY_2026" XORed with 0x5A (21 bytes, no plaintext in binary) */
static const uint8_t OBF_STAGE_KEY[21] = {
    0x09, 0x1f, 0x19, 0x08, 0x1f, 0x0e, 0x05,
    0x09, 0x0e, 0x1b, 0x1d, 0x1f, 0x05, 0x11,
    0x1f, 0x03, 0x05, 0x68, 0x6a, 0x68, 0x6c
};

static SAMPLE_NOINLINE int validate_stage_key(const char *input) {
    char revealed[sizeof(OBF_STAGE_KEY) + 1];
    reshield_xor_transform((uint8_t *)revealed, OBF_STAGE_KEY, sizeof(OBF_STAGE_KEY), 0x5Au);
    revealed[sizeof(OBF_STAGE_KEY)] = '\0';

    int match = (strcmp(input, revealed) == 0);
    reshield_secure_zero(revealed, sizeof(revealed));
    return match;
}

#endif

static SAMPLE_NOINLINE uint32_t compute_reward_code(const char *key) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; key[i] != '\0'; i++) {
        h ^= (uint8_t)key[i];
        h *= 16777619u;
    }
    return h;
}

int main(int argc, char **argv) {
#ifndef RESHIELD_UNPROTECTED
    reshield_runtime_config_t cfg = reshield_default_config();
    (void)reshield_init(&cfg);
#endif

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <stage-key>\n", argv[0]);
        return 2;
    }

#ifndef RESHIELD_UNPROTECTED
    reshield_timer_t t;
    reshield_timer_start(&t);
#endif

    int ok = validate_stage_key(argv[1]);

#ifndef RESHIELD_UNPROTECTED
    (void)reshield_periodic_check(&cfg, &t, 500);
#endif

    if (ok) {
        printf("STAGE UNLOCKED (reward=0x%08x)\n", compute_reward_code(argv[1]));
        return 0;
    }

    printf("ACCESS DENIED\n");
    return 1;
}
