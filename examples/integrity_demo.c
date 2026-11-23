#include "reshield/debug_policy.h"
#include "reshield/integrity.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Uncalled sentinel function placed in __TEXT,__text / .text so automated
 * tamper tests can flip a byte in executable code without crashing startup.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline, used))
#endif
uint32_t reshield_tamper_target(uint32_t x) {
    volatile uint32_t acc = x ^ 0x5A5A1234u;
    acc = (acc << 5) | (acc >> 27);
    return acc + 0x13572468u;
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

static const char *status_name(reshield_integrity_status_t st) {
    switch (st) {
        case RESHIELD_INTEGRITY_OK:       return "OK";
        case RESHIELD_INTEGRITY_UNSEALED: return "UNSEALED";
        case RESHIELD_INTEGRITY_TAMPERED: return "TAMPERED";
        case RESHIELD_INTEGRITY_ERROR:    return "ERROR";
        default:                          return "UNKNOWN";
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--mode=verify|guard-quiet]\n"
            "\n"
            "Modes:\n"
            "  verify       Hash in-memory code section and print detailed comparison.\n"
            "  guard-quiet  Run reshield_integrity_guard(TERMINATE): exits 1 silently on mismatch.\n",
            prog);
}

int main(int argc, char **argv) {
    const char *mode = "verify";

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            mode = argv[i] + 7;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (strcmp(mode, "guard-quiet") == 0) {
        reshield_integrity_config_t cfg = {
            .policy = RESHIELD_INTEGRITY_POLICY_TERMINATE,
            .allow_unsealed = 0,
            .callback = NULL,
            .user_data = NULL
        };
        (void)reshield_integrity_guard(&cfg);
        printf("ok (pid=%d, platform=%s, enabled=%d)\n",
               (int)getpid(), reshield_platform_name(), reshield_is_enabled());
        return 0;
    }

    if (strcmp(mode, "verify") == 0) {
        reshield_integrity_result_t res;
        reshield_integrity_status_t st = reshield_verify_code_section(&res);

        printf("[re-shield integrity] pid=%d platform=%s enabled=%d status=%s\n",
               (int)getpid(), reshield_platform_name(), reshield_is_enabled(), status_name(st));
        printf("size: actual=%" PRIu64 " expected=%" PRIu64 "\n",
               res.actual_size, res.expected_size);
        printf("actual_sha256:   ");
        print_hex(res.actual_sha256, RESHIELD_SHA256_SIZE);
        printf("\nexpected_sha256: ");
        print_hex(res.expected_sha256, RESHIELD_SHA256_SIZE);
        printf("\n");

        switch (st) {
            case RESHIELD_INTEGRITY_OK:       return 0;
            case RESHIELD_INTEGRITY_UNSEALED: return 10;
            case RESHIELD_INTEGRITY_TAMPERED: return 11;
            default:                          return 12;
        }
    }

    fprintf(stderr, "Unknown mode: %s\n", mode);
    print_usage(argv[0]);
    return 2;
}
