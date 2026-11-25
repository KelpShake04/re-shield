/* SHA-256 throughput: active backend vs portable C. `make bench`; not part of `make test`.
 * Usage: bench_sha256 [MiB per pass (default 256)] */
#include "reshield/integrity.h"
#include "../src/sha256_accel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Best of 3 passes, MB/s (1 MB = 1e6 bytes). */
static double measure(const uint8_t *buf, size_t len) {
    double best = 0.0;
    uint8_t d[RESHIELD_SHA256_SIZE];
    for (int pass = 0; pass < 3; pass++) {
        double t = now();
        reshield_sha256(buf, len, d);
        t = now() - t;
        double mbs = (double)len / 1e6 / t;
        if (mbs > best) {
            best = mbs;
        }
    }
    printf("  digest %02x%02x%02x%02x...\n", d[0], d[1], d[2], d[3]);
    return best;
}

int main(int argc, char **argv) {
    size_t mib = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 256;
    if (mib == 0) {
        mib = 256;
    }
    size_t len = mib * 1024 * 1024;
    uint8_t *buf = malloc(len);
    if (buf == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((uint32_t)i * 2654435761u >> 24);
    }

    static const char *const names[] = { "portable", "armv8", "shani" };
    int b = reshield_sha256_backend();
    const char *name = names[b >= 0 && b <= 2 ? b : 0];
    printf("input: %zu MiB, best of 3\n", mib);
    printf("sha256 backend: %s\n", name);
    double hw = measure(buf, len);
    printf("  %s: %.0f MB/s\n", name, hw);

    reshield_sha256_force_portable(1);
    printf("sha256 backend: portable (forced)\n");
    double sw = measure(buf, len);
    printf("  portable: %.0f MB/s\n", sw);
    if (b != 0) {
        printf("speedup: %.1fx\n", hw / sw);
    }
    free(buf);
    return 0;
}
