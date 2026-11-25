/* Many threads make their FIRST SHA-256 call at the same moment (backend selection in
 * sha256_accel.c runs lazily on the first call). Meant for `make tsan-test` (ThreadSanitizer):
 * a plain run only checks that every thread gets the right digest. POSIX threads only. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "reshield/integrity.h"

#define NTHREADS 8

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_go = PTHREAD_COND_INITIALIZER;
static int g_started;
static int g_bad;

/* SHA-256 of 128 x 'a' (two whole blocks, so the block function and its backend are used). */
static const uint8_t k_expect[32] = {
    0x68, 0x36, 0xcf, 0x13, 0xba, 0xc4, 0x00, 0xe9, 0x10, 0x50, 0x71, 0xcd, 0x6a, 0xf4, 0x70, 0x84,
    0xdf, 0xac, 0xad, 0x4e, 0x5e, 0x30, 0x2c, 0x94, 0xbf, 0xed, 0x24, 0xe0, 0x13, 0xaf, 0xb7, 0x3e};
static uint8_t g_input[128];

static void *worker(void *arg) {
    uint8_t h[32];
    (void)arg;
    pthread_mutex_lock(&g_mu);
    while (!g_started) {
        pthread_cond_wait(&g_go, &g_mu);
    }
    pthread_mutex_unlock(&g_mu);
    reshield_sha256(g_input, sizeof g_input, h);
    if (memcmp(h, k_expect, sizeof h) != 0) {
        pthread_mutex_lock(&g_mu);
        g_bad++;
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}

int main(void) {
    pthread_t t[NTHREADS];
    memset(g_input, 'a', sizeof g_input);
    for (int i = 0; i < NTHREADS; i++) {
        if (pthread_create(&t[i], NULL, worker, NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_create\n");
            return 1;
        }
    }
    pthread_mutex_lock(&g_mu);
    g_started = 1;
    pthread_cond_broadcast(&g_go);
    pthread_mutex_unlock(&g_mu);
    for (int i = 0; i < NTHREADS; i++) {
        pthread_join(t[i], NULL);
    }
    if (g_bad != 0) {
        fprintf(stderr, "FAIL: %d thread(s) got a wrong digest\n", g_bad);
        return 1;
    }
    printf("PASS: %d threads, first SHA-256 call concurrent, digests correct\n", NTHREADS);
    return 0;
}
