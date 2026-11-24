#ifndef RESHIELD_FUZZ_COMMON_H
#define RESHIELD_FUZZ_COMMON_H

/* Shared scratch-dir helpers for the libFuzzer harnesses (POSIX only). The scratch dir lives
 * in /dev/shm when available so per-input file writes stay off the disk. */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1 /* mkdtemp */
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_fz_dir[128];
static char g_fz_assets[160];
static char g_fz_manifest[160];

static void fz_write(const char *path, const void *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("fuzz: open");
        abort();
    }
    const unsigned char *p = (const unsigned char *)data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) {
            perror("fuzz: write");
            abort();
        }
        p += n;
        len -= (size_t)n;
    }
    close(fd);
}

/* Creates <tmp>/reshield-fuzz-XXXXXX/{assets/,manifest}; assets/ holds a.cfg (empty) and
 * sub/b.cfg ("hello\n") so seeds can reach the asset-hashing code, plus extra.bin ("x") that a
 * strict manifest must list or #allow. */
static void fz_setup(void) {
    const char *base = access("/dev/shm", W_OK) == 0 ? "/dev/shm" : "/tmp";
    snprintf(g_fz_dir, sizeof(g_fz_dir), "%s/reshield-fuzz-XXXXXX", base);
    if (mkdtemp(g_fz_dir) == NULL) {
        perror("fuzz: mkdtemp");
        abort();
    }
    snprintf(g_fz_assets, sizeof(g_fz_assets), "%s/assets", g_fz_dir);
    snprintf(g_fz_manifest, sizeof(g_fz_manifest), "%s/manifest", g_fz_dir);
    char p[200];
    if (mkdir(g_fz_assets, 0700) != 0) {
        perror("fuzz: mkdir");
        abort();
    }
    snprintf(p, sizeof(p), "%s/a.cfg", g_fz_assets);
    fz_write(p, "", 0);
    snprintf(p, sizeof(p), "%s/sub", g_fz_assets);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/sub/b.cfg", g_fz_assets);
    fz_write(p, "hello\n", 6);
    snprintf(p, sizeof(p), "%s/extra.bin", g_fz_assets); /* unlisted: reaches the strict-scan paths */
    fz_write(p, "x", 1);
}

#endif
