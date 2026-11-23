#include "reshield/manifest.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RESHIELD_DISABLE
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_sha256_hex(const char *hex, uint8_t out[RESHIELD_SHA256_SIZE]) {
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        int hi = hex_nibble(hex[i * 2 + 0]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int is_safe_relative_path(const char *rel) {
    if (rel == NULL || rel[0] == '\0' || rel[0] == '/') {
        return 0;
    }
    if (strstr(rel, "..") != NULL) {
        return 0;
    }
    return 1;
}

static void copy_failed_path(char *dst, size_t cap, const char *src) {
    if (dst == NULL || cap == 0 || src == NULL) {
        return;
    }
    size_t len = strlen(src);
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int parse_manifest_line(const char *line,
                               uint8_t out_hash[RESHIELD_SHA256_SIZE],
                               uint64_t *out_size,
                               const char **out_rel_path) {
    /* Format: <64-hex-sha256> <byte-size> <relative-path> */
    if (strlen(line) < 68) {
        return -1;
    }
    if (parse_sha256_hex(line, out_hash) != 0) {
        return -1;
    }
    if (line[64] != ' ') {
        return -1;
    }
    const char *p = line + 65;
    if (!isdigit((unsigned char)*p)) {
        return -1;
    }
    char *endptr = NULL;
    unsigned long long sz = strtoull(p, &endptr, 10);
    if (endptr == p || *endptr != ' ') {
        return -1;
    }
    const char *rel = endptr + 1;
    if (!is_safe_relative_path(rel)) {
        return -1;
    }
    *out_size = (uint64_t)sz;
    *out_rel_path = rel;
    return 0;
}

static reshield_manifest_status_t verify_manifest_root(
    const char *manifest_path,
    const uint8_t *expected_root_sha256) {
    uint8_t root_expected[RESHIELD_SHA256_SIZE];
    if (expected_root_sha256 != NULL) {
        memcpy(root_expected, expected_root_sha256, RESHIELD_SHA256_SIZE);
    } else if (reshield_get_sealed_manifest_root(root_expected) != 0) {
        return RESHIELD_MANIFEST_UNSEALED;
    }

    uint8_t root_actual[RESHIELD_SHA256_SIZE];
    if (reshield_sha256_file(manifest_path, root_actual, NULL) != 0) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    if (!reshield_digest_equal(root_actual, root_expected)) {
        return RESHIELD_MANIFEST_ROOT_MISMATCH;
    }
    return RESHIELD_MANIFEST_OK;
}

static int verify_one_asset_entry(const char *asset_base_dir,
                                  const char *rel_path,
                                  uint64_t expected_size,
                                  const uint8_t expected_hash[RESHIELD_SHA256_SIZE]) {
    char full_path[1024];
    int n = 0;
    if (asset_base_dir != NULL && asset_base_dir[0] != '\0') {
        n = snprintf(full_path, sizeof(full_path), "%s/%s", asset_base_dir, rel_path);
    } else {
        n = snprintf(full_path, sizeof(full_path), "%s", rel_path);
    }
    if (n <= 0 || (size_t)n >= sizeof(full_path)) {
        return 0;
    }

    uint8_t actual_hash[RESHIELD_SHA256_SIZE];
    uint64_t actual_size = 0;
    if (reshield_sha256_file(full_path, actual_hash, &actual_size) != 0) {
        return 0;
    }
    if (actual_size != expected_size) {
        return 0;
    }
    return reshield_digest_equal(actual_hash, expected_hash);
}
#endif

reshield_manifest_status_t reshield_verify_manifest_files(
    const char *manifest_path,
    const char *asset_base_dir,
    const uint8_t *expected_root_sha256,
    char *failed_path_buf,
    size_t failed_path_cap) {
#ifdef RESHIELD_DISABLE
    (void)manifest_path;
    (void)asset_base_dir;
    (void)expected_root_sha256;
    (void)failed_path_buf;
    (void)failed_path_cap;
    return RESHIELD_MANIFEST_OK;
#else
    if (manifest_path == NULL) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    reshield_manifest_status_t root_st = verify_manifest_root(manifest_path, expected_root_sha256);
    if (root_st != RESHIELD_MANIFEST_OK) {
        return root_st;
    }

    FILE *fp = fopen(manifest_path, "r");
    if (fp == NULL) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    char line[1024];
    int entries = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#') {
            continue;
        }

        uint8_t exp_hash[RESHIELD_SHA256_SIZE];
        uint64_t exp_size = 0;
        const char *rel_path = NULL;
        if (parse_manifest_line(line, exp_hash, &exp_size, &rel_path) != 0) {
            fclose(fp);
            return RESHIELD_MANIFEST_IO_ERROR;
        }
        entries++;

        if (!verify_one_asset_entry(asset_base_dir, rel_path, exp_size, exp_hash)) {
            copy_failed_path(failed_path_buf, failed_path_cap, rel_path);
            fclose(fp);
            return RESHIELD_MANIFEST_ASSET_MISMATCH;
        }
    }

    fclose(fp);
    return entries > 0 ? RESHIELD_MANIFEST_OK : RESHIELD_MANIFEST_IO_ERROR;
#endif
}

reshield_manifest_status_t reshield_verify_single_asset(
    const char *manifest_path,
    const char *asset_base_dir,
    const char *asset_rel_path,
    const uint8_t *expected_root_sha256) {
#ifdef RESHIELD_DISABLE
    (void)manifest_path;
    (void)asset_base_dir;
    (void)asset_rel_path;
    (void)expected_root_sha256;
    return RESHIELD_MANIFEST_OK;
#else
    if (manifest_path == NULL || !is_safe_relative_path(asset_rel_path)) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    reshield_manifest_status_t root_st = verify_manifest_root(manifest_path, expected_root_sha256);
    if (root_st != RESHIELD_MANIFEST_OK) {
        return root_st;
    }

    FILE *fp = fopen(manifest_path, "r");
    if (fp == NULL) {
        return RESHIELD_MANIFEST_IO_ERROR;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#') {
            continue;
        }

        uint8_t exp_hash[RESHIELD_SHA256_SIZE];
        uint64_t exp_size = 0;
        const char *rel_path = NULL;
        if (parse_manifest_line(line, exp_hash, &exp_size, &rel_path) != 0) {
            fclose(fp);
            return RESHIELD_MANIFEST_IO_ERROR;
        }

        if (strcmp(rel_path, asset_rel_path) == 0) {
            int ok = verify_one_asset_entry(asset_base_dir, rel_path, exp_size, exp_hash);
            fclose(fp);
            return ok ? RESHIELD_MANIFEST_OK : RESHIELD_MANIFEST_ASSET_MISMATCH;
        }
    }

    fclose(fp);
    return RESHIELD_MANIFEST_ASSET_MISMATCH;
#endif
}
