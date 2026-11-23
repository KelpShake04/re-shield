#include "reshield/manifest.h"

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

static void hash_to_hex(const uint8_t hash[RESHIELD_SHA256_SIZE], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        out[i * 2 + 0] = hex[(hash[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = hex[hash[i] & 0x0fu];
    }
    out[64] = '\0';
}

int main(void) {
    const char *asset_path = "build/test_asset_tmp.txt";
    const char *manifest_path = "build/test_manifest_tmp.txt";
    const char *payload = "level=1\nscore_cap=9999\n";

    FILE *af = fopen(asset_path, "wb");
    ASSERT_TRUE(af != NULL, "create temp asset file");
    fwrite(payload, 1, strlen(payload), af);
    fclose(af);

    uint8_t asset_hash[RESHIELD_SHA256_SIZE];
    uint64_t asset_size = 0;
    ASSERT_TRUE(reshield_sha256_file(asset_path, asset_hash, &asset_size) == 0 &&
                asset_size == strlen(payload),
                "reshield_sha256_file() hashes asset and reports exact size");

    char asset_hex[65];
    hash_to_hex(asset_hash, asset_hex);

    FILE *mf = fopen(manifest_path, "wb");
    ASSERT_TRUE(mf != NULL, "create temp manifest file");
    fprintf(mf, "%s %llu test_asset_tmp.txt\n", asset_hex, (unsigned long long)asset_size);
    fclose(mf);

    uint8_t root_hash[RESHIELD_SHA256_SIZE];
    ASSERT_TRUE(reshield_sha256_file(manifest_path, root_hash, NULL) == 0,
                "compute manifest root SHA-256");

    char failed_path[128] = { 0 };
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               failed_path, sizeof(failed_path)) == RESHIELD_MANIFEST_OK,
                "valid manifest and asset pass verification");

    ASSERT_TRUE(reshield_verify_single_asset(manifest_path, "build",
                                             "test_asset_tmp.txt", root_hash) == RESHIELD_MANIFEST_OK,
                "single-asset verification passes for valid asset");

    /* Modify asset by 1 byte */
    af = fopen(asset_path, "wb");
    fputs("level=2\nscore_cap=9999\n", af);
    fclose(af);

#ifdef RESHIELD_DISABLE
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               failed_path, sizeof(failed_path)) == RESHIELD_MANIFEST_OK,
                "disabled build skips asset mismatch");
#else
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               failed_path, sizeof(failed_path)) == RESHIELD_MANIFEST_ASSET_MISMATCH,
                "modified asset triggers RESHIELD_MANIFEST_ASSET_MISMATCH");
    ASSERT_TRUE(strcmp(failed_path, "test_asset_tmp.txt") == 0,
                "failed_path reports exact modified asset relative path");

    /* Wrong root hash */
    root_hash[0] ^= 0xffu;
    ASSERT_TRUE(reshield_verify_manifest_files(manifest_path, "build", root_hash,
                                               NULL, 0) == RESHIELD_MANIFEST_ROOT_MISMATCH,
                "wrong manifest root triggers RESHIELD_MANIFEST_ROOT_MISMATCH");
#endif

    remove(asset_path);
    remove(manifest_path);

    if (g_failures > 0) {
        fprintf(stderr, "%d test(s) failed.\n", g_failures);
        return 1;
    }
    printf("All manifest unit tests passed.\n");
    return 0;
}
