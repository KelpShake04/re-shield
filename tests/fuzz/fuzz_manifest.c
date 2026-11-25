/* libFuzzer: arbitrary bytes as a manifest file. The harness passes SHA-256(input) as the
 * expected root so parsing and asset verification are reached, not just the root check. */
#include "fuzz_common.h"

#include "reshield/manifest.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fz_setup();
    return 0;
}

static void check_status(reshield_manifest_status_t st) {
    if ((int)st < RESHIELD_MANIFEST_OK || (int)st > RESHIELD_MANIFEST_ASSET_EXTRA) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fz_write(g_fz_manifest, data, size);

    uint8_t root[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, size, root);

    char failed[48];
    memset(failed, 'X', sizeof(failed));
    reshield_manifest_status_t st =
        reshield_verify_manifest_files(g_fz_manifest, g_fz_assets, root, failed, sizeof(failed));
    check_status(st);
    if ((st == RESHIELD_MANIFEST_ASSET_MISMATCH || st == RESHIELD_MANIFEST_ASSET_EXTRA) && memchr(failed, '\0', sizeof(failed)) == NULL) {
        abort(); /* failed_path_buf must stay NUL-terminated */
    }
    check_status(reshield_verify_manifest_files(g_fz_manifest, g_fz_assets, root, NULL, 0));
    check_status(reshield_verify_manifest_files(g_fz_manifest, "", root, failed, 1));

    /* A wrong root must never pass. */
    uint8_t bad[RESHIELD_SHA256_SIZE];
    memcpy(bad, root, sizeof(bad));
    bad[0] ^= 1u;
    if (reshield_verify_manifest_files(g_fz_manifest, g_fz_assets, bad, NULL, 0) == RESHIELD_MANIFEST_OK) {
        abort();
    }

    /* Single-asset lookup of the first line's path (third field) and of fixed names. */
    char rel[1100];
    size_t n = size < sizeof(rel) - 1 ? size : sizeof(rel) - 1;
    memcpy(rel, data, n);
    rel[n] = '\0';
    char *nl = strchr(rel, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    const char *third = rel;
    for (int sp = 0; sp < 2 && third != NULL; sp++) {
        third = strchr(third, ' ');
        if (third != NULL) {
            third++;
        }
    }
    if (third != NULL) {
        check_status(reshield_verify_single_asset(g_fz_manifest, g_fz_assets, third, root));
    }
    check_status(reshield_verify_single_asset(g_fz_manifest, g_fz_assets, "a.cfg", root));
    check_status(reshield_verify_single_asset(g_fz_manifest, g_fz_assets, "sub/b.cfg", root));
    if (reshield_verify_single_asset(g_fz_manifest, g_fz_assets, "sub/b.cfg", bad) == RESHIELD_MANIFEST_OK) {
        abort();
    }
    return 0;
}
