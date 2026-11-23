/* libFuzzer: asset path rule, observed through the public API only.
 *
 * The manifest is a fixed valid one (a.cfg), so reshield_verify_single_asset() returns
 * IO_ERROR for an unsafe asset_rel_path and ASSET_MISMATCH (or OK for "a.cfg") for a safe one.
 * The same decision is cross-checked through a manifest line carrying the path.
 * With FUZZ_PATH_VERBOSE=1 each input prints "PATHDECISION <0|1>" to stderr, which
 * tests/fuzz/diff_path_rules.py compares against tools/manifest_path.py. */
#include "fuzz_common.h"

#include "reshield/manifest.h"

static uint8_t g_root[RESHIELD_SHA256_SIZE];
static int g_verbose;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fz_setup();
    static const char manifest[] =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 a.cfg\n";
    fz_write(g_fz_manifest, manifest, sizeof(manifest) - 1);
    reshield_sha256(manifest, sizeof(manifest) - 1, g_root);
    g_verbose = getenv("FUZZ_PATH_VERBOSE") != NULL;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char path[2048];
    if (size >= sizeof(path)) {
        size = sizeof(path) - 1;
    }
    memcpy(path, data, size);
    path[size] = '\0'; /* embedded NUL truncates, exactly as for any C caller */

    reshield_manifest_status_t st =
        reshield_verify_single_asset(g_fz_manifest, g_fz_assets, path, g_root);
    if (st != RESHIELD_MANIFEST_IO_ERROR && st != RESHIELD_MANIFEST_ASSET_MISMATCH &&
        st != RESHIELD_MANIFEST_OK) {
        abort(); /* manifest and root are valid: only the path rule can fail the call early */
    }
    int safe = st != RESHIELD_MANIFEST_IO_ERROR;
    if (g_verbose) {
        fprintf(stderr, "PATHDECISION %d\n", safe);
    }

    /* Same rule when the path is a manifest entry (line must be one short line). */
    size_t len = strlen(path);
    if (len > 0 && len < 900 && strchr(path, '\n') == NULL) {
        char line[1024];
        int n = snprintf(line, sizeof(line), "%064d 0 %s\n", 0, path);
        uint8_t root[RESHIELD_SHA256_SIZE];
        reshield_sha256(line, (size_t)n, root);
        fz_write(g_fz_manifest, line, (size_t)n);
        reshield_manifest_status_t st2 =
            reshield_verify_manifest_files(g_fz_manifest, g_fz_assets, root, NULL, 0);
        /* restore the fixed manifest for the next input */
        static const char manifest[] =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 a.cfg\n";
        fz_write(g_fz_manifest, manifest, sizeof(manifest) - 1);
        /* '\r' is also rejected by the whole-file check, so only the path rule can differ. */
        int safe2 = st2 == RESHIELD_MANIFEST_ASSET_MISMATCH; /* zero hash never matches */
        if (safe2 != safe && strchr(path, '\r') == NULL) {
            fprintf(stderr, "path rule disagrees: single=%d manifest=%d\n", safe, safe2);
            abort();
        }
    }
    return 0;
}
