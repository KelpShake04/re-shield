/* Helper for tests/test_seal_workflow.py: reshield_verify_app() from a copy of this binary that
 * sits next to its manifest and assets. Usage: test_verify_app <manifest_rel> [assets_rel].
 * Prints the status name; exit code = 10 + status (like examples/sample_game.c). */
#include "reshield/reshield.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <manifest_rel> [assets_rel]\n", argv[0]);
        return 2;
    }
    reshield_report_t report;
    reshield_status_t st = reshield_verify_app(argv[1], argc > 2 ? argv[2] : NULL, NULL, NULL, &report);
    printf("status=%s failed_checks=0x%x asset=%s\n", reshield_status_name(st),
           (unsigned)report.failed_checks, report.failed_asset_path);

    /* reshield_check_json() = reshield_verify_app() + reshield_report_to_json(): same status, same
     * bytes; cap 8 truncates safely (NUL at the end, a prefix of the full text); NULL json is allowed. */
    const char *assets = argc > 2 ? argv[2] : NULL;
    char want[1024], full[1024], cut[8];
    size_t want_len = reshield_report_to_json(&report, want, sizeof(want));
    memset(cut, 'X', sizeof(cut));
    int st_full = reshield_check_json(argv[1], assets, full, sizeof(full));
    int st_cut = reshield_check_json(argv[1], assets, cut, sizeof(cut));
    int st_none = reshield_check_json(argv[1], assets, NULL, 0);
    int same = want_len > 0 && want_len < sizeof(want) && st_full == (int)st && st_cut == (int)st &&
               st_none == (int)st && strcmp(full, want) == 0 && cut[sizeof(cut) - 1] == '\0' &&
               strncmp(cut, want, sizeof(cut) - 1) == 0 && strlen(cut) == sizeof(cut) - 1;
    printf("check_json=%s\n", same ? "same" : "DIFFERENT");
    if (!same) {
        return 99;
    }

    /* Boundaries: cap 0 leaves the buffer untouched, cap 1 writes only the NUL, and a NULL json
     * with a non-zero cap is safe. The status is unaffected in every case. */
    char z[4], one[4];
    memset(z, 'X', sizeof(z));
    memset(one, 'X', sizeof(one));
    int st_c0 = reshield_check_json(argv[1], assets, z, 0);
    int st_c1 = reshield_check_json(argv[1], assets, one, 1);
    int st_np = reshield_check_json(argv[1], assets, NULL, 64);
    int bounds = st_c0 == (int)st && st_c1 == (int)st && st_np == (int)st &&
                 memcmp(z, "XXXX", sizeof(z)) == 0 && memcmp(one, "\0XXX", sizeof(one)) == 0;
    printf("check_json_bounds=%s\n", bounds ? "ok" : "BAD");
    if (!bounds) {
        return 98;
    }
    return 10 + (int)st;
}
