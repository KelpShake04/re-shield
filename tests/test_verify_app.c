/* Helper for tests/test_seal_workflow.py: reshield_verify_app() from a copy of this binary that
 * sits next to its manifest and assets. Usage: test_verify_app <manifest_rel> [assets_rel].
 * Prints the status name; exit code = 10 + status (like examples/sample_game.c). */
#include "reshield/reshield.h"

#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <manifest_rel> [assets_rel]\n", argv[0]);
        return 2;
    }
    reshield_report_t report;
    reshield_status_t st = reshield_verify_app(argv[1], argc > 2 ? argv[2] : NULL, NULL, NULL, &report);
    printf("status=%s failed_checks=0x%x asset=%s\n", reshield_status_name(st),
           (unsigned)report.failed_checks, report.failed_asset_path);
    return 10 + (int)st;
}
