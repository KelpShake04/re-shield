#!/usr/bin/env python3
"""
Module-mode test: re-shield linked into a shared library verifies the LIBRARY, not the host.

tests/test_module_host.c links no re-shield code and is never sealed. It dlopen()s the library
and calls reshield_verify_code_section() in it. For a development and a release (ALLOW_UNSEALED=0)
build of the library this checks:

1. unsealed library          -> UNSEALED (exit 1)
2. library sealed by tools/seal_binary.py -> OK (exit 0), W^X check OK, sizes match
3. one byte of the library's .text changed -> TAMPERED (exit 2)
4. (Linux) library opened by a relative path -> ERROR (exit 3, fails closed)

Run through `make test` (module-test target). POSIX only: Windows is exercised by the
windows-msvc CI job.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import seal_binary  # noqa: E402
import test_seal_workflow as wf  # noqa: E402

OK, UNSEALED, TAMPERED, ERROR = 0, 1, 2, 3
# Present in every build and never called on the verification path: safe to patch.
UNCALLED_SYMBOL = "reshield_verify_buffer"


def run_host(host: str, lib: str, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([host, lib], capture_output=True, text=True, cwd=cwd)


def expect(r: subprocess.CompletedProcess[str], rc: int, status: str, what: str) -> str:
    assert r.returncode == rc and f"status={status}" in r.stdout, f"{what}: {r}"
    print(f"PASS: {what}")
    return r.stdout


def test_library(host: str, lib: str, label: str, tmpdir: str) -> None:
    ext = os.path.splitext(lib)[1]
    plain = os.path.join(tmpdir, f"{label}_plain{ext}")
    shutil.copy2(lib, plain)

    expect(run_host(host, plain), UNSEALED, "UNSEALED", f"{label}: unsealed library is UNSEALED")

    sealed = os.path.join(tmpdir, f"{label}_sealed{ext}")
    shutil.copy2(lib, sealed)
    subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "seal_binary.py"), sealed,
                    "--build-id", "11"], check=True, stdout=subprocess.DEVNULL)
    out = expect(run_host(host, sealed), OK, "OK", f"{label}: sealed library verifies OK")
    assert "wx=0" in out, f"{label}: W^X check did not pass for the library: {out}"
    m = re.search(r"actual_size=(\d+) expected_size=(\d+)", out)
    assert m and m.group(1) == m.group(2) and int(m.group(1)) > 0, f"{label}: sizes: {out}"
    print(f"PASS: {label}: W^X check follows the library and sizes match ({m.group(1)} bytes)")

    with open(sealed, "rb") as f:
        data = f.read()
    off = wf.find_symbol_file_offset(sealed, data, UNCALLED_SYMBOL)
    tampered = os.path.join(tmpdir, f"{label}_tampered{ext}")
    wf.patch_file(sealed, tampered, off, data[off] ^ 0x01)
    expect(run_host(host, tampered), TAMPERED, "TAMPERED",
           f"{label}: one changed .text byte of the library is TAMPERED")

    if sys.platform.startswith("linux"):
        # dlpi_name is relative: the file cannot be trusted to be the mapped image, so fail closed
        r = run_host(host, "./" + os.path.basename(sealed), cwd=tmpdir)
        expect(r, ERROR, "ERROR", f"{label}: relative dlopen path fails closed (ERROR, not OK)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--lib", required=True, help="development shared library")
    ap.add_argument("--release-lib", help="release (ALLOW_UNSEALED=0) shared library")
    args = ap.parse_args()

    host = os.path.abspath(args.host)
    with open(host, "rb") as f:
        assert seal_binary.MAGIC not in f.read(), "host must not contain an integrity record"
    print("PASS: test host contains no integrity record (it is never sealed)")

    with tempfile.TemporaryDirectory(prefix="reshield_module_") as tmpdir:
        test_library(host, os.path.abspath(args.lib), "dev", tmpdir)
        if args.release_lib:
            test_library(host, os.path.abspath(args.release_lib), "release", tmpdir)
    print("ALL PASS: module mode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
