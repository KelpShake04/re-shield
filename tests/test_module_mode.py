#!/usr/bin/env python3
"""
Module-mode test: re-shield linked into a shared library verifies the LIBRARY, not the host.

tests/test_module_host.c links no re-shield code and is never sealed. It dlopen()s the library
and calls reshield_verify_code_section() and the flat reshield_check_json() in it. For a development and a release (ALLOW_UNSEALED=0)
build of the library this checks:

1. unsealed library          -> UNSEALED (exit 1)
2. library sealed by tools/seal_binary.py -> OK (exit 0), W^X check OK, sizes match
3. one byte of the library's .text changed -> TAMPERED (exit 2)
4. (Linux) library opened by a relative path (also one with spaces) -> OK, a tampered one ->
   TAMPERED; if the file is deleted or replaced after loading -> ERROR (exit 3, fails closed)
5. (ELF) a host that links re-shield too and exports its symbols (-rdynamic) does not capture the
   library's calls: a sealed library is OK although the host is unsealed, and an unsealed library is
   UNSEALED although the host is sealed (-Wl,-Bsymbolic: each module uses its own record)
6. library sealed with --manifest, host EXE in ANOTHER directory calls
   reshield_check_json(manifest_rel, assets_rel): OK; one changed asset byte -> ASSET_TAMPERED (6);
   missing manifest -> MANIFEST_IO_ERROR (8). The paths are relative to the host EXE directory,
   not the library's: a valid copy next to the library is never consulted.

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


def run_host(host: str, lib: str, *extra: str,
             cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([host, lib, *extra], capture_output=True, text=True, cwd=cwd)


def expect(r: subprocess.CompletedProcess[str], rc: int, status: str, what: str,
           cj: tuple[int, str] | None = None) -> str:
    """cj = (reshield_status_t, status name) that the library's reshield_check_json must report."""
    assert r.returncode == rc and f"status={status}" in r.stdout, f"{what}: {r}"
    if cj is not None:
        assert f"check_json: status={cj[0]} json=" in r.stdout and f'"status":"{cj[1]}"' in r.stdout, \
            f"{what}: reshield_check_json: {r}"
    print(f"PASS: {what}")
    return r.stdout


def manifest_check(r: subprocess.CompletedProcess[str], status: int, name: str, what: str) -> None:
    """The manifest-bound reshield_check_json line of the host (exit code is the code-section status)."""
    assert r.returncode == OK and f"check_json_manifest: status={status} json=" in r.stdout \
        and f'"status":"{name}"' in r.stdout, f"{what}: {r}"
    print(f"PASS: {what}")


def test_manifest_binding(host: str, lib: str, label: str, tmpdir: str) -> None:
    """Module mode + manifest + assets: the host EXE's directory, not the library's, is the base."""
    ext = os.path.splitext(lib)[1]
    root = os.path.join(tmpdir, f"{label}_mb")
    lib_dir = os.path.join(root, "lib")
    host_dir = os.path.join(root, "host")
    assets_src = os.path.join(HERE, "..", "examples", "assets")
    shutil.copytree(assets_src, os.path.join(lib_dir, "assets"))
    shutil.copytree(assets_src, os.path.join(host_dir, "assets"))
    manifest = os.path.join(host_dir, "app.manifest")
    subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "gen_manifest.py"),
                    os.path.join(host_dir, "assets"), "-o", manifest], check=True, stdout=subprocess.DEVNULL)
    shutil.copy2(manifest, os.path.join(lib_dir, "app.manifest"))  # a valid decoy next to the library
    sealed = os.path.join(lib_dir, f"sealed{ext}")
    shutil.copy2(lib, sealed)
    subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "seal_binary.py"), sealed,
                    "--manifest", manifest, "--build-id", "12"], check=True, stdout=subprocess.DEVNULL)
    host_copy = os.path.join(host_dir, "host")
    shutil.copy2(host, host_copy)

    def run() -> subprocess.CompletedProcess[str]:
        # cwd is neither directory: only the host EXE directory can make the relative paths resolve
        return run_host(host_copy, sealed, "app.manifest", "assets", cwd=root)

    manifest_check(run(), 0, "OK", f"{label}: sealed library + manifest, host in another directory: OK")

    decoy = os.path.join(lib_dir, "assets", "stage1.cfg")
    with open(decoy, "ab") as f:
        f.write(b"x")
    manifest_check(run(), 0, "OK", f"{label}: a changed asset next to the library is not consulted (EXE-relative paths)")

    stage_cfg = os.path.join(host_dir, "assets", "stage1.cfg")
    with open(stage_cfg, "rb") as f:
        orig = f.read()
    with open(stage_cfg, "wb") as f:
        f.write(bytes([orig[0] ^ 0x01]) + orig[1:])
    r = run()
    manifest_check(r, 6, "ASSET_TAMPERED", f"{label}: one changed asset byte is ASSET_TAMPERED")
    assert '"failed_asset_path":"stage1.cfg"' in r.stdout, r
    with open(stage_cfg, "wb") as f:
        f.write(orig)

    os.unlink(manifest)
    manifest_check(run(), 8, "MANIFEST_IO_ERROR",
                   f"{label}: missing manifest is MANIFEST_IO_ERROR even with a valid copy next to the library")


def test_dual_record(dual_host: str, lib: str, label: str, tmpdir: str) -> None:
    ext = os.path.splitext(lib)[1]
    with open(dual_host, "rb") as f:
        assert seal_binary.MAGIC in f.read(), "dual host must contain its own integrity record"
    syms = subprocess.check_output(["nm", "-D", "--defined-only", dual_host], text=True)
    assert "reshield_verify_code_section" in syms, "dual host must export re-shield symbols (-rdynamic)"

    plain = os.path.join(tmpdir, f"{label}_dual_plain{ext}")
    sealed = os.path.join(tmpdir, f"{label}_dual_sealed{ext}")
    shutil.copy2(lib, plain)
    shutil.copy2(lib, sealed)
    subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "seal_binary.py"), sealed,
                    "--build-id", "13"], check=True, stdout=subprocess.DEVNULL)

    # Host unsealed (its record says UNSEALED), library sealed: the library must report OK.
    out = expect(run_host(dual_host, sealed), OK, "OK",
                 f"{label}: sealed library is OK although the exporting host is unsealed (own record)")
    m = re.search(r"actual_size=(\d+) expected_size=(\d+)", out)
    assert m and m.group(1) == m.group(2) and int(m.group(1)) > 0, out

    # Host sealed, library unsealed: the library must not borrow the host's sealed record.
    sealed_host = os.path.join(tmpdir, f"{label}_dual_host_sealed")
    shutil.copy2(dual_host, sealed_host)
    subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "seal_binary.py"), sealed_host,
                    "--build-id", "14"], check=True, stdout=subprocess.DEVNULL)
    expect(run_host(sealed_host, plain), UNSEALED, "UNSEALED",
           f"{label}: unsealed library stays UNSEALED although the exporting host is sealed")


def test_library(host: str, lib: str, label: str, tmpdir: str, plain_cj: tuple[int, str]) -> None:
    ext = os.path.splitext(lib)[1]
    plain = os.path.join(tmpdir, f"{label}_plain{ext}")
    shutil.copy2(lib, plain)

    expect(run_host(host, plain), UNSEALED, "UNSEALED", f"{label}: unsealed library is UNSEALED", plain_cj)

    sealed = os.path.join(tmpdir, f"{label}_sealed{ext}")
    shutil.copy2(lib, sealed)
    subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "seal_binary.py"), sealed,
                    "--build-id", "11"], check=True, stdout=subprocess.DEVNULL)
    out = expect(run_host(host, sealed), OK, "OK", f"{label}: sealed library verifies OK (also via reshield_check_json)",
                 (0, "OK"))
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
           f"{label}: one changed .text byte of the library is TAMPERED", (2, "CODE_TAMPERED"))

    if sys.platform.startswith("linux"):
        # dlpi_name is relative: the library path comes from /proc/self/maps (the mapping that
        # holds the record), so the verdict is the same as for an absolute path.
        rel = "./" + os.path.basename(sealed)
        out = expect(run_host(host, rel, cwd=tmpdir), OK, "OK",
                     f"{label}: relative dlopen path verifies OK")
        assert "wx=0" in out, f"{label}: W^X check did not pass: {out}"
        expect(run_host(host, "./" + os.path.basename(tampered), cwd=tmpdir), TAMPERED,
               "TAMPERED", f"{label}: tampered library opened by a relative path is TAMPERED")

        # a path with spaces and "(deleted)" inside it is not confused with a deleted file
        odd_dir = os.path.join(tmpdir, f"{label} dir (deleted) x")
        os.mkdir(odd_dir)
        shutil.copy2(sealed, os.path.join(odd_dir, "lib with space.so"))
        expect(run_host(host, f"{label} dir (deleted) x/lib with space.so", cwd=tmpdir),
               OK, "OK", f"{label}: relative path with spaces verifies OK")

        # the file behind the relative name is deleted, or replaced by another file, after
        # loading: the path no longer names the mapped image, so fail closed
        gone = os.path.join(tmpdir, f"{label}_gone{ext}")
        shutil.copy2(sealed, gone)
        expect(run_host(host, "./" + os.path.basename(gone), "--unlink", cwd=tmpdir),
               ERROR, "ERROR", f"{label}: relative path, library deleted after load, fails closed")
        swapped = os.path.join(tmpdir, f"{label}_swapped{ext}")
        shutil.copy2(tampered, swapped)
        spare = os.path.join(tmpdir, f"{label}_spare{ext}")
        shutil.copy2(sealed, spare)
        expect(run_host(host, "./" + os.path.basename(swapped), "--replace", spare, cwd=tmpdir),
               ERROR, "ERROR", f"{label}: relative path, library replaced after load, fails closed")

    test_manifest_binding(host, lib, label, tmpdir)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--lib", required=True, help="development shared library")
    ap.add_argument("--release-lib", help="release (ALLOW_UNSEALED=0) shared library")
    ap.add_argument("--dual-host", help="host that links re-shield and exports its symbols (ELF only)")
    args = ap.parse_args()

    host = os.path.abspath(args.host)
    with open(host, "rb") as f:
        assert seal_binary.MAGIC not in f.read(), "host must not contain an integrity record"
    print("PASS: test host contains no integrity record (it is never sealed)")

    with tempfile.TemporaryDirectory(prefix="reshield_module_") as tmpdir:
        # An unsealed development library passes reshield_check_json (allow_unsealed); a release one does not.
        test_library(host, os.path.abspath(args.lib), "dev", tmpdir, (0, "OK"))
        if args.release_lib:
            test_library(host, os.path.abspath(args.release_lib), "release", tmpdir, (1, "UNSEALED"))
        if args.dual_host:
            dual = os.path.abspath(args.dual_host)
            test_dual_record(dual, os.path.abspath(args.lib), "dev", tmpdir)
            if args.release_lib:
                test_dual_record(dual, os.path.abspath(args.release_lib), "release", tmpdir)
    print("ALL PASS: module mode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
