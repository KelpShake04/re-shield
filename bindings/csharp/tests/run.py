#!/usr/bin/env python3
"""
C# binding test: loads real re-shield shared libraries from a dotnet console program.

Needs `make shared release-shared` first (the Makefile target csharp-test does it) and the dotnet SDK.
Libraries are copied to a temp dir and sealed with tools/seal_binary.py; one dotnet process per
scenario because a DllImport is resolved once per process.

  dev library, sealed        -> OK
  release library, unsealed  -> UNSEALED
  release library, sealed    -> OK        (the dotnet host itself is never sealed)
  release library, 1 byte of .text changed after sealing -> CODE_TAMPERED
  no library                 -> -1 (MODULE_NOT_FOUND), no exception

LoadAsset (release library sealed with a manifest; the dotnet host's directory is the base, so the
manifest and assets are addressed with a relative path from there):
  good asset -> OK + exact bytes; 1 byte changed -> ASSET_TAMPERED; unlisted -> ASSET_TAMPERED;
  '..' asset path -> MANIFEST_IO_ERROR; asset over the byte cap -> MANIFEST_IO_ERROR;
  unsealed library -> UNSEALED; no library -> -1, no exception
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import test_seal_workflow as wf  # noqa: E402

EXT = {"darwin": "dylib", "linux": "so"}.get(sys.platform, "")
UNCALLED_SYMBOL = "reshield_verify_buffer"  # present in every build, never called by a check


def seal(path: str) -> None:
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "seal_binary.py"), path, "--build-id", "11"],
                   check=True, stdout=subprocess.DEVNULL)


def main() -> int:
    dotnet = shutil.which("dotnet")
    if not dotnet or not EXT:
        print("SKIP: dotnet SDK or POSIX platform not available")
        return 0
    out = os.path.join(ROOT, "build", "csharp")
    subprocess.run([dotnet, "build", os.path.join(HERE, "Reshield.Tests.csproj"), "-c", "Release",
                    "-o", out, "--nologo", "-v", "q", "--no-incremental"], check=True)
    test_dll = os.path.join(out, "Reshield.Tests.dll")
    # The IL2CPP flavor ("__Internal") only has to compile: nothing to load it from here.
    subprocess.run([dotnet, "build", os.path.join(HERE, "Reshield.Tests.csproj"), "-c", "Release",
                    "-p:DefineConstants=RESHIELD_INTERNAL", "-o", os.path.join(ROOT, "build", "csharp-internal"),
                    "--nologo", "-v", "q", "--no-incremental"], check=True)
    # ...which rewrote obj/: rebuild the normal flavor last so test_dll is the DllImport("reshield") one.
    subprocess.run([dotnet, "build", os.path.join(HERE, "Reshield.Tests.csproj"), "-c", "Release",
                    "-o", out, "--nologo", "-v", "q", "--no-incremental"], check=True)

    dev = os.path.join(ROOT, "build", f"libreshield.{EXT}")
    rel = os.path.join(ROOT, "build", "release", f"libreshield.{EXT}")
    with tempfile.TemporaryDirectory(prefix="reshield_cs_") as tmp:
        def copy(src: str, name: str) -> str:
            dst = os.path.join(tmp, f"{name}.{EXT}")
            shutil.copy2(src, dst)
            return dst

        dev_sealed = copy(dev, "dev_sealed")
        seal(dev_sealed)
        rel_plain = copy(rel, "rel_plain")
        rel_sealed = copy(rel, "rel_sealed")
        seal(rel_sealed)
        with open(rel_sealed, "rb") as f:
            data = f.read()
        off = wf.find_symbol_file_offset(rel_sealed, data, UNCALLED_SYMBOL)
        rel_tampered = os.path.join(tmp, f"rel_tampered.{EXT}")
        wf.patch_file(rel_sealed, rel_tampered, off, data[off] ^ 0x01)

        # Assets for LoadAsset. The process executable is the dotnet host, so paths are relative to it.
        host_dir = os.path.dirname(os.path.realpath(dotnet))
        assets = os.path.join(tmp, "assets")
        os.makedirs(assets)
        text = "stage_name=Emerald Valley\n"
        with open(os.path.join(assets, "stage1.cfg"), "w", newline="") as f:
            f.write(text)
        with open(os.path.join(assets, "other.cfg"), "w", newline="") as f:
            f.write("x=1\n")
        manifest = os.path.join(tmp, "assets.manifest")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_manifest.py"), assets, "-o", manifest,
                        "--exclude", "other.cfg"], check=True, stdout=subprocess.DEVNULL)
        rel_assets_sealed = copy(rel, "rel_assets_sealed")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "seal_binary.py"), rel_assets_sealed,
                        "--manifest", manifest, "--build-id", "11"], check=True, stdout=subprocess.DEVNULL)
        rel_manifest = os.path.relpath(manifest, host_dir)
        rel_dir = os.path.relpath(assets, host_dir)

        def asset(rel_path: str, cap: int, status: int, expect: str) -> list[str]:
            return [rel_manifest, rel_dir, rel_path, str(cap), str(status), expect]

        scenarios = [
            ("sealed dev library", dev_sealed, 0, "OK"),
            ("unsealed release library", rel_plain, 1, "UNSEALED"),
            ("sealed release library", rel_sealed, 0, "OK"),
            ("tampered release library", rel_tampered, 2, "CODE_TAMPERED"),
            ("library missing", "none", -1, "MODULE_NOT_FOUND"),
        ]
        asset_scenarios = [
            ("LoadAsset good", rel_assets_sealed, 0, "OK", asset("stage1.cfg", 4096, 0, text)),
            ("LoadAsset unlisted", rel_assets_sealed, 0, "OK", asset("other.cfg", 4096, 6, "-")),
            ("LoadAsset '..' path", rel_assets_sealed, 0, "OK", asset("../x.cfg", 4096, 8, "-")),
            ("LoadAsset over the cap", rel_assets_sealed, 0, "OK", asset("stage1.cfg", 4, 8, "-")),
            ("LoadAsset unsealed library", rel_plain, 1, "UNSEALED", asset("stage1.cfg", 4096, 1, "-")),
            ("LoadAsset no library", "none", -1, "MODULE_NOT_FOUND", asset("stage1.cfg", 4096, -1, "-")),
        ]
        for label, lib, status, name in scenarios:
            r = subprocess.run([dotnet, test_dll, lib, str(status), name], capture_output=True, text=True)
            assert r.returncode == 0, f"{label}: rc={r.returncode}\n{r.stdout}{r.stderr}"
            print(f"PASS: {label} -> {name}")
        for label, lib, status, name, extra in asset_scenarios:
            r = subprocess.run([dotnet, test_dll, lib, str(status), name, *extra], capture_output=True, text=True)
            assert r.returncode == 0, f"{label}: rc={r.returncode}\n{r.stdout}{r.stderr}"
            print(f"PASS: {label}")
        # Tampered: same size, one byte changed after the manifest was made and the library sealed.
        with open(os.path.join(assets, "stage1.cfg"), "r+b") as f:
            f.write(b"S")
        r = subprocess.run([dotnet, test_dll, rel_assets_sealed, "0", "OK", *asset("stage1.cfg", 4096, 6, "-")],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"LoadAsset 1 byte changed: rc={r.returncode}\n{r.stdout}{r.stderr}"
        print("PASS: LoadAsset 1 byte changed")
    print("ALL PASS: C# binding")
    return 0


if __name__ == "__main__":
    sys.exit(main())
