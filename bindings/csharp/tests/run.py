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

        scenarios = [
            ("sealed dev library", dev_sealed, 0, "OK"),
            ("unsealed release library", rel_plain, 1, "UNSEALED"),
            ("sealed release library", rel_sealed, 0, "OK"),
            ("tampered release library", rel_tampered, 2, "CODE_TAMPERED"),
            ("library missing", "none", -1, "MODULE_NOT_FOUND"),
        ]
        for label, lib, status, name in scenarios:
            r = subprocess.run([dotnet, test_dll, lib, str(status), name], capture_output=True, text=True)
            assert r.returncode == 0, f"{label}: rc={r.returncode}\n{r.stdout}{r.stderr}"
            print(f"PASS: {label} -> {name}")
    print("ALL PASS: C# binding")
    return 0


if __name__ == "__main__":
    sys.exit(main())
