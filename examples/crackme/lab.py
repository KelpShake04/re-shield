#!/usr/bin/env python3
"""
Crackme lab driver (docs/crackme-lab.md). Attacks YOUR OWN sealed build of crackme, nothing else.

Usage: lab.py <sealed-crackme> [level ...]      levels: 1 2 3 (default: all)

Every level patches a copy (the input is never modified) and runs it with a WRONG key:
  1  license check forced to return 1, seal untouched      -> blocked  (CODE_TAMPERED, rc 12)
  2  same patch, then tools/seal_binary.py re-seals        -> UNLOCKED (no key in the design)
  3  L1 patch + startup check forced to return 0, seal stale -> UNLOCKED (the check never runs)
The patch offset comes from the symbol table (nm) and the CPU from the file header; nothing is
hardcoded. A function entry is overwritten with `return <n>` (mov + ret).
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "tests"))
from test_seal_workflow import find_symbol_file_offset, resign  # noqa: E402

SEAL_TOOL = os.path.join(ROOT, "tools", "seal_binary.py")
WRONG_KEY = "WRONG-KEY"

# (cputype, e_machine) -> function that builds "return n" machine code
ARM64 = lambda n: struct.pack("<II", 0x52800000 | (n << 5), 0xD65F03C0)  # mov w0,#n ; ret
X64 = lambda n: b"\xb8" + struct.pack("<I", n) + b"\xc3"                  # mov eax,n ; ret


def stub_for(data: bytes) -> "callable":
    if data[:4] == b"\xcf\xfa\xed\xfe":  # Mach-O 64 little-endian
        cpu = struct.unpack_from("<I", data, 4)[0]
        table = {0x0100000C: ARM64, 0x01000007: X64}
    elif data[:4] == b"\x7fELF":
        cpu = struct.unpack_from("<H", data, 18)[0]
        table = {0xB7: ARM64, 0x3E: X64}
    else:
        raise ValueError("unsupported binary format (Mach-O 64 and ELF64 only)")
    if cpu not in table:
        raise ValueError(f"unsupported CPU 0x{cpu:x} (arm64 and x86-64 only)")
    return table[cpu]


def patch_return(dst: str, symbol: str, value: int) -> int:
    """Rewrite `symbol` in dst to `return value`. Returns the file offset."""
    with open(dst, "rb") as f:
        data = f.read()
    code = stub_for(data)(value)
    off = find_symbol_file_offset(dst, data, symbol)
    with open(dst, "r+b") as f:
        f.seek(off)
        f.write(code)
    resign(dst)  # macOS refuses to launch a binary whose ad-hoc signature no longer matches
    print(f"  patched {symbol} @ file offset 0x{off:x}: {code.hex(' ')}")
    return off


def reseal(path: str) -> None:
    subprocess.run([sys.executable, SEAL_TOOL, path, "--build-id", "1"], check=True,
                   stdout=subprocess.DEVNULL)
    print("  re-sealed with tools/seal_binary.py (no key needed)")


def run_level(level: int, sealed: str, workdir: str) -> subprocess.CompletedProcess:
    target = os.path.join(workdir, f"crackme_l{level}")
    shutil.copy2(sealed, target)
    if level == 1:
        print("L1: patch the license check, keep the old seal")
        patch_return(target, "crackme_check_license", 1)
    elif level == 2:
        print("L2: patch the license check, then re-seal")
        patch_return(target, "crackme_check_license", 1)
        reseal(target)
    elif level == 3:
        print("L3: patch the license check AND the startup check (never calls reshield_verify)")
        patch_return(target, "crackme_check_license", 1)
        patch_return(target, "crackme_startup_check", 0)
    else:
        raise ValueError(f"unknown level {level}")
    proc = subprocess.run([target, WRONG_KEY], capture_output=True, text=True)
    print(f"  run with wrong key: rc={proc.returncode}")
    for line in (proc.stdout + proc.stderr).splitlines():
        print(f"    {line}")
    return proc


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    levels = [int(a) for a in argv[2:]] or [1, 2, 3]
    with tempfile.TemporaryDirectory(prefix="crackme_lab_") as workdir:
        for level in levels:
            run_level(level, argv[1], workdir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
