#!/usr/bin/env python3
"""
Corrupt-ELF test (Linux only): the runtime finds its own .text through the section headers of the
file on disk (src/integrity_linux.c, reshield_platform_get_code_section). The loader never reads
those headers, so a copy of a SEALED library with damaged headers still loads. For each damaged copy
the module host (tests/test_module_host.c) must

  - end normally (no signal: returncode >= 0),
  - report TAMPERED or ERROR from reshield_verify_code_section (never OK, never UNSEALED),
  - report a non-OK status from the flat reshield_check_json too.

Fields changed: e_shoff, e_shentsize, e_shnum, e_shstrndx, the section-name string table's
sh_offset/sh_size, .text's sh_name/sh_addr/sh_size, and a truncated section header table.

Run through `make test` (corrupt-elf-test target). Skipped on non-Linux hosts.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))

TAMPERED, ERROR = 2, 3
U64 = (1 << 64) - 1
SHDR = 64  # sizeof(Elf64_Shdr)
PF_X, PF_W = 1, 2


class Elf:
    """Offsets of the ELF64 little-endian structures that the runtime parser reads."""

    def __init__(self, data: bytes) -> None:
        assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, "ELF64 LE expected"
        self.fsize = len(data)
        self.shoff, = struct.unpack_from("<Q", data, 0x28)
        self.shentsize, self.shnum, self.shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        self.phoff, = struct.unpack_from("<Q", data, 0x20)
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 0x36)
        assert self.shentsize == SHDR
        self.str_hdr = self.shoff + self.shstrndx * SHDR
        str_off, str_size = struct.unpack_from("<QQ", data, self.str_hdr + 24)
        self.text_hdr = -1
        self.text_name = 0
        for i in range(self.shnum):
            hdr = self.shoff + i * SHDR
            name, = struct.unpack_from("<I", data, hdr)
            if data[str_off + name:str_off + name + 6] == b".text\x00":
                self.text_hdr, self.text_name = hdr, name
        assert self.text_hdr >= 0
        self.text_addr, self.text_off, self.text_size = struct.unpack_from("<QQQ", data, self.text_hdr + 16)
        self.str_size = str_size
        self.exec_seg = self.writable_seg = None
        for i in range(self.phnum):
            p_type, p_flags, _, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIQQQQ", data, self.phoff + i * self.phentsize)
            if p_type != 1:
                continue
            if p_flags & PF_X and not p_flags & PF_W:
                self.exec_seg = (p_vaddr, p_filesz)
            elif p_flags & PF_W and self.writable_seg is None:
                self.writable_seg = (p_vaddr, p_filesz)
        assert self.exec_seg and self.writable_seg


def put(fmt: str, off: int, *vals: int) -> Callable[[bytearray, Elf], None]:
    def edit(d: bytearray, e: Elf) -> None:
        struct.pack_into(fmt, d, off, *vals)
    return edit


def mutations(e: Elf) -> list[tuple[str, Callable[[bytearray, Elf], None]]]:
    """(name, edit). Each edit receives the sealed library bytes and rewrites header fields."""
    str_h, txt_h = e.str_hdr, e.text_hdr
    seg_va, seg_len = e.exec_seg
    return [
        # ELF header
        ("e_shoff = 0", put("<Q", 0x28, 0)),
        ("e_shoff = file size", put("<Q", 0x28, e.fsize)),
        ("e_shoff = file size - 1", put("<Q", 0x28, e.fsize - 1)),
        ("e_shoff = 2^64-1", put("<Q", 0x28, U64)),
        ("e_shoff = 1 (table = file bytes at offset 1)", put("<Q", 0x28, 1)),
        ("e_shentsize = 0", put("<H", 0x3A, 0)),
        ("e_shentsize = 63", put("<H", 0x3A, 63)),
        ("e_shentsize = 65", put("<H", 0x3A, 65)),
        ("e_shnum = 0", put("<H", 0x3C, 0)),
        ("e_shnum = 1", put("<H", 0x3C, 1)),
        ("e_shnum = e_shnum + 1 (table runs past EOF)", put("<H", 0x3C, e.shnum + 1)),
        ("e_shnum = 0xffff", put("<H", 0x3C, 0xFFFF)),
        ("e_shstrndx = e_shnum", put("<H", 0x3E, e.shnum)),
        ("e_shstrndx = 0xffff (SHN_XINDEX)", put("<H", 0x3E, 0xFFFF)),
        ("e_shstrndx = 0 (null section as string table)", put("<H", 0x3E, 0)),
        # section-name string table header
        ("strtab sh_offset = file size", put("<Q", str_h + 24, e.fsize)),
        ("strtab sh_offset = 2^64-1", put("<Q", str_h + 24, U64)),
        ("strtab sh_size = 0", put("<Q", str_h + 32, 0)),
        ("strtab sh_size = 2^64-1 (+1 wraps the malloc size)", put("<Q", str_h + 32, U64)),
        ("strtab sh_size = file size", put("<Q", str_h + 32, e.fsize)),
        # .text header
        ("text sh_name = strtab size", put("<I", txt_h, e.str_size)),
        ("text sh_name = 0xffffffff", put("<I", txt_h, 0xFFFFFFFF)),
        ("text sh_addr = 0 (not executable)", put("<Q", txt_h + 16, 0)),
        ("text sh_addr = writable segment", put("<Q", txt_h + 16, e.writable_seg[0])),
        ("text sh_addr = 2^64-1", put("<Q", txt_h + 16, U64)),
        ("text sh_addr + sh_size wraps", put("<Q", txt_h + 16, U64 - e.text_size // 2)),
        ("text range straddles the segment end", put("<Q", txt_h + 16, seg_va + seg_len - e.text_size // 2)),
        ("text sh_addr moved by 16 (inside the segment)", put("<Q", txt_h + 16, e.text_addr + 16)),
        ("text sh_size = 0", put("<Q", txt_h + 32, 0)),
        ("text sh_size - 1", put("<Q", txt_h + 32, e.text_size - 1)),
        ("text sh_size = segment size + 1", put("<Q", txt_h + 32, seg_len + 1)),
        ("text sh_size = 2^64-1", put("<Q", txt_h + 32, U64)),
    ]


def truncate_mid_table(d: bytearray, e: Elf) -> None:
    del d[e.shoff + 32:]


def run(host: str, lib: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([host, lib], capture_output=True, text=True, timeout=60)


def check(r: subprocess.CompletedProcess[str], name: str) -> str:
    assert r.returncode >= 0, f"{name}: killed by signal {-r.returncode}: {r}"
    assert r.returncode in (TAMPERED, ERROR), f"{name}: exit {r.returncode}, not TAMPERED/ERROR: {r}"
    m = re.search(r"module_host: status=(\w+)", r.stdout)
    assert m and m.group(1) == {TAMPERED: "TAMPERED", ERROR: "ERROR"}[r.returncode], f"{name}: {r}"
    cj = re.search(r"check_json: status=(\d+) json=", r.stdout)
    assert cj and int(cj.group(1)) != 0, f"{name}: reshield_check_json reported success: {r}"
    return m.group(1)


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("SKIP: corrupt-ELF test is Linux only")
        return 0
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--lib", required=True, help="development shared library")
    args = ap.parse_args()
    host = os.path.abspath(args.host)

    with tempfile.TemporaryDirectory(prefix="reshield_corrupt_elf_") as tmpdir:
        sealed = os.path.join(tmpdir, "sealed.so")
        shutil.copy2(args.lib, sealed)
        subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "seal_binary.py"), sealed,
                        "--build-id", "21"], check=True, stdout=subprocess.DEVNULL)
        with open(sealed, "rb") as f:
            orig = f.read()
        e = Elf(orig)

        # baseline: the unmodified sealed copy is OK, so every failure below comes from the edit
        r = run(host, sealed)
        assert r.returncode == 0 and "status=OK" in r.stdout, f"baseline: {r}"
        print("PASS: baseline: sealed library is OK")

        cases = mutations(e) + [("section header table truncated mid-table", truncate_mid_table)]
        for i, (name, edit) in enumerate(cases):
            data = bytearray(orig)
            edit(data, e)
            assert bytes(data) != orig, f"{name}: edit changed nothing"
            path = os.path.join(tmpdir, f"corrupt_{i}.so")
            with open(path, "wb") as f:
                f.write(data)
            status = check(run(host, path), name)
            print(f"PASS: {name}: {status}, no signal, check_json not OK")
    print("ALL PASS: corrupt ELF")
    return 0


if __name__ == "__main__":
    sys.exit(main())
