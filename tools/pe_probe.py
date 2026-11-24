#!/usr/bin/env python3
"""Measures the PE properties that decide whether seal_binary.py can seal an EXE.

Prints .text geometry, base relocations (total and inside .text), Machine, the
DYNAMIC_BASE bit, executable sections, and finally the result of a seal attempt on a
temporary copy (the input file is never modified). Standard library only.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seal_binary as sb  # noqa: E402

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
MAX_LISTED = 10


def base_relocs(data: bytes, image: sb.PeImage) -> list[int]:
    """RVAs of all non-padding base relocation entries."""
    rva, size = image.directory(sb.IMAGE_DIRECTORY_ENTRY_BASERELOC)
    if size == 0:
        return []
    start = sb.pe_rva_to_offset(image, rva)
    if start + size > len(data):
        raise ValueError("base relocation directory extends past end of file")
    out, pos, end = [], start, start + size
    while pos < end:
        if end - pos < 8:
            raise ValueError("malformed base relocation block header")
        page_rva, block_size = struct.unpack_from("<II", data, pos)
        if block_size < 8 or block_size % 2 != 0 or pos + block_size > end:
            raise ValueError(f"malformed base relocation block (size {block_size})")
        for i in range((block_size - 8) // 2):
            entry = struct.unpack_from("<H", data, pos + 8 + i * 2)[0]
            if entry >> 12 != sb.IMAGE_REL_BASED_ABSOLUTE:
                out.append(page_rva + (entry & 0xFFF))
        pos += block_size
    return out


def seal_attempt(path: str) -> str:
    seal_tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seal_binary.py")
    with tempfile.TemporaryDirectory(prefix="pe_probe_") as tmp:
        copy = os.path.join(tmp, "copy.exe")
        shutil.copy2(path, copy)
        r = subprocess.run([sys.executable, seal_tool, copy], capture_output=True, text=True)
    detail = (r.stdout + r.stderr).strip().replace(copy, "<copy>")
    return f"{'SEALED' if r.returncode == 0 else f'REFUSED (exit {r.returncode})'}: {detail}"


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <pe-exe>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()

    try:
        image = sb.parse_pe64(data)
    except ValueError as exc:
        print(f"pe_probe: not a supported PE32+ x64 image: {exc}")
        return 2

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    dll_chars = struct.unpack_from("<H", data, e_lfanew + 24 + 70)[0]
    print(f"file: {path}")
    print(f"Machine: 0x{machine:04x}")
    print(f"DllCharacteristics: 0x{dll_chars:04x} "
          f"DYNAMIC_BASE={bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)}")

    texts = [s for s in image.sections if s.name == b".text"]
    print(f".text sections: {len(texts)}")
    for s in texts:
        print(f"  .text VA=0x{s.virtual_address:x} VirtualSize={s.virtual_size} "
              f"RawSize={s.raw_size} flags=0x{s.characteristics:08x}")
    exec_secs = [s.name.decode("ascii", "replace") for s in image.sections
                 if s.characteristics & sb.IMAGE_SCN_MEM_EXECUTE]
    print(f"executable sections: {', '.join(exec_secs) or '(none)'}")

    rva, size = image.directory(sb.IMAGE_DIRECTORY_ENTRY_BASERELOC)
    print(f"BaseReloc directory: present={size != 0} rva=0x{rva:x} size={size}")
    try:
        relocs = base_relocs(data, image)
    except ValueError as exc:
        print(f"reloc parse error: {exc}")
        relocs = []
    print(f"base relocations total: {len(relocs)}")
    in_text = [r for r in relocs
               if any(t.virtual_address <= r < t.virtual_address + t.virtual_size for t in texts)]
    print(f"base relocations inside .text: {len(in_text)}")
    print("first RVAs inside .text: " + (", ".join(f"0x{r:x}" for r in in_text[:MAX_LISTED]) or "(none)"))

    print(f"seal attempt on copy (no manifest): {seal_attempt(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
