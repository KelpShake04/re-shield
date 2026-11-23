#!/usr/bin/env python3
"""Writes a copy of a PE32+ x64 EXE with one byte of .text flipped (CI tamper-detection helper).

The flipped byte is inside a run of int3 (0xCC) inter-function padding, so the tampered EXE
still starts and reaches reshield_verify() instead of crashing on a changed instruction.
Usage: tamper_pe_text.py <src.exe> <dst.exe>
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import seal_binary  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())
    text = seal_binary.pe_find_text(seal_binary.parse_pe64(bytes(data)))
    start, end = text.raw_offset, text.raw_offset + text.virtual_size
    idx = data.find(b"\xcc" * 8, start, end)
    if idx < 0:
        print("no int3 padding run found in .text", file=sys.stderr)
        return 1
    data[idx + 4] = 0xCD
    with open(sys.argv[2], "wb") as f:
        f.write(data)
    print(f"flipped .text byte at file offset 0x{idx + 4:x} (0xCC -> 0xCD)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
