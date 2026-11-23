#!/usr/bin/env python3
"""
Build-time binary sealing tool for re-shield v2 integrity records.

Computes SHA-256 of the executable's code section (__TEXT,__text on 64-bit Mach-O;
.text on 64-bit ELF) and embeds build_id, section size, code digest, and optional
asset manifest root digest into the unique RSHLDCHK v2 record.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import sys

MAGIC = b"RSHLDCHK"
RECORD_VERSION = 2
RECORD_FMT = "<8sIIIIQ32s32s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


def find_macho64_text(data: bytes) -> tuple[int, int]:
    if len(data) < 32:
        raise ValueError("File too small for Mach-O 64-bit header")
    magic, _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags, _reserved = (
        struct.unpack_from("<IIIIIIII", data, 0)
    )
    if magic != MH_MAGIC_64:
        raise ValueError(f"Unsupported Mach-O magic: 0x{magic:08x}")

    offset = 32
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise ValueError("Truncated Mach-O load command header")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise ValueError(f"Invalid Mach-O load command size: {cmdsize}")
        if cmd == LC_SEGMENT_64:
            segname = data[offset + 8 : offset + 24].split(b"\x00", 1)[0]
            nsects = struct.unpack_from("<I", data, offset + 64)[0]
            sect_off = offset + 72
            for _ in range(nsects):
                sectname = data[sect_off : sect_off + 16].split(b"\x00", 1)[0]
                s_segname = data[sect_off + 16 : sect_off + 32].split(b"\x00", 1)[0]
                _addr, size, file_off = struct.unpack_from("<QQI", data, sect_off + 32)
                if segname == b"__TEXT" and s_segname == b"__TEXT" and sectname == b"__text":
                    return file_off, size
                sect_off += 80
        offset += cmdsize

    raise ValueError("Could not find __TEXT,__text section in Mach-O binary")


def find_elf64_text(data: bytes) -> tuple[int, int]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("Only 64-bit little-endian ELF is supported")

    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        raise ValueError("ELF binary has no valid section header table")

    strtab_hdr_off = e_shoff + e_shstrndx * e_shentsize
    strtab_off, strtab_size = struct.unpack_from("<QQ", data, strtab_hdr_off + 24)
    strtab = data[strtab_off : strtab_off + strtab_size]

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", data, sh_off)[0]
        file_off, size = struct.unpack_from("<QQ", data, sh_off + 24)
        end = strtab.find(b"\x00", sh_name)
        name = strtab[sh_name:end] if end != -1 else strtab[sh_name:]
        if name == b".text":
            return file_off, size

    raise ValueError("Could not find .text section in ELF binary")


def find_code_section(data: bytes) -> tuple[str, int, int]:
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == MH_MAGIC_64:
        off, size = find_macho64_text(data)
        return "macho64(__TEXT,__text)", off, size
    if data[:4] == b"\x7fELF":
        off, size = find_elf64_text(data)
        return "elf64(.text)", off, size
    raise ValueError("Unsupported binary format (expected 64-bit Mach-O or ELF)")


def find_integrity_record_offset(data: bytes) -> int:
    matches = []
    start = 0
    while True:
        idx = data.find(MAGIC, start)
        if idx == -1:
            break
        if idx + RECORD_SIZE <= len(data):
            _magic, version, sealed, _bid, has_m, _sz, _d1, _d2 = struct.unpack_from(
                RECORD_FMT, data, idx
            )
            if version == RECORD_VERSION and sealed in (0, 1) and has_m in (0, 1):
                matches.append(idx)
        start = idx + 1

    if len(matches) == 0:
        raise ValueError("No RSHLDCHK v2 integrity record found in binary")
    if len(matches) > 1:
        raise ValueError(f"Ambiguous: found {len(matches)} RSHLDCHK v2 records in binary")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal a binary with code + optional manifest SHA-256")
    parser.add_argument("binary", help="Path to the compiled Mach-O or ELF executable")
    parser.add_argument("--manifest", help="Optional asset manifest file to bind into the binary")
    parser.add_argument("--build-id", type=int, default=1, help="Numeric build identifier (default: 1)")
    parser.add_argument("--verify-only", action="store_true", help="Check seal without modifying file")
    parser.add_argument("--no-codesign", action="store_true", help="Skip macOS ad-hoc codesign")
    args = parser.parse_args()

    with open(args.binary, "rb") as f:
        buf = bytearray(f.read())

    fmt_name, text_off, text_size = find_code_section(bytes(buf))
    if text_off < 0 or text_size <= 0 or text_off + text_size > len(buf):
        raise ValueError(
            f"Code section bounds out of range: offset=0x{text_off:x}, size={text_size}, file_len={len(buf)}"
        )
    code_digest = hashlib.sha256(bytes(buf[text_off : text_off + text_size])).digest()

    has_manifest = 0
    manifest_digest = b"\x00" * 32
    if args.manifest:
        with open(args.manifest, "rb") as mf:
            manifest_digest = hashlib.sha256(mf.read()).digest()
        has_manifest = 1

    rec_off = find_integrity_record_offset(bytes(buf))
    if text_off <= rec_off < text_off + text_size:
        raise ValueError("Integrity record must not reside inside the hashed code section")

    if args.verify_only:
        _magic, _ver, sealed, bid, rec_has_m, exp_size, exp_code, exp_manifest = (
            struct.unpack_from(RECORD_FMT, buf, rec_off)
        )
        ok = (sealed == 1 and exp_size == text_size and exp_code == code_digest)
        if args.manifest:
            ok = ok and (rec_has_m == 1 and exp_manifest == manifest_digest)
        print(
            f"[seal_binary] {args.binary}: {fmt_name} build_id={bid} size={text_size} "
            f"sealed={sealed} has_manifest={rec_has_m} match={ok}"
        )
        return 0 if ok else 1

    packed = struct.pack(
        RECORD_FMT,
        MAGIC,
        RECORD_VERSION,
        1,
        args.build_id & 0xFFFFFFFF,
        has_manifest,
        text_size,
        code_digest,
        manifest_digest,
    )
    buf[rec_off : rec_off + RECORD_SIZE] = packed

    with open(args.binary, "wb") as f:
        f.write(buf)

    if sys.platform == "darwin" and not args.no_codesign:
        subprocess.run(
            ["codesign", "-s", "-", "--force", args.binary],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    print(
        f"[seal_binary] sealed {args.binary} ({fmt_name}, build_id={args.build_id}, "
        f"size={text_size}, has_manifest={has_manifest}, code_sha256={code_digest.hex()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
