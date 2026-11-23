#!/usr/bin/env python3
"""
Build-time binary sealing tool for re-shield v2 integrity records.

Computes SHA-256 of the executable's code section (__TEXT,__text on 64-bit Mach-O;
.text on 64-bit ELF; .text on PE32+ x64, VirtualSize bytes) and embeds build_id, section size, code digest, and optional
asset manifest root digest into the unique RSHLDCHK v2 record.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

MAGIC = b"RSHLDCHK"
RECORD_VERSION = 2
RECORD_FMT = "<8sIIIIQ32s32s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)

MH_MAGIC_64 = 0xFEEDFACF
# fat/universal Mach-O headers (stored big-endian on disk, so a little-endian read sees the CIGAM forms too)
FAT_MAGICS = (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
LC_SEGMENT_64 = 0x19


def _unpack(fmt: str, data: bytes, offset: int) -> tuple:
    """struct.unpack_from that reports a field outside the file as ValueError (untrusted headers)."""
    try:
        return struct.unpack_from(fmt, data, offset)
    except (struct.error, OverflowError):
        raise ValueError(f"Truncated or out-of-range header field at offset 0x{offset:x}") from None


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
            nsects = _unpack("<I", data, offset + 64)[0]
            sect_off = offset + 72
            for _ in range(nsects):
                sectname = data[sect_off : sect_off + 16].split(b"\x00", 1)[0]
                s_segname = data[sect_off + 16 : sect_off + 32].split(b"\x00", 1)[0]
                _addr, size, file_off = _unpack("<QQI", data, sect_off + 32)
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
    strtab_off, strtab_size = _unpack("<QQ", data, strtab_hdr_off + 24)
    strtab = data[strtab_off : strtab_off + strtab_size]

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name = _unpack("<I", data, sh_off)[0]
        file_off, size = _unpack("<QQ", data, sh_off + 24)
        end = strtab.find(b"\x00", sh_name)
        name = strtab[sh_name:end] if end != -1 else strtab[sh_name:]
        if name == b".text":
            return file_off, size

    raise ValueError("Could not find .text section in ELF binary")


DT_NULL, DT_TEXTREL, DT_FLAGS, DF_TEXTREL, PT_DYNAMIC = 0, 22, 30, 0x4, 2


def check_elf_no_textrel(data: bytes) -> None:
    """Rejects an ELF whose loader patches .text at load time (DT_TEXTREL / DF_TEXTREL):
    the in-memory bytes would differ from the file bytes, so the sealed hash would never match."""
    e_phoff = _unpack("<Q", data, 32)[0]
    e_phentsize, e_phnum = _unpack("<HH", data, 54)
    if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
        return
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = _unpack("<I", data, ph)[0]
        if p_type != PT_DYNAMIC:
            continue
        p_offset, _vaddr, _paddr, p_filesz = _unpack("<QQQQ", data, ph + 8)
        if p_offset > len(data):
            raise ValueError("ELF PT_DYNAMIC lies outside the file")
        for j in range(min(p_filesz, len(data) - p_offset) // 16):
            tag, val = _unpack("<qQ", data, p_offset + j * 16)
            if tag == DT_NULL:
                break
            if tag == DT_TEXTREL or (tag == DT_FLAGS and val & DF_TEXTREL):
                raise ValueError(
                    "ELF has DT_TEXTREL: the loader patches .text at load time, so the sealed hash "
                    "would never match; relink without text relocations (position-independent code)"
                )


# --- PE32+ (Windows x64) ---------------------------------------------------------------

PE_MACHINE_AMD64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
PE_OPT_MAGIC_PE32PLUS = 0x20B
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_REL_BASED_ABSOLUTE = 0
_RELOC_WIDTH = {1: 2, 2: 2, 3: 4, 10: 8}  # HIGH, LOW, HIGHLOW, DIR64: bytes written by the loader
PE_SECTION_HEADER_SIZE = 40


@dataclasses.dataclass(frozen=True)
class PeSection:
    name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclasses.dataclass(frozen=True)
class PeImage:
    checksum_offset: int  # file offset of OptionalHeader.CheckSum
    directories: tuple[tuple[int, int], ...]  # (value, size); Security's value is a FILE offset
    sections: tuple[PeSection, ...]

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)


def parse_pe64(data: bytes) -> PeImage:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not a PE file (missing MZ header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew % 4 != 0 or e_lfanew + 24 > len(data):
        raise ValueError(f"Invalid PE header offset e_lfanew=0x{e_lfanew:x}")
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")
    machine, nsections, _ts, _symtab, _nsyms, opt_size, _chars = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4
    )
    if machine == PE_MACHINE_ARM64:
        raise ValueError("PE ARM64 (Machine 0xAA64) is not supported yet; only x64 (0x8664)")
    if machine != PE_MACHINE_AMD64:
        raise ValueError(f"Unsupported PE Machine 0x{machine:04x}; only x64 (0x8664) is supported")

    opt = e_lfanew + 24
    if opt_size < 112 or opt + opt_size > len(data):
        raise ValueError("PE optional header is truncated")
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != PE_OPT_MAGIC_PE32PLUS:
        raise ValueError(f"Unsupported PE optional header magic 0x{magic:x} (expected PE32+ 0x20b)")
    ndirs = struct.unpack_from("<I", data, opt + 108)[0]
    if ndirs > 16 or 112 + ndirs * 8 > opt_size:
        raise ValueError("PE data directory table is malformed")
    directories = tuple(struct.unpack_from("<II", data, opt + 112 + i * 8) for i in range(ndirs))

    sect_off = opt + opt_size
    if sect_off + nsections * PE_SECTION_HEADER_SIZE > len(data):
        raise ValueError("PE section table is truncated")
    sections = []
    for i in range(nsections):
        off = sect_off + i * PE_SECTION_HEADER_SIZE
        raw_name = data[off : off + 8]
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append(PeSection(raw_name.split(b"\x00", 1)[0], vsize, vaddr, rsize, roff, chars))
    return PeImage(opt + 64, directories, tuple(sections))


def pe_find_text(image: PeImage) -> PeSection:
    texts = [sec for sec in image.sections if sec.name == b".text"]
    if len(texts) != 1:
        raise ValueError(f"Expected exactly one .text section in PE, found {len(texts)}")
    text = texts[0]
    if text.characteristics & IMAGE_SCN_MEM_WRITE:
        raise ValueError(".text section is writable (IMAGE_SCN_MEM_WRITE)")
    if text.virtual_size > text.raw_size:
        raise ValueError(
            f".text VirtualSize ({text.virtual_size}) exceeds SizeOfRawData ({text.raw_size})"
        )
    return text


def pe_rva_to_offset(image: PeImage, rva: int) -> int:
    for sec in image.sections:
        span = max(sec.virtual_size, sec.raw_size)
        if sec.virtual_address <= rva < sec.virtual_address + span:
            delta = rva - sec.virtual_address
            if delta >= sec.raw_size:
                break
            return sec.raw_offset + delta
    raise ValueError(f"RVA 0x{rva:x} is not backed by file data in any section")


def find_pe64_text(data: bytes) -> tuple[int, int]:
    text = pe_find_text(parse_pe64(data))
    return text.raw_offset, text.virtual_size


def pe_text_relocations(data: bytes, image: PeImage) -> tuple[int, int]:
    """Counts base relocations that land inside .text: (count, first RVA or -1)."""
    text = pe_find_text(image)
    rva, size = image.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
    if size == 0:
        return 0, -1
    start = pe_rva_to_offset(image, rva)
    if start + size > len(data):
        raise ValueError("PE base relocation directory extends past end of file")
    count, first = 0, -1
    pos, end = start, start + size
    while pos < end:
        if end - pos < 8:
            raise ValueError("Malformed PE base relocation block header")
        page_rva, block_size = struct.unpack_from("<II", data, pos)
        if block_size < 8 or block_size % 2 != 0 or pos + block_size > end:
            raise ValueError(f"Malformed PE base relocation block (size {block_size})")
        for i in range((block_size - 8) // 2):
            entry = struct.unpack_from("<H", data, pos + 8 + i * 2)[0]
            if entry >> 12 == IMAGE_REL_BASED_ABSOLUTE:
                continue
            target = page_rva + (entry & 0xFFF)
            # The loader patches `width` bytes at target; a patch that starts before .text but
            # ends inside it still changes the hashed bytes. Unknown types: assume the widest.
            width = _RELOC_WIDTH.get(entry >> 12, 8)
            if target < text.virtual_address + text.virtual_size and target + width > text.virtual_address:
                count += 1
                if first < 0:
                    first = target
        pos += block_size
    return count, first


def pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Standard PE checksum: 16-bit one's-complement word sum (CheckSum field as zero) + file size."""
    total = 0
    for off in range(0, len(data) - 1, 2):
        if checksum_offset <= off < checksum_offset + 4:
            continue
        total += data[off] | (data[off + 1] << 8)
    if len(data) % 2:
        total += data[-1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total + len(data)


def check_pe_sealable(data: bytes, rec_off: int) -> None:
    """Seal-time checks; a PE failing any of them cannot be sealed safely."""
    image = parse_pe64(data)
    text = pe_find_text(image)

    _sec_value, sec_size = image.directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
    if sec_size != 0:
        raise ValueError(
            "PE already carries an Authenticode signature (Security directory is not empty): "
            "seal before signing"
        )

    n_reloc, first_rva = pe_text_relocations(data, image)
    if n_reloc:
        raise ValueError(
            f"{n_reloc} base relocation(s) fall inside .text (first at RVA 0x{first_rva:x}): "
            "the loaded code would differ from the file, so the hash cannot match"
        )

    rec_end = rec_off + RECORD_SIZE
    host = [
        sec for sec in image.sections
        if sec.raw_offset <= rec_off and rec_end <= sec.raw_offset + sec.raw_size
    ]
    if not host or not (host[0].characteristics & IMAGE_SCN_MEM_WRITE) or host[0] is text:
        raise ValueError("Integrity record must live in a writable data section (e.g. .data)")

    others = [
        sec.name.decode("ascii", "replace") for sec in image.sections
        if sec is not text and sec.characteristics & IMAGE_SCN_MEM_EXECUTE
    ]
    if others:
        print(
            f"[seal_binary] warning: other executable section(s) are not hashed: {', '.join(others)}",
            file=sys.stderr,
        )


def find_code_section(data: bytes) -> tuple[str, int, int]:
    if data[:4] in FAT_MAGICS:
        raise ValueError(
            "fat/universal Mach-O is not supported; seal each architecture slice "
            "(e.g. `lipo -thin`) and re-assemble, or build a thin binary"
        )
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == MH_MAGIC_64:
        off, size = find_macho64_text(data)
        return "macho64(__TEXT,__text)", off, size
    if data[:4] == b"\x7fELF":
        off, size = find_elf64_text(data)
        check_elf_no_textrel(data)
        return "elf64(.text)", off, size
    if data[:2] == b"MZ":
        off, size = find_pe64_text(data)
        return "pe64(.text)", off, size
    raise ValueError("Unsupported binary format (expected 64-bit Mach-O, ELF or PE32+ x64)")


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
    parser.add_argument("binary", help="Path to the compiled Mach-O, ELF or PE32+ executable")
    parser.add_argument("--manifest", help="Optional asset manifest file to bind into the binary")
    parser.add_argument("--build-id", type=int, default=1, help="Numeric build identifier (default: 1)")
    parser.add_argument("--verify-only", action="store_true", help="Check seal without modifying file")
    parser.add_argument("--no-codesign", action="store_true", help="Skip macOS ad-hoc codesign (Mach-O only)")
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
    # Any overlap with the hashed section is an error, not only a record that starts inside it.
    if rec_off < text_off + text_size and rec_off + RECORD_SIZE > text_off:
        raise ValueError("Integrity record must not overlap the hashed code section")

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

    if fmt_name.startswith("pe64"):
        check_pe_sealable(bytes(buf), rec_off)

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

    if fmt_name.startswith("pe64"):
        # A zero CheckSum means "not computed" and stays zero; otherwise keep it consistent.
        cs_off = parse_pe64(bytes(buf)).checksum_offset
        if struct.unpack_from("<I", buf, cs_off)[0] != 0:
            struct.pack_into("<I", buf, cs_off, 0)
            struct.pack_into("<I", buf, cs_off, pe_checksum(bytes(buf), cs_off))

    # Write next to the target and rename over it so a failed write never leaves a truncated binary.
    target = os.path.realpath(args.binary)
    fd, tmp_path = tempfile.mkstemp(prefix=".seal_", dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(buf)
        shutil.copymode(target, tmp_path)
        os.replace(tmp_path, target)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    if sys.platform == "darwin" and not args.no_codesign and fmt_name.startswith("macho"):
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
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"[seal_binary] error: {exc}", file=sys.stderr)
        raise SystemExit(2)
