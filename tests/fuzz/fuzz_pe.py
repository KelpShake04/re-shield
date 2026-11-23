#!/usr/bin/env python3
"""Deterministic mutation fuzzer for the binary parsers in tools/seal_binary.py.

Starts from small synthetic PE32+, ELF64 and Mach-O64 images, mutates bytes with a fixed
RNG seed and feeds every result to the parser functions. The contract under test: malformed
input is rejected with ValueError, never with IndexError / struct.error / OverflowError /
MemoryError or a hang (each case has a time limit). Standard library only.

    python3 tests/fuzz/fuzz_pe.py [--iterations N] [--seed S] [--out DIR]

Exit code 1 if any unexpected exception or hang was seen (distinct findings are printed and
the first reproducer of each is written to --out).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import random
import signal
import struct
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import seal_binary as sb  # noqa: E402

RECORD = struct.pack(sb.RECORD_FMT, sb.MAGIC, sb.RECORD_VERSION, 0, 1, 0, 0, bytes(32), bytes(32))


def seed_pe() -> bytes:
    """Minimal PE32+ x64: .text (r-x) at RVA 0x1000, .data (rw-, holds the record), .reloc."""
    e_lfanew, opt_size, headers = 0x80, 112 + 16 * 8, 0x400
    text = bytes(range(0x40)).ljust(0x200, b"\0")
    data = (RECORD + b"\xAA" * 40).ljust(0x200, b"\0")
    reloc = (struct.pack("<II", 0x2000, 12) + struct.pack("<HH", 0x3000 | 0x10, 0)).ljust(0x200, b"\0")
    secs = [  # name, vsize, vaddr, rawsize, rawoff, flags
        (b".text", 0x40, 0x1000, 0x200, 0x400, 0x60000020),
        (b".data", len(RECORD) + 40, 0x2000, 0x200, 0x600, 0xC0000040),
        (b".reloc", 12, 0x3000, 0x200, 0x800, 0x42000040),
    ]
    sect_hdrs = b"".join(
        struct.pack("<8sIIIIIIHHI", n, vs, va, rs, ro, 0, 0, 0, 0, fl) for n, vs, va, rs, ro, fl in secs
    )
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt = bytearray(opt_size)
    struct.pack_into("<HBB", opt, 0, sb.PE_OPT_MAGIC_PE32PLUS, 14, 0)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 5 * 8, 0x3000, 12)
    fh = struct.pack("<HHIIIHH", sb.PE_MACHINE_AMD64, len(secs), 0, 0, 0, opt_size, 0x22)
    hdr = bytes(dos).ljust(e_lfanew, b"\0") + b"PE\0\0" + fh + bytes(opt) + sect_hdrs
    return hdr.ljust(headers, b"\0") + text + data + reloc


def seed_elf() -> bytes:
    text = b"\x90" * 16
    shstr = b"\0.text\0.shstrtab\0"
    off_text, off_str = 64, 64 + len(text)
    off_sh = (off_str + len(shstr) + 7) & ~7
    ehdr = bytearray(64)
    ehdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", ehdr, 40, off_sh)
    struct.pack_into("<HHH", ehdr, 58, 64, 3, 2)

    def sh(name: int, off: int, size: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, 1, 0, 0, off, size, 0, 0, 1, 0)

    shdrs = sh(0, 0, 0) + sh(1, off_text, len(text)) + sh(7, off_str, len(shstr))
    return (bytes(ehdr) + text + shstr).ljust(off_sh, b"\0") + shdrs


def seed_macho() -> bytes:
    text = b"\x90" * 32
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x1000, len(text), 32 + 152, 0, 0, 0, 0, 0, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", sb.LC_SEGMENT_64, 72 + 80, b"__TEXT", 0, 0x1000, 0, 0, 5, 5, 1, 0)
    hdr = struct.pack("<IIIIIIII", sb.MH_MAGIC_64, 0x0100000C, 0, 2, 1, len(seg) + len(sect), 0, 0)
    return hdr + seg + sect + text


INTERESTING = [0, 1, 2, 7, 8, 0x3F, 0x40, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
               0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 2**63 - 1, 2**63, 2**64 - 1]


def mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        if not b:
            b = bytearray(rng.randbytes(rng.randint(0, 8)))
            continue
        op = rng.randrange(9)
        pos = rng.randrange(len(b))
        if op == 0:
            b[pos] ^= 1 << rng.randrange(8)
        elif op == 1:
            b[pos] = rng.choice((0, 0xFF, 0x7F, 0x80, rng.randrange(256)))
        elif op in (2, 3, 4):
            width = (2, 4, 8)[op - 2]
            val = rng.choice(INTERESTING + [len(b), len(b) - 1, len(b) + 1, pos]) % (1 << (8 * width))
            if rng.random() < 0.5:
                pos -= pos % width
            if pos + width <= len(b):
                b[pos : pos + width] = val.to_bytes(width, "little")
        elif op == 5:
            b = b[: rng.randrange(len(b) + 1)]
        elif op == 6:
            b += bytes(rng.randrange(1, 64))
        elif op == 7:
            end = min(len(b), pos + rng.randrange(1, 32))
            del b[pos:end]
        else:
            end = min(len(b), pos + rng.randrange(1, 32))
            dst = rng.randrange(len(b))
            b[dst : dst + (end - pos)] = b[pos:end]
    return bytes(b)


class Hang(BaseException):
    pass


def _alarm(_sig, _frm):
    raise Hang("case exceeded time limit")


def exercise(data: bytes, rng: random.Random, tmpdir: str, heavy: bool) -> None:
    """Calls the parser entry points; ValueError is the only accepted failure."""
    calls = [
        lambda: sb.find_code_section(data),
        lambda: sb.find_macho64_text(data),
        lambda: sb.find_elf64_text(data),
        lambda: sb.find_pe64_text(data),
        lambda: sb.find_integrity_record_offset(data),
        lambda: sb.pe_checksum(data, rng.randrange(0, max(1, len(data)))),
    ]

    def pe_chain() -> None:
        image = sb.parse_pe64(data)
        sb.pe_text_relocations(data, image)
        sb.pe_rva_to_offset(image, rng.choice(INTERESTING + [0x1000, 0x2000, 0x3000]))
        sb.check_pe_sealable(data, rng.choice([0, 0x600, 0x600 + 8, len(data) // 2, len(data)]))

    calls.append(pe_chain)
    for call in calls:
        try:
            with contextlib.redirect_stderr(io.StringIO()):  # check_pe_sealable warns on stderr
                call()
        except ValueError:
            pass

    if heavy:  # whole CLI path on a file (stdout/stderr noise suppressed)
        path = os.path.join(tmpdir, "case.bin")
        with open(path, "wb") as f:
            f.write(data)
        for extra in (["--verify-only"], []):
            argv = ["seal_binary.py", path, "--no-codesign"] + extra
            old = sys.argv
            sys.argv = argv
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    sb.main()
            except ValueError:
                pass
            finally:
                sys.argv = old


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iterations", type=int, default=6000, help="mutated cases per seed image")
    ap.add_argument("--seed", type=int, default=20260101)
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "fuzz_pe_findings"))
    ap.add_argument("--time-limit", type=float, default=2.0, help="seconds per case")
    args = ap.parse_args()

    seeds = {"pe": seed_pe(), "elf": seed_elf(), "macho": seed_macho()}
    # Sanity: the unmutated seeds must parse, otherwise the fuzzer would test nothing.
    assert sb.find_code_section(seeds["pe"])[0] == "pe64(.text)"
    assert sb.find_code_section(seeds["elf"])[0] == "elf64(.text)"
    assert sb.find_code_section(seeds["macho"])[0] == "macho64(__TEXT,__text)"

    rng = random.Random(args.seed)
    findings: dict[tuple, tuple[str, bytes]] = {}
    cases = 0
    start = time.time()
    use_alarm = hasattr(signal, "setitimer")
    if use_alarm:
        signal.signal(signal.SIGALRM, _alarm)
    with tempfile.TemporaryDirectory(prefix="fuzz_pe_") as tmp:
        for name, seed in seeds.items():
            for i in range(args.iterations):
                data = seed if i == 0 else mutate(rng, seed if rng.random() < 0.7 else mutate(rng, seed))
                if use_alarm:
                    signal.setitimer(signal.ITIMER_REAL, args.time_limit)
                try:
                    exercise(data, rng, tmp, heavy=(i % 25 == 0))
                except BaseException as exc:  # noqa: BLE001 - everything but ValueError is a finding
                    if isinstance(exc, KeyboardInterrupt):
                        raise
                    tb = traceback.extract_tb(exc.__traceback__)
                    frame = next((f for f in reversed(tb) if f.filename.endswith("seal_binary.py")), tb[-1])
                    key = (type(exc).__name__, os.path.basename(frame.filename), frame.lineno)
                    if key not in findings:
                        findings[key] = (f"{type(exc).__name__}: {exc}", data)
                finally:
                    if use_alarm:
                        signal.setitimer(signal.ITIMER_REAL, 0)
                cases += 1
    elapsed = time.time() - start

    print(f"[fuzz_pe] seed={args.seed} cases={cases} elapsed={elapsed:.1f}s findings={len(findings)}")
    if findings:
        os.makedirs(args.out, exist_ok=True)
        for n, ((etype, fname, line), (msg, data)) in enumerate(sorted(findings.items())):
            path = os.path.join(args.out, f"finding-{n:02d}-{etype}-{fname}-{line}.bin")
            with open(path, "wb") as f:
                f.write(data)
            print(f"  {etype} at {fname}:{line}: {msg}\n    repro: {path}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
