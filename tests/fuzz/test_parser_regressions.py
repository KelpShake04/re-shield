#!/usr/bin/env python3
"""Regression cases found by tests/fuzz/fuzz_pe.py: malformed ELF / Mach-O headers must be
rejected with ValueError (they used to escape as struct.error / OverflowError)."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_pe  # noqa: E402

import manifest_policy as mp  # noqa: E402
import seal_binary as sb  # noqa: E402 (fuzz_pe put tools/ on sys.path)


def expect_value_error(fn, data: bytes, what: str) -> None:
    try:
        fn(data)
    except ValueError:
        return
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"{what}: expected ValueError, got {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"{what}: malformed input was accepted")


def test_manifest_policy() -> None:
    """Manifest v2 header parser (tools/manifest_policy.py mirrors src/manifest.c): every malformed
    header is rejected, '#' after the first entry too, and the glob matcher cannot blow up."""
    entry = "0" * 64 + " 1 a.cfg\n"
    h = "#reshield-manifest v2 strict\n"
    for bad in ("#reshield-manifest v3\n", "#reshield-manifest v2 loose\n", "#reshield-manifest\n",
                h + h, h + "#unknown\n", h + "#allow\n", h + "#allow /abs\n", h + "#allow ../x\n",
                h + "#allow a/..\n", h + "#allow a\\b\n", h + "#allow a\x01b\n", "#allow x\n" + h,
                h + "#allow " + "g" * 256 + "\n",
                h + "".join(f"#allow g{i}\n" for i in range(65)),
                entry + "# late\n", entry + h, "\r\n" + entry, entry.replace(" 1 ", " x ")):
        try:
            mp.parse_manifest((bad if bad.endswith("\n") and "a.cfg" in bad else bad + entry).encode())
        except mp.ManifestError:
            continue
        raise AssertionError(f"manifest header accepted: {bad!r}")
    pol, ents = mp.parse_manifest((h + "#allow *.log\n" + entry).encode())
    assert pol.strict and pol.allow == ["*.log"] and len(ents) == 1

    # Backtracking matcher: many stars against a long non-matching string stays fast.
    start = time.monotonic()
    assert not mp.glob_match("a*" * 40 + "b", "a" * 4000)
    assert time.monotonic() - start < 5, "glob matcher is too slow"

    with tempfile.TemporaryDirectory(prefix="reshield_pol_") as d:
        deep = os.path.join(d, *["d"] * 32)
        os.makedirs(deep)
        assert mp.find_extra(d, set(), []) is None, "32 nested empty directories pass"
        os.makedirs(os.path.join(deep, "d"))
        assert mp.find_extra(d, set(), []).startswith("<scan incomplete"), "33 levels cannot be verified"
    print("PASS: manifest v2 header parser, glob matcher and scan limits")


def main() -> int:
    test_manifest_policy()
    elf = bytearray(fuzz_pe.seed_elf())
    macho = bytearray(fuzz_pe.seed_macho())

    # ELF: section header table starts exactly at EOF, beyond EOF, and at an absurd offset.
    for shoff in (len(elf), len(elf) + 1, 1 << 40, (1 << 64) - 1):
        bad = bytearray(elf)
        struct.pack_into("<Q", bad, 40, shoff)
        expect_value_error(sb.find_elf64_text, bytes(bad), f"ELF e_shoff=0x{shoff:x}")
    # ELF: last section header cut in half.
    expect_value_error(sb.find_elf64_text, bytes(elf[:-30]), "ELF truncated section header")

    # Mach-O: nsects far beyond the file, with no __text among the sections that do exist.
    bad = bytearray(macho)
    bad[32 + 72 : 32 + 72 + 16] = b"__other".ljust(16, b"\0")
    struct.pack_into("<I", bad, 32 + 64, 0xFFFFFFFF)
    expect_value_error(sb.find_macho64_text, bytes(bad), "Mach-O nsects=0xffffffff")
    expect_value_error(sb.find_macho64_text, bytes(macho[: 32 + 70]), "Mach-O file cut inside segment")

    # ELF: DT_TEXTREL / DF_TEXTREL make the loader patch .text; the sealer must refuse such a file.
    def with_dynamic(entries):
        dyn = b"".join(struct.pack("<qQ", t, v) for t, v in entries) + struct.pack("<qQ", 0, 0)
        ph_off = len(elf)
        out = bytearray(elf)
        struct.pack_into("<Q", out, 32, ph_off)
        struct.pack_into("<HH", out, 54, 56, 1)
        out += struct.pack("<IIQQQQQQ", sb.PT_DYNAMIC, 0, ph_off + 56, 0, 0, len(dyn), len(dyn), 8)
        out += dyn
        return bytes(out)

    expect_value_error(sb.check_elf_no_textrel, with_dynamic([(sb.DT_TEXTREL, 0)]), "ELF DT_TEXTREL")
    expect_value_error(sb.check_elf_no_textrel, with_dynamic([(sb.DT_FLAGS, sb.DF_TEXTREL | 8)]),
                       "ELF DF_TEXTREL")
    sb.check_elf_no_textrel(with_dynamic([(sb.DT_FLAGS, 8)]))  # DF_BIND_NOW alone is fine
    sb.check_elf_no_textrel(bytes(elf))  # no program headers: nothing to reject

    # The unmutated seeds still parse.
    assert sb.find_elf64_text(bytes(elf))[1] == 16
    assert sb.find_macho64_text(bytes(macho))[1] == 32
    print("PASS: ELF/Mach-O header bounds regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
