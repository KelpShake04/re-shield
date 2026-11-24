#!/usr/bin/env python3
"""
CI / release verification CLI for re-shield sealed binaries.

Checks:
1. Binary has a valid, matching RSHLDCHK v2 seal (code section SHA-256).
2. If --manifest and --assets are provided, verifies manifest root binding and all assets.
3. Reports defined symbol count via nm (helpful to confirm release strip).
4. Warns (exit code unchanged) when a steam_appid.txt sits next to the binary, in --assets or in
   the manifest: Steam uses that file for development runs, so shipping it is not recommended.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
import seal_binary  # noqa: E402
from manifest_path import is_safe_relative_path  # noqa: E402


def count_defined_symbols(binary: str) -> int | str:
    """Defined symbol count via nm, or "n/a" when nm is not installed (e.g. a Windows CI box)."""
    try:
        proc = subprocess.run(["nm", binary], capture_output=True, text=True)
    except FileNotFoundError:
        return "n/a"
    if proc.returncode != 0:
        return 0
    return sum(
        1 for ln in proc.stdout.splitlines()
        if len(ln.split()) >= 3 and ln.split()[1] != "U"
    )


STEAM_APPID = "steam_appid.txt"


def steam_appid_warnings(binary: str, asset_dir: str | None, manifest: str | None) -> list[str]:
    """Where a steam_appid.txt was found (case-insensitive, like Windows). Only a hint, never a failure."""
    found = []
    for label, d in (("next to the binary", os.path.dirname(os.path.abspath(binary))),
                     ("in --assets", asset_dir)):
        if d and os.path.isdir(d) and any(n.lower() == STEAM_APPID for n in os.listdir(d)):
            found.append(f"{label} ({d})")
    if manifest:
        with open(manifest, "rb") as f:
            for raw in f.read().decode("utf-8", "replace").split("\n"):
                if raw and not raw.startswith("#") and raw.split(" ", 2)[-1].lower().split("/")[-1] == STEAM_APPID:
                    found.append(f"in the manifest ({raw.split(' ', 2)[-1]})")
    return found


def verify_manifest_entries(manifest_path: str, asset_dir: str) -> tuple[bool, int, str]:
    count = 0
    with open(manifest_path, "rb") as f:
        raw_all = f.read()
    # Same as the C runtime: CRLF / NUL manifests are rejected, not silently normalized.
    if b"\r" in raw_all or b"\0" in raw_all:
        return False, count, "manifest contains CR or NUL"
    for raw in raw_all.decode("utf-8").split("\n"):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(" ", 2)
        if len(parts) != 3:
            return False, count, f"malformed line: {raw}"
        exp_hex, exp_size_s, rel = parts
        if not (exp_size_s.isascii() and exp_size_s.isdigit()):
            return False, count, f"malformed line: {raw}"
        if not is_safe_relative_path(rel):
            return False, count, f"unsafe path: {rel!r}"
        full = os.path.join(asset_dir, rel)
        if not os.path.isfile(full):
            return False, count, f"missing asset: {rel}"
        with open(full, "rb") as af:
            data = af.read()
        if len(data) != int(exp_size_s) or hashlib.sha256(data).hexdigest() != exp_hex:
            return False, count, f"hash/size mismatch: {rel}"
        count += 1
    return count > 0, count, "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a sealed release artifact")
    parser.add_argument("binary", help="Path to sealed executable")
    parser.add_argument("--manifest", help="Path to bound asset manifest")
    parser.add_argument("--assets", help="Path to asset base directory")
    args = parser.parse_args()

    with open(args.binary, "rb") as f:
        data = f.read()

    fmt_name, text_off, text_size = seal_binary.find_code_section(data)
    rec_off = seal_binary.find_integrity_record_offset(data)
    _magic, _ver, sealed, build_id, has_m, exp_size, exp_code, exp_manifest = (
        struct.unpack_from(seal_binary.RECORD_FMT, data, rec_off)
    )

    actual_code = hashlib.sha256(data[text_off : text_off + text_size]).digest()
    code_ok = (sealed == 1 and exp_size == text_size and exp_code == actual_code)

    manifest_ok = True
    asset_msg = "not checked"
    if args.manifest:
        with open(args.manifest, "rb") as mf:
            actual_m = hashlib.sha256(mf.read()).digest()
        manifest_ok = (has_m == 1 and exp_manifest == actual_m)
        if manifest_ok and args.assets:
            assets_ok, n_assets, detail = verify_manifest_entries(args.manifest, args.assets)
            manifest_ok = manifest_ok and assets_ok
            asset_msg = f"{n_assets} asset(s) verified ({detail})"
        else:
            asset_msg = "manifest root mismatch" if not manifest_ok else "root verified"

    syms = count_defined_symbols(args.binary)
    print(f"[verify_release] binary={args.binary} ({fmt_name}, build_id={build_id})")
    print(f"  code_seal:       {'OK' if code_ok else 'FAIL'} (size={text_size})")
    print(f"  manifest_assets: {'OK' if manifest_ok else 'FAIL'} ({asset_msg})")
    print(f"  defined_symbols: {syms}")

    for where in steam_appid_warnings(args.binary, args.assets, args.manifest):
        print(f"[verify_release] warning: {STEAM_APPID} found {where}. Steam reads it for development runs; "
              "recommended: do not ship it in a release build.", file=sys.stderr)

    return 0 if (code_ok and manifest_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
