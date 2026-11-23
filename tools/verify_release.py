#!/usr/bin/env python3
"""
CI / release verification CLI for re-shield sealed binaries.

Checks:
1. Binary has a valid, matching RSHLDCHK v2 seal (code section SHA-256).
2. If --manifest and --assets are provided, verifies manifest root binding and all assets.
3. Reports defined symbol count via nm (helpful to confirm release strip).
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


def count_defined_symbols(binary: str) -> int:
    proc = subprocess.run(["nm", binary], capture_output=True, text=True)
    if proc.returncode != 0:
        return 0
    return sum(
        1 for ln in proc.stdout.splitlines()
        if len(ln.split()) >= 3 and ln.split()[1] != "U"
    )


def verify_manifest_entries(manifest_path: str, asset_dir: str) -> tuple[bool, int, str]:
    count = 0
    with open(manifest_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(" ", 2)
            if len(parts) != 3:
                return False, count, f"malformed line: {line}"
            exp_hex, exp_size_s, rel = parts
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

    return 0 if (code_ok and manifest_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
