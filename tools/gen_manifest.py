#!/usr/bin/env python3
"""
Generate a deterministic SHA-256 asset manifest for a first-party asset directory.

Output format (UTF-8, sorted by relative POSIX path):
  <64-hex-sha256> <byte-size> <relative-path>
"""

from __future__ import annotations

import argparse
import hashlib
import os


def sha256_file(path: str) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def generate_manifest(asset_dir: str, output_path: str) -> str:
    entries: list[tuple[str, int, str]] = []
    for root, _dirs, files in os.walk(asset_dir):
        for name in files:
            if name.startswith("."):
                continue
            full = os.path.join(root, name)
            if os.path.abspath(full) == os.path.abspath(output_path):
                continue
            rel = os.path.relpath(full, asset_dir).replace(os.sep, "/")
            digest_hex, size = sha256_file(full)
            entries.append((rel, size, digest_hex))

    entries.sort(key=lambda item: item[0])
    if not entries:
        raise ValueError(f"No asset files found in {asset_dir}")

    lines = [f"{digest_hex} {size} {rel}\n" for rel, size, digest_hex in entries]
    content = "".join(lines).encode("utf-8")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(content)

    root_hex = hashlib.sha256(content).hexdigest()
    print(
        f"[gen_manifest] wrote {output_path} ({len(entries)} asset(s), "
        f"root_sha256={root_hex})"
    )
    return root_hex


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SHA-256 asset manifest")
    parser.add_argument("asset_dir", help="Directory containing game/app assets")
    parser.add_argument("-o", "--output", required=True, help="Output manifest file path")
    args = parser.parse_args()
    generate_manifest(args.asset_dir, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
