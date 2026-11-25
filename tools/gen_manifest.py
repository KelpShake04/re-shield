#!/usr/bin/env python3
"""
Generate a deterministic SHA-256 asset manifest for a first-party asset directory.

Output format (UTF-8, sorted by relative POSIX path):
  <64-hex-sha256> <byte-size> <relative-path>

Policy:
- Files whose own name starts with "." are skipped.
- Directories whose name starts with "." are still traversed; their non-dot files
  are listed (only the file name is filtered, not the directory components).
- Relative paths must follow the same rule as the C runtime (see manifest_path.py).
  Violations raise ValueError instead of producing a manifest the runtime would reject.
- Names that are not NFC-normalized, and names that collide when case-folded
  ("A.cfg" / "a.cfg"), raise ValueError: they would not verify on every filesystem.
- --exclude GLOB (repeatable) drops files whose relative POSIX path matches, using
  fnmatch.fnmatchcase (case-sensitive; "*" also matches "/", so "*.pdb" and "dir/*" cover
  subdirectories). Excluded files are skipped before the path checks above.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import unicodedata

from manifest_path import is_safe_relative_path


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


def generate_manifest(asset_dir: str, output_path: str, exclude: tuple[str, ...] = ()) -> str:
    entries: list[tuple[str, int, str]] = []
    excluded = 0
    for root, _dirs, files in os.walk(asset_dir):
        for name in files:
            if name.startswith("."):
                continue
            full = os.path.join(root, name)
            if os.path.abspath(full) == os.path.abspath(output_path):
                continue
            rel = os.path.relpath(full, asset_dir).replace(os.sep, "/")
            if any(fnmatch.fnmatchcase(rel, pattern) for pattern in exclude):
                excluded += 1
                continue
            if not is_safe_relative_path(rel):
                raise ValueError(f"Unsafe asset path for manifest: {rel!r}")
            if not unicodedata.is_normalized("NFC", rel):
                raise ValueError(f"Asset path is not NFC-normalized: {rel!r}")
            digest_hex, size = sha256_file(full)
            entries.append((rel, size, digest_hex))

    entries.sort(key=lambda item: item[0])
    seen: dict[str, str] = {}
    for rel, _size, _digest in entries:
        other = seen.setdefault(rel.casefold(), rel)
        if other != rel:
            raise ValueError(f"Asset paths differ only by case: {other!r} and {rel!r}")
    if not entries:
        raise ValueError(f"No asset files found in {asset_dir}"
                         + (f" ({excluded} excluded by --exclude)" if excluded else ""))

    lines = [f"{digest_hex} {size} {rel}\n" for rel, size, digest_hex in entries]
    content = "".join(lines).encode("utf-8")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(content)

    root_hex = hashlib.sha256(content).hexdigest()
    print(
        f"[gen_manifest] wrote {output_path} ({len(entries)} asset(s)"
        + (f", {excluded} excluded" if excluded else "") + f", root_sha256={root_hex})"
    )
    return root_hex


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SHA-256 asset manifest")
    parser.add_argument("asset_dir", help="Directory containing game/app assets")
    parser.add_argument("-o", "--output", required=True, help="Output manifest file path")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="Skip files whose relative POSIX path matches GLOB (fnmatchcase); repeatable")
    args = parser.parse_args()
    generate_manifest(args.asset_dir, args.output, tuple(args.exclude))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
