#!/usr/bin/env python3
"""
Generate a deterministic SHA-256 asset manifest for a first-party asset directory.

Output format (UTF-8, sorted by relative POSIX path):
  <64-hex-sha256> <byte-size> <relative-path>

--strict writes a manifest v2 header so the runtime also rejects files that are not listed
(RESHIELD_ERR_ASSET_EXTRA); --allow GLOB (repeatable) exempts paths from that scan:
  #reshield-manifest v2 strict
  #allow <glob>
Strict adds .DS_Store, Thumbs.db and desktop.ini (any folder) to the allow list, and the
manifest itself / --exclude files when they sit inside the asset dir. The header is part of
the sealed manifest bytes, so the allow list is sealed with the root hash.

Policy:
- Files whose own name starts with "." are skipped.
- Directories whose name starts with "." are still traversed; their non-dot files
  are listed (only the file name is filtered, not the directory components).
- Relative paths must follow the same rule as the C runtime (see manifest_path.py).
  Violations raise ValueError instead of producing a manifest the runtime would reject.
- Strict runtime scans compare raw names and also see dotfiles: a skipped dotfile that no
  #allow matches would be reported as extra, so this tool warns about each one.
- Names that are not NFC-normalized, and names that collide when case-folded
  ("A.cfg" / "a.cfg"), raise ValueError: they would not verify on every filesystem.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import unicodedata

from manifest_path import is_safe_relative_path
from manifest_policy import MAX_ALLOW, glob_match, is_valid_glob

# Names the OS drops into folders on its own: allowed by default in strict mode (and, in
# strict mode, not listed, because the OS rewrites them).
OS_LITTER = (".DS_Store", "Thumbs.db", "desktop.ini")
DEFAULT_ALLOW = [f"{pre}{n}" for n in OS_LITTER for pre in ("", "*/")]


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


def generate_manifest(asset_dir: str, output_path: str, strict: bool = False,
                      allow: list[str] | None = None, exclude: list[str] | None = None) -> str:
    """exclude: files (paths) that are not listed even if they sit inside asset_dir."""
    if allow and not strict:
        raise ValueError("--allow needs --strict")
    skip = {os.path.abspath(output_path)} | {os.path.abspath(e) for e in exclude or []}
    allow_list: list[str] = []
    if strict:
        base = os.path.abspath(asset_dir)
        inside = []
        for path in sorted(skip):
            rel = os.path.relpath(path, base).replace(os.sep, "/")
            if rel != ".." and not rel.startswith("../") and not os.path.isabs(rel):
                if "*" in rel or "?" in rel:
                    raise ValueError(f"Cannot auto-allow a name containing '*' or '?': {rel!r}")
                inside.append(rel)
        for g in DEFAULT_ALLOW + inside + list(allow or []):
            if not is_valid_glob(g):
                raise ValueError(f"Invalid --allow glob: {g!r}")
            if g not in allow_list:
                allow_list.append(g)
        if len(allow_list) > MAX_ALLOW:
            raise ValueError(f"Too many allow globs: {len(allow_list)} > {MAX_ALLOW}")

    entries: list[tuple[str, int, str]] = []
    for root, dirs, files in os.walk(asset_dir):
        if strict:
            for d in dirs:
                if os.path.islink(os.path.join(root, d)):
                    print(f"[gen_manifest] warning: symlinked directory not traversed, a strict "
                          f"runtime reports ASSET_EXTRA for it: {os.path.join(root, d)}")
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, asset_dir).replace(os.sep, "/")
            if name.startswith("."):
                if strict and not any(glob_match(g, rel) for g in allow_list):
                    print(f"[gen_manifest] warning: dotfile skipped but not allowed, a strict "
                          f"runtime reports ASSET_EXTRA for it: {rel!r} (add --allow)")
                continue
            if os.path.abspath(full) in skip:
                continue
            if strict and name in OS_LITTER:
                continue  # allowed by default, not listed: the OS rewrites these files
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
        raise ValueError(f"No asset files found in {asset_dir}")

    header = ""
    if strict:
        header = "#reshield-manifest v2 strict\n" + "".join(f"#allow {g}\n" for g in allow_list)
    lines = [f"{digest_hex} {size} {rel}\n" for rel, size, digest_hex in entries]
    content = (header + "".join(lines)).encode("utf-8")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(content)

    root_hex = hashlib.sha256(content).hexdigest()
    print(
        f"[gen_manifest] wrote {output_path} ({len(entries)} asset(s)"
        f"{', strict, ' + str(len(allow_list)) + ' allow' if strict else ''}, "
        f"root_sha256={root_hex})"
    )
    return root_hex


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SHA-256 asset manifest")
    parser.add_argument("asset_dir", help="Directory containing game/app assets")
    parser.add_argument("-o", "--output", required=True, help="Output manifest file path")
    parser.add_argument("--strict", action="store_true",
                        help="Write a v2 strict header: the runtime rejects unlisted files (ASSET_EXTRA)")
    parser.add_argument("--allow", action="append", default=[], metavar="GLOB",
                        help="With --strict: path glob exempt from the scan ('*' any string incl. '/', "
                             "'?' one byte, case-sensitive, relative POSIX path); repeatable")
    parser.add_argument("--exclude", action="append", default=[], metavar="FILE",
                        help="File that must not be listed (e.g. the binary to seal when it sits in "
                             "the asset dir); allowed automatically with --strict; repeatable")
    args = parser.parse_args()
    if args.allow and not args.strict:
        parser.error("--allow needs --strict")
    generate_manifest(args.asset_dir, args.output, args.strict, args.allow, args.exclude)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
