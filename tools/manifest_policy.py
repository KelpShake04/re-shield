"""
Manifest v2 header and strict-scan rules shared by gen_manifest.py and verify_release.py.

Must stay identical to the parser in src/manifest.c (next_manifest_entry / parse_header_line /
is_valid_glob / glob_match / reshield_dir_walk limits):

- Leading '#' lines are the header. "# ..." and a bare "#" are comments. Directives:
  "#reshield-manifest v2" / "#reshield-manifest v2 strict" (once, before any #allow) and
  "#allow <glob>" (at most 64). Any other '#' line, and any '#' line after the first entry,
  is an error (fail closed). Lines over 1023 bytes, CR and NUL are errors.
- Glob: relative POSIX path pattern, 1..255 bytes, no leading '/', no control characters or
  backslash, no ".." component. '*' = any byte string (also '/'), '?' = any single byte,
  case-sensitive, matched on the UTF-8 bytes.
- Strict scan: an item under the asset dir (file, symlink, special file; links are not
  followed) that is not listed and matches no #allow glob is extra. Nesting deeper than 32 or
  more than 100000 entries cannot be verified and counts as extra too.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from manifest_path import is_safe_relative_path

MAX_LINE = 1023
MAX_ALLOW = 64
MAX_GLOB = 255
MAX_DEPTH = 32
MAX_ENTRIES = 100000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


class ManifestError(ValueError):
    pass


@dataclass
class Policy:
    strict: bool = False
    seen_version: bool = False
    allow: list[str] = field(default_factory=list)


def is_valid_glob(g: str) -> bool:
    b = g.encode("utf-8", "surrogatepass")
    if not b or len(b) > MAX_GLOB or b[0:1] == b"/":
        return False
    for i, c in enumerate(b):
        if c < 0x20 or c == 0x7F or c == 0x5C:
            return False
        if (i == 0 or b[i - 1] == 0x2F) and c == 0x2E and b[i + 1:i + 2] == b"." \
                and (i + 2 == len(b) or b[i + 2] == 0x2F):
            return False
    return True


def parse_header_line(line: str, policy: Policy) -> None:
    if len(line) == 1 or line[1] == " ":
        return
    if line.startswith("#reshield-manifest "):
        if policy.seen_version:
            raise ManifestError("duplicate #reshield-manifest directive")
        arg = line[len("#reshield-manifest "):]
        if arg == "v2":
            policy.strict = False
        elif arg == "v2 strict":
            policy.strict = True
        else:
            raise ManifestError(f"unsupported manifest version: {arg!r}")
        policy.seen_version = True
        return
    if line.startswith("#allow "):
        glob = line[len("#allow "):]
        if not policy.seen_version:
            raise ManifestError("#allow before #reshield-manifest")
        if len(policy.allow) >= MAX_ALLOW:
            raise ManifestError(f"more than {MAX_ALLOW} #allow lines")
        if not is_valid_glob(glob):
            raise ManifestError(f"invalid #allow glob: {glob!r}")
        policy.allow.append(glob)
        return
    raise ManifestError(f"unknown directive: {line!r}")


def parse_manifest(raw: bytes) -> tuple[Policy, list[tuple[str, int, str]]]:
    """Returns (policy, [(hex, size, rel), ...]); raises ManifestError. Entry paths are checked
    with the shared path rule; hashes and sizes are returned for the caller to verify."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest over 4 MiB")
    # Same as the C runtime: CRLF / NUL manifests are rejected, not silently normalized.
    if b"\r" in raw or b"\0" in raw:
        raise ManifestError("manifest contains CR or NUL")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"manifest is not valid UTF-8: {exc}") from exc
    policy = Policy()
    entries: list[tuple[str, int, str]] = []
    for line in text.split("\n"):
        if len(line.encode("utf-8")) > MAX_LINE:
            raise ManifestError("line longer than 1023 bytes")
        if not line:
            continue
        if line.startswith("#"):
            if entries:
                raise ManifestError(f"'#' line after the first entry: {line!r}")
            parse_header_line(line, policy)
            continue
        parts = line.split(" ", 2)
        if len(parts) != 3:
            raise ManifestError(f"malformed line: {line}")
        exp_hex, exp_size_s, rel = parts
        if not (exp_size_s.isascii() and exp_size_s.isdigit()):
            raise ManifestError(f"malformed line: {line}")
        if not is_safe_relative_path(rel):
            raise ManifestError(f"unsafe path: {rel!r}")
        entries.append((exp_hex, int(exp_size_s), rel))
    return policy, entries


def glob_match(glob: str, path: str) -> bool:
    """Iterative matcher over UTF-8 bytes, same algorithm as glob_match() in manifest.c."""
    g = glob.encode("utf-8", "surrogatepass")
    s = path.encode("utf-8", "surrogatepass")
    gi = si = 0
    star = mark = -1
    while si < len(s):
        if gi < len(g) and g[gi] == 0x2A:
            star = gi
            gi += 1
            mark = si
        elif gi < len(g) and (g[gi] == 0x3F or g[gi] == s[si]):
            gi += 1
            si += 1
        elif star >= 0:
            gi = star + 1
            mark += 1
            si = mark
        else:
            return False
    while gi < len(g) and g[gi] == 0x2A:
        gi += 1
    return gi == len(g)


def _is_item_link(entry: os.DirEntry) -> bool:
    is_junction = getattr(entry, "is_junction", None)
    return entry.is_symlink() or bool(is_junction and is_junction())


def find_extra(asset_dir: str, listed: set[str], allow: list[str]) -> str | None:
    """First path under asset_dir that is neither listed nor allowed (symlinks and junctions
    are items, never followed). A scan that cannot finish is reported as '<scan incomplete: ...>'."""
    count = 0
    stack: list[tuple[str, str, int]] = [(asset_dir or ".", "", 0)]
    while stack:
        full, rel, depth = stack.pop()
        try:
            entries = sorted(os.scandir(full), key=lambda e: e.name.encode("utf-8", "surrogatepass"))
        except OSError as exc:
            return f"<scan incomplete: {exc}>"
        for e in entries:
            count += 1
            if count > MAX_ENTRIES:
                return "<scan incomplete: more than 100000 entries>"
            child = f"{rel}/{e.name}" if rel else e.name
            if not _is_item_link(e) and e.is_dir(follow_symlinks=False):
                if depth + 1 > MAX_DEPTH:
                    return "<scan incomplete: nesting deeper than 32>"
                stack.append((e.path, child, depth + 1))
            elif child not in listed and not any(glob_match(g, child) for g in allow):
                return child
    return None
