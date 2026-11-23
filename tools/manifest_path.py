"""
Manifest relative-path rule shared by gen_manifest.py and verify_release.py.

Must stay identical to is_safe_relative_path() in src/manifest.c: the rule is the same on
every platform so a manifest generated anywhere verifies everywhere.

- '/' is the only separator; absolute paths and empty components are rejected.
- Rejected characters: '\\', ':', control characters 0x00-0x1F (CR/LF/NUL included),
  and '< > " | ? *'.
- A component ending in '.' or ' ' is rejected (so '.', '..' and '...' too).
- Windows reserved device names are rejected, case-insensitively (ASCII), also with an
  extension: the part before the first '.', trailing spaces stripped, is compared.
  Names that merely contain '..' (e.g. 'v1..2.cfg') are allowed.
"""

from __future__ import annotations

_FORBIDDEN = frozenset('\\:<>"|?*')
_RESERVED = frozenset(
    ["con", "prn", "aux", "nul", "conin$", "conout$"]
    + [f"com{i}" for i in range(10)]
    + [f"lpt{i}" for i in range(10)]
)


def _ascii_lower(s: str) -> str:
    # str.lower() would also fold non-ASCII letters (e.g. U+0130); the C side is ASCII-only.
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def is_safe_relative_path(rel: str) -> bool:
    if not rel or rel[0] == "/":
        return False
    for part in rel.split("/"):
        if not part:
            return False
        if any(ord(c) < 0x20 or c in _FORBIDDEN for c in part):
            return False
        if part[-1] in ". ":
            return False
        if _ascii_lower(part.split(".", 1)[0].rstrip(" ")) in _RESERVED:
            return False
    return True
