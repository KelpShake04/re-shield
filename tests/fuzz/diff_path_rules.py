#!/usr/bin/env python3
"""Differential test: C path rule (via fuzz_path, public API only) vs tools/manifest_path.py.

    python3 tests/fuzz/diff_path_rules.py --binary build-fuzz/fuzz_path [--corpus DIR ...]

Cases: tests/fuzz/seeds/path/*, every file in each --corpus DIR, and --random N generated
paths built from tricky tokens (fixed --seed). Each case is fed to the harness as one file
(a C string: bytes up to the first NUL); the Python side gets the same bytes decoded as
latin-1 (every rule character is ASCII, so this is byte-faithful). Exit 1 on any mismatch.
"""

from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import manifest_path  # noqa: E402

TOKENS = ["a", "b", "x.cfg", ".", "..", "...", " ", "  ", "/", "//", "\\", ":", "<", ">", '"', "|", "?", "*",
          "\x00", "\x01", "\x09", "\x0a", "\x0d", "\x1f", "\x7f", "\x80", "\xe9", "é", "İ", "한",
          "con", "CON", "Con", "prn", "aux", "nul", "NUL.txt", "com0", "com1", "COM9", "com10", "lpt1", "LPT9",
          "conin$", "CONOUT$", "nul ", "con.", ".com1", "a..b", "v1..2", "/..", "../", "a/", "/a"]
BATCH = 1000
MAX_LEN = 4096  # libFuzzer default max_len; larger case files would be truncated


def case_bytes_from_corpus(paths: list[str]) -> list[bytes]:
    out = []
    for d in paths:
        for name in sorted(os.listdir(d)):
            full = os.path.join(d, name)
            if os.path.isfile(full):
                with open(full, "rb") as f:
                    out.append(f.read(MAX_LEN))
    return out


def py_decision(case: bytes) -> int:
    return int(manifest_path.is_safe_relative_path(case.split(b"\x00", 1)[0].decode("latin-1")))


def c_decisions(binary: str, cases: list[bytes]) -> list[int]:
    res: list[int] = []
    env = dict(os.environ, FUZZ_PATH_VERBOSE="1")
    with tempfile.TemporaryDirectory(prefix="diff_path_") as tmp:
        for start in range(0, len(cases), BATCH):
            files = []
            for i, c in enumerate(cases[start : start + BATCH]):
                p = os.path.join(tmp, f"c{i:05d}")
                with open(p, "wb") as f:
                    f.write(c)
                files.append(p)
            r = subprocess.run([binary, f"-max_len={MAX_LEN}"] + files, env=env, capture_output=True, text=True)
            got = [int(line.split()[1]) for line in r.stderr.splitlines() if line.startswith("PATHDECISION ")]
            if r.returncode != 0 or len(got) != len(files):
                sys.exit(f"harness failed (rc={r.returncode}, {len(got)}/{len(files)} decisions):\n{r.stderr[-2000:]}")
            res += got
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--corpus", action="append", default=[])
    ap.add_argument("--random", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    dirs = [os.path.join(HERE, "seeds", "path")] + [d for d in args.corpus if os.path.isdir(d)]
    cases = case_bytes_from_corpus(dirs)
    n_files = len(cases)
    rng = random.Random(args.seed)
    for _ in range(args.random):
        s = "".join(rng.choice(TOKENS) for _ in range(rng.randint(1, 8)))
        cases.append(s.encode("utf-8", "surrogatepass")[:MAX_LEN])

    got = c_decisions(args.binary, cases)
    bad = [(c, g) for c, g in zip(cases, got) if g != py_decision(c)]
    safe = sum(got)
    print(f"[diff_path_rules] cases={len(cases)} (files={n_files}, random={args.random}) "
          f"safe={safe} unsafe={len(cases) - safe} mismatches={len(bad)}")
    for c, g in bad[:20]:
        print(f"  MISMATCH C={g} py={1 - g} bytes={c!r}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
