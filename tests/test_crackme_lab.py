#!/usr/bin/env python3
"""
Asserts the crackme lab results (docs/crackme-lab.md): L1 blocked, L2 and L3 pass.
Usage: test_crackme_lab.py <sealed-crackme-binary>   (the Makefile builds and seals it)
L2 and L3 passing is the point: they document what a keyless, report-only design cannot stop.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "crackme"))
import lab  # noqa: E402

RIGHT_KEY = "CRACKME-LAB-2026"


def run(binary: str, key: str) -> subprocess.CompletedProcess:
    return subprocess.run([binary, key], capture_output=True, text=True)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    sealed = sys.argv[1]

    r = run(sealed, lab.WRONG_KEY)
    assert r.returncode == 1 and "ACCESS DENIED" in r.stdout, f"sealed, wrong key: {r}"
    r = run(sealed, RIGHT_KEY)
    assert r.returncode == 0 and "UNLOCKED" in r.stdout, f"sealed, right key: {r}"
    print("PASS: sealed crackme denies a wrong key and unlocks with the right key")

    with tempfile.TemporaryDirectory(prefix="crackme_test_") as workdir:
        r = lab.run_level(1, sealed, workdir)
        assert r.returncode == 12 and "CODE_TAMPERED" in r.stderr and "UNLOCKED" not in r.stdout, \
            f"L1 must be blocked with CODE_TAMPERED: {r}"
        print("PASS: L1 patched .text is blocked (CODE_TAMPERED)")

        r = lab.run_level(2, sealed, workdir)
        assert r.returncode == 0 and "UNLOCKED" in r.stdout, f"L2 re-sealed patch must pass: {r}"
        print("PASS: L2 re-sealed patch passes (known limit: no signing key)")

        r = lab.run_level(3, sealed, workdir)
        assert r.returncode == 0 and "UNLOCKED" in r.stdout, f"L3 patched verify branch must pass: {r}"
        print("PASS: L3 patched verify branch passes (known limit: the check can be skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
