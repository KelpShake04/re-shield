#!/usr/bin/env python3
"""
Dev-build guard test: a development build of re-shield (compiled with RESHIELD_ALLOW_UNSEALED) carries
the marker RESHIELD-DEV-BUILD-v1, a release build never does, and the release tools refuse the former.

    test_dev_build_guard.py --dev-artifact LIB... --dev-bin EXE --release-artifact LIB... --release-bin EXE

The Makefile (`make guard-test`, part of `make test`) passes build/ (development) and build/release/
(ALLOW_UNSEALED=0) outputs; the windows-msvc CI job passes the MSVC-built files. Marker checks are plain
byte searches (no nm), so they work on static libraries, shared libraries and executables alike.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools")
sys.path.insert(0, TOOLS)
import verify_release  # noqa: E402

MARKER = b"RESHIELD-DEV-BUILD-v1"
RELEASE_TOOL = os.path.join(TOOLS, "reshield_release.py")
VERIFY_TOOL = os.path.join(TOOLS, "verify_release.py")
SEAL_TOOL = os.path.join(TOOLS, "seal_binary.py")


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def sha(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev-artifact", action="append", default=[], help="development library/binary (marker expected)")
    ap.add_argument("--release-artifact", action="append", default=[], help="release library/binary (no marker)")
    ap.add_argument("--dev-bin", required=True, help="executable linked against the development library")
    ap.add_argument("--release-bin", required=True, help="executable or DLL built as release")
    args = ap.parse_args()

    assert verify_release.DEV_BUILD_MARKER == MARKER

    # 1. The marker is in every development artifact and in no release artifact.
    for path in args.dev_artifact + [args.dev_bin]:
        assert MARKER in read(path), f"development artifact has no marker: {path}"
    for path in args.release_artifact + [args.release_bin]:
        assert MARKER not in read(path), f"release artifact must not contain the marker: {path}"
    print("PASS: marker is in development builds and absent from release builds "
          f"({len(args.dev_artifact) + 1} dev, {len(args.release_artifact) + 1} release files)")

    with tempfile.TemporaryDirectory(prefix="reshield_guard_") as tmp:
        assets = os.path.join(tmp, "assets")
        os.makedirs(assets)
        with open(os.path.join(assets, "a.cfg"), "w") as f:
            f.write("a=1\n")

        # 2. reshield_release refuses a development build: rc 2, hint, file and directory untouched.
        dev = os.path.join(tmp, "dev_game")
        shutil.copy2(args.dev_bin, dev)
        before = sha(dev)
        r = run([sys.executable, RELEASE_TOOL, dev, "--assets", assets, "--build-id", "3", "--strip"])
        assert r.returncode == 2, r
        assert "DEVELOPMENT build" in r.stderr and "ALLOW_UNSEALED=0" in r.stderr \
            and "release-shared" in r.stderr and "--allow-dev-build" in r.stderr, r
        assert sha(dev) == before, "a refused dev build must not be modified (not even stripped)"
        assert sorted(os.listdir(tmp)) == ["assets", "dev_game"], "a refused dev build must write no manifest"
        print("PASS: reshield_release refuses a development build (rc 2) before touching any file")

        # 3. --allow-dev-build lets it through with a warning (demos and CI).
        r = run([sys.executable, RELEASE_TOOL, dev, "--assets", assets, "--build-id", "3", "--allow-dev-build"])
        assert r.returncode == 0 and "DEVELOPMENT build" in r.stderr and "never ship" in r.stderr, r
        assert sha(dev) != before, "the allowed run must have sealed the binary"
        print("PASS: reshield_release --allow-dev-build seals it and warns")

        # 4. verify_release: sealed dev build fails without the flag (even though the seal is valid).
        r = run([sys.executable, VERIFY_TOOL, dev])
        assert r.returncode == 2 and "DEVELOPMENT build" in r.stderr and "code_seal" not in r.stdout, r
        r = run([sys.executable, VERIFY_TOOL, dev, "--allow-dev-build"])
        assert r.returncode == 0 and "code_seal:       OK" in r.stdout and "development build" in r.stderr, r
        print("PASS: verify_release rejects a sealed development build; --allow-dev-build verifies it with a warning")

        # 5. A release build goes through both tools without the flag and without any warning.
        rel = os.path.join(tmp, "rel_game")
        shutil.copy2(args.release_bin, rel)
        r = run([sys.executable, RELEASE_TOOL, rel, "--assets", assets, "--build-id", "4"])
        assert r.returncode == 0 and "ship:" in r.stdout and "DEVELOPMENT" not in r.stderr, r
        r = run([sys.executable, VERIFY_TOOL, rel, "--manifest", os.path.join(tmp, "rel_game.manifest"),
                 "--assets", assets])
        assert r.returncode == 0 and "code_seal:       OK" in r.stdout and "development" not in r.stderr, r
        print("PASS: a release build is sealed and verified without --allow-dev-build")

        # 6. Known limit, documented: the marker is a mistake guard, not a defense. Erasing it
        #    (same length, so nothing shifts) gets a development build past the tools.
        erased = os.path.join(tmp, "erased_game")
        data = bytearray(read(args.dev_bin))
        i = data.find(MARKER)
        data[i:i + len(MARKER)] = b"\0" * len(MARKER)
        with open(erased, "wb") as f:
            f.write(data)
        os.chmod(erased, 0o755)
        r = run([sys.executable, SEAL_TOOL, erased, "--build-id", "5"])
        assert r.returncode == 0, r
        r = run([sys.executable, VERIFY_TOOL, erased])
        assert r.returncode == 0, "known limit: an erased marker is not detected"
        print("PASS: known limit: a deliberately erased marker is not detected (mistake guard, not a defense)")

    print("All dev-build guard tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
