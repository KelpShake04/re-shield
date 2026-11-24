#!/usr/bin/env python3
"""
One-call release step for re-shield: strip -> manifest -> seal -> sign -> verify, in that order.

Run it on the final linked executable, in place:

    python3 tools/reshield_release.py dist/game --assets dist/assets --strip
    python3 tools/reshield_release.py dist/game --assets dist --exclude "*.pdb"
    python3 tools/reshield_release.py dist/game --assets dist/assets --sign "Developer ID Application: Me (TEAMID)"
    python3 tools/reshield_release.py dist/game.exe --assets dist/assets --sign-cmd "signtool sign /fd sha256 /a {}"

Sealing rewrites the binary, so signing must come after it (and strip before it). This tool only
calls the existing tools (gen_manifest.py, seal_binary.py, verify_release.py) plus strip/codesign,
so the seal format stays defined in one place. A Mach-O that already has a real signature is refused.
"""

from __future__ import annotations

import argparse
import glob
import os
import shlex
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
import seal_binary  # noqa: E402


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(shlex.quote(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True)


def file_kind(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"MZ":
        return "pe"
    if head == b"\x7fELF":
        return "elf"
    if head in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "macho"
    return "unknown"


def main() -> int:
    p = argparse.ArgumentParser(description="strip -> manifest -> seal -> sign -> verify")
    p.add_argument("binary", help="Final linked executable (not an .app bundle); modified in place")
    p.add_argument("--assets", help="Asset directory to bind (a manifest is generated from it)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="Leave files matching GLOB (relative POSIX path under --assets) out of the "
                        "manifest; repeatable. The binary itself is excluded automatically.")
    p.add_argument("--manifest-out",
                   help="Manifest output path (default: <binary dir>/<binary name without extension>.manifest)")
    p.add_argument("--build-id", type=int,
                   help="Build identifier, 0..4294967295 (default: $BUILD_NUMBER or 1)")
    p.add_argument("--strip", action="store_true", help="Run $STRIP (default 'strip') first (ELF and Mach-O)")
    p.add_argument("--sign", default="-",
                   help="macOS codesign identity after sealing ('-' = ad-hoc, the default). "
                        "A real identity also gets --options runtime --timestamp.")
    p.add_argument("--entitlements", help="macOS entitlements plist for --sign")
    p.add_argument("--sign-cmd", help="Signing command run after sealing instead of the macOS codesign; "
                                      "{} is replaced by the binary path (e.g. signtool)")
    args = p.parse_args()

    build_id = args.build_id
    if build_id is None:
        raw = os.environ.get("BUILD_NUMBER") or "1"
        if not raw.isdigit():
            raise SystemExit(f"[reshield_release] $BUILD_NUMBER must be a non-negative integer, got {raw!r}")
        build_id = int(raw)
    if not 0 <= build_id <= 0xFFFFFFFF:  # seal_binary.py would silently truncate to 32 bits
        raise SystemExit(f"[reshield_release] build id {build_id} is outside 0..4294967295")

    binary = args.binary
    if os.path.isdir(binary):
        raise SystemExit("[reshield_release] pass the executable inside the bundle "
                         "(MyGame.app/Contents/MacOS/MyGame), then sign the bundle yourself with --sign-cmd")
    kind = file_kind(binary)
    if kind == "unknown":
        raise SystemExit(f"[reshield_release] {binary}: not a Mach-O, ELF or PE executable")
    macos = kind == "macho" and sys.platform == "darwin"
    if not macos and not args.sign_cmd and (args.sign != "-" or args.entitlements):
        print("[reshield_release] warning: --sign/--entitlements only apply to a Mach-O on macOS; "
              "this binary will NOT be signed. Use --sign-cmd.", file=sys.stderr)
    if macos:
        seal_binary.check_macho_resignable(binary)  # refuses a real signature: seal first, sign last

    if args.strip and kind != "pe":
        run([os.environ.get("STRIP", "strip"), binary])

    manifest = None
    if args.assets:
        manifest = args.manifest_out or os.path.join(
            os.path.dirname(os.path.abspath(binary)),
            os.path.splitext(os.path.basename(binary))[0] + ".manifest")
        exclude = list(args.exclude)
        try:  # abspath, like gen_manifest's own output check: the same names os.walk will produce
            rel = os.path.relpath(os.path.abspath(binary), os.path.abspath(args.assets)).replace(os.sep, "/")
        except ValueError:  # Windows: binary and assets on different drives
            rel = ".."
        if not (rel == ".." or rel.startswith("../")):
            # Sealing rewrites the binary, so a manifest entry for it would fail verification.
            print(f"[reshield_release] excluding the sealed binary from the manifest: {rel}")
            exclude.append(glob.escape(rel))
        gen = [sys.executable, os.path.join(TOOLS, "gen_manifest.py"), args.assets, "-o", manifest]
        for pattern in exclude:
            gen += ["--exclude", pattern]
        run(gen)

    seal = [sys.executable, os.path.join(TOOLS, "seal_binary.py"), binary,
            "--build-id", str(build_id), "--no-codesign"]
    if manifest:
        seal += ["--manifest", manifest]
    run(seal)

    if args.sign_cmd:
        run([c.replace("{}", binary) for c in shlex.split(args.sign_cmd)])
    elif macos:
        cmd = ["codesign", "--force", "-s", args.sign]
        if args.sign != "-":
            cmd += ["--options", "runtime", "--timestamp"]
        if args.entitlements:
            cmd += ["--entitlements", args.entitlements]
        run(cmd + [binary])

    verify = [sys.executable, os.path.join(TOOLS, "verify_release.py"), binary]
    if manifest:
        verify += ["--manifest", manifest, "--assets", args.assets]
    run(verify)
    if macos and not args.sign_cmd:
        run(["codesign", "--verify", "--strict", binary])

    print(f"[reshield_release] ship: {binary}" + (f" + {manifest} + {args.assets}/" if manifest else ""))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:  # from seal_binary.check_macho_resignable
        print(f"[reshield_release] error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as exc:
        print(f"[reshield_release] step failed ({exc.returncode}): {' '.join(exc.cmd)}", file=sys.stderr)
        raise SystemExit(exc.returncode or 1)
