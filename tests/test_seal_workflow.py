#!/usr/bin/env python3
"""
End-to-end build attestation & integrity workflow test for re-shield.

Verifies:
1. gen_manifest.py + seal_binary.py + verify_release.py end-to-end pipeline.
2. Sealed sample_game runs and loads stage1.cfg with valid SHA-256 key commitment.
3. Modifying stage1.cfg by 1 byte is detected at runtime (RESHIELD_ERR_ASSET_TAMPERED).
4. Modifying manifest file is detected at runtime (RESHIELD_ERR_MANIFEST_MISMATCH).
5. Modifying 1 byte inside reshield_checksum_sentinel in integrity_demo is detected
   at runtime (RESHIELD_ERR_CODE_TAMPERED) with structured diagnostic output.
6. Disabled build (-DRESHIELD_DISABLE) passes unsealed for dev/QA workflows.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import seal_binary  # noqa: E402
import gen_manifest as gen_manifest_mod  # noqa: E402
import verify_release as verify_release_mod  # noqa: E402


def find_symbol_file_offset(binary_path: str, data: bytes, symbol: str) -> int:
    nm_out = subprocess.check_output(["nm", binary_path], text=True)
    sym_addr = None
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] != "U" and parts[2] in (symbol, "_" + symbol):
            sym_addr = int(parts[0], 16)
            break
    if sym_addr is None:
        raise RuntimeError(f"Symbol {symbol} not found in {binary_path}")

    if struct.unpack_from("<I", data, 0)[0] == seal_binary.MH_MAGIC_64:
        ncmds = struct.unpack_from("<I", data, 16)[0]
        offset = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, offset)
            if cmd == seal_binary.LC_SEGMENT_64:
                segname = data[offset + 8 : offset + 24].split(b"\x00", 1)[0]
                nsects = struct.unpack_from("<I", data, offset + 64)[0]
                sect_off = offset + 72
                for _ in range(nsects):
                    sectname = data[sect_off : sect_off + 16].split(b"\x00", 1)[0]
                    s_segname = data[sect_off + 16 : sect_off + 32].split(b"\x00", 1)[0]
                    addr, size, file_off = struct.unpack_from("<QQI", data, sect_off + 32)
                    if segname == b"__TEXT" and s_segname == b"__TEXT" and sectname == b"__text":
                        if addr <= sym_addr < addr + size:
                            return file_off + (sym_addr - addr)
                    sect_off += 80
            offset += cmdsize
    elif data[:4] == b"\x7fELF":
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
        strtab_hdr_off = e_shoff + e_shstrndx * e_shentsize
        strtab_off, strtab_size = struct.unpack_from("<QQ", data, strtab_hdr_off + 24)
        strtab = data[strtab_off : strtab_off + strtab_size]
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            sh_name = struct.unpack_from("<I", data, sh_off)[0]
            sh_addr, file_off, size = struct.unpack_from("<QQQ", data, sh_off + 16)
            end = strtab.find(b"\x00", sh_name)
            name = strtab[sh_name:end] if end != -1 else strtab[sh_name:]
            if name == b".text" and sh_addr <= sym_addr < sh_addr + size:
                return file_off + (sym_addr - sh_addr)

    raise RuntimeError(f"Could not map symbol {symbol} (0x{sym_addr:x}) to code section")


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def test_path_rules() -> None:
    safe = gen_manifest_mod.is_safe_relative_path
    assert safe("a.cfg") and safe("sub/a.cfg") and safe("v1..2.cfg") and safe(".hidden/a.cfg")
    for bad in ("", "/abs", "../x", "a/../b", "a/..", "a//b", "a/", "a\nb", "a\rb"):
        assert not safe(bad), f"path should be rejected: {bad!r}"

    with tempfile.TemporaryDirectory(prefix="reshield_paths_") as d:
        os.makedirs(os.path.join(d, "assets", ".dotdir"))
        for name in ("v1..2.cfg", ".dotfile", os.path.join(".dotdir", "in.cfg")):
            with open(os.path.join(d, "assets", name), "wb") as f:
                f.write(b"abc")
        manifest = os.path.join(d, "m.manifest")
        gen_manifest_mod.generate_manifest(os.path.join(d, "assets"), manifest)
        with open(manifest, "r", encoding="utf-8") as f:
            listed = [ln.split(" ", 2)[2].rstrip("\n") for ln in f]
        # Policy: dot-files skipped, dot-directories traversed.
        assert listed == [".dotdir/in.cfg", "v1..2.cfg"], listed
        ok, _n, _msg = verify_release_mod.verify_manifest_entries(manifest, os.path.join(d, "assets"))
        assert ok, "verify_release should accept generated manifest"

        digest = hashlib.sha256(b"abc").hexdigest()
        for label, content in (
            ("dotdot", f"{digest} 3 ../x\n"),
            ("absolute", f"{digest} 3 /abs\n"),
            ("crlf", f"{digest} 3 v1..2.cfg\r\n"),
            ("bad size", f"{digest} x v1..2.cfg\n"),
        ):
            with open(manifest, "wb") as f:
                f.write(content.encode())
            ok, _n, _msg = verify_release_mod.verify_manifest_entries(
                manifest, os.path.join(d, "assets"))
            assert not ok, f"verify_release must reject {label} manifest"
    print("PASS: gen_manifest / verify_release share the C path rules (component-wise)")


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    integrity_demo = os.path.join(repo_root, "build", "integrity_demo")
    integrity_demo_disabled = os.path.join(repo_root, "build", "integrity_demo_disabled")
    sample_game = os.path.join(repo_root, "build", "sample_game")
    assets_src = os.path.join(repo_root, "examples", "assets")

    gen_manifest = os.path.join(repo_root, "tools", "gen_manifest.py")
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    verify_tool = os.path.join(repo_root, "tools", "verify_release.py")

    with tempfile.TemporaryDirectory(prefix="reshield_wf_") as tmpdir:
        assets_dir = os.path.join(tmpdir, "assets")
        shutil.copytree(assets_src, assets_dir)
        manifest_path = os.path.join(tmpdir, "assets.manifest")

        # 1. Generate manifest and seal copies of integrity_demo and sample_game
        subprocess.run([sys.executable, gen_manifest, assets_dir, "-o", manifest_path], check=True)

        demo_sealed = os.path.join(tmpdir, "integrity_demo_sealed")
        game_sealed = os.path.join(tmpdir, "sample_game_sealed")
        shutil.copy2(integrity_demo, demo_sealed)
        shutil.copy2(sample_game, game_sealed)

        subprocess.run(
            [sys.executable, seal_tool, demo_sealed, "--manifest", manifest_path, "--build-id", "42"],
            check=True,
        )
        subprocess.run(
            [sys.executable, seal_tool, game_sealed, "--manifest", manifest_path, "--build-id", "42"],
            check=True,
        )
        subprocess.run(
            [sys.executable, verify_tool, game_sealed, "--manifest", manifest_path, "--assets", assets_dir],
            check=True,
        )
        print("PASS: E2E manifest generation, binary sealing, and release verification")

        # 2. Sealed integrity_demo passes code + W^X + manifest (+ codesign on macOS)
        demo_cmd = [demo_sealed, f"--manifest={manifest_path}", f"--assets={assets_dir}"]
        if sys.platform == "darwin":
            demo_cmd.append("--check-codesign")
        r = run_cmd(demo_cmd)
        assert r.returncode == 0 and "status=OK" in r.stdout and "build_id=42" in r.stdout, f"Demo failed: {r}"
        print("PASS: E2E sealed integrity_demo passes code + W^X + manifest + codesign")

        # 3. Sealed sample_game unlocks with valid key and rejects wrong key
        r = run_cmd([game_sealed, manifest_path, assets_dir, "STAGE-1-CLEAR-2026"])
        assert r.returncode == 0 and "STAGE UNLOCKED (build_id=42)" in r.stdout and "Emerald Valley" in r.stdout, f"Game unlock failed: {r}"
        r = run_cmd([game_sealed, manifest_path, assets_dir, "WRONG-KEY"])
        assert r.returncode == 1 and "ACCESS DENIED" in r.stdout, f"Game wrong-key failed: {r}"
        print("PASS: E2E sealed sample_game verifies SHA-256 key commitment and loads stage1.cfg")

        # 4. Asset 1-byte modification detected
        stage_cfg = os.path.join(assets_dir, "stage1.cfg")
        with open(stage_cfg, "rb") as f:
            orig_cfg = f.read()
        with open(stage_cfg, "wb") as f:
            f.write(orig_cfg.replace(b"reward_multiplier=2", b"reward_multiplier=9"))
        r = run_cmd([game_sealed, manifest_path, assets_dir, "STAGE-1-CLEAR-2026"])
        assert r.returncode == 16 and "ASSET_TAMPERED" in r.stderr and "stage1.cfg" in r.stderr, f"Asset tamper failed: {r}"
        with open(stage_cfg, "wb") as f:
            f.write(orig_cfg)
        print("PASS: E2E asset modification detected with structured diagnostic report")

        # 5. Manifest file modification detected
        with open(manifest_path, "ab") as f:
            f.write(b"# extra comment\n")
        r = run_cmd([game_sealed, manifest_path, assets_dir, "STAGE-1-CLEAR-2026"])
        assert r.returncode == 15 and "MANIFEST_MISMATCH" in r.stderr, f"Manifest tamper failed: {r}"
        print("PASS: E2E manifest file modification detected against sealed root hash")

        # 6. Code section 1-byte corruption in integrity_demo detected
        demo_corrupted = os.path.join(tmpdir, "integrity_demo_corrupted")
        shutil.copy2(demo_sealed, demo_corrupted)
        with open(demo_corrupted, "rb") as f:
            buf = bytearray(f.read())
        off = find_symbol_file_offset(demo_corrupted, bytes(buf), "reshield_checksum_sentinel")
        buf[off] ^= 0x01
        with open(demo_corrupted, "wb") as f:
            f.write(buf)
        if sys.platform == "darwin":
            subprocess.run(["codesign", "-s", "-", "--force", demo_corrupted], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = run_cmd([demo_corrupted])
        assert r.returncode == 2 and "status=CODE_TAMPERED" in r.stdout and "CODE_TAMPERED" in r.stderr, f"Code tamper failed: {r}"
        print("PASS: E2E 1-byte code section corruption detected cleanly")

        # 7. Disabled build passes unsealed
        r = run_cmd([integrity_demo_disabled])
        assert r.returncode == 0 and "status=OK" in r.stdout and "enabled=0" in r.stdout, f"Disabled demo failed: {r}"
        print("PASS: E2E disabled build (-DRESHIELD_DISABLE) passes unsealed for dev/QA")

    test_path_rules()

    print("All E2E seal workflow tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
