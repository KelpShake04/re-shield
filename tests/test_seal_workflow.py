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
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import seal_binary  # noqa: E402
import gen_manifest as gen_manifest_mod  # noqa: E402
import verify_release as verify_release_mod  # noqa: E402
import manifest_path as manifest_path_mod  # noqa: E402


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


def resign(path: str) -> None:
    """Re-sign after patching bytes so macOS still launches the binary."""
    if sys.platform == "darwin":
        subprocess.run(["codesign", "-s", "-", "--force", path], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def patch_file(src: str, dst: str, offset: int, value: int) -> None:
    shutil.copy2(src, dst)
    with open(dst, "r+b") as f:
        f.seek(offset)
        f.write(bytes([value]))
    resign(dst)


def test_status_mapping_and_records(tmpdir: str, repo_root: str, assets_dir: str) -> None:
    build = os.path.join(repo_root, "build")
    integrity_demo = os.path.join(build, "integrity_demo")
    sample_game = os.path.join(build, "sample_game")
    sample_game_disabled = os.path.join(build, "sample_game_disabled")
    gen_tool = os.path.join(repo_root, "tools", "gen_manifest.py")
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")

    manifest = os.path.join(tmpdir, "s2.manifest")
    subprocess.run([sys.executable, gen_tool, assets_dir, "-o", manifest], check=True,
                   stdout=subprocess.DEVNULL)

    # Disabled sample_game still rejects a wrong key (reshield_verify_buffer is app logic).
    args = [manifest, assets_dir]
    r = run_cmd([sample_game_disabled, *args, "WRONG-KEY"])
    assert r.returncode == 1 and "ACCESS DENIED" in r.stdout, f"disabled wrong key accepted: {r}"
    r = run_cmd([sample_game_disabled, *args, "STAGE-1-CLEAR-2026"])
    assert r.returncode == 0 and "STAGE UNLOCKED" in r.stdout, f"disabled right key rejected: {r}"
    print("PASS: disabled sample_game rejects wrong key and accepts the right key")

    game = os.path.join(tmpdir, "s2_game")
    shutil.copy2(sample_game, game)
    subprocess.run([sys.executable, seal_tool, game, "--manifest", manifest, "--build-id", "7"],
                   check=True, stdout=subprocess.DEVNULL)

    # ROOT_MISMATCH / ASSET_TAMPERED / IO error map to distinct statuses (exit = 10 + status).
    r = run_cmd([game, os.path.join(tmpdir, "missing.manifest"), assets_dir, "STAGE-1-CLEAR-2026"])
    assert r.returncode == 17 and "INTERNAL_ERROR" in r.stderr, f"IO error mapping failed: {r}"
    print("PASS: unreadable manifest maps to INTERNAL_ERROR")

    # Multiple failures: code status wins, both failed_checks bits are reported.
    demo = os.path.join(tmpdir, "s2_demo")
    shutil.copy2(integrity_demo, demo)
    subprocess.run([sys.executable, seal_tool, demo, "--manifest", manifest, "--build-id", "7"],
                   check=True, stdout=subprocess.DEVNULL)
    with open(demo, "rb") as f:
        demo_bytes = f.read()
    sentinel_off = find_symbol_file_offset(demo, demo_bytes, "reshield_checksum_sentinel")
    bad_manifest = os.path.join(tmpdir, "s2_bad.manifest")
    shutil.copy2(manifest, bad_manifest)
    with open(bad_manifest, "ab") as f:
        f.write(b"# tampered\n")
    both = os.path.join(tmpdir, "s2_both")
    patch_file(demo, both, sentinel_off, demo_bytes[sentinel_off] ^ 0x01)
    r = run_cmd([both, f"--manifest={bad_manifest}", f"--assets={assets_dir}"])
    assert r.returncode == 2 and "status=CODE_TAMPERED" in r.stdout and "failed_checks=0x9" in r.stderr, \
        f"priority/bits failed: {r}"
    print("PASS: CODE_TAMPERED wins over MANIFEST_MISMATCH and failed_checks has both bits (0x9)")

    # Invalid records must not be treated as UNSEALED (allow_unsealed must not rescue them).
    rec_off = seal_binary.find_integrity_record_offset(demo_bytes)
    ver_off = rec_off + 8
    bad_ver = os.path.join(tmpdir, "s2_badver")
    patch_file(demo, bad_ver, ver_off, 3)
    r = run_cmd([bad_ver, "--allow-unsealed"])
    assert r.returncode == 2 and "status=CODE_TAMPERED" in r.stdout, f"bad version bypassed allow_unsealed: {r}"
    bad_magic = os.path.join(tmpdir, "s2_badmagic")
    patch_file(demo, bad_magic, rec_off, ord("X"))
    r = run_cmd([bad_magic, "--allow-unsealed"])
    assert r.returncode == 2 and "status=CODE_TAMPERED" in r.stdout, f"bad magic bypassed allow_unsealed: {r}"
    print("PASS: invalid record (version/magic) is CODE_TAMPERED even with allow_unsealed")

    # Documented dev-only behavior: clearing the sealed byte + allow_unsealed passes.
    unsealed = os.path.join(tmpdir, "s2_unsealed")
    patch_file(demo, unsealed, rec_off + 12, 0)
    r = run_cmd([unsealed])
    assert r.returncode == 1 and "status=UNSEALED" in r.stdout, f"strict unsealed failed: {r}"
    r = run_cmd([unsealed, "--allow-unsealed"])
    assert r.returncode == 0, f"allow_unsealed on valid unsealed record failed: {r}"
    print("PASS: valid sealed==0 record is UNSEALED; allow_unsealed (dev only) accepts it")

    # Sealed WITHOUT a manifest, but the app asks for manifest checking: not UNSEALED, no bypass.
    nomanifest = os.path.join(tmpdir, "s2_nomanifest")
    shutil.copy2(integrity_demo, nomanifest)
    subprocess.run([sys.executable, seal_tool, nomanifest, "--build-id", "7"], check=True,
                   stdout=subprocess.DEVNULL)
    r = run_cmd([nomanifest, f"--manifest={manifest}", f"--assets={assets_dir}", "--allow-unsealed"])
    assert r.returncode == 5 and "MANIFEST_MISMATCH" in r.stderr, f"sealed-without-manifest bypass: {r}"
    print("PASS: sealed binary without manifest root fails MANIFEST check even with allow_unsealed")


def load_path_rule_table(repo_root: str) -> list[tuple[bool, str]]:
    """tests/path_rules.txt is shared with tests/test_manifest.c (same expectations)."""
    cases = []
    with open(os.path.join(repo_root, "tests", "path_rules.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            assert line[0] in "+-" and line[1] == " ", f"bad table line: {line!r}"
            path = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), line[2:])
            cases.append((line[0] == "+", path))
    return cases


def test_shared_path_rule_table(repo_root: str) -> None:
    assert gen_manifest_mod.is_safe_relative_path is manifest_path_mod.is_safe_relative_path
    assert verify_release_mod.is_safe_relative_path is manifest_path_mod.is_safe_relative_path
    cases = load_path_rule_table(repo_root)
    assert len(cases) > 40, len(cases)
    for want_ok, path in cases:
        got = manifest_path_mod.is_safe_relative_path(path)
        assert got == want_ok, f"path rule mismatch for {path!r}: want {want_ok}, got {got}"
    assert not manifest_path_mod.is_safe_relative_path("a\0b")
    # ASCII-only case folding, like the C side: U+0130 must not turn "con" into a reserved name.
    assert manifest_path_mod.is_safe_relative_path("c\u0130n") and manifest_path_mod.is_safe_relative_path("co\u0131n")
    print(f"PASS: tools/manifest_path.py matches the shared path table ({len(cases)} cases, same file as the C test)")


def test_gen_manifest_path_policy() -> None:
    def run(names: list[str]) -> str:
        """Runs generate_manifest over fake directory entries; returns the error text or ''."""
        orig_walk, orig_sha = os.walk, gen_manifest_mod.sha256_file
        try:
            os.walk = lambda _d: [("/fake", [], names)]  # type: ignore[assignment]
            gen_manifest_mod.sha256_file = lambda _p: ("0" * 64, 1)
            with tempfile.TemporaryDirectory(prefix="reshield_gm_") as d:
                gen_manifest_mod.generate_manifest("/fake", os.path.join(d, "m.manifest"))
        except ValueError as exc:
            return str(exc)
        finally:
            os.walk, gen_manifest_mod.sha256_file = orig_walk, orig_sha
        return ""

    assert run(["ok.cfg", "v1..2.cfg", "\ud55c\uae00.cfg"]) == ""
    for bad in ("nul.txt", "COM1", "a.cfg.", "a.cfg ", "a<b", "a\x01b", "a:b", "a\\b"):
        assert "Unsafe asset path" in run([bad]), f"gen_manifest must reject {bad!r}"
    assert "differ only by case" in run(["A.cfg", "a.cfg"])
    assert "NFC" in run(["e\u0301.cfg"])  # NFD "e" + combining acute
    assert run(["\u00e9.cfg"]) == ""  # NFC form is fine
    print("PASS: gen_manifest rejects unsafe names, case-fold duplicates and non-NFC names")


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


def patch_text_section(data: bytes, new_off: int, new_size: int) -> bytes:
    """Rewrites the code section's file offset/size in the section header (Mach-O or ELF)."""
    buf = bytearray(data)
    if struct.unpack_from("<I", buf, 0)[0] == seal_binary.MH_MAGIC_64:
        ncmds = struct.unpack_from("<I", buf, 16)[0]
        offset = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, offset)
            if cmd == seal_binary.LC_SEGMENT_64:
                nsects = struct.unpack_from("<I", buf, offset + 64)[0]
                sect_off = offset + 72
                for _ in range(nsects):
                    if buf[sect_off : sect_off + 6] == b"__text" and buf[sect_off + 16 : sect_off + 22] == b"__TEXT":
                        struct.pack_into("<Q", buf, sect_off + 40, new_size)
                        struct.pack_into("<I", buf, sect_off + 48, new_off)
                        return bytes(buf)
                    sect_off += 80
            offset += cmdsize
    else:
        e_shoff = struct.unpack_from("<Q", buf, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
        stroff = struct.unpack_from("<Q", buf, e_shoff + e_shstrndx * e_shentsize + 24)[0]
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            name_off = stroff + struct.unpack_from("<I", buf, sh)[0]
            if buf[name_off : name_off + 6] == b".text\x00":
                struct.pack_into("<QQ", buf, sh + 24, new_off, new_size)
                return bytes(buf)
    raise RuntimeError("code section header not found")


def test_seal_tool_and_release_cases(tmpdir: str, repo_root: str, assets_dir: str) -> None:
    build = os.path.join(repo_root, "build")
    gen_tool = os.path.join(repo_root, "tools", "gen_manifest.py")
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    verify_tool = os.path.join(repo_root, "tools", "verify_release.py")
    py = sys.executable

    manifest = os.path.join(tmpdir, "s4.manifest")
    subprocess.run([py, gen_tool, assets_dir, "-o", manifest], check=True, stdout=subprocess.DEVNULL)

    demo = os.path.join(tmpdir, "s4_demo")
    shutil.copy2(os.path.join(build, "integrity_demo"), demo)
    os.chmod(demo, 0o751)
    r = run_cmd([py, seal_tool, demo, "--manifest", manifest, "--build-id", "9"])
    assert r.returncode == 0, r
    assert (os.stat(demo).st_mode & 0o777) == 0o751, "seal_binary must keep permission bits"
    assert not [n for n in os.listdir(tmpdir) if n.startswith(".seal_")], "temp file left behind"
    print("PASS: seal_binary keeps permission bits and leaves no temp file")

    # --verify-only
    r = run_cmd([py, seal_tool, demo, "--manifest", manifest, "--verify-only"])
    assert r.returncode == 0 and "match=True" in r.stdout, r
    unsealed_copy = os.path.join(tmpdir, "s4_unsealed")
    shutil.copy2(os.path.join(build, "integrity_demo"), unsealed_copy)
    r = run_cmd([py, seal_tool, unsealed_copy, "--verify-only"])
    assert r.returncode == 1 and "match=False" in r.stdout, r
    other = os.path.join(tmpdir, "s4_other.manifest")
    shutil.copy2(manifest, other)
    with open(other, "ab") as f:
        f.write(b"# x\n")
    r = run_cmd([py, seal_tool, demo, "--manifest", other, "--verify-only"])
    assert r.returncode == 1 and "match=False" in r.stdout, r
    print("PASS: seal_binary --verify-only succeeds on sealed, fails on unsealed / wrong manifest")

    with open(os.path.join(build, "integrity_demo"), "rb") as f:
        raw = f.read()
    rec_off = seal_binary.find_integrity_record_offset(raw)

    # 0 records / 2 records
    no_rec = os.path.join(tmpdir, "s4_norec")
    with open(no_rec, "wb") as f:
        f.write(raw[:rec_off] + b"XSHLDCHK" + raw[rec_off + 8:])
    r = run_cmd([py, seal_tool, no_rec, "--no-codesign"])
    assert r.returncode == 2 and "No RSHLDCHK" in r.stderr, r
    two_rec = os.path.join(tmpdir, "s4_tworec")
    with open(two_rec, "wb") as f:
        f.write(raw + raw[rec_off : rec_off + seal_binary.RECORD_SIZE])
    r = run_cmd([py, seal_tool, two_rec, "--no-codesign"])
    assert r.returncode == 2 and "Ambiguous" in r.stderr, r
    print("PASS: seal_binary rejects 0 records and ambiguous 2 records")

    # record overlapping the code section (section starts inside the record)
    _fmt, text_off, text_size = seal_binary.find_code_section(raw)
    overlap = os.path.join(tmpdir, "s4_overlap")
    with open(overlap, "wb") as f:
        f.write(patch_text_section(raw, rec_off + 10, 100))
    r = run_cmd([py, seal_tool, overlap, "--no-codesign"])
    assert r.returncode == 2 and "overlap" in r.stderr, r
    print("PASS: seal_binary rejects a record that overlaps the code section (partial overlap)")

    # fat Mach-O
    fat = os.path.join(tmpdir, "s4_fat")
    with open(fat, "wb") as f:
        f.write(b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x00" + b"\x00" * 64)
    r = run_cmd([py, seal_tool, fat, "--no-codesign"])
    assert r.returncode == 2 and "fat/universal" in r.stderr, r
    print("PASS: seal_binary exits with a clear error on fat/universal Mach-O")

    # verify_release exit codes
    r = run_cmd([py, verify_tool, demo, "--manifest", manifest, "--assets", assets_dir])
    assert r.returncode == 0, r
    r = run_cmd([py, verify_tool, demo, "--manifest", other, "--assets", assets_dir])
    assert r.returncode == 1 and "manifest_assets: FAIL" in r.stdout, r
    with open(demo, "rb") as f:
        demo_bytes = f.read()
    sentinel_off = find_symbol_file_offset(demo, demo_bytes, "reshield_checksum_sentinel")
    corrupt = os.path.join(tmpdir, "s4_corrupt")
    patch_file(demo, corrupt, sentinel_off, demo_bytes[sentinel_off] ^ 0x01)
    r = run_cmd([py, verify_tool, corrupt, "--manifest", manifest, "--assets", assets_dir])
    assert r.returncode == 1 and "code_seal:       FAIL" in r.stdout, r
    print("PASS: verify_release returns 1 on code and manifest mismatch")

    # gen_manifest on an empty directory
    empty = os.path.join(tmpdir, "empty_assets")
    os.makedirs(empty)
    r = run_cmd([py, gen_tool, empty, "-o", os.path.join(tmpdir, "empty.manifest")])
    assert r.returncode != 0 and "No asset files" in r.stderr, r
    assert not os.path.exists(os.path.join(tmpdir, "empty.manifest"))
    print("PASS: gen_manifest fails on an empty asset directory")


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
    test_shared_path_rule_table(repo_root)
    test_gen_manifest_path_policy()
    with tempfile.TemporaryDirectory(prefix="reshield_s2_") as tmp2:
        a2 = os.path.join(tmp2, "assets")
        shutil.copytree(assets_src, a2)
        test_status_mapping_and_records(tmp2, repo_root, a2)
        test_seal_tool_and_release_cases(tmp2, repo_root, a2)

    print("All E2E seal workflow tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
