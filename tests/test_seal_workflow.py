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
import manifest_policy as manifest_policy_mod  # noqa: E402


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
    assert r.returncode == 18 and "MANIFEST_IO_ERROR" in r.stderr and "INTERNAL" not in r.stderr, \
        f"IO error mapping failed: {r}"
    print("PASS: unreadable manifest maps to MANIFEST_IO_ERROR (not INTERNAL_ERROR)")

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


def test_gen_manifest_exclude(tmpdir: str) -> None:
    root = os.path.join(tmpdir, "gx")
    for rel, data in (("a.cfg", b"a"), ("sub/b.pdb", b"b"), ("sub/c.cfg", b"c"), ("nul.txt", b"n"),
                      ("Dbg_DoNotShip/d.bin", b"d")):
        os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
        with open(os.path.join(root, rel), "wb") as f:
            f.write(data)

    def listed(*exclude: str) -> list[str]:
        out = os.path.join(tmpdir, "gx.manifest")
        gen_manifest_mod.generate_manifest(root, out, tuple(exclude))
        with open(out) as f:
            return [line.split(" ", 2)[2].strip() for line in f]

    # nul.txt is an unsafe name: without an exclude it is an error, with one it is skipped first.
    try:
        listed()
        raise AssertionError("an unsafe name must still be rejected without --exclude")
    except ValueError as exc:
        assert "Unsafe asset path" in str(exc), exc
    assert listed("nul.txt") == ["Dbg_DoNotShip/d.bin", "a.cfg", "sub/b.pdb", "sub/c.cfg"]
    assert listed("nul.txt", "*.pdb") == ["Dbg_DoNotShip/d.bin", "a.cfg", "sub/c.cfg"]  # repeatable, "*" crosses "/"
    assert listed("nul.txt", "*.pdb", "*_DoNotShip/**") == ["a.cfg", "sub/c.cfg"]
    assert listed("nul.txt", "sub/*") == ["Dbg_DoNotShip/d.bin", "a.cfg"]
    assert listed("nul.txt", "A.CFG") == ["Dbg_DoNotShip/d.bin", "a.cfg", "sub/b.pdb", "sub/c.cfg"]  # case-sensitive
    try:
        listed("*")
        raise AssertionError("excluding everything must still be an error")
    except ValueError as exc:
        assert "No asset files found" in str(exc), exc
    r = run_cmd([sys.executable, os.path.join(os.path.dirname(__file__), "..", "tools", "gen_manifest.py"),
                 root, "-o", os.path.join(tmpdir, "gx_cli.manifest"), "--exclude", "nul.txt", "--exclude", "*.pdb"])
    assert r.returncode == 0 and "2 excluded" in r.stdout and "3 asset(s)" in r.stdout, r
    r = run_cmd([sys.executable, os.path.join(os.path.dirname(__file__), "..", "tools", "gen_manifest.py"),
                 root, "-o", os.path.join(tmpdir, "gx_warn.manifest"), "--exclude", "nul.txt", "--exclude", "*.pdb", "--exclude", "./a.cfg",
                 "--exclude", "sub\\c.cfg"])
    assert r.returncode == 0, r  # a pattern that matches nothing never changes the exit code
    assert "--exclude './a.cfg' matched no file" in r.stderr and "--exclude 'sub\\\\c.cfg' matched no file" in r.stderr, r
    assert "'*.pdb' matched no file" not in r.stderr, r
    r = run_cmd([sys.executable, os.path.join(os.path.dirname(__file__), "..", "tools", "gen_manifest.py"),
                 root, "-o", os.path.join(tmpdir, "gx_warn2.manifest"), "--exclude", "nul.txt"])
    assert r.returncode == 0 and "matched no file" not in r.stderr, r
    print("PASS: gen_manifest warns on stderr about an --exclude pattern that matches no file (exit code unchanged)")
    print("PASS: gen_manifest --exclude (fnmatchcase on relative POSIX paths, repeatable, before the path checks)")


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
    r = run_cmd([py, verify_tool, demo, "--allow-dev-build", "--manifest", manifest, "--assets", assets_dir])
    assert r.returncode == 0, r
    r = run_cmd([py, verify_tool, demo, "--allow-dev-build", "--manifest", other, "--assets", assets_dir])
    assert r.returncode == 1 and "manifest_assets: FAIL" in r.stdout, r
    with open(demo, "rb") as f:
        demo_bytes = f.read()
    sentinel_off = find_symbol_file_offset(demo, demo_bytes, "reshield_checksum_sentinel")
    corrupt = os.path.join(tmpdir, "s4_corrupt")
    patch_file(demo, corrupt, sentinel_off, demo_bytes[sentinel_off] ^ 0x01)
    r = run_cmd([py, verify_tool, corrupt, "--allow-dev-build", "--manifest", manifest, "--assets", assets_dir])
    assert r.returncode == 1 and "code_seal:       FAIL" in r.stdout, r
    print("PASS: verify_release returns 1 on code and manifest mismatch")

    # gen_manifest on an empty directory
    empty = os.path.join(tmpdir, "empty_assets")
    os.makedirs(empty)
    r = run_cmd([py, gen_tool, empty, "-o", os.path.join(tmpdir, "empty.manifest")])
    assert r.returncode != 0 and "No asset files" in r.stderr, r
    assert not os.path.exists(os.path.join(tmpdir, "empty.manifest"))
    print("PASS: gen_manifest fails on an empty asset directory")

# --- PE32+ support ---------------------------------------------------------------------

PE_TEXT_FLAGS = 0x60000020  # CODE | EXECUTE | READ
PE_DATA_FLAGS = 0xC0000040  # INITIALIZED_DATA | READ | WRITE
PE_RDATA_FLAGS = 0x40000040  # INITIALIZED_DATA | READ
PE_TEXT_BYTES = bytes((i * 7 + 3) & 0xFF for i in range(1000))
PE_RECORD = struct.pack(seal_binary.RECORD_FMT, seal_binary.MAGIC, seal_binary.RECORD_VERSION,
                        0, 0, 0, 0, b"\0" * 32, b"\0" * 32)


def build_pe(sections=None, relocs=(), machine=0x8664, opt_magic=0x20B, checksum=0,
             security_size=0) -> bytes:
    """Synthesizes a minimal PE32+ image. sections: [(name, data, flags, virtual_size|None)].
    relocs: [(type, rva)] written as a .reloc section. First section starts at RVA 0x1000."""
    if sections is None:
        sections = [
            (b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS, None),
            (b".data", PE_RECORD + b"\xAA" * 40, PE_DATA_FLAGS, None),
        ]
    sections = list(sections)
    if relocs:
        pages: dict[int, list[int]] = {}
        for typ, rva in relocs:
            pages.setdefault(rva & ~0xFFF, []).append((typ << 12) | (rva & 0xFFF))
        blob = b""
        for page, entries in sorted(pages.items()):
            if len(entries) % 2:
                entries.append(0)  # IMAGE_REL_BASED_ABSOLUTE padding
            blob += struct.pack("<II", page, 8 + 2 * len(entries))
            blob += b"".join(struct.pack("<H", e) for e in entries)
        sections.append((b".reloc", blob, PE_RDATA_FLAGS, None))

    file_align, sect_align, headers_size = 0x200, 0x1000, 0x400
    e_lfanew = 0x80
    opt_size = 112 + 16 * 8
    table_off = e_lfanew + 24 + opt_size
    assert table_off + 40 * len(sections) <= headers_size

    entries, body = [], b""
    va, raw = sect_align, headers_size
    reloc_dir = (0, 0)
    for name, data, flags, vsize in sections:
        raw_size = -(-len(data) // file_align) * file_align if data else 0
        vs = len(data) if vsize is None else vsize
        entries.append(struct.pack("<8sIIIIIIHHI", name, vs, va, raw_size, raw if raw_size else 0,
                                   0, 0, 0, 0, flags))
        body += data.ljust(raw_size, b"\0")
        if name == b".reloc":
            reloc_dir = (va, len(data))
        va += -(-max(vs, 1) // sect_align) * sect_align
        raw += raw_size

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    file_hdr = struct.pack("<HHIIIHH", machine, len(sections), 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<HBB", opt, 0, opt_magic, 14, 0)
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<II", opt, 32, sect_align, file_align)
    struct.pack_into("<II", opt, 56, va, headers_size)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<I", opt, 64, checksum)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 4 * 8, 0x5000 if security_size else 0, security_size)
    struct.pack_into("<II", opt, 112 + 5 * 8, *reloc_dir)
    header = bytes(dos).ljust(e_lfanew, b"\0") + b"PE\0\0" + file_hdr + bytes(opt) + b"".join(entries)
    return header.ljust(headers_size, b"\0") + body


def pe_checksum_reference(data: bytes) -> int:
    """Independent PE checksum (32-bit dword sum with end-around carry, as pefile does it)."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    cs_off = e_lfanew + 24 + 64
    padded = data + b"\0" * (-len(data) % 4)
    total = 0
    for i in range(0, len(padded), 4):
        if i == cs_off:
            continue
        total += struct.unpack_from("<I", padded, i)[0]
        if total >= 1 << 32:
            total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total = total + (total >> 16)
    return (total & 0xFFFF) + len(data)


def pe_text_range(data: bytes) -> tuple[int, int]:
    img = seal_binary.parse_pe64(data)
    text = [s for s in img.sections if s.name == b".text"][0]
    return text.raw_offset, text.virtual_size


def test_pe_support(tmpdir: str, repo_root: str) -> None:
    py = sys.executable
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    verify_tool = os.path.join(repo_root, "tools", "verify_release.py")

    def write(name: str, data: bytes) -> str:
        path = os.path.join(tmpdir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def seal(path: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return run_cmd([py, seal_tool, path, "--build-id", "5", *extra])

    def verify_only(path: str) -> subprocess.CompletedProcess[str]:
        return run_cmd([py, seal_tool, path, "--verify-only"])

    def rejected(name: str, data: bytes, needle: str) -> None:
        path = write(name, data)
        r = seal(path)
        assert r.returncode == 2 and needle in r.stderr, f"{name}: expected rejection '{needle}': {r}"
        with open(path, "rb") as f:
            assert f.read() == data, f"{name}: rejected file must stay unmodified"

    # 1. seal + verify-only, header untouched when CheckSum is 0
    base = build_pe()
    pe = write("pe_ok.exe", base)
    r = seal(pe)
    assert r.returncode == 0 and "pe64(.text)" in r.stdout, r
    r = verify_only(pe)
    assert r.returncode == 0 and "match=True" in r.stdout and "pe64(.text)" in r.stdout, r
    with open(pe, "rb") as f:
        sealed = f.read()
    off, size = pe_text_range(sealed)
    assert (off, size) == (0x400, len(PE_TEXT_BYTES))
    rec = seal_binary.find_integrity_record_offset(sealed)
    _m, _v, sealed_flag, bid, _h, exp_size, exp_hash, _mr = struct.unpack_from(
        seal_binary.RECORD_FMT, sealed, rec)
    assert sealed_flag == 1 and bid == 5 and exp_size == len(PE_TEXT_BYTES)
    assert exp_hash == hashlib.sha256(PE_TEXT_BYTES).digest(), "hash must cover exactly VirtualSize bytes of .text"
    cs_off = seal_binary.parse_pe64(sealed).checksum_offset
    assert struct.unpack_from("<I", sealed, cs_off)[0] == 0, "CheckSum 0 must stay 0"
    diff = [i for i in range(len(base)) if base[i] != sealed[i]]
    assert all(rec <= i < rec + seal_binary.RECORD_SIZE for i in diff), "only the record may change"
    print("PASS: PE seal + --verify-only match; hash covers .text VirtualSize bytes; only the record changes")

    # 2. 1-byte .text tamper
    tampered = bytearray(sealed)
    tampered[off + 10] ^= 0x01
    r = verify_only(write("pe_tampered.exe", bytes(tampered)))
    assert r.returncode == 1 and "match=False" in r.stdout, r
    print("PASS: PE 1-byte .text change makes --verify-only fail")

    # 3. CheckSum recomputed when non-zero, matches an independent implementation
    pe_cs = write("pe_cs.exe", build_pe(checksum=0x12345))
    assert seal(pe_cs).returncode == 0
    with open(pe_cs, "rb") as f:
        data = f.read()
    got = struct.unpack_from("<I", data, seal_binary.parse_pe64(data).checksum_offset)[0]
    assert got == pe_checksum_reference(data) and got != 0x12345, (hex(got), hex(pe_checksum_reference(data)))
    odd = build_pe(sections=[(b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS, None),
                             (b".data", PE_RECORD + b"\xAA" * 41, PE_DATA_FLAGS, None)], checksum=1)
    odd = odd + b"\x7f"  # odd file length (overlay byte)
    pe_odd = write("pe_odd.exe", odd)
    assert seal(pe_odd).returncode == 0
    with open(pe_odd, "rb") as f:
        data = f.read()
    got = struct.unpack_from("<I", data, seal_binary.parse_pe64(data).checksum_offset)[0]
    assert got == pe_checksum_reference(data), "odd-length file checksum"
    print("PASS: PE CheckSum is recomputed (even and odd length) and matches the reference algorithm")

    # 4. relocations
    text_va = 0x1000
    rejected("pe_reloc_text.exe", build_pe(relocs=[(10, text_va + 0x40), (10, text_va + 0x48)]),
             "2 base relocation(s) fall inside .text (first at RVA 0x1040)")
    ok_reloc = write("pe_reloc_data.exe", build_pe(relocs=[(10, 0x2000 + 8), (0, text_va + 4)]))
    assert seal(ok_reloc).returncode == 0, "relocs outside .text and ABSOLUTE padding must not block sealing"
    print("PASS: PE seal rejects relocations inside .text, ignores padding and .data relocations")

    # A reloc that starts just before .text but writes into it changes hashed bytes.
    rejected("pe_reloc_straddle.exe", build_pe(relocs=[(10, text_va - 4)]),
             "1 base relocation(s) fall inside .text (first at RVA 0xffc)")
    ok_adjacent = write("pe_reloc_adjacent.exe", build_pe(relocs=[(3, text_va - 4)]))
    assert seal(ok_adjacent).returncode == 0, "a 4-byte reloc ending exactly at .text must not block sealing"
    print("PASS: PE seal checks the reloc write width (DIR64 straddling .text rejected, HIGHLOW adjacent ok)")

    # 5. already signed (Security directory); verify-only still works on a signed PE
    rejected("pe_signed.exe", build_pe(security_size=0x200), "seal before signing")
    signed = bytearray(sealed)
    sec_dir = seal_binary.parse_pe64(sealed).checksum_offset - 64 + 112 + 4 * 8
    struct.pack_into("<II", signed, sec_dir, len(signed), 0x200)
    r = verify_only(write("pe_signed_after.exe", bytes(signed)))
    assert r.returncode == 0 and "match=True" in r.stdout, r
    print("PASS: PE with a Security directory is rejected for sealing; sealed-then-signed still verifies")

    # 6. record placement
    inside_text = PE_TEXT_BYTES[:100] + PE_RECORD + PE_TEXT_BYTES[196:]
    rejected("pe_rec_in_text.exe", build_pe(sections=[
        (b".text", inside_text, PE_TEXT_FLAGS, None),
        (b".data", b"\xAA" * 64, PE_DATA_FLAGS, None)]), "overlap")
    rejected("pe_rec_partial.exe", build_pe(sections=[
        (b".text", PE_TEXT_BYTES[:900] + PE_RECORD[:50], PE_TEXT_FLAGS, 950),
        (b".data", PE_RECORD[50:] + b"\xAA" * 40, PE_DATA_FLAGS, None)]), "")
    rejected("pe_rec_rdata.exe", build_pe(sections=[
        (b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS, None),
        (b".rdata", PE_RECORD + b"\xAA" * 40, PE_RDATA_FLAGS, None)]), "writable data section")
    print("PASS: PE seal rejects a record inside .text (overlap) or outside a writable data section")

    # 7. section layout errors
    data_sec = (b".data", PE_RECORD + b"\xAA" * 40, PE_DATA_FLAGS, None)
    rejected("pe_no_text.exe", build_pe(sections=[data_sec]), "found 0")
    rejected("pe_two_text.exe", build_pe(sections=[
        (b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS, None),
        (b".text", PE_TEXT_BYTES[:300], PE_TEXT_FLAGS, None), data_sec]), "found 2")
    rejected("pe_w_text.exe", build_pe(sections=[
        (b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS | 0x80000000, None), data_sec]), "writable")
    rejected("pe_big_vsize.exe", build_pe(sections=[
        (b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS, 4096), data_sec]), "exceeds SizeOfRawData")
    rejected("pe_text_prefix.exe", build_pe(sections=[
        (b".text2", PE_TEXT_BYTES, PE_TEXT_FLAGS, None), data_sec]), "found 0")
    print("PASS: PE seal rejects 0/2 .text sections, writable .text and VirtualSize > SizeOfRawData")

    # 8. other machines / formats
    rejected("pe_arm64.exe", build_pe(machine=0xAA64), "ARM64")
    rejected("pe_x86.exe", build_pe(machine=0x14C), "Unsupported PE Machine")
    rejected("pe_pe32.exe", build_pe(opt_magic=0x10B), "PE32+")
    rejected("pe_truncated.exe", build_pe()[:0x90], "")
    print("PASS: PE seal rejects ARM64 (not supported yet), x86, PE32 and truncated images")

    # 9. executable extra section: warning only
    warn_pe = write("pe_warn.exe", build_pe(sections=[
        (b".text", PE_TEXT_BYTES, PE_TEXT_FLAGS, None),
        (b".init", b"\x90" * 64, PE_TEXT_FLAGS, None), data_sec]))
    r = seal(warn_pe)
    assert r.returncode == 0 and ".init" in r.stderr and "warning" in r.stderr, r
    print("PASS: PE seal only warns about other executable sections")

    # 10. verify_release on a sealed PE; nm missing -> n/a, not a failure
    r = run_cmd([py, verify_tool, pe])
    assert r.returncode == 0 and "pe64(.text)" in r.stdout and "code_seal:       OK" in r.stdout, r
    r = subprocess.run([py, verify_tool, pe], capture_output=True, text=True, env={"PATH": ""})
    assert r.returncode == 0 and "defined_symbols: n/a" in r.stdout, r
    r = run_cmd([py, verify_tool, write("pe_tampered2.exe", bytes(tampered))])
    assert r.returncode == 1 and "code_seal:       FAIL" in r.stdout, r
    print("PASS: verify_release handles PE (OK / tampered) and reports defined_symbols n/a without nm")

    # 11. tools/pe_probe.py reports .text reloc counts and the seal verdict, leaves the input alone
    probe_tool = os.path.join(repo_root, "tools", "pe_probe.py")
    probe_ok = write("pe_probe_ok.exe", build_pe())
    probe_bad = write("pe_probe_bad.exe", build_pe(relocs=[(10, 0x1010), (10, 0x1020)]))
    r = run_cmd([py, probe_tool, probe_ok])
    assert r.returncode == 0 and "base relocations inside .text: 0" in r.stdout and "SEALED" in r.stdout, r
    r = run_cmd([py, probe_tool, probe_bad])
    assert (r.returncode == 0 and "base relocations inside .text: 2" in r.stdout
            and "0x1010, 0x1020" in r.stdout and "REFUSED" in r.stdout), r
    with open(probe_ok, "rb") as f:
        assert f.read() == build_pe(), "pe_probe must not modify its input"
    print("PASS: pe_probe reports reloc counts and seal verdict without modifying the input")

    # 12. optional: a real EXE (e.g. mingw-w64 build of examples/integrity_demo.c)
    real = os.environ.get("RESHIELD_TEST_PE_EXE")
    if not real:
        print("SKIP: RESHIELD_TEST_PE_EXE not set (real PE test)")
        return
    copy = os.path.join(tmpdir, "real.exe")
    shutil.copy2(real, copy)
    r = seal(copy)
    if r.returncode == 0:
        r = verify_only(copy)
        assert r.returncode == 0 and "match=True" in r.stdout, r
        r = run_cmd([py, verify_tool, copy])
        assert r.returncode == 0, r
        print(f"PASS: real PE {os.path.basename(real)} sealed and verified")
    else:
        # mingw's .ctors list in .text carries a base relocation unless linked without a
        # .reloc section; that is a documented refusal, not a crash.
        assert r.returncode == 2 and "base relocation(s) fall inside .text" in r.stderr, r
        print(f"PASS: real PE {os.path.basename(real)} refused as documented: {r.stderr.strip()}")


# `codesign -dvv` output captured from real binaries (the Developer ID one is the documented format).
CODESIGN_LINKER = """Identifier=sample_game
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=516 flags=0x20002(adhoc,linker-signed) hashes=13+0 location=embedded
Signature=adhoc
TeamIdentifier=not set
"""
CODESIGN_ADHOC_RUNTIME = CODESIGN_LINKER.replace("0x20002(adhoc,linker-signed)", "0x10002(adhoc,runtime)")
CODESIGN_DEVID = """Identifier=com.example.game
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=300 flags=0x10000(runtime) hashes=2+7 location=embedded
Signature size=9012
Authority=Developer ID Application: Example (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=ABCDE12345
"""
CODESIGN_UNSIGNED = "/x/game: code object is not signed at all\n"


def test_macho_signature_policy(tmpdir: str, repo_root: str) -> None:
    blocker = seal_binary.macho_signature_blocker
    assert blocker(CODESIGN_LINKER) is None and blocker(CODESIGN_UNSIGNED) is None
    assert blocker(CODESIGN_DEVID) and "non-ad-hoc" in blocker(CODESIGN_DEVID)
    assert blocker(CODESIGN_ADHOC_RUNTIME) and "hardened runtime" in blocker(CODESIGN_ADHOC_RUNTIME)
    assert blocker("something unexpected") is not None, "unrecognised output must fail closed"
    print("PASS: Mach-O signature policy: linker-signed/unsigned ok, identity/runtime/unknown refused")
    if sys.platform != "darwin":
        return

    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    src = os.path.join(repo_root, "build", "sample_game")
    # A throwaway self-signed identity would need a keychain import (and prompts), so the
    # real-binary case uses ad-hoc + hardened runtime, which the re-sign would also destroy.
    signed = os.path.join(tmpdir, "signed_runtime")
    shutil.copy2(src, signed)
    subprocess.run(["codesign", "-s", "-", "--force", "--options", "runtime", signed], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    before = open(signed, "rb").read()
    r = run_cmd([sys.executable, seal_tool, signed, "--build-id", "3"])
    assert r.returncode == 2 and "Seal first, then sign" in r.stderr, r
    assert open(signed, "rb").read() == before, "refused seal must not modify the file"
    r = run_cmd([sys.executable, seal_tool, signed, "--build-id", "3", "--no-codesign"])
    assert r.returncode == 0, r
    print("PASS: seal_binary refuses a signed Mach-O (unmodified) unless --no-codesign")


def test_verify_app(tmpdir: str, repo_root: str) -> None:
    """reshield_verify_app() resolves manifest and assets next to the executable, not the CWD."""
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    gen_tool = os.path.join(repo_root, "tools", "gen_manifest.py")
    app_dir = os.path.join(tmpdir, "va_app")
    elsewhere = os.path.join(tmpdir, "va_cwd")
    os.makedirs(elsewhere)
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), os.path.join(app_dir, "assets"))
    exe = os.path.join(app_dir, "vapp")
    shutil.copy2(os.path.join(repo_root, "build", "test_verify_app"), exe)
    manifest = os.path.join(app_dir, "vapp.manifest")
    subprocess.run([sys.executable, gen_tool, os.path.join(app_dir, "assets"), "-o", manifest],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, seal_tool, exe, "--manifest", manifest, "--build-id", "9"],
                   check=True, stdout=subprocess.DEVNULL)

    def run_app(path: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([path, *args], capture_output=True, text=True, cwd=elsewhere)

    r = run_app(exe, "vapp.manifest", "assets")
    assert r.returncode == 10 and "status=OK" in r.stdout and "check_json=same" in r.stdout, r
    assert "check_json_bounds=ok" in r.stdout, f"reshield_check_json boundary values (cap 0, 1, NULL json): {r}"
    link = os.path.join(elsewhere, "vapp_link")
    os.symlink(exe, link)
    r = run_app(link, "vapp.manifest", "assets")
    assert r.returncode == 10, f"symlinked launch must resolve the real executable dir: {r}"
    r = run_app(exe, "vapp.manifest", "x" * 5000)
    assert r.returncode == 17 and "INTERNAL_ERROR" in r.stdout, f"oversized path must fail closed: {r}"
    print("PASS: verify_app finds manifest/assets next to the exe from another CWD (also via symlink); "
          "oversized path fails closed")

    # reshield_load_verified_app_asset(): same exe-relative paths, bytes handed back, unsealed binary refused.
    r = run_app(exe, "vapp.manifest", "assets", "stage1.cfg")
    assert r.returncode == 10 and "load=OK " in r.stdout and "data=stage_name=Emera" in r.stdout, r
    for rel in ("../vapp.manifest", "sub/../stage1.cfg", "/etc/passwd"):
        r = run_app(exe, "vapp.manifest", "assets", rel)
        assert "load=MANIFEST_IO_ERROR len=0" in r.stdout, f"unsafe asset path {rel!r} must be refused: {r}"
    r = run_app(exe, "vapp.manifest", "assets", "nope.cfg")
    assert "load=ASSET_TAMPERED len=0" in r.stdout, f"unlisted asset: {r}"
    plain = os.path.join(app_dir, "vplain")
    shutil.copy2(os.path.join(repo_root, "build", "test_verify_app"), plain)
    r = run_app(plain, "vapp.manifest", "assets", "stage1.cfg")
    assert "load=UNSEALED len=0" in r.stdout, f"an unsealed binary must not load assets (even in a dev library): {r}"
    os.unlink(plain)
    print("PASS: load_verified_app_asset returns the verified bytes; unsafe/unlisted paths and an unsealed binary are refused")

    stage_cfg = os.path.join(app_dir, "assets", "stage1.cfg")
    with open(stage_cfg, "ab") as f:
        f.write(b"x")
    r = run_app(exe, "vapp.manifest", "assets", "stage1.cfg")
    assert "load=ASSET_TAMPERED len=0" in r.stdout, f"a changed asset must not be loaded: {r}"
    r = run_app(exe, "vapp.manifest", "assets")
    assert r.returncode == 16 and "asset=stage1.cfg" in r.stdout and "check_json=same" in r.stdout, r
    os.unlink(manifest)
    r = run_app(exe, "vapp.manifest", "assets")
    assert r.returncode == 18 and "MANIFEST_IO_ERROR" in r.stdout and "check_json=same" in r.stdout, r
    print("PASS: verify_app reports ASSET_TAMPERED, then MANIFEST_IO_ERROR for a missing manifest")

    # assets_rel == NULL means "." (the exe directory): the entries resolve next to the binary.
    flat_dir = os.path.join(tmpdir, "va_flat")
    flat_src = os.path.join(tmpdir, "va_flat_src")
    os.makedirs(flat_dir)
    os.makedirs(flat_src)
    shutil.copy2(os.path.join(repo_root, "examples", "assets", "stage1.cfg"), flat_src)
    shutil.copy2(os.path.join(repo_root, "examples", "assets", "stage1.cfg"), flat_dir)
    flat_manifest = os.path.join(flat_dir, "flat.manifest")
    subprocess.run([sys.executable, gen_tool, flat_src, "-o", flat_manifest], check=True,
                   stdout=subprocess.DEVNULL)
    flat_exe = os.path.join(flat_dir, "vflat")
    shutil.copy2(os.path.join(repo_root, "build", "test_verify_app"), flat_exe)
    subprocess.run([sys.executable, seal_tool, flat_exe, "--manifest", flat_manifest, "--build-id", "9"],
                   check=True, stdout=subprocess.DEVNULL)
    r = run_app(flat_exe, "flat.manifest")
    assert r.returncode == 10 and "status=OK" in r.stdout and "check_json=same" in r.stdout and \
        "check_json_bounds=ok" in r.stdout, f"assets_rel NULL must default to the exe directory: {r}"
    r = run_app(flat_exe, "flat.manifest", "nope")
    assert r.returncode == 16 and "ASSET_TAMPERED" in r.stdout, f"an explicit assets_rel overrides the default: {r}"
    print("PASS: verify_app with assets_rel NULL resolves entries in the exe directory")


def test_release_cli_binary_in_assets(tmpdir: str, repo_root: str) -> None:
    """The usual engine layout: the binary sits inside the directory that is the asset set."""
    tool = os.path.join(repo_root, "tools", "reshield_release.py")
    dist = os.path.join(tmpdir, "relin")
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), os.path.join(dist, "data"))
    exe = os.path.join(dist, "game")
    shutil.copy2(os.path.join(repo_root, "build", "sample_game"), exe)
    with open(os.path.join(dist, "game.pdb"), "wb") as f:
        f.write(b"debug symbols")

    r = run_cmd([sys.executable, tool, exe, "--allow-dev-build", "--assets", dist, "--exclude", "*.pdb", "--build-id", "6"])
    assert r.returncode == 0 and "excluding the sealed binary from the manifest: game" in r.stdout, r
    with open(os.path.join(dist, "game.manifest")) as f:
        listed = [line.split(" ", 2)[2].strip() for line in f]
    assert listed == ["data/stage1.cfg"], f"binary, pdb and the manifest itself must not be listed: {listed}"
    r = run_cmd([sys.executable, os.path.join(repo_root, "tools", "verify_release.py"), exe, "--allow-dev-build", "--manifest",
                 os.path.join(dist, "game.manifest"), "--assets", dist])
    assert r.returncode == 0 and "code_seal:       OK" in r.stdout, r
    print("PASS: reshield_release excludes a binary that sits inside --assets (and --exclude patterns); "
          "verify_release passes")


def test_release_cli_edges(tmpdir: str, repo_root: str) -> None:
    """reshield_release.py: build id sources and the auto-exclude of the sealed binary at its edges."""
    tool = os.path.join(repo_root, "tools", "reshield_release.py")
    verify_tool = os.path.join(repo_root, "tools", "verify_release.py")
    src = os.path.join(repo_root, "build", "sample_game")
    assets_src = os.path.join(repo_root, "examples", "assets")

    def release(exe: str, assets: str, *extra: str, build_number: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if k != "BUILD_NUMBER"}
        if build_number is not None:
            env["BUILD_NUMBER"] = build_number
        return subprocess.run([sys.executable, tool, exe, "--allow-dev-build", "--assets", assets, *extra],
                              capture_output=True, text=True, env=env)

    def listed(manifest: str) -> list[str]:
        with open(manifest) as f:
            return [line.split(" ", 2)[2].strip() for line in f if line.strip()]

    def build_id_of(exe: str, manifest: str, assets: str) -> str:
        r = run_cmd([exe, manifest, assets, "STAGE-1-CLEAR-2026"])
        m = re.search(r"build_id=(\d+)", r.stdout)
        assert r.returncode == 0 and m, f"released binary must run: {r}"
        return m.group(1)

    # Build id: -1 is refused (nothing modified); BUILD_NUMBER="" falls back to 1; BUILD_NUMBER=42 is used.
    ids = os.path.join(tmpdir, "ids")
    shutil.copytree(assets_src, os.path.join(ids, "assets"))
    neg = os.path.join(ids, "neg")
    shutil.copy2(src, neg)
    before = open(neg, "rb").read()
    r = release(neg, os.path.join(ids, "assets"), "--build-id", "-1")
    assert r.returncode != 0 and "outside 0..4294967295" in r.stderr, r
    assert open(neg, "rb").read() == before, "a refused build id must not modify the file"
    for label, value, want in (("empty", "", "1"), ("42", "42", "42")):
        exe = os.path.join(ids, f"bn_{label}")
        shutil.copy2(src, exe)
        r = release(exe, os.path.join(ids, "assets"), build_number=value)
        assert r.returncode == 0, r
        got = build_id_of(exe, os.path.join(ids, f"bn_{label}.manifest"), os.path.join(ids, "assets"))
        assert got == want, f"BUILD_NUMBER={value!r}: build_id {got}, want {want}"
    print("PASS: reshield_release: --build-id -1 refused, BUILD_NUMBER='' -> 1, BUILD_NUMBER=42 -> 42")

    # Binary in a subdirectory of --assets, and a name with glob metacharacters, are excluded exactly.
    for rel in ("sub/game", "game[1]"):
        dist = os.path.join(tmpdir, "ex_" + rel.replace("/", "_").replace("[", "").replace("]", ""))
        shutil.copytree(assets_src, os.path.join(dist, "data"))
        exe = os.path.join(dist, *rel.split("/"))
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        shutil.copy2(src, exe)
        r = release(exe, dist, "--build-id", "6")
        assert r.returncode == 0 and f"excluding the sealed binary from the manifest: {rel}" in r.stdout, r
        manifest = os.path.join(os.path.dirname(exe), os.path.basename(exe).split(".")[0] + ".manifest")
        assert listed(manifest) == ["data/stage1.cfg"], f"{rel}: {listed(manifest)}"
        r = run_cmd([sys.executable, verify_tool, exe, "--allow-dev-build", "--manifest", manifest, "--assets", dist])
        assert r.returncode == 0 and "code_seal:       OK" in r.stdout, r
    print("PASS: reshield_release auto-excludes a binary in a subdirectory and one named with glob metacharacters")

    # Sibling directory with a shared name prefix is outside --assets: nothing is excluded.
    root = os.path.join(tmpdir, "sib")
    shutil.copytree(assets_src, os.path.join(root, "dist", "data"))
    os.makedirs(os.path.join(root, "dist2"))
    exe = os.path.join(root, "dist2", "game")
    shutil.copy2(src, exe)
    r = release(exe, os.path.join(root, "dist"), "--build-id", "6")
    assert r.returncode == 0 and "excluding the sealed binary" not in r.stdout, r
    manifest = os.path.join(root, "dist2", "game.manifest")
    assert listed(manifest) == ["data/stage1.cfg"], listed(manifest)
    r = run_cmd([sys.executable, verify_tool, exe, "--allow-dev-build", "--manifest", manifest, "--assets", os.path.join(root, "dist")])
    assert r.returncode == 0, r
    print("PASS: reshield_release does not treat dist2/game as inside --assets dist")


def test_release_cli(tmpdir: str, repo_root: str) -> None:
    """tools/reshield_release.py: fixed order strip -> manifest -> seal -> sign -> verify."""
    tool = os.path.join(repo_root, "tools", "reshield_release.py")
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    src = os.path.join(repo_root, "build", "sample_game")
    out = os.path.join(tmpdir, "rel")
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), os.path.join(out, "assets"))

    exe = os.path.join(out, "game")
    shutil.copy2(src, exe)
    r = run_cmd([sys.executable, tool, exe, "--allow-dev-build", "--assets", os.path.join(out, "assets"), "--strip", "--build-id", "5"])
    assert r.returncode == 0 and "ship:" in r.stdout, r
    manifest = os.path.join(out, "game.manifest")
    assert os.path.isfile(manifest), "default manifest is <binary name>.manifest next to the binary"
    r = run_cmd([exe, manifest, os.path.join(out, "assets"), "STAGE-1-CLEAR-2026"])
    assert r.returncode == 0 and "build_id=5" in r.stdout, f"released binary must run: {r}"

    # The sign command runs after sealing: --verify-only fails (rc 1) on an unsealed binary.
    exe2 = os.path.join(out, "game2")
    shutil.copy2(src, exe2)
    r = run_cmd([sys.executable, tool, exe2, "--allow-dev-build", "--sign-cmd", f"{sys.executable} {seal_tool} {{}} --verify-only"])
    assert r.returncode == 0 and "match=True" in r.stdout, f"sign step must see a sealed binary: {r}"
    print("PASS: reshield_release strips, seals with manifest, runs the sign step after sealing, verifies")

    r = run_cmd([sys.executable, tool, out])
    assert r.returncode != 0 and "inside the bundle" in r.stderr, r

    exe3 = os.path.join(out, "game3")
    shutil.copy2(src, exe3)
    before3 = open(exe3, "rb").read()
    r = run_cmd([sys.executable, tool, exe3, "--allow-dev-build", "--build-id", "4294967296"])
    assert r.returncode != 0 and "outside 0..4294967295" in r.stderr, r
    r = subprocess.run([sys.executable, tool, exe3, "--allow-dev-build"], capture_output=True, text=True,
                       env={**os.environ, "BUILD_NUMBER": "12a"})
    assert r.returncode != 0 and "BUILD_NUMBER" in r.stderr, r
    assert open(exe3, "rb").read() == before3, "rejected arguments must not modify the file"
    if sys.platform != "darwin":  # a non-macOS host cannot honour --sign: it must say so
        r = run_cmd([sys.executable, tool, exe3, "--allow-dev-build", "--sign", "Some Identity"])
        assert r.returncode == 0 and "will NOT be signed" in r.stderr, r
    print("PASS: reshield_release rejects bad build ids and warns when --sign cannot apply")

    if sys.platform != "darwin":
        return
    signed = os.path.join(out, "signed")
    shutil.copy2(src, signed)
    subprocess.run(["codesign", "-s", "-", "--force", "--options", "runtime", signed], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    before = open(signed, "rb").read()
    r = run_cmd([sys.executable, tool, signed, "--allow-dev-build"])
    assert r.returncode == 2 and "Seal first, then sign" in r.stderr, r
    assert open(signed, "rb").read() == before, "refused release must not modify the file"
    print("PASS: reshield_release refuses an already-signed Mach-O without touching it")


def test_strict_manifest(tmpdir: str, repo_root: str) -> None:
    """Manifest v2 / strict mode: gen_manifest, verify_release and the C runtime agree."""
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    gen_tool = os.path.join(repo_root, "tools", "gen_manifest.py")
    release_tool = os.path.join(repo_root, "tools", "reshield_release.py")
    app = os.path.join(tmpdir, "st_app")
    assets = os.path.join(app, "assets")
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), assets)
    manifest = os.path.join(app, "vapp.manifest")
    cwd = os.path.join(tmpdir, "st_cwd")
    os.makedirs(cwd)

    def gen(*extra: str, out: str = manifest) -> subprocess.CompletedProcess[str]:
        return run_cmd([sys.executable, gen_tool, assets, "-o", out, *extra])

    def c_run() -> subprocess.CompletedProcess[str]:
        """Seals a fresh test_verify_app against `manifest` and runs it (exit = 10 + status)."""
        exe = os.path.join(app, "vapp")
        shutil.copy2(os.path.join(repo_root, "build", "test_verify_app"), exe)
        subprocess.run([sys.executable, seal_tool, exe, "--manifest", manifest, "--build-id", "9"],
                       check=True, stdout=subprocess.DEVNULL)
        return subprocess.run([exe, "vapp.manifest", "assets"], capture_output=True, text=True, cwd=cwd)

    def py_verify() -> tuple[bool, str]:
        ok, _n, msg = verify_release_mod.verify_manifest_entries(manifest, assets)
        return ok, msg

    def put(rel: str, data: bytes = b"x") -> str:
        p = os.path.join(assets, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    # Header written by --strict: version line, default allow list, then the sorted entries.
    r = gen("--strict")
    assert r.returncode == 0, r
    with open(manifest, encoding="utf-8") as f:
        lines = f.read().split("\n")
    assert lines[0] == "#reshield-manifest v2 strict", lines[:3]
    for g in (".DS_Store", "*/.DS_Store", "Thumbs.db", "*/Thumbs.db", "desktop.ini", "*/desktop.ini"):
        assert f"#allow {g}" in lines, g
    policy, entries = manifest_policy_mod.parse_manifest(open(manifest, "rb").read())
    assert policy.strict and len(entries) == 1 and entries[0][2] == "stage1.cfg", (policy, entries)
    assert py_verify()[0] and c_run().returncode == 10, "clean strict directory must pass in both"

    # An unlisted file: Python and C both reject, C reports ASSET_EXTRA (19) and names the file.
    put("evil.dll")
    ok, msg = py_verify()
    assert not ok and "evil.dll" in msg, msg
    r = c_run()
    assert r.returncode == 19 and "ASSET_EXTRA" in r.stdout and "asset=evil.dll" in r.stdout, r
    os.unlink(os.path.join(assets, "evil.dll"))
    put("sub/dir/proxy.dll")
    r = c_run()
    assert r.returncode == 19 and "asset=sub/dir/proxy.dll" in r.stdout, r
    shutil.rmtree(os.path.join(assets, "sub"))
    print("PASS: strict manifest: unlisted file (also nested) is ASSET_EXTRA in the runtime and rejected by verify_release")

    # Default allow list: OS litter passes at any depth; other dotfiles are extra and gen warns.
    put(".DS_Store")
    put("sub/Thumbs.db")
    put("sub/deeper/desktop.ini")
    r = gen("--strict")
    assert r.returncode == 0 and "warning" not in r.stdout, r
    assert py_verify()[0] and c_run().returncode == 10, ".DS_Store / Thumbs.db / desktop.ini are allowed by default"
    _p, entries = manifest_policy_mod.parse_manifest(open(manifest, "rb").read())
    assert [e[2] for e in entries] == ["stage1.cfg"], f"OS litter must not be listed: {entries}"
    put(".x.dll")
    r = gen("--strict")
    assert r.returncode == 0 and "dotfile skipped but not allowed" in r.stdout and ".x.dll" in r.stdout, r
    r = c_run()
    assert r.returncode == 19 and "asset=.x.dll" in r.stdout, r
    r = gen("--strict", "--allow", ".x.*")
    assert "warning" not in r.stdout and py_verify()[0] and c_run().returncode == 10, r
    shutil.rmtree(os.path.join(assets, "sub"))
    for n in (".DS_Store", ".x.dll"):
        os.unlink(os.path.join(assets, n))
    print("PASS: strict manifest: default allow list for OS litter, dotfile warning, --allow")

    # --allow: sealed with the manifest; user saves in the asset dir pass, anything else is extra.
    put("saves/slot1.sav")
    gen("--strict", "--allow", "saves/*")
    assert py_verify()[0] and c_run().returncode == 10
    put("evil.dll")
    assert c_run().returncode == 19
    os.unlink(os.path.join(assets, "evil.dll"))
    shutil.rmtree(os.path.join(assets, "saves"))
    r = gen("--allow", "saves/*")
    assert r.returncode != 0, "--allow without --strict must be refused"
    for bad in ("/abs", "../x", "a/../b", "a\\b", ""):
        r = gen("--strict", "--allow", bad)
        assert r.returncode != 0 and "Invalid --allow glob" in r.stderr, (bad, r)
    r = gen("--strict", *sum((["--allow", f"g{i}"] for i in range(60)), []))
    assert r.returncode != 0 and "Too many allow globs" in r.stderr, r
    print("PASS: gen_manifest --allow needs --strict, rejects bad globs and more than 64 allow lines")

    # Manifest inside the asset dir is allowed automatically in strict mode (and not listed).
    inside = os.path.join(assets, "game.manifest")
    r = gen("--strict", out=inside)
    assert r.returncode == 0, r
    text = open(inside, encoding="utf-8").read()
    assert "#allow game.manifest\n" in text and " game.manifest\n" not in text.replace("#allow game.manifest\n", "")
    ok, _n, msg = verify_release_mod.verify_manifest_entries(inside, assets)
    assert ok, msg
    os.unlink(inside)
    print("PASS: strict manifest stored inside the asset dir allows itself and is not listed")

    # --exclude GLOB under --strict: the excluded files are not listed but allowed automatically (one
    # literal #allow per file unless an --allow glob covers it), so the runtime does not call them extra.
    put("a.pdb")
    put("sub/b.pdb")
    r = gen("--strict", "--exclude", "*.pdb")
    assert r.returncode == 0, r
    policy, entries = manifest_policy_mod.parse_manifest(open(manifest, "rb").read())
    assert "a.pdb" in policy.allow and "sub/b.pdb" in policy.allow, policy.allow
    assert [e[2] for e in entries] == ["stage1.cfg"], entries
    assert py_verify()[0] and c_run().returncode == 10, "excluded files must pass the strict scan"
    r = gen("--strict", "--exclude", "*.pdb", "--allow", "*.pdb")
    assert r.returncode == 0, r
    policy, _entries = manifest_policy_mod.parse_manifest(open(manifest, "rb").read())
    assert "a.pdb" not in policy.allow and "*.pdb" in policy.allow, policy.allow
    assert py_verify()[0] and c_run().returncode == 10
    r = gen("--exclude", "*.pdb")
    assert r.returncode == 0, r
    policy, _entries = manifest_policy_mod.parse_manifest(open(manifest, "rb").read())
    assert not policy.strict and not policy.allow, "non-strict --exclude adds no #allow"
    put("odd*name.dll")
    r = gen("--strict", "--exclude", "odd*name.dll")
    assert r.returncode != 0 and "Cannot auto-allow" in r.stderr, r
    for stale in ("a.pdb", "sub", "odd*name.dll"):
        p = os.path.join(assets, stale)
        shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
    print("PASS: strict manifest: --exclude files are allowed automatically (unless an --allow glob covers them)")

    # Python and the C runtime must agree on every header (incl. the section 13 '#' rule).
    h = "#reshield-manifest v2 strict\n"
    digest = hashlib.sha256(open(os.path.join(assets, "stage1.cfg"), "rb").read()).hexdigest()
    size = os.path.getsize(os.path.join(assets, "stage1.cfg"))
    entry = f"{digest} {size} stage1.cfg\n"
    header_cases = [
        ("", True), ("# comment\n", True), ("#\n# c\n", True), ("\n", True),
        (h, True), ("#reshield-manifest v2\n", True), (h + "#allow *.log\n", True),
        ("# c\n" + h + "# c\n#allow a\n", True), (h + "#allow v1..2*\n", True),
        ("#reshield-manifest v3\n", False), ("#reshield-manifest v2 loose\n", False),
        ("#reshield-manifest v2 strict \n", False), ("#reshield-manifest\n", False),
        (h + h, False), (h + "#frob\n", False), (h + "#Allow x\n", False), (h + "#allow\n", False),
        (h + "#allow \n", False), (h + "#allow /abs\n", False), (h + "#allow ../x\n", False),
        (h + "#allow a/../b\n", False), (h + "#allow a/..\n", False), (h + "#allow a\\b\n", False),
        ("#allow x\n" + h, False), ("#allow x\n", False),
        (h + "".join(f"#allow g{i}\n" for i in range(64)), True),
        (h + "".join(f"#allow g{i}\n" for i in range(65)), False),
        (h + "#allow " + "g" * 255 + "\n", True), (h + "#allow " + "g" * 256 + "\n", False),
    ]
    for header, want in header_cases:
        with open(manifest, "w", encoding="utf-8", newline="") as f:
            f.write(header + entry)
        py_ok, py_msg = py_verify()
        c_rc = c_run().returncode
        assert py_ok == want and (c_rc == 10) == want and (want or c_rc == 18), \
            f"header {header!r}: python={py_ok} ({py_msg}) C exit={c_rc}, want ok={want}"
    for text in (entry + h, entry + "# late comment\n", entry + "\n#\n"):
        with open(manifest, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        c_rc = c_run().returncode
        assert not py_verify()[0] and c_rc == 18, f"'#' after the first entry must be rejected: {text!r} ({c_rc})"
    print(f"PASS: verify_release and the C runtime agree on {len(header_cases) + 3} manifest header cases")

    # Glob semantics: Python matcher and C matcher give the same verdict.
    glob_cases = [
        ("*.log", "x.log", True), ("*.log", "a/b/x.log", True), ("*.LOG", "x.log", False),
        ("a?c", "abc", True), ("a?c", "ac", False), ("a?c", "a/c", True), ("*/x", "x", False),
        ("*/x", "d/x", True), ("a*b*c", "aXXbYYc", True), ("a*b*c", "aXXbYY", False),
        ("*", "any/thing/deep", True), ("sav", "sav/x", False), ("sav*", "sav/x/y", True),
        ("x*", "xx", True), ("**", "q", True), ("a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaac", False),
    ]
    for glob, rel, want in glob_cases:
        assert manifest_policy_mod.glob_match(glob, rel) == want, f"python glob {glob!r} vs {rel!r}"
        shutil.rmtree(os.path.join(assets, "gl"), ignore_errors=True)
        for stale in os.listdir(assets):
            if stale != "stage1.cfg":
                p = os.path.join(assets, stale)
                shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
        put(rel)
        with open(manifest, "w", encoding="utf-8", newline="") as f:
            f.write(f"{h}#allow {glob}\n{entry}")
        py_ok, _msg = py_verify()
        c_rc = c_run().returncode
        assert py_ok == want and c_rc == (10 if want else 19), \
            f"glob {glob!r} vs {rel!r}: want match={want}, python={py_ok}, C exit={c_rc}"
    for stale in os.listdir(assets):
        if stale != "stage1.cfg":
            p = os.path.join(assets, stale)
            shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
    print(f"PASS: allow glob matcher agrees between Python and the C runtime ({len(glob_cases)} cases)")

    # Symlinks are items (not followed) in both implementations.
    os.symlink("stage1.cfg", os.path.join(assets, "link.cfg"))
    os.symlink(".", os.path.join(assets, "selfdir"))
    r = gen("--strict")
    assert r.returncode == 0 and "symlinked directory not traversed" in r.stdout, r
    ok, msg = py_verify()
    assert not ok and "selfdir" in msg, msg
    r = c_run()
    assert r.returncode == 19 and "asset=" in r.stdout, r
    os.unlink(os.path.join(assets, "selfdir"))
    os.unlink(os.path.join(assets, "link.cfg"))
    print("PASS: strict manifest: symlinks (also to directories) are extra items, never followed")

    # reshield_release.py: the binary to seal may live inside --assets (excluded from the manifest,
    # allowed automatically with --strict); --allow is passed through.
    rel = os.path.join(tmpdir, "st_rel")
    rel_assets = os.path.join(rel, "assets")
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), rel_assets)
    sample = os.path.join(repo_root, "build", "sample_game")
    exe = os.path.join(rel_assets, "game")
    shutil.copy2(sample, exe)
    r = run_cmd([sys.executable, release_tool, exe, "--allow-dev-build", "--assets", rel_assets, "--build-id", "6"])
    assert r.returncode == 0, f"binary inside --assets must release (non-strict): {r}"
    with open(os.path.join(rel_assets, "game.manifest"), encoding="utf-8") as f:
        listed = [ln.split(" ", 2)[2] for ln in f.read().splitlines() if ln and not ln.startswith("#")]
    assert listed == ["stage1.cfg"], f"binary and manifest must not be listed: {listed}"
    r = run_cmd([exe, os.path.join(rel_assets, "game.manifest"), rel_assets, "STAGE-1-CLEAR-2026"])
    assert r.returncode == 0 and "STAGE UNLOCKED" in r.stdout, r

    rel2 = os.path.join(tmpdir, "st_rel2")
    rel2_assets = os.path.join(rel2, "assets")
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), rel2_assets)
    exe2 = os.path.join(rel2_assets, "game")
    shutil.copy2(sample, exe2)
    r = run_cmd([sys.executable, release_tool, exe2, "--allow-dev-build", "--assets", rel2_assets, "--strict", "--allow", "saves/*",
                 "--build-id", "6"])
    assert r.returncode == 0, f"strict release with binary inside --assets: {r}"
    m2 = os.path.join(rel2_assets, "game.manifest")
    text = open(m2, encoding="utf-8").read()
    assert text.startswith("#reshield-manifest v2 strict\n") and "#allow game\n" in text \
        and "#allow game.manifest\n" in text and "#allow saves/*\n" in text, text
    r = run_cmd([exe2, m2, rel2_assets, "STAGE-1-CLEAR-2026"])
    assert r.returncode == 0 and "STAGE UNLOCKED" in r.stdout, f"sealed strict release must run: {r}"
    os.makedirs(os.path.join(rel2_assets, "saves"))
    with open(os.path.join(rel2_assets, "saves", "slot1.sav"), "wb") as f:
        f.write(b"s")
    r = run_cmd([exe2, m2, rel2_assets, "STAGE-1-CLEAR-2026"])
    assert r.returncode == 0, f"#allow saves/* must admit user saves: {r}"
    with open(os.path.join(rel2_assets, "evil.dll"), "wb") as f:
        f.write(b"MZ")
    r = run_cmd([exe2, m2, rel2_assets, "STAGE-1-CLEAR-2026"])
    assert r.returncode == 19 and "ASSET_EXTRA" in r.stderr and "asset=evil.dll" in r.stderr, r
    r = run_cmd([sys.executable, release_tool, exe2, "--allow", "x"])
    assert r.returncode != 0, "--allow without --strict must be refused by reshield_release"
    print("PASS: reshield_release --strict/--allow: binary inside --assets is excluded and allowed, drop-in DLL is ASSET_EXTRA")


def test_verify_release_steam_appid_warning(tmpdir: str, repo_root: str) -> None:
    """steam_appid.txt in the shipped set only warns: verify_release keeps rc 0."""
    tool = os.path.join(repo_root, "tools", "reshield_release.py")
    verify = os.path.join(repo_root, "tools", "verify_release.py")
    dist = os.path.join(tmpdir, "steam")
    shutil.copytree(os.path.join(repo_root, "examples", "assets"), os.path.join(dist, "assets"))
    exe = os.path.join(dist, "game")
    shutil.copy2(os.path.join(repo_root, "build", "sample_game"), exe)
    assets = os.path.join(dist, "assets")
    r = run_cmd([sys.executable, tool, exe, "--allow-dev-build", "--assets", assets, "--build-id", "2"])
    assert r.returncode == 0 and "steam_appid" not in r.stderr, f"no warning without the file: {r}"

    with open(os.path.join(assets, "Steam_AppID.TXT"), "w") as f:  # case-insensitive match
        f.write("480")
    r = run_cmd([sys.executable, tool, exe, "--allow-dev-build", "--assets", assets, "--build-id", "2"])
    assert r.returncode == 0 and "steam_appid.txt found in --assets" in r.stderr \
        and "in the manifest (Steam_AppID.TXT)" in r.stderr, f"warn, but still pass: {r}"

    os.remove(os.path.join(assets, "Steam_AppID.TXT"))
    with open(os.path.join(dist, "steam_appid.txt"), "w") as f:
        f.write("480")
    r = run_cmd([sys.executable, verify, exe, "--allow-dev-build"])
    assert r.returncode == 0 and "found next to the binary" in r.stderr, r
    print("PASS: verify_release warns about steam_appid.txt (assets, manifest, binary dir) without failing")


def test_incremental_scan(tmpdir: str, repo_root: str) -> None:
    """Incremental scan on a sealed binary: OK, then TAMPERED after a 1-byte .text patch.
    tests/test_incremental_real.c checks that every chunk size matches the one-shot result."""
    src = os.path.join(repo_root, "build", "test_incremental_real")
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")
    sealed = os.path.join(tmpdir, "incr_sealed")
    shutil.copy2(src, sealed)
    subprocess.run([sys.executable, seal_tool, sealed, "--build-id", "9"], check=True,
                   stdout=subprocess.DEVNULL)
    r = run_cmd([sealed])
    assert r.returncode == 0 and "status=OK" in r.stdout, f"sealed incremental scan not OK: {r}"
    if sys.platform.startswith("linux"):
        assert "patch behind the cursor: TAMPERED in the next pass" in r.stdout, f"mid-scan patch test did not run: {r}"
    print("PASS: incremental scan of a sealed binary matches the one-shot check (OK)")

    with open(sealed, "rb") as f:
        buf = bytearray(f.read())
    off = find_symbol_file_offset(sealed, bytes(buf), "reshield_incr_sentinel")
    buf[off] ^= 0x01
    tampered = os.path.join(tmpdir, "incr_tampered")
    with open(tampered, "wb") as f:
        f.write(buf)
    os.chmod(tampered, 0o755)
    resign(tampered)
    r = run_cmd([tampered])
    assert r.returncode == 0 and "status=TAMPERED" in r.stdout, f"tampered incremental scan not TAMPERED: {r}"
    print("PASS: incremental scan of a 1-byte-patched sealed binary matches the one-shot check (TAMPERED)")


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
            [sys.executable, verify_tool, game_sealed, "--allow-dev-build", "--manifest", manifest_path, "--assets", assets_dir],
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
    with tempfile.TemporaryDirectory(prefix="reshield_gx_") as tmp_gx:
        test_gen_manifest_exclude(tmp_gx)
    with tempfile.TemporaryDirectory(prefix="reshield_s2_") as tmp2:
        a2 = os.path.join(tmp2, "assets")
        shutil.copytree(assets_src, a2)
        test_status_mapping_and_records(tmp2, repo_root, a2)
        test_seal_tool_and_release_cases(tmp2, repo_root, a2)
        test_macho_signature_policy(tmp2, repo_root)
        test_verify_app(tmp2, repo_root)
        test_strict_manifest(tmp2, repo_root)
        test_release_cli(tmp2, repo_root)
        test_release_cli_binary_in_assets(tmp2, repo_root)
        test_release_cli_edges(tmp2, repo_root)
        test_verify_release_steam_appid_warning(tmp2, repo_root)
        test_incremental_scan(tmp2, repo_root)
    with tempfile.TemporaryDirectory(prefix="reshield_pe_") as tmp3:
        test_pe_support(tmp3, repo_root)

    print("All E2E seal workflow tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
