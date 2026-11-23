#!/usr/bin/env python3
"""
End-to-end integrity verification test for re-shield's own first-party demo binary.

Simulates a 1-byte corruption in a temporary copy of build/integrity_demo to verify:
1. Unsealed binary reports UNSEALED (exit 10) and enforces TERMINATE policy (exit 1).
2. Sealed binary reports OK (exit 0) and passes guard (exit 0).
3. Flipping 1 byte inside an unused test sentinel function (reshield_tamper_target)
   triggers TAMPERED (exit 11) and exit 1 under TERMINATE policy.
4. Disabled build (-DRESHIELD_DISABLE) skips checks as designed for dev/QA builds.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import seal_binary  # noqa: E402


def find_symbol_file_offset(binary_path: str, data: bytes, symbol: str) -> int:
    """Resolve symbol address via nm and convert to file offset within code section."""
    nm_out = subprocess.check_output(["nm", binary_path], text=True)
    sym_addr = None
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in (symbol, "_" + symbol):
            sym_addr = int(parts[0], 16)
            break
    if sym_addr is None:
        raise RuntimeError(f"Symbol {symbol} not found in {binary_path}")

    # Find section virtual address + file offset
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


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    demo_src = os.path.join(repo_root, "build", "integrity_demo")
    demo_disabled = os.path.join(repo_root, "build", "integrity_demo_disabled")
    seal_tool = os.path.join(repo_root, "tools", "seal_binary.py")

    with tempfile.TemporaryDirectory(prefix="reshield_e2e_") as tmpdir:
        unsealed = os.path.join(tmpdir, "demo_unsealed")
        sealed = os.path.join(tmpdir, "demo_sealed")
        tampered = os.path.join(tmpdir, "demo_tampered")
        shutil.copy2(demo_src, unsealed)
        shutil.copy2(demo_src, sealed)

        # 1. Unsealed binary
        r = run_cmd([unsealed, "--mode=verify"])
        assert r.returncode == 10 and "status=UNSEALED" in r.stdout, f"Unsealed verify failed: {r}"
        r = run_cmd([unsealed, "--mode=guard-quiet"])
        assert r.returncode == 1 and r.stdout == "" and r.stderr == "", f"Unsealed guard-quiet failed: {r}"
        print("PASS: E2E unsealed binary reports UNSEALED and exits quietly under guard")

        # 2. Seal binary and verify
        subprocess.run([sys.executable, seal_tool, sealed], check=True)
        subprocess.run([sys.executable, seal_tool, "--verify-only", sealed], check=True)
        r = run_cmd([sealed, "--mode=verify"])
        assert r.returncode == 0 and "status=OK" in r.stdout, f"Sealed verify failed: {r}"
        r = run_cmd([sealed, "--mode=guard-quiet"])
        assert r.returncode == 0 and r.stdout.startswith("ok "), f"Sealed guard-quiet failed: {r}"
        print("PASS: E2E sealed binary passes verify and guard-quiet")

        # 3. Tamper 1 byte in executable code (reshield_tamper_target)
        shutil.copy2(sealed, tampered)
        with open(tampered, "rb") as f:
            buf = bytearray(f.read())
        target_off = find_symbol_file_offset(tampered, bytes(buf), "reshield_tamper_target")
        buf[target_off] ^= 0x01
        with open(tampered, "wb") as f:
            f.write(buf)
        if sys.platform == "darwin":
            subprocess.run(["codesign", "-s", "-", "--force", tampered], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        r = run_cmd([tampered, "--mode=verify"])
        assert r.returncode == 11 and "status=TAMPERED" in r.stdout, f"Tampered verify failed: {r}"
        r = run_cmd([tampered, "--mode=guard-quiet"])
        assert r.returncode == 1 and r.stdout == "" and r.stderr == "", f"Tampered guard-quiet failed: {r}"
        print("PASS: E2E 1-byte code section tamper detected and terminated silently")

        # 4. Disabled build
        r = run_cmd([demo_disabled, "--mode=verify"])
        assert r.returncode == 0 and "status=OK" in r.stdout, f"Disabled verify failed: {r}"
        print("PASS: E2E disabled build (-DRESHIELD_DISABLE) bypasses check as designed")

    print("All E2E tamper detection tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
