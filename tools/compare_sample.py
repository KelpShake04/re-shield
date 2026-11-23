#!/usr/bin/env python3
"""
Before/after reversing difficulty comparison script for examples/sample_game.c.

Compares:
  - build/sample_game_unprotected  (plain build, no re-shield, unstripped)
  - build/sample_game_protected    (libreshield.a + XOR key + strip + seal_binary.py)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))
import seal_binary  # noqa: E402

SECRET_KEY = "SECRET_STAGE_KEY_2026"


def count_strings_match(binary: str, needle: str) -> bool:
    out = subprocess.check_output(["strings", binary], text=True, errors="ignore")
    return needle in out


def count_defined_symbols(binary: str) -> tuple[int, bool]:
    proc = subprocess.run(["nm", binary], capture_output=True, text=True)
    if proc.returncode != 0:
        return 0, False
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    has_app_sym = any("validate_stage_key" in ln or "compute_reward_code" in ln for ln in lines)
    return len(lines), has_app_sym


def avg_runtime_ms(binary: str, runs: int = 10) -> float:
    start = time.perf_counter()
    for _ in range(runs):
        r = subprocess.run([binary, SECRET_KEY], capture_output=True, text=True)
        if r.returncode != 0 or "STAGE UNLOCKED" not in r.stdout:
            raise RuntimeError(f"Expected valid execution for {binary}, got: {r}")
    return (time.perf_counter() - start) * 1000.0 / runs


def test_1byte_patch_behavior(binary: str) -> str:
    """Flip 1 byte near the end of the code section in a copy and run it."""
    with tempfile.TemporaryDirectory(prefix="reshield_cmp_") as tmpdir:
        copy_path = os.path.join(tmpdir, "patched")
        shutil.copy2(binary, copy_path)
        with open(copy_path, "rb") as f:
            buf = bytearray(f.read())
        _fmt, text_off, text_size = seal_binary.find_code_section(bytes(buf))
        buf[text_off + text_size - 1] ^= 0x01
        with open(copy_path, "wb") as f:
            f.write(buf)
        if sys.platform == "darwin":
            subprocess.run(["codesign", "-s", "-", "--force", copy_path], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run([copy_path, "WRONG_KEY"], capture_output=True, text=True)
        if "ACCESS DENIED" in r.stdout:
            return "runs normally (no tamper detection)"
        if r.returncode == 1 and r.stdout == "" and r.stderr == "":
            return "silent exit(1) (tamper detected)"
        return f"exited rc={r.returncode}"


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    unprot = os.path.join(repo_root, "build", "sample_game_unprotected")
    prot = os.path.join(repo_root, "build", "sample_game_protected")

    for path in (unprot, prot):
        if not os.path.exists(path):
            print(f"Missing binary: {path}. Run `make sample-compare` first.", file=sys.stderr)
            return 2

    u_str = count_strings_match(unprot, SECRET_KEY)
    p_str = count_strings_match(prot, SECRET_KEY)

    u_syms, u_has_app = count_defined_symbols(unprot)
    p_syms, p_has_app = count_defined_symbols(prot)

    u_size = os.path.getsize(unprot)
    p_size = os.path.getsize(prot)

    u_ms = avg_runtime_ms(unprot)
    p_ms = avg_runtime_ms(prot)

    u_patch = test_1byte_patch_behavior(unprot)
    p_patch = test_1byte_patch_behavior(prot)

    print("# Before vs After Comparison (`sample_game`)")
    print()
    print("| 항목 | 적용 전 (`sample_game_unprotected`) | 적용 후 (`sample_game_protected`) |")
    print("| --- | --- | --- |")
    print(f"| `strings` 평문 키 노출 (`{SECRET_KEY}`) | {'노출됨 (YES)' if u_str else '미 노출 (NO)'} | {'노출됨 (YES)' if p_str else '미 노출 (NO)'} |")
    print(f"| `nm` 심볼 수 (핵심 함수명 노출) | {u_syms} ({'노출됨' if u_has_app else '제거됨'}) | {p_syms} ({'노출됨' if p_has_app else '제거됨'}) |")
    print(f"| 코드 섹션 1바이트 변조 시 동작 | {u_patch} | {p_patch} |")
    print(f"| 바이너리 크기 | {u_size:,} bytes | {p_size:,} bytes |")
    print(f"| 평균 실행 시간 (10회) | {u_ms:.2f} ms | {p_ms:.2f} ms |")

    # Sanity assertions for CI / make test
    assert u_str is True, "Expected plaintext key in unprotected binary"
    assert p_str is False, "Protected binary must not contain plaintext key"
    assert u_has_app is True, "Unprotected binary should retain local app symbols"
    assert p_has_app is False, "Protected binary should strip local app symbols"
    assert "silent exit(1)" in p_patch, f"Expected silent tamper exit on protected binary, got: {p_patch}"
    print("\nPASS: Before/after comparison assertions satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
