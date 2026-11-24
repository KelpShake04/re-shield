# Sanitizers and fuzzing

Trust-boundary inputs of re-shield: the manifest file, asset paths (manifest entries and the
`asset_rel_path` argument), and the PE/ELF/Mach-O binaries read by `tools/seal_binary.py`.
This page describes how they are stress-tested and what was found. CI runs `make sanitize` and `tests/fuzz/test_parser_regressions.py` on Linux; the libFuzzer harnesses and the mutational PE fuzzer are run by hand.

## ASan + UBSan over the test suite

```
make sanitize
```

Runs the `make test` flow with `-fsanitize=address,undefined -fno-sanitize-recover=undefined
-O1 -g` in `build/san/` (UBSan findings abort the run). Differences from `make test`:

- `tests/test_seal_workflow.py` is skipped (`SEAL_WORKFLOW_TEST=true`): it drives the
  hardcoded `build/` binaries and Python, so it would not exercise the sanitized build.
  `tools/verify_release.py` on the sanitized sealed sample still runs.
- The C tests still write scratch files under `build/` (hardcoded paths); `make sanitize`
  creates that directory.
- On macOS (Apple clang) LeakSanitizer does not exist, so leaks are not checked there. On
  Linux it is on by default.
- No test was excluded: the W^X test and the code-section hash test pass under sanitizers
  (sealing hashes the `.text` bytes of the sanitized binary itself, so instrumentation does
  not matter).

Result (104 `PASS`, no `FAIL`, no sanitizer report): macOS arm64 (Apple clang 21) and Linux
aarch64 (`gcc:14` container, `docker run -v "$PWD":/src:ro ...` on a copy of the tree).

## libFuzzer harnesses (`tests/fuzz/`)

libFuzzer needs a clang with the fuzzer runtime; Apple clang has none. Use a container:

```
# Dockerfile: ubuntu:24.04 + clang libclang-rt-18-dev make python3
docker build -t reshield-fuzz -f Dockerfile.fuzz .
docker run --rm -v "$PWD":/src:ro -v /path/to/corpus:/corpus reshield-fuzz bash -c \
  'mkdir /w && cd /src && tar cf - --exclude=./build . | tar xf - -C /w && cd /w && \
   mkdir -p build && make fuzz FUZZ_TIME=120 FUZZ_CORPUS=/corpus'
```

Make targets (inside such an environment): `make fuzz-build` builds
`build/fuzz/fuzz_{manifest,path,sha256}` (ASan+UBSan+libFuzzer); `make fuzz-pe` runs the
Python mutation fuzzer; `make fuzz FUZZ_TIME=<s per fuzzer>` does both, runs each libFuzzer
binary and then the path differential test. Corpora go to `FUZZ_CORPUS` (default
`build/fuzz/corpus`), crashes to `build/fuzz/crash-<name>-*`. Only small hand-made seeds are
committed (`tests/fuzz/seeds/`).

| Harness | Input | Checks |
|---|---|---|
| `fuzz_manifest.c` | bytes written as the manifest file; expected root = SHA-256 of the input | `reshield_verify_manifest_files` and `reshield_verify_single_asset` never crash or return an out-of-range status; `failed_path_buf` stays NUL-terminated; a wrong root never returns `OK`. The asset dir is a tmpfs dir holding `a.cfg` (empty), `sub/b.cfg` and an unlisted `extra.bin`, so seeds/dictionary reach the asset-hashing code and the strict-scan (`#reshield-manifest v2 strict`, `#allow`) paths. |
| `fuzz_path.c` | bytes used as `asset_rel_path` (C string) | Path decision observed through the public API (`IO_ERROR` = rejected); the same path as a manifest entry must give the same decision. |
| `fuzz_sha256.c` | 2-byte prefix limit + message | One-shot hash == `reshield_verify_buffer` == file hash (4 KiB chunked) == one-shot hash of the prefix for `reshield_sha256_file_limited`. No reference implementation is linked, so a bug present in every path would not be seen (NIST vectors are in `tests/test_integrity.c`). |
| `fuzz_pe.py` | seeded mutations of synthetic PE32+ / ELF64 / Mach-O64 images | The parsers in `tools/seal_binary.py` (including the `main()` flow on a temp file, `--verify-only` and sealing) reject malformed input with `ValueError` only; 2 s limit per case catches hangs. Deterministic (`--seed`), stdlib only. |
| `diff_path_rules.py` | seed files, libFuzzer corpus, 20000 generated tricky paths | C rule (via `fuzz_path`) vs `tools/manifest_path.py` give the same decision. |

`tests/fuzz/test_parser_regressions.py` holds the regression cases for the bugs below.

## Findings

Run on Linux aarch64 (Docker on macOS, ubuntu:24.04, clang 18), `FUZZ_TIME=120`, fresh corpus:

| Harness | Time | Executions | Findings |
|---|---|---|---|
| `fuzz_manifest` | 121 s | 1,211,444 | 0 |
| `fuzz_path` | 121 s | 5,697,298 | 0 |
| `fuzz_sha256` | 121 s | 1,255,526 | 0 |
| `diff_path_rules.py` | - | 20,275 paths (3,068 safe) | 0 mismatches |
| `fuzz_pe.py` (macOS, `--seed 7 --iterations 100000`) | 32 s | 300,000 cases | 0 (after the fix below) |

**C code (`src/`): no bug found.** The path rule in `src/manifest.c` and
`tools/manifest_path.py` agree on all cases. Sanity check that the harnesses can see bugs:
removing `|` from the C forbidden-character set makes `diff_path_rules.py` report mismatches
within seconds.

**Python parsers, 1 bug class fixed (low severity).** `tools/seal_binary.py` let
`struct.error` / `OverflowError` escape from `find_elf64_text` (section header table or
string table at/after EOF, offset above 2^63) and `find_macho64_text` (`nsects` or load
command running past EOF) instead of raising `ValueError`. The CLI therefore died with a
traceback (exit 1) rather than the `error:` message (exit 2). It always failed closed: no
malformed file could be sealed or reported as verified. Fix: a small `_unpack()` wrapper that
turns out-of-range reads into `ValueError`, used at the five unchecked `unpack_from` calls.
Five distinct crash sites were found by `fuzz_pe.py` in 3,000 cases per seed image; the PE
parser (`parse_pe64`, relocation walk, `check_pe_sealable`) produced none. Regression test:
`tests/fuzz/test_parser_regressions.py` (fails on the old code, passes now).

## Limits

- Runs were short (see table); absence of findings is not a proof. Coverage-guided fuzzing
  was done for the C parser only; the Python parsers get random byte/field mutations of three
  seed images, not coverage guidance.
- Harnesses call the public API with `expected_root` supplied; the sealed-record lookup
  (`reshield_get_sealed_manifest_root`) and the in-memory code-section hashing are not fuzzed.
- The PE seed is hand-built; real linker output (e.g. MinGW) is not in the corpus.
- Linux/aarch64 container only. The Windows file layer (`src/file_windows.c`) is not exercised.
- `tools/gen_manifest.py` and `tools/verify_release.py` (Python manifest readers) have no
  fuzz harness.
