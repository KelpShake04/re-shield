# re-shield

A zero-dependency C11 library and build tools that make tampering with your own native binaries and assets **evident**. It is tamper-evidence, not tamper-proof.

English | [한국어](README.ko.md)

[![ci](https://github.com/KelpShake04/re-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/KelpShake04/re-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What it does

- **Code-section hash.** `tools/seal_binary.py` records the SHA-256 of the executable's code section (`__TEXT,__text` on macOS, `.text` on Linux and Windows) in the binary at build time. At runtime the library hashes the code in memory and compares. SHA-256 is built in (FIPS 180-4), so there is no external dependency.
- **Asset manifest root.** `tools/gen_manifest.py` writes a SHA-256 manifest of an asset directory. Its root hash is sealed into the binary, so the executable and its asset bundle are checked as a pair.
- **W^X check.** The code segment must be readable and executable, never writable (`mach_vm_region` on macOS, `/proc/self/maps` on Linux, `VirtualQuery` on Windows).
- **OS code-signature check.** `SecCodeCheckValidity` on macOS, `WinVerifyTrust` on Windows. By default any valid signer passes. Set `cfg.codesign_requirement` to pin the signer: a code requirement string on macOS, `leaf-sha256:<64 hex>` (SHA-256 of the signing certificate) on Windows.
- **Report only.** The library never kills the process. `reshield_verify()` returns a status and fills a `reshield_report_t`. Your app decides what to do. `reshield_report_to_json()` writes the report as one line of JSON (`"v":1`) for logs or telemetry.

## When to use it, and when not to

re-shield detects tampering. It does not prevent it. There is no secret key, so an attacker who changes the code can seal the record again. Code that hashes itself also has a known generic bypass that separates the code being hashed from the code being run (van Oorschot et al., IEEE TDSC 2005). A report built on the client cannot serve as proof on a server.

Good fit:

- A C/C++ game or app without an engine, where you want to know if the asset bundle shipped next to the executable was changed. The authors did not find an open-source, engine-independent tool that pairs an executable with an asset manifest. That search was not exhaustive.
- You want to catch broken installs, mistakes and simple binary patches, send them to logs or telemetry, and measure the false-positive rate before you ever kill a process.
- You want a small library that you can read and audit yourself, with no dependencies.

Not a fit:

- You must stop cheats or cracks. Look at anti-cheat or a commercial protector.
- The server needs a verdict it can trust. Use platform attestation (Apple App Attest, Google Play Integrity and similar) with server-side checks.
- OS signing and OS policy (Hardened Runtime, App Control and similar) already enforce what you ship. That is stronger. re-shield does not replace OS signing: seal first, then sign. Pinning the signer helps against "re-seal, then re-sign with a different certificate". It does not stop an attacker who patches the verification function itself.

It is not anti-cheat, DRM or a kernel-level defense. It does not block debuggers (no `ptrace`).

## Platform support

| Platform | Supported | What CI checks |
|---|---|---|
| macOS, Mach-O 64 | yes | `make clean && make all test release-demo` on `macos-latest` |
| Linux, ELF64 (glibc and musl) | yes | glibc on `ubuntu-latest`, including `make sanitize`; musl on Alpine for dynamic, `-no-pie`, static and static-pie; `ld.so ./prog` must exit with an error, not crash |
| Windows x64, PE32+ (MSVC) | yes | `windows-latest` with `cl`: build, seal, run, flip one `.text` byte and expect `CODE_TAMPERED`, sealed-then-signed EXE with a throwaway self-signed certificate (valid signature and `leaf-sha256:` pin match, mismatch, bad format) |
| Windows with mingw-w64 | cross-compile and tool tests only | Not run in CI. The default link leaves one relocation inside `.text`, so sealing is refused. Linking with `-Wl,--disable-dynamicbase -Wl,--disable-reloc-section` allows sealing but turns ASLR off, so it is not recommended for shipping. |
| Windows ARM64, 32-bit, fat/universal Mach-O | no | Sealing is refused or fails closed |

Not verified: signatures from a public CA, timestamped signatures, and revocation checks on Windows. A real macOS Team ID was not tested either; only ad-hoc negative and positive requirement tests were. Details: [Windows section](docs/integrity-verification.md#7-windows-pe32-x64).

## Quickstart

Build the library and run the demo flow:

```bash
make all test release-demo      # needs a C11 compiler, make, python3
```

Call it at startup. This is the whole program:

```c
#include <stdio.h>
#include "reshield/reshield.h"

int main(void) {
    reshield_config_t cfg = reshield_default_config();  /* code section + W^X */
    reshield_report_t report;
    reshield_status_t st = reshield_verify(&cfg, &report);

    char json[512];
    reshield_report_to_json(&report, json, sizeof json);
    printf("%s\n%s\n", reshield_status_name(st), json);
    return st == RESHIELD_OK ? 0 : 1;
}
```

```bash
# link: libreshield.a + -Iinclude; macOS also needs -framework Security -framework CoreFoundation
cc -std=c11 -Iinclude app.c build/libreshield.a -framework Security -framework CoreFoundation -o app
./app                                          # UNSEALED: it was never sealed
strip app
python3 tools/seal_binary.py app --build-id 1
./app                                          # OK
```

On macOS this prints `UNSEALED` first, then `OK` after sealing. On Linux drop the `-framework` flags.

Release order matters: link, `strip`, seal, sign, verify. One command runs it in that order on the final executable (in place):

```bash
python3 tools/reshield_release.py dist/game --assets dist/assets --strip              # writes dist/game.manifest
python3 tools/reshield_release.py dist/game --assets dist/assets --sign "Developer ID Application: Me (TEAMID)"   # macOS
python3 tools/reshield_release.py dist/game.exe --assets dist/assets --sign-cmd "signtool sign /fd sha256 /a {}"  # any signer
```

It refuses a Mach-O that is already signed with a real identity, because sealing rewrites the binary and the signature would be lost. Seal first, sign last. `seal_binary.py` refuses it too (linker-signed and ad-hoc binaries are fine). The manual steps are:

1. Link, then `strip`.
2. `python3 tools/gen_manifest.py assets -o game.manifest`, then `python3 tools/seal_binary.py app --manifest game.manifest --build-id N` (omit `--manifest` if you ship no assets).
3. OS code signing (Developer ID, Authenticode). Signing does not change the sealed code hash. On macOS `seal_binary.py` applies an ad-hoc signature; sign again for distribution.
4. In CI: `python3 tools/verify_release.py app --manifest game.manifest --assets assets`.

Ship the manifest file with the binary. Its root hash is sealed in the binary, so changing the manifest gives `MANIFEST_MISMATCH`.

To check assets at startup, call `reshield_verify_app()`. It checks code and manifest, and resolves both paths against the directory of the running executable, so it still works when a launcher or shortcut changes the working directory:

```c
if (reshield_verify_app("game.manifest", "assets", NULL, NULL, &report) != RESHIELD_OK) { /* handle */ }
```

Or set it up yourself with `reshield_verify()` (paths then relative to the current directory):

```c
cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
cfg.manifest_path  = "game.manifest";
cfg.asset_base_dir = "assets";
```

A manifest or asset path that cannot be opened is reported as `MANIFEST_IO_ERROR` (`RESHIELD_ERR_MANIFEST_IO`, value 8), not `INTERNAL_ERROR`, so a wrong path is not mistaken for an internal fault. Before this change it was `INTERNAL_ERROR`.

If you load an asset after verifying it by path, the file can change in between (TOCTOU). Read the file into memory, check it with `reshield_verify_buffer()`, then use that buffer. See `examples/sample_game.c` for a complete program.

## Development and release builds

- Development and release libraries are built in separate directories: `make lib` gives `build/libreshield.a` (development), `make ALLOW_UNSEALED=0 lib` gives `build/release/libreshield.a`. Switching never reuses the other's objects. `-std=c11`, `-Iinclude` and the `ALLOW_UNSEALED` define are always applied, so `make CFLAGS=-O0` or a parent make cannot drop them.
- `-DRESHIELD_DISABLE` turns `reshield_verify()` and the other runtime checks into no-ops. It must be set when the **library** is compiled (e.g. `make CFLAGS="-O2 -DRESHIELD_DISABLE"` after `make clean`); adding it only to your app's flags changes nothing. Use it while debugging, because a breakpoint patches `.text` and gives `CODE_TAMPERED`. `reshield_verify_buffer()` still compares hashes in this build, because it is app logic, not an integrity check.
- `cfg.allow_unsealed = 1` lets a binary that was never sealed pass. It works only if the library was compiled with `-DRESHIELD_ALLOW_UNSEALED`. This repository's Makefile turns that on by default. For a release build use `make ALLOW_UNSEALED=0 lib` and link `build/release/libreshield.a`.
- If the field is set on a library built without the macro, `reshield_verify()` returns `INTERNAL_ERROR`. It is neither ignored nor bypassed.
- Never ship a build with `RESHIELD_ALLOW_UNSEALED`. An attacker could then skip the code and manifest checks by changing the sealed byte in the record.

## Known limitations

- Only `__TEXT,__text` / `.text` is hashed. `__stubs`, `.plt`, `__const` and the `__DATA` that holds the record are not.
- The record starts with a plain `RSHLDCHK` magic, so the place to edit is easy to find.
- Files that are not in the manifest are not detected.
- A binary and its manifest can be re-sealed together. Runtime API replacement is not prevented.
- A software breakpoint patches code bytes and is reported as `CODE_TAMPERED`.
- On Linux, `.text` is located from the section headers on disk. An attacker who can edit the file can change them, and copying the original bytes into a code cave in the same segment is not caught.
- `verify_release.py` only reports the number of defined symbols. It does not check it.

Full list: [docs/integrity-verification.md](docs/integrity-verification.md#5-한계).

## Documentation

The design and verification guides are written in Korean.

- [docs/architecture.md](docs/architecture.md): design, the 96-byte `RSHLDCHK` v2 record, limits.
- [docs/integrity-verification.md](docs/integrity-verification.md): sealing pipeline, runtime integration, manifest format rules, Windows details.
- [docs/fuzzing.md](docs/fuzzing.md): sanitizers and fuzzing, in English.
- Public API: `include/reshield/reshield.h`, `integrity.h`, `manifest.h`, `attestation.h`.

## Testing

```bash
make all test release-demo      # build, unit tests, sealed demo
make sanitize                   # same tests under ASan + UBSan
```

Fuzzing (libFuzzer harnesses and PE parser tests) needs clang with libFuzzer. See [docs/fuzzing.md](docs/fuzzing.md).

## License

[MIT](LICENSE)
