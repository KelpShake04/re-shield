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
- **Module mode.** Link re-shield into a shared library (`.so` / `.dylib` / `.dll`) instead of the executable and the library is the sealed, checked image; the host executable (an engine, say) needs no re-shield code and is not sealed. See [Known limitations](#known-limitations).
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
| Linux, ELF64 (glibc and musl) | yes | glibc on `ubuntu-latest`, including `make sanitize`; musl on Alpine for dynamic, `-no-pie`, static and static-pie; `ld.so ./prog` must exit with an error, not crash; module mode (`make module-test`, development and release shared library) and a C++11 syntax check of `src/*.c` |
| Windows x64, PE32+ (MSVC) | yes | `windows-latest` with `cl`: build, seal, run, flip one `.text` byte and expect `CODE_TAMPERED`, sealed-then-signed EXE with a throwaway self-signed certificate (valid signature and `leaf-sha256:` pin match, mismatch, bad format), module mode (a release `reshield.dll` built with `reshield.def`, checked by an unsealed host EXE: unsealed, sealed OK, tampered, including the `reshield_check_json` output) and a C++ compile gate (`cl /TP`) |
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

From another language or an engine binding, `reshield_check_json()` does the same check with flat C types only (an `int` status, the report as one JSON line, no struct to mirror):

```c
char json[512];
int status = reshield_check_json("game.manifest", "assets", json, sizeof json);  /* 0 = RESHIELD_OK */
```

Both calls resolve the two paths against the directory of the **process executable**, not the library: when re-shield is linked into a shared library (module mode), the manifest and assets are looked up next to the host EXE. In a development library (`make lib` / `make shared`, compiled with `-DRESHIELD_ALLOW_UNSEALED`) an unsealed binary reports `OK`; a release library (`ALLOW_UNSEALED=0`) requires a sealed one.

Binaries inside the asset directory and build leftovers can be left out of the manifest: `python3 tools/gen_manifest.py dist -o dist/game.manifest --exclude "*.pdb" --exclude "cache/*"` (repeatable globs on the relative POSIX path). `reshield_release.py` takes the same `--exclude` and always leaves the binary it seals out of the manifest, Binaries inside the asset directory and build leftovers can be left out of the manifest: `python3 tools/gen_manifest.py dist -o dist/game.manifest --exclude "*.pdb" --exclude "cache/*"` (repeatable globs on the relative POSIX path). `reshield_release.py` takes the same `--exclude` and always leaves the binary it seals out of the manifest, so `reshield_release.py dist/game --assets dist` works. A pattern that matches no file (a typo, `./x`, a backslash path) is reported on stderr by `gen_manifest.py`; the exit code does not change.

Or set it up yourself with `reshield_verify()` (paths then relative to the current directory):

```c
cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
cfg.manifest_path  = "game.manifest";
cfg.asset_base_dir = "assets";
```

A manifest file that cannot be opened or parsed (wrong path, missing file, malformed or empty manifest, an unsafe asset path inside it) is reported as `MANIFEST_IO_ERROR` (`RESHIELD_ERR_MANIFEST_IO`, value 8), not `INTERNAL_ERROR`, so a wrong path is not mistaken for an internal fault. Before this change it was `INTERNAL_ERROR`. An asset that is missing, resized or altered is `ASSET_TAMPERED` (6), a tamper verdict.

If you load an asset after verifying it by path, the file can change in between (TOCTOU). Read the file into memory, check it with `reshield_verify_buffer()`, then use that buffer. See `examples/sample_game.c` for a complete program.

## Development and release builds

- Development and release libraries are built in separate directories: `make lib` gives `build/libreshield.a` (development), `make ALLOW_UNSEALED=0 lib` gives `build/release/libreshield.a`. Switching never reuses the other's objects. `-std=c11`, `-Iinclude` and the `ALLOW_UNSEALED` define are always applied, so `make CFLAGS=-O0` or a parent make cannot drop them.
- `-DRESHIELD_DISABLE` turns `reshield_verify()` and the other runtime checks into no-ops. It must be set when the **library** is compiled (e.g. `make CFLAGS="-O2 -DRESHIELD_DISABLE"` after `make clean`); adding it only to your app's flags changes nothing. Use it while debugging, because a breakpoint patches `.text` and gives `CODE_TAMPERED`. `reshield_verify_buffer()` still compares hashes in this build, because it is app logic, not an integrity check.
- `cfg.allow_unsealed = 1` lets a binary that was never sealed pass. It works only if the library was compiled with `-DRESHIELD_ALLOW_UNSEALED`. This repository's Makefile turns that on by default. For a release build use `make ALLOW_UNSEALED=0 lib` and link `build/release/libreshield.a`.
- If the field is set on a library built without the macro, `reshield_verify()` returns `INTERNAL_ERROR`. It is neither ignored nor bypassed.
- Never ship a build with `RESHIELD_ALLOW_UNSEALED`. An attacker could then skip the code and manifest checks by changing the sealed byte in the record.
- **`make lib` and `make shared` build the development library by default.** To ship, use `make release-shared` (shared library) or `make ALLOW_UNSEALED=0 lib`, or compile your own copy without `-DRESHIELD_ALLOW_UNSEALED`.
- A development build contains the marker `RESHIELD-DEV-BUILD-v1`; a release build never does. `tools/reshield_release.py` and `tools/verify_release.py` refuse a binary that contains it (exit code 2, before anything is modified). `--allow-dev-build` (action input `allow-dev-build`) overrides this for demos and CI only. `tools/seal_binary.py` does not check it, because the tests and demos seal development builds directly.
- Limit: the marker is a guard against shipping the wrong build by mistake, not a defense. An attacker who holds a shipped development build can erase the marker (and flip the sealed byte); only a release build protects against that.

## Shared library and C++

- `make shared` builds `build/libreshield.so` (`build/libreshield.dylib` on macOS) for module mode; `make release-shared` builds the release flavor (`ALLOW_UNSEALED=0`) in `build/release/`. On Windows the DLL is built with `cl /LD ... /link /DEF:reshield.def`, which exports only the subset an engine binding needs (`reshield_verify_code_section`, `reshield_verify_code_page_wx`, `reshield_verify_app`, `reshield_check_json`, `reshield_report_to_json`, `reshield_status_name`); a POSIX shared library exports the whole public API. Seal the library with `tools/seal_binary.py`.
- `src/*.c` and the public headers also compile as C++ (checked in CI as a syntax-only gate: `c++ -std=c++11 -fsyntax-only` on Linux and macOS, `cl /TP` on Windows). The gate does not link or run C++ objects.

## Known limitations

- The code check covers the image that holds the sealed record: the main executable when re-shield is linked statically, or the shared library (`.so` / `.dylib` / `.dll`) when re-shield is linked into one. Seal that file; the host executable is neither checked nor required to be sealed. Other modules (an engine binary, other plugins) are not checked. The code-signature check always looks at the process executable. On Linux, a library opened by a relative path works too (its absolute path comes from `/proc/self/maps`); the check fails closed if `/proc` is unavailable or the library file was deleted or replaced after loading.
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
- [docs/steam-pipeline.md](docs/steam-pipeline.md): sealing in GitHub Actions (`action.yml`) before a `steamcmd` upload; what was not tested (Korean).
- [docs/fuzzing.md](docs/fuzzing.md): sanitizers and fuzzing, in English.
- [docs/crackme-lab.md](docs/crackme-lab.md): crackme lab, patch your own sealed binary to see what re-shield stops and what it cannot (Korean).
- [docs/engines-unity.md](docs/engines-unity.md): C# binding and an untested Unity package skeleton (Korean).
- Public API: `include/reshield/reshield.h`, `integrity.h`, `manifest.h`, `attestation.h`.

## Testing

```bash
make all test release-demo      # build, unit tests, sealed demo
make sanitize                   # same tests under ASan + UBSan
```

Fuzzing (libFuzzer harnesses and PE parser tests) needs clang with libFuzzer. See [docs/fuzzing.md](docs/fuzzing.md).

## License

[MIT](LICENSE)
