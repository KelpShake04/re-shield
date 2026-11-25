# Loading a verified asset

`reshield_verify_single_asset()` answers "was this file right a moment ago". An engine that then
opens the file again can be fed a different file in between (check/use race, TOCTOU).
`reshield_load_verified_asset()` closes that gap: it reads the asset once and hands back the very
bytes it hashed.

## API

```c
/* include/reshield/manifest.h: explicit paths and root (tools, tests, servers) */
reshield_manifest_status_t reshield_load_verified_asset(
    const char *manifest_path, const char *asset_base_dir, const char *asset_rel_path,
    const uint8_t *expected_root_sha256 /* NULL = the binary's sealed root */,
    size_t max_size, void **out_buf, size_t *out_len);

/* include/reshield/reshield.h: paths relative to the process executable, like reshield_verify_app() */
reshield_status_t reshield_load_verified_app_asset(
    const char *manifest_rel, const char *assets_rel /* NULL = "." */, const char *asset_rel,
    size_t max_size, void **out_buf, size_t *out_len);

void reshield_free_asset(void *buf);   /* release the buffer; NULL is allowed */
```

```c
void *data; size_t len;
reshield_status_t st = reshield_load_verified_app_asset("game.manifest", "assets", "levels/1.pck",
                                                        64u << 20, &data, &len);
if (st != RESHIELD_OK) { /* data is NULL: do not use the file, report st */ }
else { parse(data, len); reshield_free_asset(data); }
```

C# (`bindings/csharp/Reshield.cs`, same file in the Unity package):
`Reshield.Guard.LoadAsset("game.manifest", "assets", "levels/1.pck", 64 << 20)` returns an
`AssetResult` with `Ok`, `Status`, `StatusName` and `Data` (a `byte[]` copy, null unless `Ok`). It
never throws for a missing native module (`Status` -1, as `Check()`); that is a deployment problem,
decide yourself whether to fall back to an unverified read.

## What a call does

1. Rejects an unsafe `asset_rel_path` with the same rules as manifest entries (no absolute path, no
   `..` or empty component, no `\`, `:` or control characters, no Windows device names, no trailing
   `.` or space).
2. Reads the manifest once and compares its SHA-256 with the root (every call; nothing is cached).
3. Finds the entry for the path. Opens the asset once, takes its size from that open file, and
   requires it to equal the manifest size and to be at most `max_size`. The check happens before
   any byte is read.
4. Reads size + 1 bytes into a fresh buffer (a file that grew is noticed), hashes that buffer and
   compares it with the entry. Only then is the buffer returned.

The caller owns the buffer. Changing the file afterwards does not change it. Free it with
`reshield_free_asset()`, not `free()` (a DLL can use another C runtime than the game).

## Statuses

No new codes beyond `ASSET_UNREADABLE` (`ERR_ASSET_UNREADABLE`, value 10, appended to the enums; existing values unchanged). The manifest-level call returns `reshield_manifest_status_t`, the app-level call the
matching `reshield_status_t`.

| Case | manifest status | app status |
|---|---|---|
| verified | `OK` | `OK` |
| binary has no sealed root | `UNSEALED` | `ERR_UNSEALED` |
| manifest changed | `ROOT_MISMATCH` | `ERR_MANIFEST_MISMATCH` |
| asset not listed, missing, not a regular file, resized, 1 byte changed, path too long | `ASSET_MISMATCH` | `ERR_ASSET_TAMPERED` |
| asset exists but cannot be opened or read: permission denied, sharing or lock violation, antivirus block, I/O error | `ASSET_UNREADABLE` | `ERR_ASSET_UNREADABLE` |
| unsafe `asset_rel_path`, manifest unreadable or malformed, NULL output, asset larger than `max_size` | `IO_ERROR` | `ERR_MANIFEST_IO` |
| executable path or a joined path does not fit 4096 bytes (app-level only) | n/a | `ERR_INTERNAL` |

On every non-OK status `*out_buf` is NULL and `*out_len` is 0. "Larger than `max_size`" is not a
tamper verdict: it is the caller's own limit, so it is `IO_ERROR`, checked against the size on disk
without reading the file. `ASSET_UNREADABLE` is not a tamper verdict either, and not a pass: the
library only reports it. Log it apart from `ASSET_TAMPERED` and let the caller pick the policy
(retry, or fail open as for `IO_ERROR`). A cause the library does not recognise stays
`ASSET_MISMATCH` (fail closed). Under `-DRESHIELD_DISABLE` nothing is verified and an unreadable
file is `IO_ERROR`, as before.

## Limits and decisions

- `max_size` has no default. The whole asset is held in memory, so this is for assets you would load
  into memory anyway (configs, levels, scripts, small packs). A multi-GB `.pck` that the engine
  streams cannot be bound this way: verify it at start with `reshield_verify_app()` instead.
- `UNSEALED` is never waved through here, also in a development library built with
  `-DRESHIELD_ALLOW_UNSEALED` (unlike `reshield_verify_app()`, which only reports). This call hands
  back data, so a dev binary must be sealed (`tools/seal_binary.py --manifest ...`) or use the
  explicit-root function. In an editor build, skip the call (for Unity: `Debug.isDebugBuild`).
- Symlinks: the path is opened as given, so a symlink to a regular file is read through. Its content
  still has to match the manifest hash, which is what matters; a link to a device, a dangling link
  and a link to different bytes fail with `ASSET_MISMATCH`. The strict scan is not part of this call.
- Windows: a path that does not fit the internal 1024-byte buffer, or that the file layer cannot open
  (longer than `MAX_PATH`), is refused (`ASSET_MISMATCH`), as in `reshield_verify_manifest_files()`.
- `-DRESHIELD_DISABLE`: nothing is verified. The file is only read, with the same path rules and the
  `max_size` cap, so game code behaves the same in a disabled build.
- Not covered: tampering after the load (memory edits), and an attacker who can write both the
  manifest and the sealed record (there is no key; see `docs/integrity-verification.md`).
- Thread safety: stateless, safe to call from several threads. Each call re-reads and re-hashes the
  manifest (typically well under a millisecond for a 100 KB manifest).

## Tests

`tests/test_manifest.c` (`test_load_verified_asset`: valid, empty, 1-byte change, longer, shorter,
missing, unlisted, `max_size`, unsafe and `..` paths, wrong root, symlinks, replaced file after
load, plus the `RESHIELD_DISABLE` variant), `tests/test_seal_workflow.py` (app-level paths, sealed
and unsealed binaries), `tests/fuzz/fuzz_manifest.c` (no leak, buffer exactly when `OK`, never
accepts what `reshield_verify_single_asset()` rejects) and `bindings/csharp/tests` (`LoadAsset`
against real sealed libraries).

Windows (CI `windows-msvc` only): `tests/test_load_asset_windows.c` (backslash, drive letter, UNC,
`\\?\`, `..`, device names, trailing dot or space and `:` stream paths refused; a path over `MAX_PATH`
that exists on disk fails closed; rename-over replacement, a file held open by another handle and a
directory in place of the file) and a CI step that runs `reshield_load_verified_app_asset` from a
sealed `test_verify_app.exe` with another CWD.
