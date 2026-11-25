# Native plugin placement

No binaries are shipped here. Build them from the re-shield sources (`make shared`, `make release-shared`; on Windows `cl /LD ... /link /DEF:reshield.def`, see the `windows-msvc` CI job) and copy them in. Use the **release** build (`ALLOW_UNSEALED=0`) for what you ship: it reports `UNSEALED` for an unsealed file instead of passing.

| Platform | File | Folder (suggested) | Import settings |
|---|---|---|---|
| Windows x64 | `reshield.dll` | `Plugins/x86_64/` | Windows x64 only |
| macOS | `libreshield.dylib` (Unity also accepts a `.bundle`) | `Plugins/macOS/` | macOS only |
| Linux x64 | `libreshield.so` | `Plugins/Linux/x86_64/` | Linux x64 only |

Set the Editor to "Exclude" for these, or leave it unchecked: the check is skipped in the Editor and in development builds by default.

## Mono vs IL2CPP

- **Mono**: ship the prebuilt library above. re-shield checks the library's own `.text`. It does not look at `Assembly-CSharp.dll` memory (IL, not machine code). Bind the managed DLLs with a manifest instead.
- **IL2CPP**: do not ship the prebuilt library. Add the re-shield C sources (`src/*.c`, `include/`) as an IL2CPP source plugin so they compile into `GameAssembly`, and add the scripting define symbol `RESHIELD_INTERNAL` (Player Settings > Scripting Define Symbols). `Reshield.cs` then imports from `"__Internal"`. Then seal `GameAssembly.dll/.so/.dylib` after the build. This path is a design, not tested here.

## Seal after the build

```bash
python3 tools/reshield_release.py <Build>/GameAssembly.dll --assets <Build> \
    --exclude "*.pdb" --exclude "*_BackUpThisFolder_ButDontShipItWithYourGame/*"
```

Mono: seal `reshield.dll` instead. Sign after sealing (the tool does it in order). Then run the player once and read the log line `[re-shield] OK`.
