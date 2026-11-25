# re-shield Architecture (Defensive Build Attestation & Integrity)

`re-shield`는 **빌드 증명(Build Attestation)**과 **런타임 무결성 검증(Runtime Integrity Verification)**에 집중하는 100% 유저스페이스 C11 + Python 3 도구다.

## 설계 원칙

1. **표준 방어 API만 사용**: OS 공식 로더·메모리 조회·코드 서명 API(`dladdr`, `getsectiondata`, `mach_vm_region`, `SecCodeCheckValidity`, `dl_iterate_phdr`, `/proc/self/maps`)와 자체 FIPS 180-4 SHA-256만 사용한다.
2. **능동적 디버거 차단 미포함**: `ptrace` 기반 attach 차단이나 타이밍 트랩을 사용하지 않아 `lldb`/`gdb`/프로파일러/크래시 리포터 등 정당한 개발 도구와 충돌하지 않는다.
3. **명시적 진단 리포트**: 라이브러리가 직접 `_exit()`를 호출하지 않고 `reshield_report_t`와 선택적 `on_violation` 콜백으로 결과를 전달한다.
4. **과장 금지**: 로컬에서 실행되는 바이너리는 공격자가 바이너리와 매니페스트를 동시에 재봉인할 수 있으므로 완전한 방어가 아님을 명확히 전제한다.

## 모듈 구성

| 모듈 | 파일 | 역할 |
| --- | --- | --- |
| `integrity` | `include/reshield/integrity.h`, `src/sha256.c`, `src/integrity_*.c` | FIPS 180-4 SHA-256, `RSHLDCHK` v2(96바이트) 레코드 조회, 메모리 코드 섹션 해시 대조 |
| `manifest` | `include/reshield/manifest.h`, `src/manifest.c` | 봉인된 매니페스트 루트 해시 대조 및 에셋 파일별 크기·SHA-256 검증 |
| `file` (내부) | `src/file_platform.h`, `src/file_posix.c`, `src/file_windows.c` | 일반 파일만 여는 플랫폼별 파일 I/O(POSIX `open`/`fstat`, Windows `CreateFileW`). `sha256.c`와 `manifest.c`가 사용 |
| `attestation` | `include/reshield/attestation.h`, `src/attestation_*.c` | 코드 섹션 전 범위의 W^X(쓰기 금지) 권한 검증 및 macOS `SecCodeCheckValidity`·Windows `WinVerifyTrust` 유효성 검증 |
| `runtime` | `include/reshield/reshield.h`, `src/reshield.c` | 통합 `reshield_verify()` 파이프라인, `reshield_secure_zero()` |
| `verify_app` | `src/verify_app.c` | `reshield_verify_app()`(프로세스 EXE 디렉터리 기준 경로로 코드+매니페스트 검사)와 엔진 바인딩용 `reshield_check_json()`(평면 C 타입) |
| `tools` | `tools/gen_manifest.py`, `tools/manifest_path.py`, `tools/seal_binary.py`, `tools/verify_release.py`, `tools/reshield_release.py` | 에셋 매니페스트 생성(경로 규칙은 `manifest_path.py`), 바이너리 봉인(Mach-O·ELF·PE32+ x64), 릴리스 아티팩트 CI 검증, 한 번에 실행하는 릴리스 단계(`reshield_release.py`: strip, 매니페스트, 봉인, 서명, 검증) |

## `RSHLDCHK` v2 레코드 구조 (96 bytes)

코드 섹션 외부의 데이터 영역(`__DATA,__data` / `.data`)에 `volatile` + `used`로 배치해 순환 해싱과 컴파일러 상수 접기를 방지한다.

```text
Offset  Size  Field
0       8     magic ("RSHLDCHK")
8       4     version (2)
12      4     sealed (0 = unsealed, 1 = sealed)
16      4     build_id
20      4     has_manifest (0 or 1)
24      8     expected_size (code section bytes)
32      32    expected_sha256 (code section SHA-256)
64      32    manifest_root_sha256 (manifest file SHA-256)
```

## 한계

- 검증 대상 이미지는 "봉인 레코드가 들어 있는 이미지"다(자기 모듈 모드). 정적 링크한 EXE에서는 메인 실행 파일이고, re-shield를 공유 라이브러리(`.so`/`.dylib`/`.dll`, Unity IL2CPP의 `GameAssembly`나 Godot GDExtension 등)에 링크하면 그 라이브러리다. 호스트 프로세스의 EXE는 보지 않는다. 코드 서명 검사(`RESHIELD_CHECK_CODESIGN`)만 예외로 모듈 모드에서도 프로세스 EXE를 본다. 다른 모듈(엔진 본체 등)의 메모리는 검사하지 않는다. [integrity-verification.md](integrity-verification.md#8-자기-모듈-모드-공유-라이브러리) 참고.
- 해시 대상은 `__TEXT,__text` / `.text`뿐이다. `__stubs`, `.plt`, `__const`, 레코드가 놓이는 `__DATA`는 포함되지 않는다.
- 레코드의 평문 `RSHLDCHK` 매직이 수정 지점을 노출한다.
- 소프트웨어 breakpoint(코드 바이트 패치)가 설치된 상태에서는 `CODE_TAMPERED`로 보고된다.
- 매니페스트에 없는 추가 파일은 감지하지 못한다.
- macOS 코드 서명 검증은 기본적으로 `SecCodeCheckValidity`를 requirement `NULL`로 호출해 서명 유효성만 확인하며 서명 주체는 고정하지 않는다. `cfg.codesign_requirement`를 설정하면 `SecRequirementCreateWithString`으로 만든 requirement를 함께 검사한다(Team ID 고정 등). Windows는 `leaf-sha256:<64 hex>` 형식이다(아래 Windows 항목).
- fat/universal Mach-O는 `seal_binary.py`가 지원하지 않는다.
- Windows(PE32+ x64, MSVC)는 봉인 도구, 파일 I/O, 런타임 백엔드(`src/integrity_windows.c`의 `.text` 위치 찾기, `src/attestation_windows.c`의 `VirtualQuery` W^X 순회와 `WinVerifyTrust` 코드 서명 검사)가 구현되어 있고 CI `windows-msvc` 잡(`windows-latest`)이 실제로 빌드·봉인·실행·변조 탐지를 확인한다. Windows의 코드 서명 검사는 `WinVerifyTrust` 후 `requirement`(`leaf-sha256:<64 hex>`, 서명 leaf 인증서 DER의 SHA-256)가 주어지면 그 해시와 비교한다. 형식이 다른 문자열은 `FAILED`(fail-closed)이고, 서명 안 된 EXE도 `FAILED`다. CI가 일회용 자체 서명 인증서로 서명한 EXE에서 `OK`와 leaf pin 일치/불일치를 확인한다(공인 CA 서명은 미검증). macOS와 Windows의 requirement 문법이 달라 플랫폼별로 `#ifdef` 안에서 설정한다. 정식 지원 대상은 MSVC 빌드(CI 측정: MSVC 링크 EXE의 `.text` 안 base relocation 0개, 봉인 성공)이며 mingw-w64는 크로스 컴파일·도구 테스트 전용이다. [integrity-verification.md](integrity-verification.md#7-windows-pe32-x64) 참고.
- macOS·Linux·Windows 외 플랫폼에서는 코드 섹션을 찾지 못해 무결성 검사가 `RESHIELD_INTEGRITY_ERROR` → `RESHIELD_ERR_INTERNAL`(기본 설정에서 fail-closed)이 된다. W^X·코드 서명 검사는 `RESHIELD_ATTEST_UNSUPPORTED`를 반환하며 `reshield_verify()`는 이를 Linux 코드 서명 검사와 같이 조용히 통과시킨다.
- 자세한 내용: [integrity-verification.md](integrity-verification.md#5-한계).
