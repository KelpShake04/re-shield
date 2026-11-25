# re-shield Architecture (Defensive Build Attestation & Integrity)

`re-shield`는 **빌드 증명(Build Attestation)**과 **런타임 무결성 검증(Runtime Integrity Verification)**에 집중하는 100% 유저스페이스 C11 + Python 3 도구다.

## 설계 원칙

1. **표준 방어 API만 사용**: OS 공식 로더·메모리 조회·코드 서명 API(macOS `dladdr`·`getsectiondata`·`mach_vm_region`·`SecCodeCheckValidity`, Linux `dl_iterate_phdr`·`/proc/self/maps`, Windows `GetModuleHandleExW`·`VirtualQuery`·`WinVerifyTrust`)와 자체 FIPS 180-4 SHA-256만 사용한다(CPU 해시 명령도 컴파일러 intrinsics로만 쓴다).
2. **능동적 디버거 차단 미포함**: `ptrace` 기반 attach 차단이나 타이밍 트랩을 사용하지 않아 `lldb`/`gdb`/프로파일러/크래시 리포터 등 정당한 개발 도구와 충돌하지 않는다.
3. **명시적 진단 리포트**: 라이브러리가 직접 `_exit()`를 호출하지 않고 `reshield_report_t`와 선택적 `on_violation` 콜백으로 결과를 전달한다.
4. **과장 금지**: 로컬에서 실행되는 바이너리는 공격자가 바이너리와 매니페스트를 동시에 재봉인할 수 있으므로 완전한 방어가 아님을 명확히 전제한다.

## 모듈 구성

| 모듈 | 파일 | 역할 |
| --- | --- | --- |
| `integrity` | `include/reshield/integrity.h`, `src/sha256.c`, `src/integrity_common.c`, `src/integrity_{macos,linux,windows}.c` | FIPS 180-4 SHA-256, `RSHLDCHK` v2(96바이트) 레코드 조회, 메모리 코드 섹션 해시 대조. 레코드가 든 이미지는 레코드 변수의 주소를 돌려주는 내부 함수 `reshield_internal_record_anchor()`로 찾는다(자기 모듈 모드: [integrity-verification.md §8](integrity-verification.md#8-자기-모듈-모드-공유-라이브러리)) |
| `sha256_accel` (내부) | `src/sha256_accel.h`, `src/sha256_accel.c`, `src/sha256_internal.h` | SHA-256 블록 압축의 CPU 명령 경로(AArch64 SHA2, x86-64 SHA-NI)와 첫 사용 때 한 번 하는 backend 선택. `sha256.c`가 부르며 공개 API·ABI는 그대로다. `-DRESHIELD_NO_HW_SHA`로 뺀다([integrity-verification.md §9](integrity-verification.md#9-sha-256-하드웨어-가속)). `sha256_internal.h`는 여러 버퍼를 이어 붙이지 않고 해시하는 `reshield_sha256_parts()`를 선언한다(save seal이 사용) |
| `manifest` | `include/reshield/manifest.h`, `src/manifest.c` | 봉인된 매니페스트 루트 해시 대조 및 에셋 파일별 크기·SHA-256 검증. v2 `strict` 매니페스트는 에셋 폴더를 열거해 `RESHIELD_ERR_ASSET_EXTRA`(값 9)를 낸다([integrity-verification.md §10](integrity-verification.md#10-매니페스트-v2와-strict-모드)) |
| `file` (내부) | `src/file_platform.h`, `src/file_posix.c`, `src/file_windows.c` | 일반 파일만 여는 플랫폼별 파일 I/O(POSIX `open`/`fstat`, Windows `CreateFileW`)와 strict 스캔용 재귀 디렉터리 열거 `reshield_dir_walk()`(POSIX `opendir`/`readdir`/`lstat`, Windows `FindFirstFileExW`, 심볼릭 링크·재분석 지점은 따라가지 않음). `sha256.c`와 `manifest.c`가 사용 |
| `attestation` | `include/reshield/attestation.h`, `src/attestation_*.c` | 코드 섹션 전 범위의 W^X(쓰기 금지) 권한 검증 및 macOS `SecCodeCheckValidity`·Windows `WinVerifyTrust` 유효성 검증 |
| `runtime` | `include/reshield/reshield.h`, `src/reshield.c` | 통합 `reshield_verify()` 파이프라인, `reshield_report_to_json()`, `reshield_status_name()`, `reshield_secure_zero()`. 위 세 플랫폼 외 OS를 위한 attestation 대체 정의(`UNSUPPORTED`)도 여기 있다 |
| `verify_app` | `src/verify_app.c` | `reshield_verify_app()`(프로세스 EXE 디렉터리 기준 경로로 코드+매니페스트 검사)와 엔진 바인딩용 `reshield_check_json()`(평면 C 타입) |
| `save_seal` | `include/reshield/save_seal.h`, `src/save_seal.c` | 세이브·설정 파일용 HMAC-SHA256 태그: `reshield_hmac_sha256()`, `reshield_save_tag()`, `reshield_save_verify()`. 실행 파일 봉인과 별개이며 캐주얼 편집·손상 탐지용이다([save-seal.md](save-seal.md)) |
| `tools` | `tools/gen_manifest.py`, `tools/manifest_path.py`, `tools/manifest_policy.py`, `tools/seal_binary.py`, `tools/verify_release.py`, `tools/reshield_release.py`, `tools/pe_probe.py` | 에셋 매니페스트 생성(경로 규칙은 `manifest_path.py`, v2 헤더·strict 규칙은 `manifest_policy.py`로 `gen_manifest.py`와 `verify_release.py`가 공유), 바이너리 봉인(Mach-O·ELF·PE32+ x64), 릴리스 아티팩트 CI 검증, 한 번에 실행하는 릴리스 단계(`reshield_release.py`: strip, 매니페스트, 봉인, 서명, 검증), PE 봉인 가능 여부 측정(`pe_probe.py`). 개발 빌드 마커 `RESHIELD-DEV-BUILD-v1`이 든 바이너리는 `reshield_release.py`와 `verify_release.py`가 거부한다 |
| `bindings`, `action.yml` | `bindings/csharp/Reshield.cs`, `bindings/unity/com.reshield.guard/`, `action.yml` | `reshield_check_json()`을 부르는 C# P/Invoke 바인딩과 Unity 패키지 골격([engines-unity.md](engines-unity.md)), `reshield_release.py`를 실행하는 composite GitHub Action([steam-pipeline.md](steam-pipeline.md)) |

### 소스 파일 목록

| 파일 | 내용 |
| --- | --- |
| `src/sha256.c` | 이식성 SHA-256, 스트리밍 `update`, 파일 해시(`reshield_sha256_file`, 내부 `reshield_sha256_file_limited`), `reshield_sha256_parts()` |
| `src/sha256_accel.c`, `src/sha256_accel.h` | CPU 명령 블록 압축과 backend 선택(`reshield_sha256_backend()`) |
| `src/sha256_internal.h` | `reshield_sha256_parts()` 선언(내부) |
| `src/integrity_common.c` | `RSHLDCHK` 레코드(`static volatile`), `reshield_internal_record_anchor()`, 개발 빌드 마커(`RESHIELD_ALLOW_UNSEALED`일 때만), `reshield_verify_code_section()`, `reshield_get_sealed_manifest_root()`, `reshield_verify_buffer()` |
| `src/integrity_macos.c` | 레코드 주소에서 `dladdr`로 이미지 헤더를 얻고 `getsectiondata`로 `__TEXT,__text` 위치를 구함 |
| `src/integrity_linux.c` | `dl_iterate_phdr`로 레코드가 든 이미지를 찾고, 그 파일(`/proc/self/exe`, 절대경로 `dlpi_name`, 상대경로면 `/proc/self/maps`의 절대경로)의 디스크 section header에서 `.text`를 읽음 |
| `src/integrity_windows.c` | `GetModuleHandleExW`로 레코드가 든 모듈을 얻고 PE 헤더에서 `.text`를 찾음 |
| `src/attestation_macos.c`, `src/attestation_linux.c`, `src/attestation_windows.c` | W^X 검사(`mach_vm_region` / `/proc/self/maps` / `VirtualQuery`)와 코드 서명 검사(`SecCodeCheckValidity` / Linux는 `UNSUPPORTED` / `WinVerifyTrust`) |
| `src/manifest.c` | 매니페스트 파싱(v1, v2 헤더), 경로 규칙 `is_safe_relative_path`, 에셋 검증, strict 스캔과 `#allow` glob 매칭 |
| `src/file_platform.h`, `src/file_posix.c`, `src/file_windows.c` | 플랫폼 파일 I/O와 디렉터리 열거(내부) |
| `src/reshield.c` | `reshield_verify()`, 기본 설정, 상태 이름, JSON 직렬화, `reshield_secure_zero()` |
| `src/verify_app.c` | `reshield_verify_app()`, `reshield_check_json()` |
| `src/save_seal.c` | HMAC-SHA256과 save 태그 |

공개 헤더는 `include/reshield/`의 `reshield.h`(위 모듈을 묶는 진입점), `integrity.h`, `manifest.h`, `attestation.h`, `save_seal.h`다.

### 모듈 구조도

화살표는 "호출한다"이다. 앱이 직접 쓰는 공개 진입점은 맨 위 두 줄이다.

```text
앱 / 엔진 바인딩                         앱 (세이브 파일)
  reshield_verify / _verify_app            reshield_save_tag / _verify
  reshield_check_json                                |
        |                                            v
        v                                       save_seal --> sha256 (reshield_sha256_parts)
   verify_app --> runtime (reshield.c)
                     |-------------------+-------------------+
                     v                   v                   v
                 integrity            manifest          attestation
              (integrity_common)         |                   |
                     |                   |                   |
                     +------> platform hook <----------------+
                              reshield_platform_get_code_section()
                              integrity_{macos,linux,windows}.c
                              (레코드 anchor로 이미지를 찾아 코드 섹션 위치를 반환)

   integrity, manifest --> sha256 --> sha256_accel (CPU 명령 가능하면)
   manifest, sha256    --> file (파일 열기, strict 디렉터리 열거)
```

## `RSHLDCHK` v2 레코드 구조 (96 bytes)

코드 섹션 외부의 데이터 영역(`__DATA,__data` / `.data`)에 `volatile` + `used`로 배치해 순환 해싱과 컴파일러 상수 접기를 방지한다. 레코드는 `src/integrity_common.c`의 `static` 변수라 re-shield를 링크한 모듈마다 자기 레코드를 하나씩 갖는다.

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

- 검증 대상 이미지는 "봉인 레코드가 들어 있는 이미지"다(자기 모듈 모드). 정적 링크한 EXE에서는 메인 실행 파일이고, re-shield를 공유 라이브러리(`.so`/`.dylib`/`.dll`, Unity IL2CPP의 `GameAssembly`나 Godot GDExtension 등)에 링크하면 그 라이브러리다. 호스트 프로세스의 EXE는 보지 않는다. 코드 서명 검사(`RESHIELD_CHECK_CODESIGN`)만 예외로 모듈 모드에서도 프로세스 EXE를 본다. 다른 모듈(엔진 본체 등)의 메모리는 검사하지 않는다. Linux에서 라이브러리를 상대경로로 열어도 `/proc/self/maps`에서 절대경로를 얻어 검증하며, `/proc`이 없거나 로드 뒤 파일이 지워지거나 교체되면 fail-closed(`INTERNAL_ERROR`)다. [integrity-verification.md](integrity-verification.md#8-자기-모듈-모드-공유-라이브러리) 참고.
- 해시 대상은 `__TEXT,__text` / `.text`뿐이다. `__stubs`, `.plt`, `__const`, 레코드가 놓이는 `__DATA`는 포함되지 않는다.
- 레코드의 평문 `RSHLDCHK` 매직이 수정 지점을 노출한다.
- 소프트웨어 breakpoint(코드 바이트 패치)가 설치된 상태에서는 `CODE_TAMPERED`로 보고된다.
- 기본 매니페스트는 목록에 없는 추가 파일을 감지하지 못한다. v2 `strict` 모드(`#reshield-manifest v2 strict`, `#allow`)는 에셋 폴더를 열거해 `RESHIELD_ERR_ASSET_EXTRA`로 보고한다. 키 없는 설계라 재봉인은 막지 못한다. [integrity-verification.md](integrity-verification.md#10-매니페스트-v2와-strict-모드) 참고.
- macOS 코드 서명 검증은 기본적으로 `SecCodeCheckValidity`를 requirement `NULL`로 호출해 서명 유효성만 확인하며 서명 주체는 고정하지 않는다. `cfg.codesign_requirement`를 설정하면 `SecRequirementCreateWithString`으로 만든 requirement를 함께 검사한다(Team ID 고정 등). Windows는 `leaf-sha256:<64 hex>` 형식이다(아래 Windows 항목).
- fat/universal Mach-O는 `seal_binary.py`가 지원하지 않는다.
- Windows(PE32+ x64, MSVC)는 봉인 도구, 파일 I/O, 런타임 백엔드(`src/integrity_windows.c`의 `.text` 위치 찾기, `src/attestation_windows.c`의 `VirtualQuery` W^X 순회와 `WinVerifyTrust` 코드 서명 검사)가 구현되어 있고 CI `windows-msvc` 잡(`windows-latest`)이 실제로 빌드·봉인·실행·변조 탐지를 확인한다. Windows의 코드 서명 검사는 `WinVerifyTrust` 후 `requirement`(`leaf-sha256:<64 hex>`, 서명 leaf 인증서 DER의 SHA-256)가 주어지면 그 해시와 비교한다. 형식이 다른 문자열은 `FAILED`(fail-closed)이고, 서명 안 된 EXE도 `FAILED`다. CI가 일회용 자체 서명 인증서로 서명한 EXE에서 `OK`와 leaf pin 일치/불일치를 확인한다(공인 CA 서명은 미검증). macOS와 Windows의 requirement 문법이 달라 플랫폼별로 `#ifdef` 안에서 설정한다. 정식 지원 대상은 MSVC 빌드(CI 측정: MSVC 링크 EXE의 `.text` 안 base relocation 0개, 봉인 성공)이며 mingw-w64는 크로스 컴파일·도구 테스트 전용이다. [integrity-verification.md](integrity-verification.md#7-windows-pe32-x64) 참고.
- macOS·Linux·Windows 외 플랫폼에서는 코드 섹션을 찾지 못해 무결성 검사가 `RESHIELD_INTEGRITY_ERROR` → `RESHIELD_ERR_INTERNAL`(기본 설정에서 fail-closed)이 된다. W^X·코드 서명 검사는 `RESHIELD_ATTEST_UNSUPPORTED`를 반환하며 `reshield_verify()`는 이를 Linux 코드 서명 검사와 같이 조용히 통과시킨다. 단 `cfg.codesign_requirement`가 NULL이 아니면 플랫폼이 pin을 강제할 수 없으므로 `RESHIELD_ERR_CODESIGN_INVALID`다(`RESHIELD_CHECK_CODESIGN`을 켠 경우).
- `make lib`/`make shared`의 기본 빌드(`-DRESHIELD_ALLOW_UNSEALED`)는 개발 빌드이며 마커 `RESHIELD-DEV-BUILD-v1`을 담는다. 마커는 릴리스 도구가 실수로 개발 빌드를 배포하는 것을 거부하게 하는 장치일 뿐 방어가 아니다([integrity-verification.md](integrity-verification.md#4-개발-옵션과-경고)).
- save seal(`save_seal`)의 키는 게임 바이너리에 들어 있어야 하므로 바이너리나 프로세스 메모리를 읽을 수 있는 공격자는 태그를 위조할 수 있다. 캐주얼 편집·손상 탐지용이다([save-seal.md](save-seal.md)).
- 자세한 내용: [integrity-verification.md](integrity-verification.md#5-한계).
