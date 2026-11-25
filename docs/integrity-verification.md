# Code-Section & Asset Manifest Verification Guide

## 1. 빌드 및 봉인 파이프라인

```bash
# 1. 에셋 매니페스트 생성
python3 tools/gen_manifest.py examples/assets -o build/sample_assets.manifest

# 2. 바이너리 빌드 및 내부 심볼 정리
make build/sample_game
cp build/sample_game build/sample_game_sealed
strip build/sample_game_sealed

# 3. 코드 섹션 SHA-256 + 매니페스트 루트 해시 봉인 (macOS는 ad-hoc codesign 자동 적용)
python3 tools/seal_binary.py build/sample_game_sealed \
  --manifest build/sample_assets.manifest \
  --build-id 1

# 4. 릴리스 아티팩트 검증 (CI/CD 용도)
# (이 예제는 저장소 기본인 개발 빌드를 링크하므로 --allow-dev-build가 필요하다. 배포용 빌드에는 쓰지 않는다. 4절 참고)
python3 tools/verify_release.py build/sample_game_sealed --allow-dev-build \
  --manifest build/sample_assets.manifest \
  --assets examples/assets
```

## 2. 런타임 통합 예시

```c
#include "reshield/reshield.h"

reshield_config_t cfg = reshield_default_config();
cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
cfg.manifest_path = "sample_assets.manifest";
cfg.asset_base_dir = "assets";

reshield_report_t report;
if (reshield_verify(&cfg, &report) != RESHIELD_OK) {
    fprintf(stderr, "Integrity error: %s\n", reshield_status_name(report.status));
    return 1;
}
```

## 3. 자동 테스트

```bash
make clean
make all test
make release-demo
```

`make test`는 SHA-256 NIST 테스트 벡터, 매니페스트/에셋 변조 탐지, W^X 페이지 권한 검증, macOS 코드 서명 검증, 코드 섹션 1바이트 손상 탐지, `-DRESHIELD_DISABLE` 개발 빌드를 모두 검증한다.

## 4. 개발 옵션과 경고

- `cfg.allow_unsealed = 1`은 라이브러리를 `-DRESHIELD_ALLOW_UNSEALED`로 컴파일한 개발 빌드에서만 효과가 있다(이 저장소의 Makefile은 기본으로 켠다. 릴리스는 `make ALLOW_UNSEALED=0`). 그 매크로 없이 컴파일한 라이브러리에서 필드를 켜면 우회되지도, 조용히 무시되지도 않고 `reshield_verify()`가 `RESHIELD_ERR_INTERNAL`(설정 오류)을 반환한다. 매크로를 켠 빌드를 릴리스에 쓰면 레코드의 sealed 바이트를 0으로 바꾸는 변조만으로 코드·매니페스트 검사가 우회된다. 릴리스 금지.
- **개발 빌드 배포 방지(도구 단계).** `make lib`/`make shared`의 기본값은 개발 빌드다. 배포는 `make release-shared` 또는 `make ALLOW_UNSEALED=0 lib`(`build/release/`)로 하거나, 자기 빌드에서 `-DRESHIELD_ALLOW_UNSEALED`를 뺀다. 개발 빌드(`RESHIELD_ALLOW_UNSEALED`로 컴파일, `src/integrity_common.c`)에는 마커 문자열 `RESHIELD-DEV-BUILD-v1`이 상수로 들어가고, 릴리스 빌드에는 들어가지 않는다. `tools/reshield_release.py`와 `tools/verify_release.py`는 대상 바이너리 바이트에서 마커를 찾으면 거부한다(종료 코드 2, `reshield_release.py`는 바이너리를 수정하기 전에 검사). `--allow-dev-build`(GitHub Action 입력 `allow-dev-build`)는 데모·CI 전용 우회이고 사용하면 경고가 나온다. `seal_binary.py`는 검사하지 않는다(테스트와 데모가 개발 빌드를 직접 봉인한다). 런타임 동작은 바뀌지 않는다. `make test`의 `guard-test`와 `windows-msvc` CI가 마커 유무(정적·공유 라이브러리, 실행 파일)와 도구의 거부·통과를 확인한다.
  - **한계**: 마커는 실수로 개발 빌드를 배포하는 것을 막는 장치이지 방어가 아니다. 개발 빌드를 손에 넣은 공격자는 마커를 지울 수 있고(같은 길이의 0으로 덮어쓰면 도구도 통과한다. `tests/test_dev_build_guard.py`가 이 한계를 그대로 기록한다), sealed 바이트와 함께 바꾸면 검사가 우회된다. 이는 개발 빌드의 본질적 한계이고, 막는 것은 릴리스 빌드뿐이다.
- UNSEALED 판정은 레코드가 유효(magic·version 일치, 플래그 0/1)하고 `sealed == 0`일 때만 내려진다. 유효하지 않은 레코드는 `CODE_TAMPERED`, 매니페스트 검사 경로에서 sealed이지만 매니페스트 루트가 없는 바이너리는 `MANIFEST_MISMATCH`로 처리되어 `allow_unsealed`로 통과하지 못한다.
- `-DRESHIELD_DISABLE`에서도 `reshield_verify_buffer()`는 실제 해시 비교를 수행한다(앱 로직이며 무결성 검사가 아님).

## 5. 한계

- 로컬 바이너리의 자체 무결성 검증은 바이너리와 매니페스트가 동시에 재봉인되거나 런타임 API가 교체될 경우 우회될 수 있다.
- macOS 코드 서명 검증(`RESHIELD_CHECK_CODESIGN`)은 `SecCodeCheckValidity`를 requirement `NULL`로 호출해 서명 유효성만 확인하며, 서명 주체(Developer ID/Team ID)는 고정하지 않는다. ad-hoc 서명이나 다른 주체의 유효한 서명으로 재서명한 바이너리도 이 검사는 통과한다. 서명자를 고정하려면 `cfg.codesign_requirement`(또는 `reshield_verify_os_codesign_req()`)에 requirement 문자열을 준다(예: `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`). 문자열이 파싱되지 않으면 통과시키지 않고 `CODESIGN_INVALID`로 처리한다. 이 저장소에서는 Developer ID 인증서가 없어 ad-hoc 바이너리에 대한 음성·양성 테스트(`anchor apple` 실패, `!anchor apple` 통과, 잘못된 문법 실패)만 검증했고, 실제 Team ID 문자열은 검증하지 못했다. 검증 함수 자체를 패치하는 공격은 이 옵션으로도 막지 못한다.
- 검증 대상은 메인 EXE가 아니라 봉인 레코드가 들어 있는 이미지다(§8). re-shield를 공유 라이브러리에 넣었다면 그 라이브러리를 봉인해야 하고, 호스트 EXE는 봉인하지 않아도 되며 검사되지도 않는다. 코드 서명 검사는 모듈 모드에서도 프로세스 EXE 기준이다.
- Linux 런타임은 `.text` 위치를 레코드가 들어 있는 이미지의 파일(메인이면 `/proc/self/exe`, 공유 라이브러리면 절대경로 `dlpi_name`)의 디스크 section header에서 읽는다(로더는 이 헤더를 쓰지 않으므로 파일을 고칠 수 있는 공격자가 바꿀 수 있다). 그래서 범위가 그 이미지(`dl_iterate_phdr` 항목 중 레코드 주소를 포함하는 것)의 실행 가능·쓰기 불가 `PT_LOAD` 안에 완전히 들어가는지 검증하고 아니면 `INTERNAL_ERROR`로 처리한다. 같은 세그먼트 안의 다른 구간으로 돌리는 공격(코드 케이브에 원본 바이트 복사)은 막지 못한다. `ld.so ./prog`로 직접 실행하면 glibc에서는 프로그램 이미지의 `dlpi_name`이 비어 있어 `INTERNAL_ERROR`(fail-closed, 크래시 아님)다(musl에서 프로그램을 절대경로로 주면 그 파일이 맞으므로 정상 판정이 나올 수 있다). 공유 라이브러리를 상대경로(`dlopen("./x.so")`)로 열면 `dlpi_name`이 상대경로라 현재 디렉터리가 바뀌었을 수 있으므로 믿지 않고, `/proc/self/maps`에서 레코드 주소를 포함하는 매핑 줄의 절대경로를 쓴다(`dl_iterate_phdr` 콜백 밖에서 읽는다). 줄은 직접 파싱한다(경로에 공백 가능, 줄 길이 상한 `PATH_MAX+128`, 정적 상태 없음). 주소 범위(`lo <= 앵커 < hi`)가 앵커를 포함하는 매핑만 쓰고, 그 줄이 비정상·과장이거나 경로가 없거나(`[heap]`·익명) `/`로 시작하지 않거나 끝이 ` (deleted)`(로드 뒤 파일이 지워지거나 교체됨)이면 `INTERNAL_ERROR`(fail-closed)다. `/proc`이 없는 환경도 마찬가지다. 이름이 빈 비메인 이미지(`ld.so ./prog`의 프로그램 맵)는 이 폴백을 쓰지 않고 그대로 `INTERNAL_ERROR`다. 파일 내용을 읽는 위치는 절대경로 `dlpi_name`일 때와 같고(디스크 section header, 범위 검증 동일), 테스트가 상대경로의 정상·변조·공백 경로·삭제·교체를 확인한다. musl(dynamic, static, static-pie)과 glibc를 CI에서 확인한다. `seal_binary.py`는 `DT_TEXTREL`/`DF_TEXTREL`이 있는 ELF(로더가 `.text`를 패치)를 거부한다.
- 해시 대상은 `__TEXT,__text`(macOS) 또는 `.text`(Linux)뿐이다. `__stubs`, `.plt`, `__const`, 그리고 레코드가 놓이는 `__DATA`는 해시 대상이 아니다.
- 레코드는 평문 `RSHLDCHK` 매직으로 시작하므로 바이너리에서 문자열 검색만으로 수정 지점이 드러난다(`seal_binary.py`도 같은 방식으로 찾는다).
- 소프트웨어 breakpoint는 코드 바이트를 패치하므로, 설치된 상태에서 검사하면 `CODE_TAMPERED`로 보고된다.
- 매니페스트는 목록에 있는 파일만 검증한다. 매니페스트에 없는 추가 파일은 감지하지 못한다.
- fat/universal Mach-O는 `seal_binary.py`가 지원하지 않는다(오류로 종료). 슬라이스별로 봉인해야 한다.
- `verify_release.py`의 `defined_symbols`는 `nm` 결과를 보고할 뿐 검증하지 않는다.

## 6. 매니페스트 형식 규칙 (C 런타임과 Python 도구 공통)

- 매니페스트는 한 번만 읽어(최대 4 MiB, 일반 파일만) 같은 버퍼로 루트 해시를 계산하고 파싱한다. 해시 후 재오픈하지 않는다.
- 1023자를 넘는 줄, CR(`\r`, CRLF 포함)·NUL이 있는 매니페스트, 잘못된 줄은 `IO_ERROR`다. 항목이 하나도 없는 매니페스트도 `IO_ERROR`다.
- `reshield_verify()`는 이 `IO_ERROR`(경로 오류, 파일 없음, 형식 오류)를 `RESHIELD_ERR_MANIFEST_IO`(값 8, `MANIFEST_IO_ERROR`)로 보고한다. 이전에는 `RESHIELD_ERR_INTERNAL`이었다. 변조 판정이 아니므로 현장 텔레메트리에서 경로 문제와 진짜 내부 오류를 구분할 수 있다. 값은 열거형 끝에 추가했고 기존 값은 그대로다.
- 경로 규칙은 모든 플랫폼에서 같다(C: `src/manifest.c`의 `is_safe_relative_path`, Python: `tools/manifest_path.py`). 구분자는 `/`만 허용하고 구성요소 단위로 검사한다. 다음은 거부한다.
  - 선행 `/`(절대경로)와 빈 구성요소
  - `\`, `:`, 제어문자(0x00–0x1F, CR/LF 포함), `< > " | ? *`
  - `.` 또는 공백으로 끝나는 구성요소(`.`, `..`, `...` 포함)
  - Windows 예약 장치명 `CON PRN AUX NUL COM0`–`COM9` `LPT0`–`LPT9` `CONIN$` `CONOUT$`: 대소문자(ASCII)를 구분하지 않고, 첫 `.` 앞 부분에서 끝 공백을 제거해 비교하므로 `nul.txt`, `CON .txt`도 거부한다.
  - `v1..2.cfg`, 한글 이름, `sub/dir/ok.cfg`는 허용한다. 두 구현은 `tests/path_rules.txt`의 같은 케이스 표로 검증한다.
- **동작 변경**: 이 규칙은 이전보다 엄격하다(예: `a.cfg.`, `a:b`, `con.txt`, `a<b`). 이런 항목이 들어 있는 기존 매니페스트는 런타임에서 `IO_ERROR`가 되고 `verify_release.py`도 거부한다. 해당 에셋 이름을 바꾸고 매니페스트를 다시 생성·재봉인해야 한다.
- `gen_manifest.py`는 규칙을 어기는 파일, 대소문자만 다른 중복 경로(`A.cfg`/`a.cfg`), NFC가 아닌 파일명이 있으면 오류로 종료한다(대소문자 비구분·정규화 비구분 파일시스템에서 모호해지는 것을 막기 위함).
- 에셋은 일반 파일이어야 하며(FIFO·장치 파일·그것을 가리키는 심볼릭 링크는 불일치) 기대 크기+1바이트까지만 읽는다.
- `gen_manifest.py`는 이름이 `.`으로 시작하는 파일을 제외하고, `.`으로 시작하는 디렉터리는 순회한다.
- `gen_manifest.py --exclude GLOB`(반복 가능)는 매니페스트에서 파일을 뺀다. 매칭은 `fnmatch.fnmatchcase`로 에셋 루트 기준 상대 POSIX 경로(`sub/a.cfg`)에 적용하므로 대소문자를 구분하고, `*`는 `/`도 포함한다(`cache/*`는 하위 디렉터리 전체). 이 필터는 경로 안전 검사보다 먼저 적용되어, 제외된 파일은 규칙을 어겨도(예: 예약 장치명) 오류가 되지 않는다. `reshield_release.py`는 같은 `--exclude`를 받고, 봉인하는 바이너리 자신(에셋 디렉터리 안에 있을 때)은 항상 제외한다.

## 7. Windows (PE32+ x64)

봉인 도구와 런타임 백엔드(MSVC x64)가 모두 구현되어 있다.

- 코드 섹션 위치(`src/integrity_windows.c`): `GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT, <봉인 레코드 주소>)`로 레코드가 들어 있는 모듈(EXE 또는 re-shield를 링크한 DLL)의 매핑된 이미지를 얻고 PE 헤더를 직접 읽어 `.text`를 찾는다. 봉인 도구와 같은 규칙이다(이름이 정확히 `.text`인 섹션 하나, 쓰기 불가, `VirtualSize <= SizeOfRawData`, 해시 범위는 `base + VirtualAddress`부터 `VirtualSize` 바이트). 모든 헤더 읽기는 먼저 첫 페이지(0x1000)로, 이어서 `SizeOfHeaders`/`SizeOfImage`로 범위를 검사하고, 어긋나면 `-1`(→ `RESHIELD_ERR_INTERNAL`, fail-closed)이다. 봉인 레코드는 macOS·Linux와 같이 정적 변수이며 `integrity_common.c`를 그대로 쓴다.
- W^X(`src/attestation_windows.c`): `.text` 범위 전체를 `VirtualQuery`로 따라가며 모든 영역이 커밋됨·실행 가능·쓰기 불가(`PAGE_GUARD` 아님)여야 하고, 틈(미커밋·예약·해제 영역)이 있으면 실패한다. 의미는 macOS·Linux 구현과 같다.
- 코드 서명(`reshield_verify_os_codesign_req`): 실행 중인 프로세스 EXE(re-shield가 DLL 안에 있어도 DLL이 아니라 EXE)를 받치는 파일을 `WinVerifyTrust`(`WINTRUST_ACTION_GENERIC_VERIFY_V2`, UI 없음, 폐기 확인 끔, 네트워크 조회 없음)로 검사해 `OK`/`FAILED`를 반환한다. `requirement`가 `NULL`이면 유효성만 확인한다. 서명자를 고정하려면 `requirement`(= `cfg.codesign_requirement`)에 정확히 `leaf-sha256:` 다음 64자리 hex(대소문자 무관)를 준다. 값은 서명(leaf) 인증서 DER 바이트의 SHA-256이다(thumbprint는 SHA-1이라 다르다). 구현은 `WinVerifyTrust`를 `WTD_STATEACTION_VERIFY`로 실행해 성공하면 `WTHelperProvDataFromStateData`/`WTHelperGetProvSignerFromChain`/`WTHelperGetProvCertFromChain`로 첫 번째 서명자의 leaf 인증서를 얻고, 라이브러리 자신의 `reshield_sha256`으로 해시해 비교한 뒤 모든 경로에서 `WTD_STATEACTION_CLOSE`를 호출한다. 형식이 다르거나(접두어·길이·hex 아님) 어느 단계든 실패하면 `FAILED`(fail-closed)다. 첫 서명자만 보며 중첩·다중 서명은 구분하지 않는다. macOS와 Windows의 requirement 문법이 서로 다르므로 플랫폼별로 `#ifdef` 안에서 설정한다. 서명 인증서만 고정하므로 같은 인증서로 서명된 다른 빌드는 막지 못한다(그 구분은 봉인 해시의 몫). Authenticode 서명이 없는 EXE는 `FAILED`이므로, `RESHIELD_CHECK_CODESIGN`을 켠 서명 안 한 개발 빌드는 `reshield_verify()`가 `RESHIELD_ERR_CODESIGN_INVALID`를 반환한다. 기본 검사 집합(`RESHIELD_CHECK_DEFAULT`)에는 코드 서명이 없다. 검사 대상 파일은 모듈 경로가 아니라 매핑된 이미지의 파일이다. `GetMappedFileNameW`로 NT 경로를 얻어 `GetLogicalDriveStringsW`+`QueryDosDeviceW`로 DOS 경로로 바꾸고, `CreateFileW`(읽기 전용, `FILE_SHARE_READ|FILE_SHARE_DELETE`)로 연 핸들을 `WINTRUST_FILE_INFO.hFile`로 넘긴다. 그래서 실행 중인 EXE를 rename한 뒤 서명된 파일을 같은 경로에 복사해도 검증 대상은 바뀌지 않는다(CI의 `tests/test_codesign_toctou_windows.c`가 이 공격을 재현하고 `FAILED`를 확인). 변환이 실패하면(예: UNC 공유의 EXE) `FAILED`(fail-closed)다. 검증은 파일 내용에 대한 것이고 메모리의 `.text`는 코드 섹션 해시가 따로 본다. `psapi.lib`도 MSVC에서 자동 링크되고 mingw는 `-lpsapi`(Makefile)지만, 이번 변경 이후 mingw 빌드는 컴파일도 실행도 확인하지 않았다(로컬에 mingw가 없고 CI는 MSVC만 돌린다). `wintrust.lib`는 MSVC에서 `#pragma comment(lib)`로 자동 링크되고, mingw는 `-lwintrust`(Makefile이 지정)다.

검증 범위: CI의 `windows-msvc` 잡(GitHub Actions `windows-latest`)이 `cl`로 라이브러리·예제·테스트를 빌드하고 다음을 실제로 실행한다. 봉인 전 EXE의 `UNSEALED` 보고와 `--allow-unsealed` 통과(W^X 검사 포함), `seal_binary.py`로 봉인한 복사본의 `status=OK` 실행, `verify_release.py`, `.text`의 int3 패딩 1바이트를 바꾼 복사본의 `CODE_TAMPERED` 탐지(`tests/tamper_pe_text.py`), 서명 안 된 봉인 EXE에서 `--check-codesign`이 `CODESIGN_INVALID`를 내는지, 일회용 자체 서명 인증서(`New-SelfSignedCertificate`, 러너의 Root·TrustedPublisher 저장소에만 등록)로 봉인 뒤 서명한 복사본에서 `--check-codesign`이 `status=OK`를 내는지, 올바른 `leaf-sha256:` 값(대소문자 모두)은 통과하고 다른 값·한 니블만 다른 값·형식이 틀린 값은 `CODESIGN_INVALID`인지, 서명한 파일에 `seal_binary.py --verify-only`·`verify_release.py`가 통과하는지, 실행 중 EXE rename-and-replace 후에도 검사가 `FAILED`인지(`test_codesign_toctou_windows`), 서명한 파일의 `.text` 1바이트를 바꾸면 `CODE_TAMPERED`이고 `--check-codesign`을 켜면 `failed_checks=0x5`(코드 섹션+코드 서명)인지, 매니페스트를 묶은 `sample_game` 봉인·실행, 그리고 `test_integrity`·`test_manifest`·`test_runtime`·`test_wx`. `test_wx`는 플랫폼 훅을 덮어써 `VirtualAlloc`한 페이지(쓰기 가능·실행 불가·결번)로 W^X 순회를 검사한다. 건너뛴 것: `tests/test_seal_workflow.py`(`nm`과 POSIX 경로 필요), `-DRESHIELD_DISABLE` 변형, `test_manifest.c` 안의 POSIX 전용 케이스(`#ifndef _WIN32`). 검증하지 못한 것: 공인 CA가 발급한 인증서·타임스탬프가 있는 서명(CI는 타임스탬프 없는 자체 서명 인증서만 쓴다), 폐기 확인, 다중·중첩 서명, 서명 뒤 봉인 순서 이외의 Authenticode 경로, Windows ARM64와 32비트 x86(후자는 헤더 검사에서 fail-closed).

지원 정책: 정식 지원 대상은 MSVC 빌드이고, mingw-w64는 맥/Linux에서의 크로스 컴파일·도구 테스트 전용이다. CI의 `windows-msvc-probe` 잡(`.github/workflows/ci.yml`)이 `cl`로 `examples/integrity_demo.c`를 빌드해 `tools/pe_probe.py`와 `dumpbin` 결과를 아티팩트로 남긴다. 2026-11-24 측정(GitHub Actions `windows-latest`, run 45239478134)에서 `.text` 안 base relocation은 0개(전체 797개는 다른 섹션)였고 `seal_binary.py` 봉인에 성공했다. 즉 MSVC 링크 EXE는 봉인 가정(`.text`가 로드 시 바뀌지 않음)을 만족한다. 측정은 이 데모 한 개에 대한 것이므로, 다른 프로젝트의 링크 설정에서는 `pe_probe.py`로 직접 확인한다. 런타임 검증은 위의 `windows-msvc` 잡이 같은 MSVC 설정으로 실행해 확인한다.

`seal_binary.py`와 `verify_release.py`는 PE32+ x64(Machine `0x8664`)를 지원한다. ARM64(`0xAA64`)와 PE32(32비트)는 오류로 거부한다.

- 해시 대상: 이름이 정확히 `.text`인 섹션 하나. 파일의 `[PointerToRawData, PointerToRawData + VirtualSize)` 구간이다. `.text`가 0개나 2개 이상이거나, `IMAGE_SCN_MEM_WRITE`가 켜져 있거나, `VirtualSize > SizeOfRawData`이면 오류다.
- 봉인 시 거부 조건:
  - base relocation이 `.text` RVA 범위 안에 하나라도 있으면 거부한다(`IMAGE_REL_BASED_ABSOLUTE` 패딩은 제외). 재배치되면 메모리의 코드가 파일과 달라져 해시가 맞지 않기 때문이다.
  - 레코드가 쓰기 가능한 데이터 섹션(`.data` 등)의 raw 범위 안에 없거나 `.text`와 겹치면 거부한다.
  - Security 디렉터리(Authenticode)가 이미 있으면 거부한다. 서명 전에 봉인해야 한다. 이미 봉인된 파일을 나중에 서명해도 `.text`는 바뀌지 않으므로 `--verify-only`와 `verify_release.py`는 통과한다.
- OptionalHeader의 CheckSum이 0이 아니면 봉인 뒤 표준 알고리즘으로 다시 계산해 기록하고, 0이면 그대로 둔다.
- `.text` 외의 실행 가능 섹션은 해시 대상이 아니며 stderr 경고로 나열만 한다.
- `verify_release.py`는 `nm`이 없으면 `defined_symbols`를 `n/a`로 보고하고 실패로 처리하지 않는다.
- macOS에서 PE를 봉인해도 ad-hoc codesign은 실행하지 않는다(Mach-O만 대상).

### mingw-w64 빌드 실측

`examples/integrity_demo.c`를 `x86_64-w64-mingw32-gcc`(Ubuntu 24.04 gcc-mingw-w64-x86-64)로 `-O2`·`-O0` 빌드해 확인한 결과다.

- 기본 링크 옵션: `.text`(VirtualSize 35064/37752 바이트, 플래그 `0x60000060`) 안에 base relocation이 1개 있다(`.ctors`/`__CTOR_LIST__`의 포인터, DIR64). 전체 relocation은 53개다. 그래서 `seal_binary.py`가 봉인을 거부한다.
- `-Wl,--disable-dynamicbase -Wl,--disable-reloc-section`으로 링크하면 relocation 디렉터리가 없어 봉인과 `--verify-only`가 통과한다. 이 경우 이미지는 재배치할 수 없으므로 고정 ImageBase(`0x140000000`)에 로드되어야 한다(ASLR 없음). 따라서 이 옵션은 크로스 테스트 용도로만 쓰고 배포용으로는 권장하지 않는다. `-Wl,--disable-dynamicbase`만으로는 relocation이 남아 거부된다.
- 이에 따라 mingw로 `make all`을 하면 `sample_game_sealed` 봉인 단계가 기본 옵션에서는 실패한다. `make CC=x86_64-w64-mingw32-gcc ... LDFLAGS="-Wl,--disable-dynamicbase -Wl,--disable-reloc-section" all`처럼 링크 옵션을 지정해야 한다. mingw 기본 링크 옵션은 바꾸지 않는다(mingw는 정식 지원 대상이 아니다).

## 8. 자기 모듈 모드 (공유 라이브러리)

`reshield_verify_code_section()`과 W^X 검사는 "프로세스의 메인 이미지"가 아니라 "봉인 레코드가 들어 있는 이미지"를 본다. 레코드는 re-shield를 링크한 모듈의 `.data`에 있으므로, 정적 링크한 EXE에서는 두 이미지가 같고(동작 변화 없음) re-shield를 `.so`/`.dylib`/`.dll`에 넣으면 그 라이브러리가 검증 대상이 된다. 공개 함수 시그니처는 바뀌지 않는다.

- 이미지를 찾는 기준은 레코드 변수의 주소(내부 함수 `reshield_internal_record_anchor()`)다. macOS는 `dladdr`의 `dli_fbase`, Linux는 `dl_iterate_phdr`에서 그 주소를 포함하는 `PT_LOAD`를 가진 항목, Windows는 `GetModuleHandleExW(FROM_ADDRESS)`다.
- 봉인은 그 라이브러리 파일에 한다: `python3 tools/seal_binary.py libfoo.so --build-id N`. `seal_binary.py`는 형식(ELF·Mach-O·PE)만 보고 EXE인지 라이브러리인지 구분하지 않는다. 호스트 EXE는 봉인하지 않아도 된다.
- 엔진 바인딩(C#, GDScript 등)은 구조체 없이 `int`와 문자열만 주고받는 `reshield_check_json()`을 부르면 된다(`reshield_verify_app()` + `reshield_report_to_json()` 한 번에). 매니페스트·에셋 경로는 라이브러리가 아니라 프로세스 EXE의 디렉터리 기준이다. 라이브러리에서는 `reshield.def`(Windows)나 기본 가시성(POSIX)으로 내보낸다.
- 코드 서명 검사(`RESHIELD_CHECK_CODESIGN`)는 모듈 모드에서도 프로세스 EXE를 본다. 라이브러리 자체의 서명은 검사하지 않는다(엔진 DLL은 대개 서명이 없다).
- Windows DLL의 export는 `reshield.def`에 나열한 부분집합(엔진 바인딩에 필요한 `reshield_verify_code_section`, `reshield_verify_code_page_wx`, `reshield_verify_app`, `reshield_check_json`, `reshield_report_to_json`, `reshield_status_name` 6개)뿐이다. 나머지 공개 함수(`reshield_verify` 등)는 DLL 밖에서 부를 수 없다. POSIX 공유 라이브러리는 기본 가시성이라 공개 API 전체가 보인다.
- 확인한 것: `make test`의 `module-test`(`tests/test_module_host.c` + `tests/test_module_mode.py`)가 호스트(미봉인, re-shield 코드 없음)에서 라이브러리를 `dlopen`해 미봉인 라이브러리 `UNSEALED`, 봉인 후 `OK`(W^X 포함), `.text` 1바이트 변조 `TAMPERED`를 개발·릴리스 두 빌드로 확인한다(macOS, Linux glibc·musl). 매니페스트를 함께 봉인한 라이브러리와 다른 디렉터리의 호스트 EXE가 `reshield_check_json(manifest_rel, assets_rel, ...)`을 부르는 시나리오(정상 `OK`, 에셋 1바이트 변조 `ASSET_TAMPERED`, 매니페스트 삭제 `MANIFEST_IO_ERROR`, 라이브러리 옆의 유효한 사본은 쓰이지 않음)와, ELF에서 re-shield를 링크하고 심볼을 export한 호스트(`-rdynamic`)가 라이브러리를 `dlopen`해도 라이브러리가 자기 레코드로 검증하는지(`-Wl,-Bsymbolic` 이중 레코드)도 확인한다. Windows는 CI `windows-msvc` 잡이 `reshield.def`로 `reshield.dll`을 빌드해 같은 시나리오를 실행한다. `make shared`가 `build/libreshield.so`(macOS는 `.dylib`)를 만든다(Linux는 `-Wl,-Bsymbolic`로 같은 이름의 호스트 심볼에 가려지지 않게 한다).
- 한계: 호스트 EXE나 다른 모듈(엔진 본체 등)의 메모리는 검사하지 않는다. Linux에서 라이브러리를 상대경로로 열어도 `/proc/self/maps`로 절대경로를 얻어 검증한다(`/proc`이 없거나 로드 뒤 파일이 지워지거나 교체되면 fail-closed `INTERNAL_ERROR`). 한 프로세스에 re-shield가 두 모듈(예: EXE와 플러그인)에 들어 있으면 각자 자기 레코드를 자기 이미지에서 검증하지만, ELF에서 두 복사본의 심볼이 기본 가시성으로 내보내지면 동적 링커가 한쪽으로 합칠 수 있으니 라이브러리를 `-Wl,-Bsymbolic`으로 링크한다(`make shared`는 그렇게 한다).
