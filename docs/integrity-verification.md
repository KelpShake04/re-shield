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
python3 tools/verify_release.py build/sample_game_sealed \
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

- `cfg.allow_unsealed = 1`은 런타임 필드라서 릴리스 빌드에서도 켤 수 있다. **릴리스 빌드에서 켜면 레코드의 sealed 바이트를 0으로 바꾸는 변조만으로 코드·매니페스트 검사가 우회된다. 릴리스 금지.**
- UNSEALED 판정은 레코드가 유효(magic·version 일치, 플래그 0/1)하고 `sealed == 0`일 때만 내려진다. 유효하지 않은 레코드는 `CODE_TAMPERED`, 매니페스트 검사 경로에서 sealed이지만 매니페스트 루트가 없는 바이너리는 `MANIFEST_MISMATCH`로 처리되어 `allow_unsealed`로 통과하지 못한다.
- `-DRESHIELD_DISABLE`에서도 `reshield_verify_buffer()`는 실제 해시 비교를 수행한다(앱 로직이며 무결성 검사가 아님).

## 5. 한계

- 로컬 바이너리의 자체 무결성 검증은 바이너리와 매니페스트가 동시에 재봉인되거나 런타임 API가 교체될 경우 우회될 수 있다.
- macOS 코드 서명 검증(`RESHIELD_CHECK_CODESIGN`)은 `SecCodeCheckValidity`를 requirement `NULL`로 호출해 서명 유효성만 확인하며, 서명 주체(Developer ID/Team ID)는 고정하지 않는다. ad-hoc 서명이나 다른 주체의 유효한 서명으로 재서명한 바이너리도 이 검사는 통과한다.
- 해시 대상은 `__TEXT,__text`(macOS) 또는 `.text`(Linux)뿐이다. `__stubs`, `.plt`, `__const`, 그리고 레코드가 놓이는 `__DATA`는 해시 대상이 아니다.
- 레코드는 평문 `RSHLDCHK` 매직으로 시작하므로 바이너리에서 문자열 검색만으로 수정 지점이 드러난다(`seal_binary.py`도 같은 방식으로 찾는다).
- 소프트웨어 breakpoint는 코드 바이트를 패치하므로, 설치된 상태에서 검사하면 `CODE_TAMPERED`로 보고된다.
- 매니페스트는 목록에 있는 파일만 검증한다. 매니페스트에 없는 추가 파일은 감지하지 못한다.
- fat/universal Mach-O는 `seal_binary.py`가 지원하지 않는다(오류로 종료). 슬라이스별로 봉인해야 한다.
- `verify_release.py`의 `defined_symbols`는 `nm` 결과를 보고할 뿐 검증하지 않는다.

## 6. 매니페스트 형식 규칙 (C 런타임과 Python 도구 공통)

- 매니페스트는 한 번만 읽어(최대 4 MiB, 일반 파일만) 같은 버퍼로 루트 해시를 계산하고 파싱한다. 해시 후 재오픈하지 않는다.
- 1023자를 넘는 줄, CR(`\r`, CRLF 포함)·NUL이 있는 매니페스트, 잘못된 줄은 `IO_ERROR`다. 항목이 하나도 없는 매니페스트도 `IO_ERROR`다.
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
