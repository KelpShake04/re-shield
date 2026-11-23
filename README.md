# re-shield

자사(1st-party) 네이티브 소프트웨어·게임의 **빌드 무결성(Code Integrity)**, **에셋 매니페스트 바인딩(Asset Manifest Binding)**, **실행 환경 권한·서명 검증(W^X & OS Code Signing)**을 제공하는 C11 유저스페이스 라이브러리 및 빌드 도구다.

## 목적

네이티브 애플리케이션·게임의 실행 파일이나 외부 스테이지·설정 리소스가 무단으로 변조되거나 분리 복제되는 것을 감지하고, 릴리스 파이프라인에서 아티팩트 무결성을 검증할 수 있도록 최소 침습 런타임(`libreshield.a`)과 후처리 CLI를 제공한다.

## 핵심 기능

- **코드 섹션 무결성 (`include/reshield/integrity.h`)**: 외부 의존성 없는 FIPS 180-4 SHA-256 구현으로 빌드 시 실행 파일의 코드 섹션(`__TEXT,__text` / `.text`) 해시를 기록하고 런타임에 메모리에서 재검증(macOS·Linux). Windows PE의 `.text`는 봉인 도구만 지원한다(런타임 검증 미구현).
- **에셋 매니페스트 바인딩 (`include/reshield/manifest.h`)**: `tools/gen_manifest.py`로 에셋 디렉터리의 SHA-256 매니페스트를 생성하고, 그 루트 해시를 바이너리에 함께 봉인해 실행 파일과 리소스 번들의 짝을 런타임에 검증.
- **메모리 W^X 및 OS 코드 서명 검증 (`include/reshield/attestation.h`)**:
  - macOS: `mach_vm_region`으로 코드 세그먼트의 W^X(읽기·실행 전용, 쓰기 금지) 확인(코드 섹션 전 범위를 영역 단위로 순회, 공백·쓰기 가능 영역은 실패) 및 `Security.framework`(`SecCodeCheckValidity`) 코드 서명 유효성 검증(기본은 서명 주체를 고정하지 않음. `cfg.codesign_requirement`에 code requirement 문자열, 예: `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`를 주면 그 서명자로 고정하고, 파싱 실패는 `CODESIGN_INVALID`로 fail-closed).
  - Linux: `/proc/self/maps`에서 `.text` 범위 전체가 `r-x` 매핑으로 덮이는지 확인.
- **구조화된 진단 리포트 (`include/reshield/reshield.h`)**: 라이브러리가 프로세스를 임의 강제 종료하지 않고 `reshield_report_t`와 콜백을 반환해 호스트 앱이 안내·로깅·안전 종료를 결정.
- **릴리스 검증 CLI (`tools/verify_release.py`)**: CI/CD 단계에서 바이너리 봉인과 매니페스트 일치를 검증하고, 정의 심볼 수는 보고만 한다(검증하지 않음).

## Non-goals / Anti-goals

- 서버 라이선스 인증, DRM 전체 시스템 (범위 밖).
- 커널 레벨 방어(안티치트 드라이버, kext/커널 모듈) — 100% 유저스페이스 구현만 유지.
- "절대 못 뚫는다"는 주장 — 로컬 실행 파일의 자체 무결성 검증은 변조 마찰을 높이고 사고성·단순 변조를 감지하기 위한 것이며, 절대 방어가 아니다.
- 정당한 개발·디버깅·프로파일링 방해 — 디버거 attach 차단(`ptrace`)을 사용하지 않으며, `-DRESHIELD_DISABLE` 및 `allow_unsealed`로 개발 빌드를 지원한다.

## 알려진 한계

자세한 목록은 [docs/integrity-verification.md](docs/integrity-verification.md#5-한계)를 따른다. 요약: 해시 대상은 `__TEXT,__text`/`.text`뿐이고(`__stubs`, `.plt`, `__const`, 레코드가 있는 `__DATA`는 제외), 레코드의 평문 `RSHLDCHK` 매직이 수정 지점을 노출하며, 매니페스트에 없는 추가 파일은 감지하지 않고, fat/universal Mach-O는 `seal_binary.py`가 지원하지 않는다.

## 빠른 시작

```bash
make all
make test
make release-demo
```

- 아키텍처 설계 및 한계: [docs/architecture.md](docs/architecture.md)
- 코드 섹션·에셋 매니페스트 봉인 및 검증 가이드: [docs/integrity-verification.md](docs/integrity-verification.md)

## 내 프로젝트에 적용하기

지원 플랫폼은 macOS(Mach-O 64)와 Linux(ELF64)다. Windows(PE32+ x64)는 빌드·봉인 도구까지 준비되어 있고(`seal_binary.py`/`verify_release.py`의 PE 지원), 정식 지원 대상은 MSVC 빌드이지만 MSVC EXE의 `.text` base relocation 여부를 CI(Windows 러너)에서 측정 중이라 "지원 예정, 미검증"이다. mingw-w64는 맥/Linux에서의 크로스 컴파일·도구 테스트 전용이며, 기본 링크 EXE는 `.text` 안 relocation 1개 때문에 봉인되지 않는다(`-Wl,--disable-dynamicbase -Wl,--disable-reloc-section`으로 봉인은 되지만 ASLR이 꺼지므로 배포용으로 권장하지 않는다). 런타임 검증(코드 섹션 해시·W^X·코드 서명)은 아직 구현되지 않았다. Windows에서 `reshield_verify()`의 코드 섹션 검사는 `INTERNAL_ERROR`가 되며, 이 저장소에서는 Windows 실행을 검증하지 못했다(컴파일·링크와 봉인 도구 테스트만 확인). Windows ARM64와 fat/universal Mach-O는 지원하지 않는다. 자세한 내용은 [docs/integrity-verification.md](docs/integrity-verification.md#7-windows-pe32-x64-봉인-런타임-미구현).

**1. 링크.** `libreshield.a`를 링크하고 `-Iinclude`를 추가한다. macOS는 `-framework Security -framework CoreFoundation`도 필요하다. `RSHLDCHK` 레코드는 `libreshield.a` 안에 있으며, 앱이 `reshield_verify()`를 호출하면 바이너리에 함께 링크된다.

```bash
make build/libreshield.a
cc game.c build/libreshield.a -Iinclude -o game -framework Security -framework CoreFoundation  # 프레임워크는 macOS만
```

**2. 시작 시 검증.** 라이브러리는 프로세스를 종료하지 않는다. 실패 시 반응(종료, 경고, 온라인 기능 차단)은 앱이 정한다.

```c
#include "reshield/reshield.h"

reshield_config_t cfg = reshield_default_config();
cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;   // 에셋 검증을 쓸 때
cfg.manifest_path  = "game.manifest";
cfg.asset_base_dir = "assets";
cfg.on_violation   = my_report_cb;               // 로그·텔레메트리용(선택)

reshield_report_t report;
if (reshield_verify(&cfg, &report) != RESHIELD_OK) {
    // report.status, report.failed_checks, report.failed_asset_path 참고
}
```

**3. 릴리스 파이프라인(CI).** 순서가 중요하다.

```bash
python3 tools/gen_manifest.py assets -o build/game.manifest
strip build/game                                    # 봉인 전에 strip
python3 tools/seal_binary.py build/game --manifest build/game.manifest --build-id "$BUILD_NUMBER"
python3 tools/verify_release.py build/game --manifest build/game.manifest --assets assets
```

- 봉인은 마지막 링크·`strip` 뒤에 한다. 이후 코드 섹션을 바꾸는 단계(패커, 난독화, 재링크)가 있으면 해시가 어긋난다.
- macOS에서 `seal_binary.py`는 ad-hoc 서명을 적용한다. 배포용이면 봉인 뒤에 Developer ID로 다시 서명한다. 서명은 `__text` 해시에 영향을 주지 않는다.
- 매니페스트 파일도 함께 배포한다. 루트 해시가 바이너리에 봉인되어 있어, 매니페스트를 바꾸면 `MANIFEST_MISMATCH`가 난다.

**4. 에셋 로딩.** 검증한 뒤 같은 경로를 다시 열면 그 사이 파일이 바뀔 수 있다(TOCTOU). 파일을 메모리로 읽고 `reshield_verify_buffer()`로 검증한 뒤 그 버퍼를 사용한다. `reshield_verify_single_asset()`도 경로 기반이라 같은 한계가 있다.

**5. 개발 중.** `-DRESHIELD_DISABLE`로 검사를 끈다. 디버거 중단점이 `.text`를 바꾸면 `CODE_TAMPERED`가 나므로 디버깅 중에는 꺼 둔다.

**기대치.** 설치 손상, 실수로 인한 변조, 단순한 바이너리·에셋 패치를 감지하는 용도다. 바이너리와 매니페스트를 함께 재봉인하는 공격이나 런타임 API 교체는 막지 못한다. 안티치트나 DRM 대용으로 쓰지 않는다. 중요한 판정은 서버에서 하고 클라이언트 검사 결과는 신호로만 쓴다.

## 개발·테스트 빌드 옵션

- `-DRESHIELD_DISABLE`: `reshield_verify()` 등 모든 런타임 무결성 검증을 no-op으로 비활성화. 단 `reshield_verify_buffer()`는 앱 로직(예: 키 커밋먼트 비교)이므로 이 빌드에서도 실제 SHA-256 비교를 수행한다.
- `cfg.allow_unsealed = 1`: `tools/seal_binary.py`를 거치지 않은 로컬 개발 빌드 허용. **경고: 릴리스 빌드에서 켜면 sealed 바이트 변조만으로 코드·매니페스트 검사가 우회된다. 릴리스 금지.** (레코드 magic/version 불일치나 매니페스트 없이 봉인된 바이너리는 unsealed로 취급하지 않고 실패 처리한다.)
