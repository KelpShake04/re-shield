[English](README.md) | 한국어

# re-shield

자사(1st-party) 네이티브 소프트웨어·게임의 **빌드 무결성(Code Integrity)**, **에셋 매니페스트 바인딩(Asset Manifest Binding)**, **실행 환경 권한·서명 검증(W^X & OS Code Signing)**을 제공하는 C11 유저스페이스 라이브러리 및 빌드 도구다.

## 목적

네이티브 애플리케이션·게임의 실행 파일이나 외부 스테이지·설정 리소스가 무단으로 변조되거나 분리 복제되는 것을 감지하고, 릴리스 파이프라인에서 아티팩트 무결성을 검증할 수 있도록 최소 침습 런타임(`libreshield.a`)과 후처리 CLI를 제공한다.

## 핵심 기능

- **코드 섹션 무결성 (`include/reshield/integrity.h`)**: 외부 의존성 없는 FIPS 180-4 SHA-256 구현으로 빌드 시 실행 파일의 코드 섹션(`__TEXT,__text` / `.text`) 해시를 기록하고 런타임에 메모리에서 재검증(macOS·Linux·Windows x64 MSVC).
- **에셋 매니페스트 바인딩 (`include/reshield/manifest.h`)**: `tools/gen_manifest.py`로 에셋 디렉터리의 SHA-256 매니페스트를 생성하고, 그 루트 해시를 바이너리에 함께 봉인해 실행 파일과 리소스 번들의 짝을 런타임에 검증.
- **메모리 W^X 및 OS 코드 서명 검증 (`include/reshield/attestation.h`)**:
  - macOS: `mach_vm_region`으로 코드 세그먼트의 W^X(읽기·실행 전용, 쓰기 금지) 확인(코드 섹션 전 범위를 영역 단위로 순회, 공백·쓰기 가능 영역은 실패) 및 `Security.framework`(`SecCodeCheckValidity`) 코드 서명 유효성 검증(기본은 서명 주체를 고정하지 않음. `cfg.codesign_requirement`에 code requirement 문자열, 예: `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`를 주면 그 서명자로 고정하고, 파싱 실패는 `CODESIGN_INVALID`로 fail-closed).
  - Linux: `/proc/self/maps`에서 `.text` 범위 전체가 `r-x` 매핑으로 덮이는지 확인.
- **구조화된 진단 리포트 (`include/reshield/reshield.h`)**: 라이브러리가 프로세스를 임의 강제 종료하지 않고 `reshield_report_t`와 콜백을 반환해 호스트 앱이 안내·로깅·안전 종료를 결정. `reshield_report_to_json()`은 리포트를 한 줄 JSON(`"v":1`)으로 직렬화한다(텔레메트리용. 클라이언트가 보낸 리포트는 위조될 수 있어 서버가 진본 증거로 쓰면 안 된다).
- **모듈 모드**: re-shield를 실행 파일 대신 공유 라이브러리(`.so`/`.dylib`/`.dll`)에 링크하면 그 라이브러리가 봉인·검사 대상 이미지가 된다. 호스트 실행 파일(엔진 등)은 re-shield 코드가 없어도 되고 봉인하지 않는다(아래 [알려진 한계](#알려진-한계)와 [docs/integrity-verification.md](docs/integrity-verification.md#8-자기-모듈-모드-공유-라이브러리) 참고).
- **strict 매니페스트 (v2)**: 에셋 폴더에 끼워 넣은 파일을 `RESHIELD_ERR_ASSET_EXTRA`(값 9)로 보고한다. `#allow` 글롭으로 세이브·로그 경로를 허용한다(아래 [strict 모드](#내-프로젝트에-적용하기)와 [docs/integrity-verification.md](docs/integrity-verification.md#10-매니페스트-v2와-strict-모드) 참고).
- **SHA-256 하드웨어 가속**: 코드 섹션·에셋 해시의 블록 압축을 CPU 명령(AArch64 SHA2, x86-64 SHA-NI)으로 처리하고, 명령이 없거나 확인하지 않은 조합이면 이식성 C로 폴백한다. 라이브러리를 `-DRESHIELD_NO_HW_SHA`로 컴파일하면 끈다. 처리량은 `make bench`로 잰다(GitHub Actions 러너: macos 1441, ubuntu 1813, windows 1582 MB/s. 로컬 Apple M1 Pro: 가속 2223 MB/s, 같은 기계의 이식성 C 220 MB/s). 조건과 측정 환경은 [docs/integrity-verification.md](docs/integrity-verification.md#9-sha-256-하드웨어-가속).
- **세이브·설정 파일 seal (`include/reshield/save_seal.h`)**: `reshield_save_tag()`/`reshield_save_verify()`가 HMAC-SHA256 태그로 캐주얼 편집·손상을 탐지한다. 키가 바이너리에 있어야 하므로 전문 공격자는 막지 못한다([docs/save-seal.md](docs/save-seal.md)).
- **엔진 바인딩**: 평면 C 함수 `reshield_check_json()`을 부르는 C# P/Invoke 바인딩(`bindings/csharp/Reshield.cs`)과 Unity 패키지 골격(`bindings/unity/com.reshield.guard`, Unity 미검증)이 있다([docs/engines-unity.md](docs/engines-unity.md)).
- **릴리스 검증 CLI (`tools/verify_release.py`)**: CI/CD 단계에서 바이너리 봉인과 매니페스트 일치를 검증하고, 정의 심볼 수는 보고만 한다(검증하지 않음). 개발 빌드 마커가 든 바이너리는 거부한다.
- **GitHub Action (`action.yml`)**: `tools/reshield_release.py`(strip, 매니페스트, 봉인, 서명, 검증)를 한 단계로 실행한다([docs/steam-pipeline.md](docs/steam-pipeline.md)).

## Non-goals / Anti-goals

- 서버 라이선스 인증, DRM 전체 시스템 (범위 밖).
- 커널 레벨 방어(안티치트 드라이버, kext/커널 모듈) — 100% 유저스페이스 구현만 유지.
- "절대 못 뚫는다"는 주장 — 로컬 실행 파일의 자체 무결성 검증은 변조 마찰을 높이고 사고성·단순 변조를 감지하기 위한 것이며, 절대 방어가 아니다.
- 정당한 개발·디버깅·프로파일링 방해 — 디버거 attach 차단(`ptrace`)을 사용하지 않으며, `-DRESHIELD_DISABLE` 및 `allow_unsealed`로 개발 빌드를 지원한다.

## 알려진 한계

자세한 목록은 [docs/integrity-verification.md](docs/integrity-verification.md#5-한계)를 따른다. 요약: 코드 검사는 봉인 레코드가 들어 있는 이미지를 본다(정적 링크면 메인 실행 파일, re-shield를 공유 라이브러리 `.so`/`.dylib`/`.dll`에 링크했으면 그 라이브러리이며 호스트 EXE는 검사하지 않고 봉인할 필요도 없다. 다른 모듈은 보지 않고, 코드 서명 검사는 항상 프로세스 EXE 기준이다. Linux에서는 라이브러리를 상대경로로 열어도 `/proc/self/maps`로 절대경로를 얻어 검증하며, `/proc`이 없거나 로드 뒤 라이브러리 파일이 지워지거나 교체되면 fail-closed다), 해시 대상은 `__TEXT,__text`/`.text`뿐이고(`__stubs`, `.plt`, `__const`, 레코드가 있는 `__DATA`는 제외), 레코드의 평문 `RSHLDCHK` 매직이 수정 지점을 노출하며, 매니페스트에 없는 추가 파일은 기본으로는 감지하지 않고(v2 strict 모드를 켜면 감지), fat/universal Mach-O는 `seal_binary.py`가 지원하지 않는다.

## 언제 쓰고, 언제 쓰지 말아야 하나

re-shield는 **변조 감지(tamper evidence)** 도구이지 변조 방지(tamper proof) 도구가 아니다. 키가 없어서 공격자가 코드를 바꾼 뒤 레코드를 다시 봉인할 수 있고, 코드 자기 해시 방식에는 "해시되는 코드"와 "실행되는 코드"를 분리하는 알려진 범용 우회가 있다(van Oorschot 외, IEEE TDSC 2005). 클라이언트가 만든 리포트는 서버가 진본 증거로 쓸 수 없다.

쓰기 좋은 경우:
- 엔진 기능 없이 C/C++로 만든 게임·앱에서, 실행 파일과 함께 배포하는 에셋 묶음이 바뀌었는지 알고 싶을 때. 엔진 비종속으로 실행 파일과 에셋 매니페스트를 짝지어 검증하는 오픈소스는 조사 범위에서 찾지 못했다(전수 조사는 아니다).
- 설치 손상, 실수, 단순 바이너리 패치를 감지해 로그·텔레메트리로 모으고, 프로세스를 죽이기 전에 오탐률부터 측정하고 싶을 때(종료하지 않는 설계).
- 외부 의존성 없이 코드를 직접 읽고 감사할 수 있는 작은 라이브러리가 필요할 때.

쓰지 말아야 하는 경우:
- 치트·크랙을 막아야 할 때: 안티치트나 상용 보호기를 검토한다.
- 서버가 신뢰할 판정이 필요할 때: 플랫폼 증명(Apple App Attest, Google Play Integrity 등)과 서버 측 검증을 쓴다.
- Windows·macOS 서명과 OS 정책(Hardened Runtime, App Control 등)이 이미 배포물을 강제하는 환경이면 그것이 더 강하다. re-shield는 OS 서명을 대체하지 않고, 봉인 뒤에 OS 서명을 얹어 함께 쓴다. macOS(requirement 문자열)와 Windows(`leaf-sha256:` leaf 인증서 해시)에서는 `cfg.codesign_requirement`로 서명자를 고정하면 "재봉인 후 다른 서명으로 재서명"하는 경로를 막는 데 도움이 된다(검증 함수 자체를 패치하는 공격은 못 막는다).

## 빠른 시작

```bash
make all
make test
make release-demo
```

그 밖의 타깃: `make shared`·`make release-shared`(모듈 모드용 공유 라이브러리), `make module-test`·`make guard-test`(둘 다 `make test`에 포함), `make csharp-test`(dotnet SDK가 있을 때), `make bench`(SHA-256 처리량), `make sanitize`(ASan+UBSan). 전체 Makefile 타깃과 CI 잡 목록: [docs/integrity-verification.md](docs/integrity-verification.md#11-도구-makefile-타깃-ci-잡).

- 아키텍처 설계 및 한계: [docs/architecture.md](docs/architecture.md)
- 코드 섹션·에셋 매니페스트 봉인 및 검증 가이드: [docs/integrity-verification.md](docs/integrity-verification.md)
- 무엇을 막고 무엇을 못 막는지 직접 실험하는 crackme 랩(자기 바이너리만 대상): [docs/crackme-lab.md](docs/crackme-lab.md)
- Unity(C# P/Invoke 바인딩, Unity 미검증 패키지 골격): [docs/engines-unity.md](docs/engines-unity.md)
- GitHub Actions로 봉인한 뒤 steamcmd로 올리기(검증하지 못한 부분 포함): [docs/steam-pipeline.md](docs/steam-pipeline.md)
- 세이브·설정 파일의 캐주얼 편집·손상 탐지(HMAC-SHA256, 전문 공격자는 못 막음): [docs/save-seal.md](docs/save-seal.md)

## 내 프로젝트에 적용하기

지원 플랫폼은 macOS(Mach-O 64), Linux(ELF64, x86-64와 aarch64), Windows x64(PE32+, MSVC)다. Linux aarch64는 CI의 네이티브 arm64 러너(`ubuntu-24.04-arm`, `uname -m`=aarch64 확인)에서 glibc(`make all test release-demo`, `ld.so ./prog` 검사)와 Alpine arm64 musl(dynamic, `-no-pie`, static, static-pie 봉인·실행)을 확인한다. aarch64에서는 `make sanitize`와 퍼저 회귀 테스트를 돌리지 않는다. Windows는 런타임 백엔드(코드 섹션 해시, `VirtualQuery` W^X 순회, `WinVerifyTrust` 코드 서명 검사)와 봉인 도구(`seal_binary.py`/`verify_release.py`의 PE 지원)가 구현되어 있다. CI(GitHub Actions `windows-latest`)의 `windows-msvc` 잡이 `cl`로 빌드한 EXE를 봉인해 실행하고, `.text` 1바이트를 바꾼 복사본이 `CODE_TAMPERED`로 탐지되는 것까지 확인한다. 코드 서명 검사는 `WinVerifyTrust` 결과에 더해 `cfg.codesign_requirement`로 서명자 leaf 인증서를 고정할 수 있다. 형식은 `leaf-sha256:<64자리 hex>`(서명 인증서 DER의 SHA-256, 대소문자 무관)이고, 다른 문자열은 `FAILED`(fail-closed)다. 서명 안 된 EXE도 `FAILED`다. CI는 일회용 자체 서명 인증서로 봉인 뒤 서명한 EXE에서 `OK`, leaf pin 일치/불일치/형식 오류를 실제로 확인한다(공인 CA·타임스탬프 서명은 검증하지 못했다). macOS와 Windows의 requirement 문법이 달라 플랫폼별로 `#ifdef` 안에서 설정한다(Linux는 코드 서명 검사가 UNSUPPORTED지만 requirement가 있으면 통과시키지 않는다). CI는 `reshield.def`로 만든 릴리스 `reshield.dll`(모듈 모드)을 미봉인 호스트 EXE가 검사하는 테스트(미봉인, 봉인 후 `OK`, 변조 탐지, `reshield_check_json` 출력 단언)와 소스의 C++ 컴파일 게이트(`cl /TP`)도 실행한다. CI는 POSIX 전용인 `tests/test_seal_workflow.py`와 `RESHIELD_DISABLE` 변형 테스트를 Windows에서 돌리지 않는다. mingw-w64는 맥/Linux에서의 크로스 컴파일·도구 테스트 전용이며, 기본 링크 EXE는 `.text` 안 relocation 1개 때문에 봉인되지 않는다(`-Wl,--disable-dynamicbase -Wl,--disable-reloc-section`으로 봉인은 되지만 ASLR이 꺼지므로 배포용으로 권장하지 않는다). mingw 빌드는 컴파일·링크만 보고 Windows에서 실행해 검증하지 않았다. Windows ARM64와 fat/universal Mach-O는 지원하지 않는다. 자세한 내용은 [docs/integrity-verification.md](docs/integrity-verification.md#7-windows-pe32-x64).

**1. 링크.** `libreshield.a`를 링크하고 `-Iinclude`를 추가한다. macOS는 `-framework Security -framework CoreFoundation`도 필요하다. `RSHLDCHK` 레코드는 `libreshield.a` 안에 있으며, 앱이 `reshield_verify()`를 호출하면 바이너리에 함께 링크된다.

```bash
make lib                      # 개발용: build/libreshield.a (릴리스용은 아래 5번)
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

에셋까지 검사한다면 `reshield_verify_app()` 한 줄이 더 간단하다. 코드와 매니페스트를 검사하고, 두 경로를 현재 디렉터리가 아니라 **실행 파일이 있는 디렉터리** 기준으로 해석하므로 런처·바로가기가 작업 디렉터리를 바꿔도 동작한다.

```c
if (reshield_verify_app("game.manifest", "assets", NULL, NULL, &report) != RESHIELD_OK) { /* 처리 */ }
```

다른 언어나 엔진 바인딩에서는 `reshield_check_json()`이 같은 검사를 평면 C 타입만으로 한다(`int` 상태값과 한 줄 JSON 리포트, 구조체를 미러링할 필요 없음).

```c
char json[512];
int status = reshield_check_json("game.manifest", "assets", json, sizeof json);  /* 0 = RESHIELD_OK */
```

두 함수 모두 경로를 라이브러리가 아니라 **프로세스 실행 파일**의 디렉터리 기준으로 해석한다. re-shield를 공유 라이브러리에 링크한 모듈 모드에서도 매니페스트와 에셋은 호스트 EXE 옆에서 찾는다. 개발용 라이브러리(`make lib`/`make shared`, `-DRESHIELD_ALLOW_UNSEALED`로 컴파일)에서는 봉인되지 않은 바이너리도 `OK`로 나오고, 릴리스 라이브러리(`ALLOW_UNSEALED=0`)는 봉인된 바이너리를 요구한다.

에셋 폴더 안의 바이너리나 빌드 부산물은 매니페스트에서 뺄 수 있다: `python3 tools/gen_manifest.py dist -o dist/game.manifest --exclude "*.pdb" --exclude "cache/*"`(상대 POSIX 경로에 대한 glob, 반복 가능). `reshield_release.py`도 같은 `--exclude`를 받고, 봉인하는 바이너리 자신은 항상 매니페스트에서 뺀다. 그래서 `reshield_release.py dist/game --assets dist`가 동작한다. 어떤 파일에도 매치되지 않는 패턴(오타, `./x`, 역슬래시 경로)은 `gen_manifest.py`가 stderr에 경고한다(종료 코드는 그대로).

매니페스트 파일을 열거나 파싱할 수 없으면(경로 오류, 파일 없음, 형식이 잘못되었거나 빈 매니페스트, 그 안의 안전하지 않은 에셋 경로) `INTERNAL_ERROR`가 아니라 `MANIFEST_IO_ERROR`(`RESHIELD_ERR_MANIFEST_IO`, 값 8)로 보고한다(경로 실수가 내부 오류로 오인되지 않도록. 이전에는 `INTERNAL_ERROR`였다). 에셋 파일이 없거나 크기·해시가 다르면 변조 판정인 `ASSET_TAMPERED`(6)다.

**strict(allowlist) 모드.** 에셋 폴더에 끼워 넣은 파일(프록시 DLL, 크랙, 모드)을 잡으려면 매니페스트를 `python3 tools/gen_manifest.py assets -o game.manifest --strict --allow "saves/*"`로 만든다(`tools/reshield_release.py`에는 `--strict --allow`를 준다). 매니페스트 맨 앞에 `#reshield-manifest v2 strict`와 `#allow` 줄이 들어가고 루트 해시와 함께 봉인된다. 런타임은 목록의 에셋을 모두 검증한 뒤 에셋 폴더를 열거해 목록에도 `#allow`에도 없는 파일·심볼릭 링크·특수 파일이 있으면 `ASSET_EXTRA`(`RESHIELD_ERR_ASSET_EXTRA`, 값 9)로 보고한다. 이름은 바이트로 비교하므로 APFS의 NFD 이름은 오탐이 될 수 있고, 에셋 폴더에 세이브를 쓰는 게임은 `#allow`가 필요하다. 바이너리와 매니페스트를 함께 재봉인하는 공격은 막지 못한다. 자세한 내용과 한계: [docs/integrity-verification.md](docs/integrity-verification.md#10-매니페스트-v2와-strict-모드). 이제 `#` 줄은 매니페스트 맨 앞(첫 항목 앞)에서만 허용된다(이전에는 어디서든 건너뛰었다).

**3. 릴리스 파이프라인(CI).** 순서가 중요하다(링크, `strip`, 봉인, 서명, 검증). 최종 실행 파일에 한 명령으로 이 순서를 실행한다(제자리 수정).

```bash
python3 tools/reshield_release.py dist/game --assets dist/assets --strip             # dist/game.manifest 생성
python3 tools/reshield_release.py dist/game --assets dist/assets --sign "Developer ID Application: Me (TEAMID)"   # macOS
python3 tools/reshield_release.py dist/game.exe --assets dist/assets --sign-cmd "signtool sign /fd sha256 /a {}"  # 임의 서명 도구
```

이미 실제 서명(Developer ID 등)이 있는 Mach-O는 거부한다. 봉인이 바이너리를 다시 쓰므로 서명이 사라지기 때문이다. 봉인 먼저, 서명은 마지막이다(`seal_binary.py`도 같은 경우를 거부하며, linker-signed·ad-hoc 바이너리는 괜찮다). 수동으로 하려면 다음과 같다.

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

**5. 개발 중, 릴리스 빌드.** 개발용과 릴리스용 라이브러리는 디렉터리가 다르다: `make lib`은 `build/libreshield.a`(개발용), `make ALLOW_UNSEALED=0 lib`은 `build/release/libreshield.a`(릴리스용)를 만든다. 서로의 오브젝트를 재사용하지 않는다. `-std=c11`, `-Iinclude`, `ALLOW_UNSEALED` 정의는 항상 적용되어 `make CFLAGS=-O0`이나 상위 make가 지울 수 없다. `-DRESHIELD_DISABLE`로 검사를 끈다. 이 매크로는 **라이브러리를 컴파일할 때** 줘야 한다(`make clean` 후 `make CFLAGS="-O2 -DRESHIELD_DISABLE"` 등). 앱 컴파일 플래그에만 넣으면 아무 효과가 없다. 디버거 중단점이 `.text`를 바꾸면 `CODE_TAMPERED`가 나므로 디버깅 중에는 꺼 둔다.

**기대치.** 설치 손상, 실수로 인한 변조, 단순한 바이너리·에셋 패치를 감지하는 용도다. 바이너리와 매니페스트를 함께 재봉인하는 공격이나 런타임 API 교체는 막지 못한다. 안티치트나 DRM 대용으로 쓰지 않는다. 중요한 판정은 서버에서 하고 클라이언트 검사 결과는 신호로만 쓴다.

## 공유 라이브러리와 C++

- `make shared`는 모듈 모드용 `build/libreshield.so`(macOS는 `build/libreshield.dylib`)를, `make release-shared`는 릴리스판(`ALLOW_UNSEALED=0`)을 `build/release/`에 만든다. Windows DLL은 `cl /LD ... /link /DEF:reshield.def`로 만들며, `reshield.def`는 엔진 바인딩에 필요한 부분집합(`reshield_verify_code_section`, `reshield_verify_code_page_wx`, `reshield_verify_app`, `reshield_check_json`, `reshield_report_to_json`, `reshield_status_name`, `reshield_platform_name`)만 export한다. POSIX 공유 라이브러리는 공개 API 전체가 보인다. 라이브러리는 `tools/seal_binary.py`로 봉인한다.
- `src/*.c`와 공개 헤더는 C++로도 컴파일된다(CI의 구문 검사 게이트: Linux·macOS는 `c++ -std=c++11 -fsyntax-only`, Windows는 `cl /TP`). C++ 오브젝트를 링크·실행하는 검증은 하지 않는다.

## 개발·테스트 빌드 옵션

- `-DRESHIELD_DISABLE`: `reshield_verify()` 등 모든 런타임 무결성 검증을 no-op으로 비활성화. 단 `reshield_verify_buffer()`는 앱 로직(예: 키 커밋먼트 비교)이므로 이 빌드에서도 실제 SHA-256 비교를 수행한다.
- `cfg.allow_unsealed = 1`: `tools/seal_binary.py`를 거치지 않은 로컬 개발 빌드 허용. 라이브러리를 `-DRESHIELD_ALLOW_UNSEALED`로 컴파일했을 때만 동작한다(저장소 Makefile 기본값, 릴리스는 `make ALLOW_UNSEALED=0 lib`로 `build/release/libreshield.a`). 매크로 없이 컴파일한 라이브러리에서 필드를 켜면 `INTERNAL_ERROR`(설정 오류)다. **경고: 매크로를 켠 빌드를 릴리스에 쓰면 sealed 바이트 변조만으로 코드·매니페스트 검사가 우회된다. 릴리스 금지.** (레코드 magic/version 불일치나 매니페스트 없이 봉인된 바이너리는 unsealed로 취급하지 않고 실패 처리한다.) **`make lib`/`make shared`의 기본값은 개발 빌드다.** 배포는 `make release-shared`(공유 라이브러리) 또는 `make ALLOW_UNSEALED=0 lib`로 하거나, 자기 빌드에서 `-DRESHIELD_ALLOW_UNSEALED`를 빼고 컴파일한다. 개발 빌드에는 마커 `RESHIELD-DEV-BUILD-v1`이 들어 있고 릴리스 빌드에는 절대 없다. `tools/reshield_release.py`와 `tools/verify_release.py`는 이 마커가 있는 바이너리를 거부한다(종료 코드 2, 파일을 바꾸기 전에 검사). `--allow-dev-build`(action 입력 `allow-dev-build`)는 데모·CI 전용 우회 옵션이다. `tools/seal_binary.py`는 검사하지 않는다(테스트와 데모가 개발 빌드를 직접 봉인한다). 한계: 마커는 실수로 개발 빌드를 배포하는 것을 막는 장치이지 방어가 아니다. 개발 빌드를 손에 넣은 공격자는 마커를 지울 수 있다(sealed 바이트와 함께). 이를 막는 것은 릴리스 빌드뿐이다.
