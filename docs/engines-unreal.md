# Unreal Engine에서 re-shield 쓰기

English summary: an Unreal Shipping build is a monolithic EXE, so the existing EXE path (`reshield_check_json` / `reshield_verify_app` / `reshield_verify_code_section`) works as is. Compile the re-shield C sources into a game module (`examples/unreal/Reshield.Build.cs`, `bUseUnity = false`), call the check once on a worker thread in Shipping builds only, and seal the packaged `*-Win64-Shipping.exe` with `tools/reshield_release.py` after packaging. No new runtime code was written for this. **Nothing here was built or run with Unreal Engine**; see the last section.

> **Unreal Engine으로 검증하지 않았다.** 이 저장소에는 UBT/UAT 실빌드도, Shipping EXE 봉인도, 패키징 결과물 실행도 없다. `examples/unreal/Reshield.Build.cs`는 컴파일해 본 적이 없다. re-shield 쪽 사실(함수 이름, 봉인 순서, Windows `.text` 규칙, `hex_nibble` 중복)은 이 저장소의 코드·CI로 확인한 것이고, Unreal 쪽 절차는 설계와 공식 문서 열람 기준이다. 첫 적용 때 직접 확인해야 한다. 확인 못 한 항목은 맨 아래 "미검증"에 모았다.

## 왜 EXE 경로를 그대로 쓰는가

- Unreal의 Shipping 빌드는 게임 코드와 엔진 모듈을 하나의 실행 파일로 링크하는 모놀리식 빌드가 기본이다(Epic 공식 문서에서 이 문서를 쓰며 다시 확인하지는 않았다, 미확인). 그러면 re-shield를 컴파일해 넣은 모듈의 봉인 레코드도 `<Project>-Win64-Shipping.exe` 안에 들어간다. 레코드가 든 이미지 = 프로세스 EXE이므로 Unity IL2CPP/Mono 같은 라이브러리 분리가 없고, `reshield_verify_code_section()`이 EXE의 `.text` 전체를 해시한다. 게임 C++ 코드가 전부 `.text`에 있으므로 보호 범위가 넓다.
- 따라서 공유 라이브러리용 "자기 모듈 모드"([integrity-verification.md §8](integrity-verification.md#8-자기-모듈-모드-공유-라이브러리))나 `reshield.def`는 쓰지 않는다. 호출은 평소 EXE와 같다: `reshield_check_json`(평면 C 타입, 권장) 또는 `reshield_verify_app`.
- 모듈러 빌드(에디터, Development 등)에서는 레코드가 모듈 DLL로 들어갈 수 있고 그 DLL은 봉인하지 않으므로 `UNSEALED`가 나온다. 그래서 Shipping에서만 호출하고 나머지는 건너뛴다(`UE_BUILD_SHIPPING`, 미확인: 이 문서에서 컴파일하지 않았다).

## 적용 순서

### 1. 소스를 게임 모듈로

`examples/unreal/Reshield.Build.cs`를 `Source/Reshield/`에 복사하고, 같은 모듈에 re-shield를 넣는다.

```text
Source/Reshield/Reshield.Build.cs
Source/Reshield/ThirdParty/include/reshield/*.h    <- include/reshield/
Source/Reshield/Private/ThirdParty/src/*           <- src/*.c, src/*.h
```

- 새 모듈이면 `.uproject`의 `Modules`에 등록하고 모듈 클래스 선언이 필요하다(관례상 `IMPLEMENT_MODULE(FDefaultModuleImpl, Reshield)` 한 줄, 이 문서에서 컴파일하지 않았다, 미확인). 기존 게임 모듈에 같은 설정을 넣는 쪽이 더 간단할 수 있다.
- `src/*.c`는 플랫폼별 파일이 첫 줄에서 `#if`로 자기 플랫폼이 아니면 비워지므로 전부 넣어도 된다(`src/attestation_linux.c`는 `#if defined(__linux__)`, `src/integrity_windows.c`는 `#ifdef _WIN32` 등). Win64만 쓴다면 CI의 Windows 목록(`sha256`, `sha256_accel`, `integrity_common`, `integrity_windows`, `file_windows`, `manifest`, `attestation_windows`, `reshield`, `verify_app`, `save_seal`)과 같다.
- **`.c`를 UBT가 컴파일하는지는 확인하지 못했다**(포럼에 "UBT가 `.c`를 인식 못 한다/PCH 오류"라는 구버전 보고가 있다: [Compiling C (not C++) source as part of a plugin module](https://forums.unrealengine.com/t/compiling-c-not-c-source-as-part-of-a-plugin-module/70465), 현재 UE5 동작은 미확인). 안 되면 `src/X.c`마다 `#include "X.c"` 한 줄짜리 `X.cpp` 래퍼를 둔다. 이 저장소의 CI는 `src/*.c`를 C++로도 컴파일해 확인하므로(Linux·macOS는 `c++ -std=c++11 -fsyntax-only -Wpedantic -Werror`, Windows는 `cl /TP /std:c++14 /WX`) 래퍼 방식에는 근거가 있다. 단 Windows 게이트는 `save_seal.c`를 포함하지 않고, UE5가 쓰는 C++ 표준(C++20 등)과 UE의 경고 설정으로는 확인하지 않았다.
- 개발/Shipping 구분: `Reshield.Build.cs`는 Shipping이 아닐 때만 `RESHIELD_ALLOW_UNSEALED`를 켠다. Shipping은 릴리스 빌드이므로 봉인하지 않은 EXE는 `UNSEALED`로 보고된다. 개발 빌드(마커 `RESHIELD-DEV-BUILD-v1` 포함)를 봉인하려 하면 `reshield_release.py`가 종료 코드 2로 거부한다([steam-pipeline.md §1](steam-pipeline.md)).
- **`bUseUnity = false`가 필요하다.** `static int hex_nibble(char)`가 `src/attestation_windows.c:79`와 `src/manifest.c:20`에 둘 다 있다. 두 파일이 한 번역 단위로 합쳐지면(Unity 빌드) 재정의 오류가 난다(이 저장소의 CI도 `src/*.c`를 파일별로 따로 컴파일한다). `static` 함수 이름 중복은 이것 하나뿐이다(`src/*.c` 대조 결과). UE에서 실제로 Unity 빌드가 두 파일을 합치는지는 UE로 재현하지 않았지만, 끄는 비용이 작다.

### 2. 호출

Shipping에서만, 워커 스레드에서 한 번 부른다. 큰 `.text`를 해시하므로 게임 스레드에서 부르면 멈춘다(시간은 UE 빌드에서 측정하지 않았다).

```c
/* C ABI, 워커 스레드에서: UE의 스레드 풀(예: Async(EAsyncExecution::ThreadPool, ...))은
   이 문서에서 컴파일하지 않았다. */
char json[512];
int status = reshield_check_json("reshield.manifest", "../../..", json, sizeof json); /* 0 = OK */
```

- 두 경로는 **프로세스 EXE가 있는 폴더** 기준이다. 패키징한 Shipping EXE는 보통 `<Stage>/<Project>/Binaries/Win64/`에 있으므로, 에셋 루트가 `<Stage>`라면 `assets_rel`이 `../../..`가 된다. 이 레이아웃은 내 기억이고 확인하지 않았다(미확인). `reshield_check_json`은 경로를 검증하지 않고 EXE 폴더에 이어 붙이므로 `..`는 OS 규칙을 따르지만, `..`로 시작하는 `assets_rel`을 이 저장소에서 테스트하지 않았다.
- 실패 처리와 위반 시 대응 원칙은 Unity 문서와 같다. 즉시 종료하지 않고 `status`와 `json`을 로그·텔레메트리로 남긴다([engines-unity.md](engines-unity.md#위반-시-권장-대응)). `0`이 아닌 값 중 환경 문제(파일 잠금 등)는 변조 증거가 아니다.

### 3. 패키징 후 봉인

순서는 **빌드 -> strip -> manifest -> seal -> sign -> verify**이고, `tools/reshield_release.py`가 이 순서를 지킨다(strip은 ELF·Mach-O만 대상이고 PE에는 실행하지 않는다). 봉인은 바이너리를 고치므로 서명보다 먼저다. UAT `BuildCookRun`으로 스테이징·패키징을 끝낸 뒤, 스테이징 폴더에서 한 번 실행한다.

```bash
python3 tools/reshield_release.py <Stage>/<Project>/Binaries/Win64/<Project>-Win64-Shipping.exe \
    --assets <Stage> --manifest-out <Stage>/<Project>/Binaries/Win64/reshield.manifest \
    --exclude "*.pdb" --sign-cmd "signtool sign /fd sha256 /a {}"
```

- `--manifest-out`은 매니페스트 위치를 위 호출의 `manifest_rel`(EXE 폴더 기준 `reshield.manifest`)과 맞추기 위해서다. 봉인 대상 EXE는 매니페스트에서 자동 제외된다.
- `.pak`/`.ucas` 같은 큰 파일은 해시 시간과 디스크 부담이 크다. `--exclude "*.pak"`로 빼는 것을 먼저 권한다. 포함했을 때 시간은 측정하지 않았다. Unreal의 pak 서명 같은 자체 기능과의 관계는 이 문서에서 다루지 않는다(미확인).
- `--sign-cmd`의 `{}`는 봉인된 EXE 경로로 바뀌고, 어느 단계든 실패하면 0이 아닌 종료 코드로 끝나 CI 잡이 멈춘다. 서명은 `.text`를 바꾸지 않는다(CI의 "Authenticode-signed sealed EXE" 단계가 확인한다). 서명자 고정은 `leaf-sha256:` ([integrity-verification.md §7](integrity-verification.md#7-windows-pe32-x64)).
- CI/Steam 연결은 [steam-pipeline.md](steam-pipeline.md): 봉인은 `steamcmd` 직전의 마지막 단계여야 하고, 봉인 뒤에 파일을 다시 쓰는 도구(패커, 리소스 편집기, 안티 바이러스 래퍼)를 두지 않는다.
- 봉인 전에 `python3 tools/pe_probe.py <EXE>`로 `.text` 안 base relocation 개수와 봉인 가능 여부를 본다. 이 저장소가 측정한 건 MSVC 데모 한 개(`.text` 안 relocation 0개)뿐이라 UE의 Shipping EXE는 직접 확인해야 한다. `.text` 안에 relocation이 하나라도 있으면 `seal_binary.py`가 봉인을 거부한다.

## 오탐 위험

모두 실측하지 않은 추정이다. 먼저 report-only로 켜서 비율을 본다.

- **오버레이(Steam, Discord, OBS), 백신, 모드/업데이트로 섞인 파일**: [engines-unity.md의 오탐 절](engines-unity.md#오탐-위험)과 같다. 파일 잠금은 `MANIFEST_IO_ERROR`(변조 아님), 바뀐 에셋은 `ASSET_TAMPERED`다.
- **Steam DRM 래퍼(SteamStub)**: 실행 파일을 다시 쓰므로 `.text` 해시가 맞지 않을 수 있다. 봉인 -> 래핑 순서에서 오탐이 나는지 실측하지 않았다([steam-pipeline.md](steam-pipeline.md)). UE의 Steamworks 온라인 서브시스템과는 별개의 이야기다.
- **Proton/Wine**: 실행해 보지 않았다.

## 한계

- **키 없는 설계**다. 코드를 고친 공격자는 공개된 `seal_binary.py`로 다시 봉인할 수 있다. 서명자 고정(`leaf-sha256:`)은 프로세스 EXE의 서명만 본다.
- **검사 함수 호출 자체를 패치할 수 있다.** 분기 1바이트, 호출 삭제, `reshield_check_json` 본문 교체로 통과시킬 수 있다.
- 시작 시 1회 검사는 이후의 메모리 패치(Cheat Engine 등)를 보지 못한다. 해시 대상은 `.text`뿐이고 `.pak` 등 에셋은 매니페스트에 넣은 파일만 본다.
- 엔진 덤프·리버싱처럼 읽기만 하는 행위는 변조가 아니므로 막지 못한다.
- 한 줄 요약: "정직한 사용자의 깨진 설치"와 "게으른 변조"를 본다. 의지 있는 공격자는 못 막는다. 전체 한계: [integrity-verification.md](integrity-verification.md#5-한계).

## 미검증

이 PR은 문서와 템플릿뿐이고 Unreal 쪽은 아무것도 실행하지 않았다.

- `examples/unreal/Reshield.Build.cs`가 UBT에서 컴파일되는지(속성 이름은 Epic의 [Module Properties](https://dev.epicgames.com/documentation/en-us/unreal-engine/module-properties-in-unreal-engine) 페이지로 확인했지만, `Target.Configuration`/`UnrealTargetConfiguration.Shipping`은 공식 페이지로 확인하지 못했다).
- UBT가 `.c`를 컴파일하는지, 래퍼 `.cpp`가 UE5의 C++ 표준·경고 정책(예: `/W4 /WX`, C4668 등)에서 통과하는지.
- `windows.h`를 포함하는 `src/integrity_windows.c`·`src/attestation_windows.c`가 UE의 Windows 헤더 처리(매크로 충돌, 프리/포스트 Windows 헤더 래퍼)와 충돌하는지. `#pragma comment(lib)`를 UBT 링크가 따르는지.
- Shipping이 정말 모놀리식 단일 EXE인지(프로젝트·타깃 설정에 따라 다를 수 있다), 레코드가 그 EXE에 들어가는지.
- 실제 Shipping EXE의 `.text` 크기, `.text` 안 base relocation 개수, 이름이 정확히 `.text`인 섹션 하나라는 가정(`seal_binary.py` 요구), 100MB 이상일 때의 해시 시간.
- 스테이징 레이아웃(`<Stage>/<Project>/Binaries/Win64/...`), 루트 런처 EXE와 Shipping EXE의 관계, `assets_rel`이 `..`로 시작할 때의 동작, 매니페스트를 스테이징에 포함하고 depot에 올리는 방법.
- UAT 후 봉인을 `PostBuildSteps`나 UAT 스크립트로 자동화할 수 있는지(문서는 수동/CI 단계로만 적었다).
- 워커 스레드에서 호출하는 UE 코드, `UE_BUILD_SHIPPING` 가드, `IMPLEMENT_MODULE` 보일러플레이트 컴파일.
- 오탐 비율(오버레이·백신·SteamStub·Proton). macOS/Linux용 UE 패키징 경로는 다루지 않았다.
- 이 저장소에서 확인한 것은 re-shield 쪽뿐이다: Windows EXE 경로(봉인·실행·변조 탐지·서명 후 검증)는 CI `windows-msvc` 잡이 일반 MSVC 빌드 기준으로 확인한다.
