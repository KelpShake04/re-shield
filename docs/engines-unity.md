# Unity에서 re-shield 쓰기

English summary: a C# P/Invoke binding (`bindings/csharp/Reshield.cs`) and an untested Unity package skeleton (`bindings/unity/com.reshield.guard`) call the flat `reshield_check_json` once at startup, on a worker thread, and report the result without ever quitting the game.

> **Unity 에디터에서 검증하지 않았다.** `Reshield.cs`는 dotnet 콘솔 테스트(`make csharp-test`: macOS arm64, Linux amd64 컨테이너)로 실제 라이브러리를 불러 확인했다. `ReshieldGuard.cs`와 UPM 패키지 골격, IL2CPP 소스 플러그인 경로는 Unity에서 컴파일도 실행도 하지 않았다. 아래 Unity 쪽 절차는 설계와 문서 기준이며, 첫 적용 때 직접 확인해야 한다.

## 10분 적용

### 1. 플러그인 배치

`bindings/unity/com.reshield.guard/`를 프로젝트의 `Packages/`에 복사하거나 Package Manager의 "Add package from disk"로 `package.json`을 지정한다. 네이티브 라이브러리는 이 저장소에서 직접 빌드한다(릴리스 빌드 = `make release-shared`, Windows는 `cl /LD`와 `reshield.def`). 어디에 어떻게 넣는지는 [`Runtime/Plugins/README.md`](../bindings/unity/com.reshield.guard/Runtime/Plugins/README.md)에 있다: Windows x64 `reshield.dll`, macOS `libreshield.dylib`, Linux `libreshield.so`. IL2CPP는 미리 빌드한 라이브러리 대신 C 소스를 소스 플러그인으로 넣고 스크립팅 정의 심볼 `RESHIELD_INTERNAL`을 추가한다.

### 2. 릴리스 빌드 후 `reshield_release.py`

플레이어를 평소처럼 빌드한 다음, 최종 결과물 폴더에서 한 번 실행한다(봉인은 바이너리를 고치므로 서명보다 먼저, 스크립트가 순서를 지킨다).

```bash
# IL2CPP (Windows 예): GameAssembly.dll을 봉인
python3 tools/reshield_release.py Build/GameAssembly.dll --assets Build \
    --manifest-out Build/reshield.manifest --exclude "*.pdb" \
    --exclude "*_BackUpThisFolder_ButDontShipItWithYourGame/*" \
    --exclude "*_BurstDebugInformation_DoNotShip/*"

# Mono: 플러그인 라이브러리를 봉인하고 Managed/*.dll은 매니페스트로 묶는다
python3 tools/reshield_release.py Build/Game_Data/Plugins/x86_64/reshield.dll --assets Build \
    --manifest-out Build/reshield.manifest
```

`--manifest-out`을 쓰는 이유: 매니페스트 위치를 `manifestPath`(실행 파일 폴더 기준 상대 경로)와 맞추기 위해서다. 큰 에셋(`*.assets`, `*.resS`, `StreamingAssets/**`)은 해시 시간과 디스크 부담 때문에 `--exclude`로 빼는 편이 좋다. 사전 요구는 Python 3이다.

### 3. 첫 호출

씬에 빈 GameObject를 만들고 `ReshieldGuard`를 붙인다. 매니페스트를 쓰면 `manifestPath = reshield.manifest`, `assetsPath = .`(없으면 코드 검사만). 코드에서 쓰려면:

```csharp
// 반드시 워커 스레드에서: 큰 GameAssembly는 0.1~0.5초쯤 블로킹된다
var r = await System.Threading.Tasks.Task.Run(() => Reshield.Guard.Check("reshield.manifest", "."));
if (!r.Ok) Debug.LogWarning($"[re-shield] {r.StatusName} {r.Json}");
```

`Check()`는 예외를 던지지 않는다. 라이브러리를 못 찾거나 진입점이 없으면 `Status = -1`(`MODULE_NOT_FOUND`)을 돌려준다. 이것은 변조 증거가 아니라 배포·환경 문제이므로 런타임에서는 fail-open이다: 게임은 계속하고 `verified=false`로 기록한다. 반대로 빌드 단계의 실패(봉인 거부, `verify_release.py` 실패)는 fail-closed로 빌드를 멈춘다. 에디터와 개발 빌드는 봉인되지 않았으므로 `ReshieldGuard`가 기본으로 건너뛴다.

## Mono vs IL2CPP

| | IL2CPP (권장) | Mono |
|---|---|---|
| re-shield 위치 | C 소스 플러그인으로 `GameAssembly`에 컴파일 | 미리 빌드한 `reshield` 라이브러리 |
| 메모리(.text) 검사 대상 | `GameAssembly`의 `.text` | 플러그인 자신의 `.text`뿐 |
| 게임 코드 보호 | 게임 C#이 네이티브 코드가 되어 `.text`에 들어간다 | **해당 없음** |
| 디스크 검사 | 매니페스트(EXE, `UnityPlayer.dll`, `global-metadata.dat` 등) | 매니페스트(`Managed/Assembly-CSharp.dll` 포함) |

Mono의 `Assembly-CSharp.dll`은 IL(관리 코드)이고 JIT가 메모리에서 기계어로 바꾼다. re-shield의 코드 검사는 봉인된 이미지의 `.text`를 해시하므로 이 IL은 메모리 검사 대상이 아니다. 따라서 Mono에서 게임 로직 변조(예: dnSpy로 C# 수정)를 보려면 **디스크의 매니페스트 해시**에 의존해야 한다. 이 검사는 파일을 고치고 같은 위치에 둔 경우만 본다. 플러그인 라이브러리 자체를 "항상 0을 반환"하는 스텁으로 바꾸는 것도 막지 못한다(IL2CPP 소스 플러그인 쪽이 낫다). IL2CPP 경로는 이 저장소에서 Unity로 빌드해 확인하지 않았다.

## 오탐 위험

모두 실측하지 않은 추정이다. 먼저 report-only로 켜서 비율을 본 뒤에 판단한다.

- **Steam 오버레이, Discord/OBS 오버레이**: 보통 그래픽·입력 시스템 DLL을 훅하고 게임 모듈의 `.text`는 건드리지 않는다. 낮은 위험이지만 오버레이 켬/끔별로 비율을 보는 것이 좋다.
- **백신**: 파일을 잠그면 매니페스트 읽기가 `MANIFEST_IO_ERROR`가 된다(변조 아님, fail-open으로 처리). 격리·삭제는 진짜 파일 손상이다.
- **Proton/Wine(Steam Deck)**: 메모리 보호 비트, 섹션 매핑, 코드 서명 API 동작이 Windows와 다를 수 있다. 이 저장소는 Proton에서 실행해 보지 않았다. Wine에서 `PAGE_PERMISSIONS`나 `CODESIGN_INVALID`가 나오면 변조가 아니라 환경 차이일 수 있다.
- **Steam 업데이트 중단, 모드 로더(BepInEx 등)**: 섞인 버전이나 하드 패치된 `Managed/*.dll`은 `ASSET_TAMPERED`로 잡힌다(진짜 불일치지만 정상 사용자가 고의로 한 것일 수 있다).

## 위반 시 권장 대응

- **즉시 종료는 권하지 않는다.** 오탐이면 환불·부정 리뷰로 이어지고, 변조자는 종료 호출만 패치하면 된다. 지연 크래시도 정상 사용자가 원인을 모르는 버그로 겪으므로 같다.
- 온라인 게임: 세션에 **조용히 표식**을 남기고 **서버가 판단**한다(랭크·리더보드 제외, 별도 큐). 클라이언트 리포트 하나만으로 영구 정지하지 않는다. 리포트는 클라이언트가 만든 주장이라 서버가 증거로 믿을 수 없다.
- 오프라인 싱글: 아무것도 하지 않거나 `ASSET_TAMPERED`일 때만 비차단 안내("Steam > 속성 > 설치된 파일 > 게임 파일 무결성 확인").
- `OnResult` 이벤트로 `StatusName`과 `Json`을 텔레메트리에 보내는 것까지만 패키지가 한다.

## 한계

- **키 없는 설계**다. 코드를 고친 공격자는 공개된 `seal_binary.py`로 다시 봉인할 수 있다. 서명자 고정(macOS requirement, Windows `leaf-sha256:`)은 프로세스 EXE만 본다.
- **검증 호출 자체를 패치할 수 있다.** IL2CPP에서는 분기 1바이트, Mono에서는 dnSpy로 호출 삭제, 플러그인 교체로 통과시킬 수 있다.
- 시작 시 1회 검사는 이후의 메모리 패치(Cheat Engine 등)를 보지 못한다.
- 읽기만 하는 에셋 추출·리버싱(Il2CppDumper 등)은 변조가 아니므로 막지 못한다.
- 한 줄 요약: "정직한 사용자의 깨진 설치"와 "게으른 변조"를 본다. 의지 있는 공격자는 못 막는다. 전체 한계: [integrity-verification.md](integrity-verification.md#5-한계).
