**UNTESTED in Unity: 이 골격은 Unity 에디터에서 검증되지 않았다.** (This skeleton has never been compiled or run in a Unity Editor.) Only `Runtime/Reshield.cs` is compile-checked and exercised, with plain `dotnet` (`make csharp-test`). `ReshieldGuard.cs`, the `.asmdef` and `package.json` are unverified.

# com.reshield.guard

re-shield 시작 시 무결성 검사를 Unity에서 부르는 UPM 패키지 골격. 기본값은 report-only(결과를 로그와 `OnResult` 이벤트로만 알림)이고 게임을 종료하는 코드는 없다.

- `Runtime/Reshield.cs`: P/Invoke 바인딩. `bindings/csharp/Reshield.cs`의 사본이다(`make csharp-test`가 두 파일이 같은지 확인한다. 고칠 때는 원본을 고치고 복사한다).
- `Runtime/ReshieldGuard.cs`: `MonoBehaviour`. `Start`에서 백그라운드 스레드로 검사하고 메인 스레드에서 `OnResult`를 호출한다. 에디터·개발 빌드는 기본으로 건너뛴다.
- `Runtime/Plugins/README.md`: 네이티브 플러그인 배치(Mono는 미리 빌드한 라이브러리, IL2CPP는 C 소스 + `RESHIELD_INTERNAL`).
- 빌드 후 봉인 훅(`Editor/`)은 아직 없다. 빌드 뒤 `tools/reshield_release.py`를 직접 호출한다.

사용: 씬의 빈 GameObject에 `ReshieldGuard`를 붙이고, 매니페스트를 쓰면 `manifestPath`/`assetsPath`(실행 파일 폴더 기준 상대 경로)를 채운다. 단계별 안내와 한계: [docs/engines-unity.md](../../../docs/engines-unity.md).
