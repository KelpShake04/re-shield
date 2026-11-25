# Steam 파이프라인: GitHub Actions로 봉인하고 steamcmd로 올리기

English summary: seal the final build with the composite action (`action.yml`, wraps `tools/reshield_release.py`) right before `steamcmd +run_app_build`, and let nothing rewrite the files afterwards. Steam's DRM wrapper (SteamStub / `drm_wrap`) interaction and the `steamcmd` upload itself were **not tested**.

## 1. 권장 순서

```text
엔진 빌드 -> (staging 폴더에 올릴 파일만 복사) -> strip -> reshield_release(매니페스트 + 봉인 + verify) -> (OS 서명) -> steamcmd +run_app_build
```

- 봉인은 **steamcmd 직전**에 한다. SteamPipe에는 업로드 전에 끼울 후처리 훅이 없으므로, 업로드 폴더(depot의 `contentroot`)를 만드는 마지막 CI 단계가 봉인이어야 한다.
- 봉인 뒤에 파일을 다시 쓰는 도구는 두지 않는다. 봉인 후 strip, UPX 같은 패커, 리소스 편집기, 버전 정보 도구, 안티 바이러스 래퍼는 코드 해시 또는 에셋 해시를 깨뜨린다. 서명은 예외로 봉인 뒤에 한다(코드 섹션만 해시하므로 서명이 해시를 바꾸지 않는다. `--sign`/`--sign-cmd`가 이 순서를 지킨다).
- 이미 실제 서명이 들어간 Mach-O는 `reshield_release.py`가 거부한다(봉인 먼저, 서명은 나중).
- **개발 빌드는 거부된다.** `make lib`/`make shared`의 기본값은 개발 빌드(`RESHIELD_ALLOW_UNSEALED`)이고, 그대로 배포하면 레코드의 sealed 바이트 하나를 0으로 바꾸는 것만으로 코드·매니페스트 검사가 통과한다. 배포용 re-shield는 `make release-shared` 또는 `make ALLOW_UNSEALED=0 lib`로 만들거나, 자기 빌드에서 `-DRESHIELD_ALLOW_UNSEALED`를 뺀다. 개발 빌드에만 들어 있는 마커(`RESHIELD-DEV-BUILD-v1`)가 바이너리에서 발견되면 `reshield_release.py`와 `verify_release.py`(그리고 action)는 종료 코드 2로 거부하고, `reshield_release.py`는 파일을 바꾸기 전에 멈춘다. `--allow-dev-build`(action 입력 `allow-dev-build: "true"`)는 데모·CI 전용이고 쓰면 경고가 나온다. 한계: 마커는 배포 실수를 막는 장치이지 방어가 아니다. 공격자가 마커를 지우는 것은 막지 못한다([integrity-verification.md](integrity-verification.md#4-개발-옵션과-경고)).
- `tools/reshield_release.py`의 단계: strip, `gen_manifest.py`, `seal_binary.py`, 서명, `verify_release.py`. 어느 하나라도 실패하면 0이 아닌 종료 코드로 끝나므로 잡이 실패하고 업로드 단계로 넘어가지 않는다.

## 2. GitHub Actions 예제

이 저장소의 루트 `action.yml`은 composite action이다. 호출한 사용자의 워크플로가 이 저장소를 체크아웃하지 않아도 `github.action_path`로 `tools/`를 찾는다.

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh                        # 직접 만든 빌드. 결과를 dist/ 에 둔다고 가정

      - name: Seal
        id: seal
        uses: KelpShake04/re-shield@main       # 권장: 검토한 커밋 SHA로 고정
        with:
          binary: dist/game
          assets: dist/data
          exclude: |
            *.pdb
            debug/*
          strip: "true"
          # build-id 기본값은 github.run_number

      - name: Upload with steamcmd
        env:
          STEAM_USER: ${{ secrets.STEAM_USER }}      # re-shield 단계에는 시크릿이 필요 없다
        run: ./upload.sh                             # 아래 3절의 steamcmd 호출
```

- **참조 고정**: `action.yml`은 아직 릴리스(태그)에 들어 있지 않다. 그래서 위 예제는 `@main`이지만, 공급망 안전을 위해 검토한 커밋 **SHA 고정을 권장**한다. 태그가 생기기 전까지 `@v...` 형태는 쓸 수 없다.
- 입력: `binary`(필수), `assets`, `exclude`(줄바꿈 구분 glob), `build-id`, `strip`, `sign-cmd`, `sign`(macOS identity), `python`(기본 `python3`), `allow-dev-build`(기본 `"false"`, 개발 빌드 거부를 푸는 데모·CI 전용 스위치. 1절 참고).
- 출력: `manifest`(생성된 매니페스트 경로, `assets`가 없으면 빈 값), `build-id`.
- 모든 입력은 환경 변수로 스크립트에 전달한다(`${{ inputs.* }}`를 셸 스크립트에 직접 끼우지 않는다). `sign-cmd`는 셸을 거치지 않고 POSIX 셸 규칙으로 쪼개 실행하므로 Windows 경로는 슬래시로 쓴다.
- 매니페스트는 기본적으로 `<binary 폴더>/<binary 이름>.manifest`에 생기고, 런타임은 `reshield_verify_app("game.manifest", "data", ...)`처럼 실행 파일 폴더 기준으로 찾는다. **매니페스트도 depot에 들어가야 한다.**
- 이 저장소의 CI(`action-test` 잡, Linux·macOS, 그리고 `windows-msvc` 잡의 한 단계)가 이 action을 `uses: ./`로 실제로 호출해 샘플 게임을 봉인하고 실행한 뒤, 에셋 1바이트 변조를 거부하는지 확인한다. 그 샘플은 개발 빌드라서 `allow-dev-build: "true"`로 봉인하고, 같은 잡이 이 입력이 없을 때 action이 실패하고 파일을 건드리지 않는지도 확인한다. 이는 sample_game 기준이며 실제 게임이나 steamcmd까지의 검증은 아니다.

## 3. steamcmd `run_app_build` 예

Steamworks 문서의 일반적인 형태를 옮긴 **예시**다. 이 문서를 쓰는 동안 steamcmd를 실행하지 않았고 Steam 계정도 쓰지 않았다. 필드 이름과 동작은 Steamworks SteamPipe 문서로 확인한다.

`app_build_1234.vdf`:

```text
"appbuild"
{
  "appid"       "1234"
  "desc"        "reshield build_id=42"     // 6절 참고: 매핑용 메모
  "buildoutput" "./output"
  "contentroot" "./"
  "depots"
  {
    "1235" "depot_build_1235.vdf"
  }
}
```

`depot_build_1235.vdf`:

```text
"DepotBuildConfig"
{
  "DepotID" "1235"
  "contentroot" "./dist"
  "FileMapping"
  {
    "LocalPath" "*"
    "DepotPath" "."
    "recursive" "1"
  }
  "FileExclusion" "*.pdb"
}
```

```bash
steamcmd +login "$STEAM_USER" +run_app_build "$PWD/app_build_1234.vdf" +quit
```

### 매니페스트와 depot 제외 목록은 일치해야 한다

런타임은 매니페스트에 적힌 파일이 **디스크에 있는지** 확인한다(없거나 해시가 다르면 에셋 불일치, 즉 `ASSET_TAMPERED`로 보고된다). 그래서 depot에서 `FileExclusion`으로 빠지는 파일이 매니페스트에 들어 있으면, 플레이어 PC에서 "파일 없음" 오탐이 난다. 반대로 매니페스트에 없는 추가 파일은 감지하지 않는다.

- 가장 안전한 방법(권장): staging 폴더에 **실제로 올릴 파일만** 복사한 뒤 그 폴더를 `assets`와 depot `contentroot`로 쓴다. 이러면 `exclude`가 필요 없고 두 목록이 어긋날 수 없다.
- `exclude`를 쓸 때: `gen_manifest.py`는 상대 POSIX 경로에 `fnmatch.fnmatchcase`(대소문자 구분, `*`가 `/`도 매칭)를 쓴다. Steam `FileExclusion`의 패턴 문법이 이와 같은지는 **확인하지 못했다**. 같은 문자열을 양쪽에 넣었다고 같은 파일 집합이 된다고 가정하지 말고, 첫 업로드 뒤 depot 파일 목록과 매니페스트를 대조해 본다. 어떤 파일에도 매치되지 않는 `--exclude` 패턴(오타, `./x`, 역슬래시 경로)은 `gen_manifest.py`가 stderr에 경고한다(종료 코드는 그대로이므로 CI 로그를 확인한다).
- `steam_appid.txt`: 개발용으로 Steam이 읽는 파일이다. 배포 빌드에 넣지 않기를 **권장**한다(Steam 경유 실행 확인을 무력화할 수 있다는 것이 Valve 문서의 경고로 알려져 있다). `verify_release.py`는 이 파일이 실행 파일 폴더, `--assets`, 매니페스트 항목에 있으면 경고를 출력한다. 경고는 종료 코드를 바꾸지 않으므로, 막으려면 CI에서 로그를 보거나 staging에서 직접 제외한다.

## 4. 빌드 ID

- re-shield의 `build_id`는 봉인할 때 32비트 정수(0..4294967295)로 바이너리에 들어간다. action 기본값은 `github.run_number`다. `github.run_id`는 2^32를 넘을 수 있어 쓰지 않는다.
- **Steam BuildID는 업로드한 뒤에야 알 수 있다.** 봉인 시점에는 Steam이 아직 번호를 주지 않았으므로, 두 값을 같게 만들 수 없다.
- 그래서 CI run number로 봉인하고, app build VDF의 `desc`에 `reshield build_id=<N>`을 적어 Steamworks 빌드 목록에서 바로 대응이 보이게 한다(`desc`는 내부 설명 필드로 알고 있으나 형식 제한은 확인하지 못했다). 업로드 뒤 Steam BuildID를 CI가 기록할 수 있으면 `(depot, steam_buildid) -> (build_id, 매니페스트 해시)` 매핑표를 아티팩트로 남긴다. steamcmd 출력에서 BuildID를 읽는 정확한 방법은 확인하지 못했다.
- depot(OS)과 베타 브랜치마다 바이너리가 다르므로 매핑표 키에 depot을 포함한다.

## 5. 오탐 위험

- 봉인이 매니페스트 항목과 어긋나는 모든 변경은 위반으로 보고된다. Steam 클라이언트는 업데이트 때 파일을 교체하지만, 플레이어가 모드를 넣거나 에셋을 편집해도 같은 결과다. 처음에는 **report-only**로 시작해 오탐률을 보고 단계를 올리기를 권장한다.
- 봉인 후 파일을 다시 쓰는 도구(1절)가 파이프라인에 있으면 항상 실패한다. 업로드 직전에 `verify_release.py`를 다시 돌려 보는 것이 가장 싸다.
- 다른 폴더 구조(런처, 심볼릭 링크)와 Proton 같은 비정상 환경의 동작은 이 저장소에서 검증하지 않았다.

## 6. 검증하지 못한 것

- **`steamcmd`로 실제 업로드**: 실행하지 않았다. 이 문서의 VDF는 예시이며 필드 동작은 Steamworks 문서로 확인해야 한다.
- **SteamStub / Steam DRM 래퍼(`drm_wrap`) 적용 후의 동작**: 래핑은 Valve 쪽에서 실행 파일을 다시 쓰는 것으로 알려져 있다. 봉인 -> 래핑 순서에서 `.text` 해시와 W^X 검사가 오탐을 내는지 **실측하지 않았다**. 따라서 "SteamStub과 호환된다"고 말할 수 없다. 래퍼를 쓸 계획이면 별도 베타 브랜치에서 먼저 실측한다.
- Steam 클라이언트가 설치한 파일에 대한 런타임 검증, Steam Cloud, 베타 브랜치, 여러 depot 조합.
- Windows PE 봉인에는 MSVC로 빌드한 EXE가 필요하다(mingw 기본 링크 EXE는 `.text` 안 relocation 때문에 봉인되지 않는다). `windows-msvc` CI가 샘플 게임에서 확인했지만, 실제 게임 엔진 빌드는 확인하지 않았다.
- 공개 CA 서명, 타임스탬프 서명, 폐기 확인은 검증하지 못했다([integrity-verification.md](integrity-verification.md#7-windows-pe32-x64) 참고).

이 도구는 변조를 막지 않고 드러내는 report-only 방어다. 해적판 크랙, 치트, 게임 도용은 이 파이프라인의 범위가 아니다.
