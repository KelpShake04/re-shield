자기 소유 바이너리만 대상. 이 랩은 방어의 한계를 이해하기 위한 교육용이다. (Own binaries only. This lab teaches the limits of a defense; it is not a cracking guide.)

# crackme 랩: re-shield는 무엇을 막고 무엇을 못 막는가

re-shield는 변조를 막지 않고 드러낸다(report-only, 비밀 키 없음). 이 랩은 그 문장을 말이 아니라 실험으로 확인한다. 이 저장소가 빌드한 작은 프로그램 `examples/crackme/crackme.c`를 직접 패치해 보고, 어떤 패치는 `CODE_TAMPERED`로 막히고 어떤 패치는 그대로 통과하는지 본다.

## 대상 프로그램

`crackme <키>`는 시작할 때 `reshield_verify_app()`을 부르고(위반이면 콜백이 `INTEGRITY VIOLATION: ...`을 출력하고 앱이 종료 코드 `10 + status`를 반환한다. 라이브러리는 종료하지 않는다), 그다음 키를 SHA-256 commitment와 비교해 `UNLOCKED` 또는 `ACCESS DENIED`를 출력한다. 올바른 키는 `CRACKME-LAB-2026`이다.

공격 표면은 일부러 함수 두 개로 나눴다. 둘 다 `noinline`이라 심볼과 진입점이 `.text`에 따로 남는다.

| 함수 | 역할 |
|---|---|
| `crackme_check_license` | 키가 맞으면 1을 반환 |
| `crackme_startup_check` | `reshield_verify_app()` 호출, 통과하면 0 |

`examples/crackme/lab.py`가 패치를 자동으로 한다. 패치 위치는 `nm` 심볼 테이블에서, CPU(arm64, x86-64)는 파일 헤더에서 구하므로 하드코딩한 오프셋이 없다. 함수 진입점을 "`n`을 반환" 기계어(`mov` + `ret`)로 덮어쓴다. 원본 파일은 건드리지 않고 임시 복사본만 고친다. macOS는 패치 뒤 ad-hoc 재서명(`codesign -f -s -`)까지 스크립트가 한다.

이 저장소는 개발용 라이브러리(`RESHIELD_ALLOW_UNSEALED`)로 링크하지만, 실습 대상은 `tools/seal_binary.py`로 봉인한 바이너리다. 봉인하지 않은 바이너리는 개발용 라이브러리에서 통과하므로 아무것도 막지 못한다.

## 실행

```bash
make crackme        # 빌드 + 봉인 + 레벨 1~3 실행과 단언 (tests/test_crackme_lab.py)
```

수동으로 해 보려면:

```bash
make build/crackme_sealed
build/crackme_sealed CRACKME-LAB-2026      # UNLOCKED
build/crackme_sealed WRONG-KEY             # ACCESS DENIED
python3 examples/crackme/lab.py build/crackme_sealed 1 2 3
```

레벨 스크립트는 모두 틀린 키(`WRONG-KEY`)로 패치본을 실행한다. 키 없이 열리면 공격이 성공한 것이다.

## 레벨 1: 코드만 패치 (막힘)

`crackme_check_license`가 항상 1을 반환하게 패치하고, 봉인 레코드는 그대로 둔다.

```
L1: patch the license check, keep the old seal
  patched crackme_check_license @ file offset 0x72c: 20 00 80 52 c0 03 5f d6
  run with wrong key: rc=12
    INTEGRITY VIOLATION: CODE_TAMPERED (checks=0x1)
```

`.text`의 SHA-256이 레코드와 달라져 `CODE_TAMPERED`(status 2, 종료 코드 12)로 막힌다. 오프셋과 바이트 값은 CPU와 빌드마다 다르다(x86-64는 `b8 01 00 00 00 c3`). 이것이 re-shield가 하는 일이다.

## 레벨 2: 패치 후 재봉인 (통과, 못 막는 것)

같은 패치를 한 뒤 `tools/seal_binary.py`로 레코드를 다시 쓴다.

```
L2: patch the license check, then re-seal
  ...
  re-sealed with tools/seal_binary.py (no key needed)
  run with wrong key: rc=0
    UNLOCKED
```

통과한다. 해시를 기록한 곳과 해시를 확인하는 곳이 같은 파일이고 서명 키가 없어서, 코드를 고친 사람이 레코드도 새로 만들 수 있다. 레코드가 평문 `RSHLDCHK` 매직으로 시작해 찾기도 쉽다(그래서 난독화는 하지 않는다. 키가 없으면 어떤 난독화도 obscurity일 뿐이다). 이 한계는 설계에서 나온 것이고 버그가 아니다. 변조를 "증거로 남기려면" 봉인 값을 바이너리 밖의 신뢰할 수 있는 곳(서버, 서명)과 대조해야 한다.

## 레벨 3: 검사 호출 자체를 패치 (통과, 못 막는 것)

레벨 1의 패치에 더해 `crackme_startup_check`가 항상 0을 반환하게 한다. 재봉인은 하지 않는다.

```
L3: patch the license check AND the startup check (never calls reshield_verify)
  ...
  run with wrong key: rc=0
    UNLOCKED
```

통과한다. 봉인은 낡았지만 `reshield_verify`가 아예 실행되지 않으므로 비교할 일이 없다. 스스로를 해시하는 코드에는 "해시되는 코드"와 "실행되는 코드"를 분리하는 일반적인 우회가 있다(van Oorschot 외, IEEE TDSC 2005). 검사 호출을 여러 곳에 흩뿌리거나 난독화해도 비용만 올릴 뿐 근본 해법은 아니다.

## 무엇이 막고 무엇이 못 막는가

| 공격 | 결과 | 이유 |
|---|---|---|
| `.text` 패치, 봉인 유지 (L1) | 막힘 (`CODE_TAMPERED`) | 코드 해시가 레코드와 다름 |
| `.text` 패치 + 재봉인 (L2) | 못 막음 | 키가 없어 레코드를 누구나 다시 쓸 수 있음 |
| 검사 호출 우회 (L3) | 못 막음 | 검사가 실행되지 않으면 아무것도 비교하지 않음 |
| 봉인 안 한 바이너리 | 개발용 라이브러리에서는 통과 | `RESHIELD_ALLOW_UNSEALED`는 개발 전용, 릴리스 빌드는 `UNSEALED`로 거부 |

re-shield는 우발적 손상과 가장 쉬운 패치를 드러내는 도구다. 크랙이나 치트를 막으려면 상용 보호기나 안티치트, 서버 쪽 검증이 필요하다.

## 범위와 다음 단계

- 이 랩은 Mach-O 64와 ELF64의 arm64, x86-64 코드를 패치할 수 있다. 실제로 확인한 조합은 macOS arm64와 Linux x86-64(Docker `gcc:14`)뿐이다. Windows(PE)는 이번 범위에서 제외했다. `make test`도 mingw 타깃에서는 이 랩을 건너뛴다.
- 미구현: 레벨 4(macOS/Windows 서명자 고정을 켜고 재봉인 + 자기 서명이 `CODESIGN_INVALID`로 막히는지 확인. 단 검사 함수 패치는 여전히 통과한다), 레벨 5(strict 모드).
