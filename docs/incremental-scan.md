# 점진 코드 섹션 재검증 (`reshield_code_scan_*`)

`reshield_verify_code_section()`은 코드 섹션 전체를 한 번에 해시한다. 큰 섹션에서는 한 프레임을 넘길 수 있다(아래 측정). 이 API는 같은 해시를 여러 호출에 나눠서 한다. 봉인 레코드 형식(v2)과 기존 API는 바뀌지 않았다.

## 사용

```c
#include "reshield/integrity.h"

static reshield_code_scan_t g_scan;            // 호출자 소유, 192 B, malloc 없음

void game_init(void) {
    if (reshield_code_scan_begin(&g_scan) != RESHIELD_INTEGRITY_OK) { /* 섹션을 못 찾음: 실패로 처리 */ }
}

void game_frame(void) {                          // 한 스레드에서만 호출
    reshield_integrity_result_t r;
    int rc = reshield_code_scan_step(&g_scan, 256 * 1024, &r);
    if (rc == 1 && r.status != RESHIELD_INTEGRITY_OK) { /* TAMPERED 등 */ }
}
```

- `begin`은 섹션 위치를 한 번만 찾는다. Linux에서는 이미지 파일을 열어 ELF 섹션 테이블을 읽으므로 프레임마다 부르지 않는다. 아무것도 해시하지 않는다.
- `step(scan, max_bytes, out)`: 최대 `max_bytes`만 해시한다. 반환값 `0`은 pass 진행 중(`out`은 건드리지 않음), `1`은 pass 끝(`out`은 `reshield_verify_code_section()`과 같은 판정), `-1`은 인자 오류(NULL, `max_bytes == 0`, `begin`을 안 한 상태).
- 레코드는 pass가 끝날 때 읽는다. 시작 때 읽으면 pass 도중의 레코드 변경을 놓친다.
- 일괄 함수 `reshield_verify_code_section()`은 내부적으로 `begin` + `step(SIZE_MAX)`이다. 판정 코드가 한 곳이라 청크 크기와 관계없이 변조 없는 메모리에서는 결과가 같다.
- `-DRESHIELD_DISABLE`: `begin`은 OK, 첫 `step`이 곧바로 `1`과 OK를 돌려준다.
- 예산은 시간이 아니라 바이트다(시계 호출과 플랫폼 차이를 피함).

### pass가 끝난 뒤

`1`을 돌려준 다음 `step`은 같은 섹션 위치로 새 pass를 자동으로 시작한다. `begin`을 다시 부를 필요가 없다. 이유: 로드된 이미지의 코드 섹션 주소는 바뀌지 않으므로 다시 찾을 이유가 없고(Linux는 파일 파싱 비용이 든다), 이 API의 용도가 "상시 감시"라서 매 pass마다 호출자가 상태를 다시 세우게 하면 호출부만 복잡해진다. 반대로 한 번만 돌리고 멈추고 싶으면 `1`을 받은 뒤 `step`을 그만 부르면 된다. 섹션을 다시 찾고 싶으면(예: 라이브러리를 다시 로드) `begin`을 다시 부른다. pass 도중 `begin`을 부르면 처음부터 다시 시작한다.

## 비용 (직접 측정)

측정 환경: Apple M1 Pro, macOS, `cc -O2`, 합성 8 MiB 버퍼(실제 게임 `.text` 아님), 같은 버퍼로 pass 5회 중 가장 빠른 pass. 하드웨어 SHA-256(AArch64 SHA2)과 이식 C(`reshield_sha256_force_portable(1)`)를 비교했다.

| 호출당 예산 | 하드웨어: step 평균 | 이식 C: step 평균 | 8 MiB 한 pass의 step 수 |
|---|---|---|---|
| 4 KiB | 1.9 us | 19.5 us | 2048 |
| 64 KiB | 31 us | 321 us | 128 |
| 256 KiB | 123 us | 1.33 ms | 32 |
| 1 MiB | 482 us | 5.48 ms | 8 |

- 8 MiB 전체를 한 번에 해시하면 하드웨어 4.1 ms, 이식 C 44.4 ms였다(같은 환경). 청크로 나눈 pass의 총 시간은 이와 거의 같다(하드웨어 3.9 ms, 이식 C 40~44 ms). 청크 분할 비용(상태 복사 192 B x 2회/step)은 이 측정에서 보이지 않았다.
- 한 호출의 최악 시간은 평균보다 크다(하드웨어 0.26~0.55 ms, 이식 C 64 KiB에서 3.6 ms). 스케줄러 선점이 섞인 값이라 상한 보장이 아니다.
- 권장: 이식 C는 64 KiB, 하드웨어 경로는 256 KiB~1 MiB. 60 fps 기준 프레임 예산의 몇 %를 쓸지는 앱이 정한다.
- 미측정: x86-64(SHA-NI 포함), Windows, Linux, 캐시 오염(청크만큼 L2를 밀어냄), 실제 게임 크기의 섹션.

## 한계 (키 없는 설계)

- **검증기 자체와 레코드는 보호되지 않는다.** `.text`를 쓸 수 있는 공격자는 `step`이나 그 호출부를 NOP으로 바꿀 수 있고, 레코드(쓰기 가능한 데이터 영역)의 기대 해시를 다시 계산해 덮어쓸 수 있다. 키도 서명도 없다. 일괄 검사와 같은 한계다.
- **이미 지난 청크의 변경은 늦게 잡힌다.** 커서가 지나간 청크를 패치하면 다음 pass가 끝날 때 잡힌다. 최악은 약 2 pass 길이다. 패치했다가 두 방문 사이에 되돌리면 잡지 못한다. 커서 위치와 순서가 고정이라 예측할 수 있다. 무작위 순서나 청크 즉시 판정은 청크별 해시 표(레코드 v3)가 있어야 한다. 이 PR의 범위가 아니다.
- 바이트를 바꾸지 않는 공격(하드웨어 브레이크포인트, 페이지 재매핑, shadow page, 하이퍼바이저 뷰)은 보지 못한다.
- 얻는 것: 시작 검사 뒤에 생긴 inline hook, 소프트웨어 브레이크포인트(int3), 트레이너 패치를 상시 탐지한다. 의지 있는 공격자는 못 막는다. 전체 한계는 [integrity-verification.md](integrity-verification.md#5-한계)와 같다.

## 스레드와 수명

- 상태(`reshield_code_scan_t`)는 호출자 소유다. 한 상태에 대한 `step`은 한 번에 한 스레드에서만 부른다. 잠금은 없다. 서로 다른 상태는 서로 다른 스레드에서 써도 된다.
- 라이브러리의 다른 가변 전역 상태는 SHA-256 백엔드 선택 하나(`g_backend`, 첫 사용 때 CPU 기능을 감지해 저장)다. 값이 결정적이라 두 스레드가 동시에 처음 부르면 같은 값을 쓰지만, `volatile int`이지 atomic이 아니라서 C11 기준으로는 data race다. 실질 위험은 낮다고 보지만 TSan은 보고할 수 있다(미확인). 이 API가 새로 만든 문제는 아니며, 일괄 `reshield_verify_code_section()`도 같다.
- 섹션 주소를 `begin`에서 저장한다. 그 코드 섹션을 가진 모듈을 언로드(`dlclose`, `FreeLibrary`)한 뒤 `step`을 부르면 안 된다.
- 초기화하지 않은 구조체의 오용은 확실히 잡지 못한다. 사용 전에 0으로 채우거나 `begin`을 부른다. 실패한 `begin`은 구조체를 0으로 만들어 `step`이 `-1`을 돌려준다.

## export

POSIX 공유 라이브러리는 공개 API 전체가 보인다. Windows DLL은 `reshield.def`에 있는 것만 보이는데, `reshield_code_scan_begin`과 `reshield_code_scan_step`을 추가했다. 이유: 이 API의 용도가 프레임 루프(게임 엔진 쪽 호출)이고, DLL의 import library로 링크하는 네이티브 C++ 호스트가 이 API를 부르려면 export가 있어야 한다. 구조체가 192 B 고정 크기라 바인딩에서 마샬링하기도 쉽다. 아직 C#/Unity 바인딩 래퍼는 없다.

## 테스트

- `tests/test_incremental.c`: 합성 섹션(플랫폼 훅을 덮어씀). 예산 1/63/64/65/4096/섹션-1/섹션/섹션+1/1 MiB/`SIZE_MAX` 모두 일괄 결과와 필드 단위로 같음, 두 번째 pass(`begin` 없이) 동일, 하드웨어 경로와 이식 C 경로 둘 다, pass 도중 변경(아직 안 읽은 바이트는 이번 pass, 이미 읽은 바이트는 다음 pass, 되돌린 패치는 못 잡음), 인자 오류, 훅 실패 시 ERROR, 상태 크기 192 B. `-DRESHIELD_DISABLE` 변형 포함.
- `tests/test_incremental_real.c`: 이 바이너리의 실제 섹션. 같은 예산들에서 일괄 결과와 같음, 독립 SHA-256과 일치. `tests/test_seal_workflow.py`가 복사본을 봉인해 OK를 확인하고, `reshield_incr_sentinel`의 1바이트를 바꿔 TAMPERED를 확인한다. Linux에서는 봉인된 상태에서 `mprotect`로 `.text`를 쓰기 가능하게 만들어 pass 도중 패치를 넣고, 앞쪽 패치는 이번 pass에서 TAMPERED, 뒤쪽 패치는 다음 pass에서 TAMPERED임을 확인한다. macOS에서는 코드 페이지를 쓸 수 없어 이 부분은 합성 섹션 테스트로만 확인한다.
- Windows(CI `windows-msvc`): 봉인한 `test_incremental_real.exe`의 실제 PE `.text`에서 같은 예산 7종이 일괄 결과와 같음(봉인 전 UNSEALED, 봉인 후 OK, `.text` 1바이트 변조 후 TAMPERED)을 CI 스텝이 출력으로 확인한다.
- `-DRESHIELD_NO_HW_SHA`로 빌드해도 같은 테스트가 통과한다.
