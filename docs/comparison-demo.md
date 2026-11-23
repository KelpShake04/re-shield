# Unified Runtime & Before/After Comparison Demo

`re-shield`의 3·4단계 체크리스트에 해당하는 **단일 런타임 라이브러리 통합(`include/reshield/reshield.h`)** 및 **샘플 프로그램 적용 전/후 비교 시연(`examples/sample_game.c`)** 문서다.

## 1. 최소 침습 통합 API (`libreshield.a`)

기존 프로젝트의 `main()`에 아래 몇 줄만 추가하고, 빌드 파이프라인에 `strip` + `tools/seal_binary.py`를 연결하면 디버거 탐지·차단과 코드 섹션 무결성 검증을 함께 적용할 수 있다.

```c
#include "reshield/reshield.h"

int main(int argc, char **argv) {
    reshield_runtime_config_t cfg = reshield_default_config();
    (void)reshield_init(&cfg); /* 디버거 탐지 + attach 차단 + 코드 섹션 SHA-256 검증 */

    reshield_timer_t t;
    reshield_timer_start(&t);
    /* ... 핵심 로직 ... */
    (void)reshield_periodic_check(&cfg, &t, 500);
}
```

- **합법적 디버깅·개발 지원**: `-DRESHIELD_DISABLE` 컴파일 플래그로 모든 런타임 검사를 no-op으로 비활성화할 수 있다.
- **민감 문자열 보조 헬퍼**: `reshield_xor_transform()` + `reshield_secure_zero()`로 평문 문자열이 바이너리 `strings`와 스택 메모리에 그대로 남는 것을 줄인다(단, XOR은 암호화가 아닌 최소한의 정적 분석 마찰 용도임을 명시한다).

## 2. 샘플 프로그램 적용 전/후 비교 시연

동일한 소스(`examples/sample_game.c`)를 두 방식으로 빌드해 `tools/compare_sample.py`로 비교한다.

```bash
make sample-compare
```

### 실측 비교 결과 (macOS arm64, Apple clang 21.0.0)

| 항목 | 적용 전 (`sample_game_unprotected`) | 적용 후 (`sample_game_protected`) |
| --- | --- | --- |
| `strings` 평문 키 노출 (`SECRET_STAGE_KEY_2026`) | 노출됨 (YES) | 미 노출 (NO) |
| `nm` 심볼 (핵심 함수명 노출) | 로컬/함수 심볼 노출 (`validate_stage_key`, `compute_reward_code`) | `strip`으로 내부 심볼 제거 |
| 코드 섹션 1바이트 변조 시 동작 | 변조 탐지 없이 정상 실행 (`ACCESS DENIED`) | `reshield_init()`에서 무출력 즉시 종료 (`exit(1)`) |
| 디버거 attach (`lldb`) | 제한 없이 attach 및 브레이크포인트 가능 | `P_TRACED` 탐지 + `PT_DENY_ATTACH` 차단 |
| 바이너리 크기 | 33,688 bytes | 51,024 bytes |

### 로컬 터미널에서 직접 확인하기

```bash
# 1. 자동 비교 스크립트 실행
make sample-compare

# 2. 정적 분석 비교 (strings / nm)
strings build/sample_game_unprotected | grep SECRET_STAGE_KEY_2026
strings build/sample_game_protected   | grep SECRET_STAGE_KEY_2026 || echo "not found"
nm build/sample_game_unprotected
nm build/sample_game_protected

# 3. 동적 분석 비교 (lldb)
lldb --batch -o run -o quit -- ./build/sample_game_unprotected SECRET_STAGE_KEY_2026
lldb --batch -o run -o quit -- ./build/sample_game_protected   SECRET_STAGE_KEY_2026
```

## 3. 한계 및 Non-goals 재확인

- 이 데모는 **초급 정적/동적 분석(`strings`, `nm`, 단순 1바이트 패치, 기본 `lldb` attach)의 비용을 높이는 것**을 보여준다.
- **완전한 방어가 아니다**: 숙련된 리버서는 API 후킹(`DYLD_INSERT_LIBRARIES`/`LD_PRELOAD`/Frida), `reshield_init` 호출부 패치 + `RSHLDCHK` 재봉인, 디스어셈블을 통한 XOR 키(`0x5A`) 추출로 우회할 수 있다.
- 커널 모듈/드라이버는 사용하지 않으며, 정당한 디버깅·보안 연구 시 `-DRESHIELD_DISABLE`로 해제할 수 있다.
