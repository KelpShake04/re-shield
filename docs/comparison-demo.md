# Unified Runtime & Before/After Comparison Demo

`re-shield`의 **단일 런타임 라이브러리 통합(`include/reshield/reshield.h`)** 및 **샘플 프로그램 적용 전/후 비교 시연(`examples/sample_game.c`)** 문서다.

## 1. 최소 침습 통합 API (`libreshield.a`)

기존 자사 C/C++ 프로젝트의 `main()`에 아래 몇 줄을 추가하고, 릴리스 빌드 파이프라인에 `strip` + `tools/seal_binary.py`를 연결하면 디버그 정책과 코드 섹션 무결성 검증을 함께 적용할 수 있다.

```c
#include "reshield/reshield.h"

int main(int argc, char **argv) {
    reshield_runtime_config_t cfg = reshield_default_config();
    (void)reshield_init(&cfg); /* 디버그 정책 + 코드 섹션 SHA-256 검증 */

    reshield_timer_t t;
    reshield_timer_start(&t);
    /* ... 핵심 로직 ... */
    (void)reshield_periodic_check(&cfg, &t, 500);
}
```

- **개발·보안 연구 지원**: `-DRESHIELD_DISABLE` 컴파일 플래그로 모든 런타임 검사를 no-op으로 비활성화할 수 있다.
- **민감 상수 메모리 관리**: `reshield_xor_transform()` + `reshield_secure_zero()`로 설정 문자열이 평문으로 바이너리나 스택 메모리에 오래 남지 않도록 정리한다(단, XOR은 암호화가 아니며 기본적인 평문 노출 방지 용도다).

## 2. 샘플 프로그램 적용 전/후 비교 시연

동일한 1st-party 샘플(`examples/sample_game.c`)을 두 방식으로 빌드해 `tools/compare_sample.py`로 비교한다.

```bash
make sample-compare
```

### 실측 비교 결과 (macOS arm64, Apple clang 21.0.0)

| 항목 | 적용 전 (`sample_game_unprotected`) | 적용 후 (`sample_game_protected`) |
| --- | --- | --- |
| `strings` 평문 키 노출 (`SECRET_STAGE_KEY_2026`) | 노출됨 (YES) | 미 노출 (NO) |
| `nm` 정의 심볼 수 (핵심 함수명 노출) | 4 (노출됨: `validate_stage_key`, `compute_reward_code`) | 1 (내부 심볼 제거) |
| 코드 섹션 1바이트 손상 시 동작 | 손상 감지 없이 정상 실행 (`ACCESS DENIED`) | `reshield_init()`에서 `TERMINATE` 정책으로 종료 (`exit(1)`) |
| 디버거 attach (`lldb`) | 제한 없이 attach 가능 | `P_TRACED` 확인 + `PT_DENY_ATTACH` 적용 |
| 바이너리 크기 | 33,688 bytes | 51,024 bytes |

### 로컬 터미널에서 확인하기

```bash
# 1. 자동 비교 스크립트 실행
make sample-compare

# 2. 정적 심볼·문자열 비교
strings build/sample_game_unprotected | grep SECRET_STAGE_KEY_2026
strings build/sample_game_protected   | grep SECRET_STAGE_KEY_2026 || echo "not found"
nm build/sample_game_unprotected
nm build/sample_game_protected

# 3. 디버거 실행 비교 (lldb)
lldb --batch -o run -o quit -- ./build/sample_game_unprotected SECRET_STAGE_KEY_2026
lldb --batch -o run -o quit -- ./build/sample_game_protected   SECRET_STAGE_KEY_2026
```

## 3. 한계 및 Non-goals 재확인

- 이 데모는 단순 평문 검색, 심볼 조회, 1바이트 코드 손상, 기본 디버거 연결에 대한 방어적 마찰 증가를 보여준다.
- **완전한 방어가 아니다**: 유저스페이스 보호는 동적 계측, 바이너리 수정, 정적 역분석으로 우회될 수 있으며, 본 프로젝트는 이를 숨기거나 과장하지 않는다.
- 커널 모듈/드라이버는 사용하지 않으며, 정당한 디버깅·보안 연구 시 `-DRESHIELD_DISABLE`로 해제할 수 있다.
