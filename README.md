# re-shield

자사(1st-party) 네이티브 소프트웨어·게임의 **바이너리 무결성 검증(Integrity Verification)**과 **런타임 디버거 연결 정책(Debug Policy)**을 제공하는 방어적 C11 런타임 라이브러리다.

> **사용 범위(Intended Use)**: 개발자가 자신이 소유·배포하는 네이티브 애플리케이션의 무단 변조와 단순 복제를 어렵게 만들기 위한 **방어적·교육용** 도구다. 악성코드·분석 회피(evasion) 목적이나 권한 없는 바이너리 수정 용도로 사용하지 않는다. 개발·QA·보안 연구 시 `-DRESHIELD_DISABLE`로 모든 검사를 비활성화할 수 있다.

## 배경

네이티브 게임·애플리케이션의 바이너리를 변조하거나 리소스를 그대로 복제하는 사례가 있다. 바이너리를 로컬에서 실행 가능한 형태로 배포하는 한 완전한 방어는 불가능하지만, 기본적인 무결성 검증과 디버그 정책을 최소 침습으로 적용해 무단 변조 비용을 높이는 것이 목표다.

## 목표

- **무결성 검증**: 빌드 시 코드 섹션(`__TEXT,__text` / `.text`) SHA-256 해시를 기록하고, 런타임에 메모리 상 코드 섹션을 재검증.
- **런타임 디버그 정책**: OS 표준 API를 이용해 디버거 연결 여부를 확인하고, 정책(`REPORT` / `CALLBACK` / `TERMINATE`)에 따라 대응.
- **민감 데이터 메모리 관리**: 민감 상수를 평문으로 오래 유지하지 않고 사용 직후 `reshield_secure_zero()`로 메모리 초기화.
- **최소 침습 통합**: 단일 정적 라이브러리(`libreshield.a`)와 빌드 후처리(`tools/seal_binary.py`)로 기존 C/C++ 프로젝트에 쉽게 적용.

## Non-goals / Anti-goals

- 서버 라이선스 인증, DRM 전체 시스템 (범위 밖).
- 커널 레벨 방어(안티치트 드라이버, kext/커널 모듈) — 서명·배포 문턱이 높아 1차 범위에서 제외.
- "절대 못 뚫는다"는 주장 — 유저스페이스 무결성 보호는 지연·마찰이 목적이지 절대 차단이 아니다. 과장된 보안 주장은 anti-goal.
- 합법적 보안 연구·개발 디버깅을 막는 수준의 과잉 방어 — `-DRESHIELD_DISABLE` 및 정책 분리를 통해 정당한 디버깅을 지원한다.

## 아키텍처 개요

### 1. 빌드·심볼 정리 및 메모리 관리
- 릴리스 빌드 시 불필요한 내부 심볼 `strip`.
- 민감 설정값은 사용 직전 복원 후 `reshield_secure_zero()`로 즉시 메모리에서 제거.

### 2. 런타임 디버그 정책 (`include/reshield/anti_debug.h`)
- macOS: `sysctl`(`P_TRACED`) 상태 조회 + `ptrace(PT_DENY_ATTACH)` (Apple 플랫폼 표준 디버거 attach 제한 API).
- Linux: `/proc/self/status`의 `TracerPid` 조회 + `ptrace(PTRACE_TRACEME)` 기반 연결 제한.
- 공통: `CLOCK_MONOTONIC` 기반 구간 실행 시간 측정 헬퍼(보조 휴리스틱).

### 3. 바이너리 무결성 검증 (`include/reshield/integrity.h`)
- 빌드 후 `tools/seal_binary.py`가 실행 파일의 코드 섹션(`__TEXT,__text` / `.text`) SHA-256을 계산해 데이터 섹션의 `RSHLDCHK` 레코드에 기록.
- 런타임에 메모리 상 코드 섹션의 SHA-256을 재계산해 상수 시간 비교(`ct_memcmp`)로 변조 여부 확인.

### 4. 통합 런타임 (`include/reshield/reshield.h`)
- `reshield_init()` / `reshield_periodic_check()` 단일 진입점으로 디버그 정책과 무결성 검증을 함께 적용.

## 제약

- 완전한 방어는 불가능하다는 전제를 모든 설계·문서에 명시한다(과장 금지).
- 1차 구현은 네이티브 바이너리(C/C++) 대상. 스크립트 언어(바이트코드 VM 등)는 범위 밖.
- 플랫폼: macOS·Linux 우선. Windows는 2차.

## 빠른 시작

```bash
make all
make test
make sample-compare
```

- 런타임 디버그 정책 PoC 상세 및 한계: [docs/poc-anti-debug.md](docs/poc-anti-debug.md)
- 코드 섹션 무결성 검증 PoC 상세 및 한계: [docs/poc-integrity.md](docs/poc-integrity.md)
- 통합 런타임 API 및 적용 전/후 비교 시연: [docs/comparison-demo.md](docs/comparison-demo.md)
- 개발·보안 연구 목적의 디버깅 시 `-DRESHIELD_DISABLE`로 모든 검사를 비활성화할 수 있다.

## 다음 단계

- [x] 대상 플랫폼/언어 확정 후 PoC: 디버거 attach 탐지 단일 기능부터 구현. (C11, macOS/Linux — `include/reshield/anti_debug.h`, `src/anti_debug_*.c`)
- [x] 변조 탐지(체크섬) PoC. (자체 SHA-256 + `tools/seal_binary.py` + `include/reshield/integrity.h`, `src/integrity_*.c`)
- [x] 두 기능을 하나의 런타임 라이브러리로 통합. (`include/reshield/reshield.h`, `src/reshield.c`, `libreshield.a`)
- [x] 샘플 프로그램에 적용 전/후 비교 시연. (`examples/sample_game.c`, `tools/compare_sample.py`, `docs/comparison-demo.md`)

## 상태

1차 로드맵(디버그 정책 PoC → 무결성 체크섬 PoC → 단일 런타임 라이브러리 통합 → 적용 전/후 비교 시연) 완료.
