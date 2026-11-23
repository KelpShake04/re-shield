# re-shield

소프트웨어/게임을 리버스 엔지니어링(디컴파일, 메모리 덤프, 디버거 attach)으로부터 보호하는 안티 리버싱 도구. 현재는 **C11 통합 런타임 라이브러리(`libreshield.a`)**, **빌드 타임 봉인 도구(`tools/seal_binary.py`)**, **적용 전/후 비교 시연(`examples/sample_game.c`)**까지 구현되어 있다.

## 배경

리버싱으로 소스코드·에셋을 추출해 게임을 그대로 복제하는 사례가 있다. 완전한 방어는 불가능하지만(바이너리를 실행 가능한 형태로 주는 한, 공격자는 결국 디스어셈블·동적 분석으로 우회할 수 있다), 비용과 난이도를 크게 올려 "그대로 복제"를 막는 것이 목표다.

## 목표

- 정적 분석 난이도 상승: 코드/문자열 난독화, 심볼 제거.
- 동적 분석 난이도 상승: 디버거 attach 탐지·차단, 프로세스 메모리 덤프 방해.
- 변조 탐지: 바이너리/핵심 로직 체크섬 검증, 위변조 시 실행 중단.
- 위 세 가지를 하나의 빌드 단계 + 런타임 라이브러리로 통합해, 기존 프로젝트에 최소 침습으로 적용 가능하게.

## Non-goals / Anti-goals

- 서버 라이선스 인증, DRM 전체 시스템 (범위 밖).
- 커널 레벨 방어(안티치트 드라이버, kext/커널 모듈) — 서명·배포 문턱이 높아 1차 범위에서 제외.
- "절대 못 뚫는다"는 주장 — 리버싱 방지는 지연이 목적이지 차단 보장이 아니다. 과장된 보안 주장은 anti-goal.
- 합법적 보안 연구(디버깅, 취약점 분석)를 막는 수준의 과잉 방어 — 정당한 디버깅 목적까지 차단하면 실패로 본다.

## 개념 설계

### 1. 정적 분석 방지
- 심볼/디버그 정보 strip.
- 문자열 상수 암호화/난독화(런타임 복호화 + 사용 후 즉시 0으로 덮어쓰기).
- 핵심 로직은 제어 흐름 난독화(flattening) 또는 간단한 바이트코드 인터프리터로 우회(향후 과제).

### 2. 동적 분석 방지
- macOS: `sysctl`(`P_TRACED`) 기반 비파괴 탐지 + `ptrace(PT_DENY_ATTACH)` 호출로 디버거 attach 차단.
- Linux: `/proc/self/status` TracerPid 확인 + `ptrace(PTRACE_TRACEME)` self-trace 트릭.
- 공통: 실행 중 주기적으로 환경 재검사(타이밍 기반 디버거 탐지 — 브레이크포인트로 인한 실행 지연 측정).

### 3. 메모리 보호
- 민감 데이터(키, 핵심 상수)는 메모리에 평문으로 오래 두지 않고 사용 직전 복호화 → 사용 후 즉시 0으로 덮어쓰기(`reshield_secure_zero`).
- `mprotect`/`VirtualProtect`로 코드 페이지를 읽기 전용 + 실행 전용으로 설정, 실행 중 페이지 속성 변경 시도를 탐지(향후 과제).

### 4. 변조 탐지
- 빌드 시 핵심 섹션(`__TEXT,__text` / `.text`) SHA-256 해시를 계산해 바이너리에 삽입(`tools/seal_binary.py`).
- 런타임에 메모리 상 코드 섹션 해시를 재계산 → 불일치 시 조용히 비정상 종료(에러 메시지로 공격자에게 탐지 로직을 알려주지 않음).

## 제약

- 완전한 방어는 불가능하다는 전제를 설계·발표 문서에 명시한다(과장 금지).
- 1차 구현은 네이티브 바이너리(C/C++) 대상. 스크립트 언어(바이트코드 VM 등)는 범위 밖.
- 플랫폼: macOS·Linux 우선(현재 개발 환경 기준). Windows는 2차.

## 빠른 시작

```bash
make all
make test
make sample-compare
```

- 디버거 attach 탐지 PoC 상세·`lldb` 검증·우회 한계: [docs/poc-anti-debug.md](docs/poc-anti-debug.md)
- 변조 탐지(체크섬) PoC 상세·봉인/변조 시연·우회 한계: [docs/poc-integrity.md](docs/poc-integrity.md)
- 통합 런타임 API 및 적용 전/후 비교 시연: [docs/comparison-demo.md](docs/comparison-demo.md)
- 개발·보안 연구 목적의 디버깅 시 `-DRESHIELD_DISABLE`로 모든 탐지/검증을 비활성화할 수 있다.

## 다음 단계

- [x] 대상 플랫폼/언어 확정 후 PoC: 디버거 attach 탐지 단일 기능부터 구현. (C11, macOS/Linux — `include/reshield/anti_debug.h`, `src/anti_debug_*.c`)
- [x] 변조 탐지(체크섬) PoC. (자체 SHA-256 + `tools/seal_binary.py` + `include/reshield/integrity.h`, `src/integrity_*.c`)
- [x] 두 기능을 하나의 런타임 라이브러리로 통합. (`include/reshield/reshield.h`, `src/reshield.c`, `libreshield.a`)
- [x] 샘플 프로그램에 적용 전/후 리버싱 난이도 비교 시연. (`examples/sample_game.c`, `tools/compare_sample.py`, `docs/comparison-demo.md`)

## 상태

1차 로드맵(디버거 attach 탐지 PoC → 변조 탐지 체크섬 PoC → 단일 런타임 라이브러리 통합 → 적용 전/후 비교 시연) 완료.
