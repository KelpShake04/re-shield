# Runtime Debug Policy PoC (`debug_policy`)

`re-shield`의 첫 번째 PoC 단계로, 자사 네이티브 바이너리를 위한 **유저스페이스 전용(C11)** 디버거 연결 탐지 및 정책 적용 기능을 구현했다.

## 범위 및 설계 원칙

- **대상 플랫폼 / 언어**: C11 네이티브 정적 라이브러리(`libreshield.a`, C/C++ 호환 헤더). macOS 및 Linux 지원.
- **커널 모듈 없음**: 모든 기능은 OS가 제공하는 표준 유저스페이스 API만 사용한다.
- **과장 금지**: 이 구현은 비인가 동적 분석의 마찰을 높이는 보조 수단이며, 완전한 차단을 보장하지 않는다.
- **합법적 디버깅 존중**:
  - `-DRESHIELD_DISABLE` 컴파일 플래그로 모든 검사를 no-op으로 비활성화할 수 있다(개발/QA/보안 연구 빌드 분리).
  - 대응 정책(`RESHIELD_POLICY_REPORT`, `RESHIELD_POLICY_CALLBACK`, `RESHIELD_POLICY_TERMINATE`)을 호출자가 선택할 수 있다.

## 구현된 기능

| 플랫폼 | 함수 | OS API / 메커니즘 | 비고 |
| --- | --- | --- | --- |
| macOS | `reshield_check_debugger()` | `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID)` → `kp_proc.p_flag & P_TRACED` | 비파괴적 상태 조회 |
| macOS | `reshield_deny_attach()` | `ptrace(PT_DENY_ATTACH, 0, 0, 0)` | Apple 플랫폼 표준 attach 제한 플래그(`P_LNOATTACH`) 설정 |
| Linux | `reshield_check_debugger()` | `/proc/self/status`의 `TracerPid` 파싱 | 비파괴적 상태 조회 (자신의 `PTRACE_TRACEME` 부모 PID 제외) |
| Linux | `reshield_deny_attach()` | `ptrace(PTRACE_TRACEME, 0, NULL, NULL)` | 프로세스당 1회 호출 가드 적용 |
| 공통 | `reshield_timer_*()` | `CLOCK_MONOTONIC` 기반 구간 실행 시간 측정 | 실행 지연 측정(보조 휴리스틱) |

## 빌드 및 실행

```bash
make all
make test
```

### 데모 CLI

```bash
# 1. 일반 실행 (정상 통과)
./build/debug_policy_demo --mode=check
./build/debug_policy_demo --mode=deny
./build/debug_policy_demo --mode=guard-quiet

# 2. 디버거(lldb) 하에서 상태 조회 확인 (exit code 10)
lldb --batch -o run -o quit -- ./build/debug_policy_demo --mode=check

# 3. 디버거(lldb) 하에서 PT_DENY_ATTACH 동작 확인 (exit status 45)
lldb --batch -o run -o quit -- ./build/debug_policy_demo --mode=deny

# 4. 디버거(lldb) 하에서 TERMINATE 정책 확인 (exit status 1)
lldb --batch -o run -o quit -- ./build/debug_policy_demo --mode=guard-quiet

# 5. 타이밍 임계치 초과 테스트 (exit code 12)
./build/debug_policy_demo --mode=timing --threshold-ms=50 --sleep-ms=100

# 6. 개발/연구용 비활성화 빌드
make build/debug_policy_demo_disabled
lldb --batch -o run -o quit -- ./build/debug_policy_demo_disabled --mode=check
```

## 한계

본 PoC는 유저스페이스 구현의 근본적 한계를 전제한다.

- 유저스페이스 API 기반 검사는 동적 계측 환경, API 인터셉션, 또는 바이너리 수정으로 우회될 수 있다.
- 타이밍 기반 측정은 CPU 부하·절전·가상화 일시정지 등으로 인해 정상 환경에서도 오탐(False Positive)이 발생할 수 있으므로 보수적 임계치와 보조 신호로만 사용해야 한다.
- 본 모듈은 단독 방어 수단이 아니라 무결성 검증 등 다른 방어 계층과 함께 마찰을 높이는 용도로 설계되었다.
