# Debugger Attach Detection PoC (`anti_debug`)

`re-shield`의 첫 번째 PoC 단계로, **유저스페이스 전용(C11)** 디버거 attach 탐지 및 차단 기능을 구현했다.

## 범위 및 설계 원칙

- **대상 플랫폼 / 언어**: C11 네이티브 정적 라이브러리(`libreshield.a`, C/C++ 호환 헤더). macOS(주 검증 환경) 및 Linux(백엔드 구현) 지원.
- **커널 모듈 없음**: 모든 탐지/차단은 유저스페이스 시스템 콜 및 OS 제공 인터페이스만 사용한다.
- **과장 금지**: 이 구현은 리버싱·동적 분석의 **비용과 마찰을 높이는 것**이 목적이며, 완전한 차단을 보장하지 않는다.
- **합법적 디버깅 존중**:
  - `-DRESHIELD_DISABLE` 컴파일 플래그로 모든 체크를 no-op으로 비활성화할 수 있다(개발/보안 연구/QA 빌드 분리).
  - 정책(`RESHIELD_POLICY_REPORT`, `RESHIELD_POLICY_CALLBACK`, `RESHIELD_POLICY_TERMINATE`)을 호출자가 선택할 수 있다.

## 구현된 탐지·차단 기법

| 플랫폼 | 함수 | 메커니즘 | 비고 |
| --- | --- | --- | --- |
| macOS | `reshield_check_debugger()` | `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID)` → `kp_proc.p_flag & P_TRACED` | 비파괴적 탐지 |
| macOS | `reshield_deny_attach()` | `ptrace(PT_DENY_ATTACH, 0, 0, 0)` | 이후 attach 차단(`P_LNOATTACH`), 이미 attach된 경우 프로세스 종료(exit 45 / `ENOTSUP`) |
| Linux | `reshield_check_debugger()` | `/proc/self/status`의 `TracerPid` 파싱 | 비파괴적 탐지 |
| Linux | `reshield_deny_attach()` | `ptrace(PTRACE_TRACEME, 0, NULL, NULL)` | 프로세스당 1회만 호출하도록 atomic 가드 적용 |
| 공통 | `reshield_timer_*()` | `CLOCK_MONOTONIC` 기반 구간 실행 시간 측정 | 브레이크포인트/싱글스텝 지연 탐지(휴리스틱) |

## 빌드 및 실행

```bash
make all
make test
```

### 데모 CLI

```bash
# 1. 일반 실행 (정상 통과)
./build/anti_debug_demo --mode=check
./build/anti_debug_demo --mode=deny
./build/anti_debug_demo --mode=guard-quiet

# 2. 디버거(lldb) 하에서 비파괴 탐지 확인 (exit code 10)
lldb --batch -o run -o quit -- ./build/anti_debug_demo --mode=check

# 3. 디버거(lldb) 하에서 PT_DENY_ATTACH 동작 확인 (exit status 45)
lldb --batch -o run -o quit -- ./build/anti_debug_demo --mode=deny

# 4. 디버거(lldb) 하에서 조용한 종료 정책 확인 (출력 없이 exit status 1)
lldb --batch -o run -o quit -- ./build/anti_debug_demo --mode=guard-quiet

# 5. 타이밍 임계치 초과 시뮬레이션 (exit code 12)
./build/anti_debug_demo --mode=timing --threshold-ms=50 --sleep-ms=100

# 6. 개발/연구용 비활성화 빌드
make build/anti_debug_demo_disabled
lldb --batch -o run -o quit -- ./build/anti_debug_demo_disabled --mode=check
```

## 알려진 우회 기법 및 한계

본 PoC는 **유저스페이스 방어의 한계**를 명확히 전제한다. 숙련된 분석가는 다음과 같은 방법으로 우회할 수 있다:

1. **API 후킹 (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` / Frida)**:
   - `ptrace`, `sysctl`, `fopen`, `clock_gettime`을 후킹하여 `PT_DENY_ATTACH`를 무시하거나 `P_TRACED`/`TracerPid`를 0으로 위조할 수 있다.
2. **바이너리 패치 및 디버거 레지스터 조작**:
   - `ptrace` 호출 지점을 `NOP`으로 패치하거나, 분기 조건을 반전시키거나, `lldb` 브레이크포인트로 `ptrace` 진입 시 바로 리턴시킬 수 있다.
3. **커널/에뮬레이터 레벨 분석**:
   - 유저스페이스 체크는 커널 디버거, 하이퍼바이저, DBI(Dynamic Binary Instrumentation) 환경에서 투명하게 우회될 수 있다.
4. **타이밍 체크 오탐(False Positive)**:
   - CPU 과부하, 절전 모드, 가상화 일시정지 등으로 인해 정상 실행에서도 임계치를 초과할 수 있으므로 보수적 임계치 설정과 보조 신호로만 사용해야 한다.

향후 체크섬/변조 탐지 PoC와 결합해 단순 바이너리 패치 난이도를 추가로 높일 예정이나, 그 역시 우회 비용 상승이 목적이지 절대 방어가 아니다.
