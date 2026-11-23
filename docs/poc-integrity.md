# Tamper Detection (Checksum) PoC (`integrity`)

`re-shield`의 두 번째 PoC 단계로, **빌드 시 코드 섹션 SHA-256 해시 삽입 + 런타임 메모리 검증** 기능을 구현했다.

## 범위 및 설계 원칙

- **유저스페이스 전용(C11 + Python 3 stdlib)**: 외부 암호화 라이브러리나 커널 모듈 없이 자체 FIPS 180-4 SHA-256 구현과 OS 실행 이미지 조회 API만 사용한다.
- **순환 해싱 방지**: 기대 해시 레코드(`RSHLDCHK`, `volatile` + `used`)는 코드 섹션(`__TEXT,__text` / `.text`)이 아닌 데이터 섹션(`__DATA,__data` / `.data`)에 배치해, 코드 섹션 해시를 삽입해도 코드 섹션 자체가 변하지 않는다.
- **조용한 종료**: `RESHIELD_INTEGRITY_POLICY_TERMINATE` 정책은 불일치 시 에러 메시지를 출력하지 않고 `_exit(1)`로 즉시 종료한다.
- **합법적 디버깅·개발 존중**:
  - `-DRESHIELD_DISABLE`로 전체 검증을 컴파일 타임에 비활성화할 수 있다.
  - 개발 빌드(미봉인)에서는 `UNSEALED` 상태를 구분 반환하며, `allow_unsealed = 1` 옵션으로 개발 편의성을 유지할 수 있다.

## 동작 흐름

1. **컴파일**: `libreshield.a`를 링크해 실행 바이너리를 빌드한다(초기 상태: `sealed = 0`).
2. **봉인(Sealing)**: `tools/seal_binary.py <binary>`가 바이너리의 코드 섹션(`__TEXT,__text` on 64-bit Mach-O / `.text` on 64-bit ELF) 바이트를 읽어 SHA-256을 계산한 뒤, 바이너리 내 유일한 `RSHLDCHK` 레코드에 `sealed = 1`, 크기, 해시를 기록한다.
   - macOS(Apple Silicon)에서는 바이너리 수정 후 실행을 위해 ad-hoc `codesign -s - --force`를 자동 재적용한다.
3. **런타임 검증**: `reshield_verify_code_section()`이 메모리에 매핑된 코드 섹션을 직접 읽어 SHA-256을 재계산하고, 상수 시간 비교(`ct_memcmp`)로 봉인 레코드와 대조한다.
   - macOS: `_dyld_get_image_header(0)` + `getsectiondata(..., "__TEXT", "__text", ...)`
   - Linux: `dl_iterate_phdr`로 메인 이미지 베이스 주소를 구하고 `/proc/self/exe` ELF64 섹션 헤더에서 `.text` 오프셋/크기를 조회.

## 빌드 및 검증

```bash
make all
make test
```

### 수동 시연

```bash
# 1. 미봉인 바이너리 실행 (UNSEALED, exit 10)
./build/integrity_demo --mode=verify

# 2. 코드 섹션 해시 봉인 후 실행 (OK, exit 0)
cp ./build/integrity_demo /tmp/demo_sealed
python3 tools/seal_binary.py /tmp/demo_sealed
/tmp/demo_sealed --mode=verify
/tmp/demo_sealed --mode=guard-quiet

# 3. E2E 1바이트 변조 탐지 테스트
python3 tests/test_tamper_e2e.py
```

## 알려진 우회 기법 및 한계

본 PoC 역시 **완전 방어가 아닌 우회 비용 상승**이 목적이다. 공격자는 다음 방법으로 우회할 수 있다:

1. **재봉인(Re-sealing)**:
   - 공격자가 코드 섹션을 패치한 뒤, 바이너리 내 `RSHLDCHK` 레코드의 `expected_sha256`도 새 해시로 함께 덮어쓰면 로컬 체크섬 검증을 통과한다.
2. **검증 호출 패치 / 후킹**:
   - `reshield_verify_code_section` 호출부를 `NOP` 처리하거나 반환값을 `0`으로 강제, 또는 `getsectiondata` / `dl_iterate_phdr`를 후킹해 원본 코드 사본을 가리키게 할 수 있다.
3. **데이터 섹션·동적 라이브러리 변조 미포함**:
   - 1차 PoC는 메인 실행 파일의 코드 섹션(`__TEXT,__text` / `.text`)만 검증하며, 데이터 섹션이나 외부 `.dylib`/`.so` 변조는 범위 밖이다.

이후 단계에서 디버거 attach 탐지와 통합하고, 심볼 strip·분산 검증 등으로 단순 패치 난이도를 추가로 높일 수 있다(단, 로컬 실행 바이너리의 근본적 한계는 변하지 않는다).
