# Code-Section Integrity Verification PoC (`integrity`)

`re-shield`의 두 번째 PoC 단계로, 자사 네이티브 바이너리의 **빌드 시 코드 섹션 SHA-256 기록 + 런타임 메모리 무결성 검증** 기능을 구현했다.

## 범위 및 설계 원칙

- **유저스페이스 전용(C11 + Python 3 stdlib)**: 외부 암호화 라이브러리나 커널 모듈 없이 자체 FIPS 180-4 SHA-256 구현과 OS 실행 이미지 조회 API만 사용한다.
- **순환 해싱 방지**: 기대 해시 레코드(`RSHLDCHK`, `volatile` + `used`)는 코드 섹션(`__TEXT,__text` / `.text`)이 아닌 데이터 섹션(`__DATA,__data` / `.data`)에 배치한다.
- **정책 기반 대응**: 불일치 시 호출자가 선택한 정책(`REPORT` / `CALLBACK` / `TERMINATE`)에 따라 동작한다.
- **개발·디버깅 존중**:
  - `-DRESHIELD_DISABLE`로 전체 검증을 컴파일 타임에 비활성화할 수 있다.
  - 미봉인 개발 빌드에서는 `UNSEALED` 상태를 구분 반환하며, `allow_unsealed = 1` 옵션으로 개발 편의성을 유지할 수 있다.

## 동작 흐름

1. **컴파일**: `libreshield.a`를 링크해 실행 바이너리를 빌드한다(초기 상태: `sealed = 0`).
2. **해시 기록(Sealing)**: `tools/seal_binary.py <binary>`가 코드 섹션(`__TEXT,__text` on 64-bit Mach-O / `.text` on 64-bit ELF)의 SHA-256을 계산해 `RSHLDCHK` 레코드에 기록한다.
   - macOS(Apple Silicon)에서는 파일 수정 후 실행 가능하도록 ad-hoc `codesign -s - --force`를 재적용한다.
3. **런타임 검증**: `reshield_verify_code_section()`이 메모리에 매핑된 코드 섹션의 SHA-256을 재계산하고 상수 시간 비교(`ct_memcmp`)로 일치 여부를 판정한다.
   - macOS: `_dyld_get_image_header(0)` + `getsectiondata(..., "__TEXT", "__text", ...)`
   - Linux: `dl_iterate_phdr` + `/proc/self/exe` ELF64 섹션 헤더에서 `.text` 매핑 주소 조회.

## 빌드 및 검증

```bash
make all
make test
```

### 수동 확인

```bash
# 1. 미봉인 바이너리 실행 (UNSEALED, exit 10)
./build/integrity_demo --mode=verify

# 2. 코드 섹션 해시 기록 후 실행 (OK, exit 0)
cp ./build/integrity_demo /tmp/demo_sealed
python3 tools/seal_binary.py /tmp/demo_sealed
/tmp/demo_sealed --mode=verify
/tmp/demo_sealed --mode=guard-quiet

# 3. 1바이트 손상 감지 E2E 테스트
python3 tests/test_tamper_e2e.py
```

## 한계

본 PoC는 로컬 실행 바이너리의 자체 무결성 검증이 갖는 한계를 전제한다.

- 로컬에 저장된 기대 해시 레코드와 검증 로직 자체가 함께 수정되거나 우회될 수 있으므로, 완전한 위변조 방지를 보장하지 않는다.
- 1차 PoC는 메인 실행 파일의 코드 섹션(`__TEXT,__text` / `.text`)만 대상으로 하며, 데이터 섹션이나 외부 동적 라이브러리(`.dylib`/`.so`)는 범위 밖이다.
