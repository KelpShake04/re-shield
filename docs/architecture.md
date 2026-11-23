# re-shield Architecture (Defensive Build Attestation & Integrity)

`re-shield`는 **빌드 증명(Build Attestation)**과 **런타임 무결성 검증(Runtime Integrity Verification)**에 집중하는 100% 유저스페이스 C11 + Python 3 도구다.

## 설계 원칙

1. **표준 방어 API만 사용**: OS 공식 로더·메모리 조회·코드 서명 API(`_dyld_get_image_header`, `getsectiondata`, `mach_vm_region`, `SecCodeCheckValidity`, `dl_iterate_phdr`, `/proc/self/maps`)와 자체 FIPS 180-4 SHA-256만 사용한다.
2. **능동적 디버거 차단 미포함**: `ptrace` 기반 attach 차단이나 타이밍 트랩을 사용하지 않아 `lldb`/`gdb`/프로파일러/크래시 리포터 등 정당한 개발 도구와 충돌하지 않는다.
3. **명시적 진단 리포트**: 라이브러리가 직접 `_exit()`를 호출하지 않고 `reshield_report_t`와 선택적 `on_violation` 콜백으로 결과를 전달한다.
4. **과장 금지**: 로컬에서 실행되는 바이너리는 공격자가 바이너리와 매니페스트를 동시에 재봉인할 수 있으므로 완전한 방어가 아님을 명확히 전제한다.

## 모듈 구성

| 모듈 | 파일 | 역할 |
| --- | --- | --- |
| `integrity` | `include/reshield/integrity.h`, `src/sha256.c`, `src/integrity_*.c` | FIPS 180-4 SHA-256, `RSHLDCHK` v2(96바이트) 레코드 조회, 메모리 코드 섹션 해시 대조 |
| `manifest` | `include/reshield/manifest.h`, `src/manifest.c` | 봉인된 매니페스트 루트 해시 대조 및 에셋 파일별 크기·SHA-256 검증 |
| `attestation` | `include/reshield/attestation.h`, `src/attestation_*.c` | 코드 페이지 W^X(쓰기 금지) 권한 검증 및 macOS `SecCodeCheckValidity` 검증 |
| `runtime` | `include/reshield/reshield.h`, `src/reshield.c` | 통합 `reshield_verify()` 파이프라인, `reshield_secure_zero()` |
| `tools` | `tools/gen_manifest.py`, `tools/seal_binary.py`, `tools/verify_release.py` | 에셋 매니페스트 생성, 바이너리 봉인, 릴리스 아티팩트 CI 검증 |

## `RSHLDCHK` v2 레코드 구조 (96 bytes)

코드 섹션 외부의 데이터 영역(`__DATA,__data` / `.data`)에 `volatile` + `used`로 배치해 순환 해싱과 컴파일러 상수 접기를 방지한다.

```text
Offset  Size  Field
0       8     magic ("RSHLDCHK")
8       4     version (2)
12      4     sealed (0 = unsealed, 1 = sealed)
16      4     build_id
20      4     has_manifest (0 or 1)
24      8     expected_size (code section bytes)
32      32    expected_sha256 (code section SHA-256)
64      32    manifest_root_sha256 (manifest file SHA-256)
```
