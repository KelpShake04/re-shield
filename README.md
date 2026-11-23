# re-shield

자사(1st-party) 네이티브 소프트웨어·게임의 **빌드 무결성(Code Integrity)**, **에셋 매니페스트 바인딩(Asset Manifest Binding)**, **실행 환경 권한·서명 검증(W^X & OS Code Signing)**을 제공하는 C11 유저스페이스 라이브러리 및 빌드 도구다.

## 목적

네이티브 애플리케이션·게임의 실행 파일이나 외부 스테이지·설정 리소스가 무단으로 변조되거나 분리 복제되는 것을 감지하고, 릴리스 파이프라인에서 아티팩트 무결성을 검증할 수 있도록 최소 침습 런타임(`libreshield.a`)과 후처리 CLI를 제공한다.

## 핵심 기능

- **코드 섹션 무결성 (`include/reshield/integrity.h`)**: 외부 의존성 없는 FIPS 180-4 SHA-256 구현으로 빌드 시 실행 파일의 코드 섹션(`__TEXT,__text` / `.text`) 해시를 기록하고 런타임에 메모리에서 재검증.
- **에셋 매니페스트 바인딩 (`include/reshield/manifest.h`)**: `tools/gen_manifest.py`로 에셋 디렉터리의 SHA-256 매니페스트를 생성하고, 그 루트 해시를 바이너리에 함께 봉인해 실행 파일과 리소스 번들의 짝을 런타임에 검증.
- **메모리 W^X 및 OS 코드 서명 검증 (`include/reshield/attestation.h`)**:
  - macOS: `mach_vm_region`으로 코드 세그먼트의 W^X(읽기·실행 전용, 쓰기 금지) 확인 및 `Security.framework`(`SecCodeCheckValidity`) 코드 서명 검증.
  - Linux: `/proc/self/maps`로 `.text` 매핑이 `r-xp` 권한을 유지하는지 확인.
- **구조화된 진단 리포트 (`include/reshield/reshield.h`)**: 라이브러리가 프로세스를 임의 강제 종료하지 않고 `reshield_report_t`와 콜백을 반환해 호스트 앱이 안내·로깅·안전 종료를 결정.
- **릴리스 검증 CLI (`tools/verify_release.py`)**: CI/CD 단계에서 바이너리 봉인, 매니페스트 일치, 정의 심볼 수를 자동 검증.

## Non-goals / Anti-goals

- 서버 라이선스 인증, DRM 전체 시스템 (범위 밖).
- 커널 레벨 방어(안티치트 드라이버, kext/커널 모듈) — 100% 유저스페이스 구현만 유지.
- "절대 못 뚫는다"는 주장 — 로컬 실행 파일의 자체 무결성 검증은 변조 마찰을 높이고 사고성·단순 변조를 감지하기 위한 것이며, 절대 방어가 아니다.
- 정당한 개발·디버깅·프로파일링 방해 — 디버거 attach 차단(`ptrace`)을 사용하지 않으며, `-DRESHIELD_DISABLE` 및 `allow_unsealed`로 개발 빌드를 지원한다.

## 빠른 시작

```bash
make all
make test
make release-demo
```

- 아키텍처 설계 및 한계: [docs/architecture.md](docs/architecture.md)
- 코드 섹션·에셋 매니페스트 봉인 및 검증 가이드: [docs/integrity-verification.md](docs/integrity-verification.md)

## 개발·테스트 빌드 옵션

- `-DRESHIELD_DISABLE`: `reshield_verify()` 등 모든 런타임 무결성 검증을 no-op으로 비활성화. 단 `reshield_verify_buffer()`는 앱 로직(예: 키 커밋먼트 비교)이므로 이 빌드에서도 실제 SHA-256 비교를 수행한다.
- `cfg.allow_unsealed = 1`: `tools/seal_binary.py`를 거치지 않은 로컬 개발 빌드 허용. **경고: 릴리스 빌드에서 켜면 sealed 바이트 변조만으로 코드·매니페스트 검사가 우회된다. 릴리스 금지.** (레코드 magic/version 불일치나 매니페스트 없이 봉인된 바이너리는 unsealed로 취급하지 않고 실패 처리한다.)
