# Code-Section & Asset Manifest Verification Guide

## 1. 빌드 및 봉인 파이프라인

```bash
# 1. 에셋 매니페스트 생성
python3 tools/gen_manifest.py examples/assets -o build/sample_assets.manifest

# 2. 바이너리 빌드 및 내부 심볼 정리
make build/sample_game
cp build/sample_game build/sample_game_sealed
strip build/sample_game_sealed

# 3. 코드 섹션 SHA-256 + 매니페스트 루트 해시 봉인 (macOS는 ad-hoc codesign 자동 적용)
python3 tools/seal_binary.py build/sample_game_sealed \
  --manifest build/sample_assets.manifest \
  --build-id 1

# 4. 릴리스 아티팩트 검증 (CI/CD 용도)
python3 tools/verify_release.py build/sample_game_sealed \
  --manifest build/sample_assets.manifest \
  --assets examples/assets
```

## 2. 런타임 통합 예시

```c
#include "reshield/reshield.h"

reshield_config_t cfg = reshield_default_config();
cfg.enabled_checks |= RESHIELD_CHECK_MANIFEST;
cfg.manifest_path = "sample_assets.manifest";
cfg.asset_base_dir = "assets";

reshield_report_t report;
if (reshield_verify(&cfg, &report) != RESHIELD_OK) {
    fprintf(stderr, "Integrity error: %s\n", reshield_status_name(report.status));
    return 1;
}
```

## 3. 자동 테스트

```bash
make clean
make all test
make release-demo
```

`make test`는 SHA-256 NIST 테스트 벡터, 매니페스트/에셋 변조 탐지, W^X 페이지 권한 검증, macOS 코드 서명 검증, 코드 섹션 1바이트 손상 탐지, `-DRESHIELD_DISABLE` 개발 빌드를 모두 검증한다.

## 4. 개발 옵션과 경고

- `cfg.allow_unsealed = 1`은 런타임 필드라서 릴리스 빌드에서도 켤 수 있다. **릴리스 빌드에서 켜면 레코드의 sealed 바이트를 0으로 바꾸는 변조만으로 코드·매니페스트 검사가 우회된다. 릴리스 금지.**
- UNSEALED 판정은 레코드가 유효(magic·version 일치, 플래그 0/1)하고 `sealed == 0`일 때만 내려진다. 유효하지 않은 레코드는 `CODE_TAMPERED`, 매니페스트 검사 경로에서 sealed이지만 매니페스트 루트가 없는 바이너리는 `MANIFEST_MISMATCH`로 처리되어 `allow_unsealed`로 통과하지 못한다.
- `-DRESHIELD_DISABLE`에서도 `reshield_verify_buffer()`는 실제 해시 비교를 수행한다(앱 로직이며 무결성 검사가 아님).

## 5. 한계

- 로컬 바이너리의 자체 무결성 검증은 바이너리와 매니페스트가 동시에 재봉인되거나 런타임 API가 교체될 경우 우회될 수 있다.
- macOS 코드 서명 검증(`RESHIELD_CHECK_CODESIGN`)은 배포 시 정식 Developer ID 서명과 함께 사용할 때 신뢰성이 높아지며, ad-hoc 서명은 로컬 테스트 용도다.
