# 팀 작업 규칙

## 브랜치

- `main`: 발표와 시연이 가능한 안정 버전만 유지합니다.
- `develop`: 기능 통합 브랜치입니다.
- `feature/<담당자>-<작업내용>`: 기능 구현·수정과 관련 문서를 함께 작업합니다.
- `docs/*`: 코드 변경이 없는 공통 문서·협업 양식 작업에 사용합니다. `docs/<담당자>-<주제>` 형식을 권장합니다.

## Pull Request 규칙

1. 기능 구현·수정은 `feature/*`, 코드 변경 없는 공통 문서는 `docs/*` 브랜치에서 작업합니다. PR 대상은 기본적으로 `develop`입니다.
2. [PR 템플릿](../.github/pull_request_template.md)의 10개 제목을 유지하고 해당하지 않는 항목은 `해당 없음`으로 표시합니다. 의존 PR과 병합 순서를 적습니다.
3. DB 구조를 변경하면 `db/migrations/`와 `docs/db-schema.md`를 갱신하고 Migration 재실행·기존 데이터 보존·복구를 확인합니다.
4. API 계약을 변경하면 `docs/api-spec.md`, 사용하는 Mock·호출부·화면의 영향을 확인하고 필요한 부분을 갱신합니다. API만 변경한 경우 DB Migration을 요구하지 않습니다.
5. MQTT Topic, Device ID, 상태값, Event Type, Feature·모델·Threshold, Window·단위·시간 계약을 변경하면 관련 코드·설정·테스트와 해당 내용을 설명하는 문서를 함께 확인합니다. 변경과 무관한 문서를 일괄 수정하지 않습니다.
6. 작성자 외 팀원 최소 1명이 변경 코드·검증 근거를 검토하고 승인한 뒤 병합합니다. 작성자의 체크리스트 완료나 테스트 통과만으로 리뷰를 대신하지 않습니다.
7. 병합 전 필수로 남긴 검증과 미해결 필수 수정 의견은 병합 전에 완료합니다. 배포 전 필수 검증은 운영 적용 전에 완료하며, 팀원의 로컬 개발과 운영 배포를 구분합니다.
8. 시연 직전에는 `develop`에서 통합 테스트 후 `main`으로 merge합니다.

## 검증 상태와 리뷰 근거

- **통과 / 실패:** 실제 실행한 Commit·환경·명령 또는 시나리오, 기대 결과와 실제 결과를 남깁니다. 테스트의 skip·경고를 숨기지 않습니다.
- **미검증:** 이번 PR에서 바꾼 동작 중 실행하지 못한 검증입니다. 사유·담당·병합 전 또는 배포 전 완료 시점을 적고 완료 체크하지 않습니다. 새 플랫폼 전용 안전 경로의 합성 회귀는 병합 전, 실제 장비 운영 조건은 배포 전 검증으로 구분할 수 있습니다.
- **해당 없음:** 이번 변경에 적용되지 않는 항목입니다. 미검증과 구분하고 억지로 완료 체크하지 않습니다.
- **후속 작업:** 이번 PR 범위 밖의 작업입니다. 제외 범위에 작업 ID·링크를 적고 현재 PR의 미완료 체크에 섞지 않습니다.
- 화면 변경은 주요 화면·실패 상태, API·탐지·장비 변경은 핵심 응답·실행 로그를 남깁니다. 긴 로그는 접기 블록이나 팀원이 접근 가능한 공유/CI 링크를 사용합니다. 개인 PC 경로만으로 검증 근거를 대신하지 않습니다.
- 스크린샷·로그에서 비밀번호·토큰·개인정보를 제거합니다. 개인 `output/`과 운영 DB·설정 원본·모델·대용량 수집 자료는 Git에 올리지 않습니다. 필요한 공유 증거는 비밀값을 제거한 요약이나 별도 공유 자료로 제공합니다.

## 구현 경계

탐지·Trust 판단과 방화벽 실행은 `edge`에서 담당합니다. `backend`는 조회와 관리자 명령의 인증·입력 검증·요청 저장·기존 Edge 기능 호출을 담당합니다. 관리자 API에 탐지·감점 로직이나 직접적인 OS 방화벽 실행을 중복 구현하지 않습니다. `frontend`의 표시나 버튼 비활성화만으로 서버 권한 검증을 대신하지 않습니다.

## Commit Message 예시

```txt
feat: mqtt subscriber stores normal telemetry
feat: rule detection saves flooding events
feat: train isolation forest model
feat: apply trust score penalty
feat: dashboard shows detection events
fix: handle malformed mqtt payload
docs: update demo scenario
```

## MVP 상수

```txt
MQTT topic: iot/{device_id}/sensor
구독 topic: iot/+/sensor
기본 device_id: esp32_01
상태값: normal, warning, danger, isolated
격리 기준: trust_score < 30
```

## Label

```txt
backend
frontend
firmware
mqtt
db
detection
ai
trust-score
docs
bug
integration
```
