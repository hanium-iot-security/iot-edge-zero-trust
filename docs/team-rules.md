# 팀 작업 규칙

## 브랜치

- `main`: 발표와 시연이 가능한 안정 버전만 유지합니다.
- `develop`: 기능 통합 브랜치입니다.
- `feature/*`: 각자 작업 브랜치입니다.

## Pull Request 규칙

1. 모든 기능은 `feature/*` 브랜치에서 작업합니다.
2. PR 대상은 기본적으로 `develop`입니다.
3. DB schema 또는 API 응답 변경이 있으면 `docs/db-schema.md`, `db/migrations/`, `docs/api-spec.md`를 함께 수정합니다.
4. MQTT topic, device_id, status, event_type 변경은 README와 docs 전체에 함께 반영합니다.
5. 최소 1명 이상 리뷰 후 merge합니다.
6. 시연 직전에는 `develop`에서 통합 테스트 후 `main`으로 merge합니다.

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
