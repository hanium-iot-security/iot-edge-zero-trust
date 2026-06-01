# API 명세

모든 API 경로는 `/api` prefix를 사용합니다. 백엔드는 SQLite를 조회해 대시보드용 JSON을 반환합니다. 탐지와 Trust Score 판단은 `edge/`에 둡니다.

## 엔드포인트

```txt
GET /api/health
GET /api/dashboard/summary
GET /api/devices
GET /api/devices/{device_id}
GET /api/mqtt-logs
GET /api/feature-logs
GET /api/detection-events
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
GET /api/isolation/history
```

MVP에서는 중복 endpoint를 줄이기 위해 기기별 feature/event 조회는 query parameter 방식으로 처리합니다.

```txt
/api/feature-logs?device_id=esp32_01
/api/detection-events?device_id=esp32_01
```

최근 MQTT 로그, feature 로그, 탐지 이벤트를 한 번에 묶어 반환하는 `/api/dashboard/recent`는 MVP 필수 API에서 제외하고, 프론트엔드에서 필요한 API를 각각 호출합니다.

기본 조회 예시:

예: `/api/mqtt-logs?device_id=esp32_01&limit=100`

## Health 응답

```json
{
  "status": "ok",
  "db_connected": true,
  "server_time": "2026-05-26 14:35:00"
}
```

## Isolation History 응답 예시

```json
{
  "id": 1,
  "device_id": "esp32_01",
  "action": "ISOLATED",
  "reason": "Trust Score below threshold",
  "trust_score": 25,
  "trigger_event_id": 9,
  "created_at": "2026-05-26 14:35:00"
}
```

`devices.status`는 현재 상태값이므로 `isolated`를 사용하고, `isolation_history.action`은 이력 action 코드이므로 `ISOLATED`를 사용합니다.

## 현재 구현 상태

현재 구현된 API는 `/api/health`입니다. 나머지 endpoint는 다음 API 구현 단계에서 맞춰야 할 MVP 계약입니다.
