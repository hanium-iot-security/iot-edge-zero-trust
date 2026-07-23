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
GET /api/packet-feature-logs
GET /api/gateway-metrics
GET /api/detection-events
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
GET /api/isolation/history
GET /api/firewall-rules
```

## Packet Gateway Read APIs

### GET /api/packet-feature-logs

Query parameters:

- `session_id`
- `device_id`
- `peer_ip`
- `direction`: `INBOUND` or `OUTBOUND`
- `from`: timezone-aware ISO 8601 timestamp
- `to`: timezone-aware ISO 8601 timestamp
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

Response wrapper:

```json
{
  "items": [],
  "total": 0
}
```

Each item includes packet window fields from `packet_feature_logs`, the joined `session_id`, UTC `Z` timestamps, and derived values based on the fixed 10 second packet window:

```text
packets_per_second = packet_count / 10.0
bytes_per_second = total_bytes / 10.0
nominal_packets_per_second = packet_count / 10.0
nominal_bytes_per_second = total_bytes / 10.0
```

`packets_per_second` and `bytes_per_second` are kept as nominal-rate aliases for backward compatibility.

If `packet_capture_segments.captured_duration_seconds` is available and greater than `0`, the API also returns:

```text
effective_packets_per_second = packet_count / captured_duration_seconds
effective_bytes_per_second = total_bytes / captured_duration_seconds
coverage_ratio = captured_duration_seconds / 10.0
```

If the duration is `NULL` or `0`, `effective_packets_per_second` and `effective_bytes_per_second` are `null`. `capture_eligible` and `capture_exclusion_reason` are reserved for the shared capture policy integration; this PR does not duplicate another owner's capture eligibility algorithm.

Unmapped peer IP rows return `device_id: null`. Empty results return `items: []` and `total: 0`.

### GET /api/gateway-metrics

Query parameters:

- `from`: timezone-aware ISO 8601 timestamp
- `to`: timezone-aware ISO 8601 timestamp
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

`GET /api/gateway-metrics?limit=1` returns the latest gateway metric row by `collected_at DESC, id DESC`.

Response wrapper:

```json
{
  "items": [],
  "total": 0
}
```

The API parses DB `interface_metrics_json` into the response field `interface_metrics`. It preserves role keys such as `internal_lan` and `usb_lan`, interface names, `exists`, `is_up`, IP address, counters, rates, and null values.

The following DB/internal fields are not exposed in the response:

- `interface_metrics_json`
- `network_rx_bytes`
- `network_tx_bytes`
- `created_at`
- `disk_total_mb`
- `gateway_status`

First samples may return `sample_interval_seconds: null`, `cpu_percent: null`, `temperature_c: null`, and null interface rates. Missing USB LAN is represented inside `interface_metrics.usb_lan` with `exists: false` and `is_up: false`.

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
  "database": "ok"
}
```

DB 연결 오류 시 실제 DB 경로, SQL, stack trace, 환경변수, secret은 노출하지 않고 다음처럼 상태만 반환합니다.

```json
{
  "status": "degraded",
  "database": "error"
}
```

## Detection Events

### GET /api/detection-events

Query parameters:

- `device_id`
- `detector_type`: `RULE` or `AI`
- `event_type`
- `incident_family`
- `subject_ip`
- `applied_to_score`: `0` or `1`
- `processing_reason`
- `window_start_from`: timezone-aware ISO 8601 timestamp
- `window_end_to`: timezone-aware ISO 8601 timestamp
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

Response items include Phase 4 source FK fields, Trust processing metadata, UTC `Z` timestamps, and parsed `evidence`.

```text
evidence_json -> evidence object
```

Input validation errors return `422`. Stored JSON or timestamp conversion errors return `500`.

## Trust Score History

### GET /api/trust-score/{device_id}/history

Phase 4 reads from `trust_score_history`. It does not recalculate history by summing `detection_events.score_delta`.

Items are sorted by:

```text
analysis_window_end DESC, id DESC
```

`representative_event_ids_json` is parsed into `representative_event_ids`.

## Isolation History 응답 예시

```json
{
  "id": 1,
  "device_id": "esp32_01",
  "action": "ISOLATED",
  "reason": "Trust Score below threshold",
  "trust_score": 25,
  "trigger_event_id": 9,
  "trust_score_history_id": 3,
  "created_at": "2026-05-26 14:35:00"
}
```

`devices.status`는 현재 상태값이므로 `isolated`를 사용하고, `isolation_history.action`은 이력 action 코드이므로 `ISOLATED`를 사용합니다.

Isolation History는 Trust 정책상 격리 결정을 표현합니다. 실제 네트워크 차단 적용 여부는 `firewall_rules.status`와 Firewall Worker 결과로 구분합니다.

## Firewall Rules

### GET /api/firewall-rules

Query parameters:

- `status`: `PENDING`, `APPLIED`, `FAILED`, or `REMOVED`
- `device_id`
- `source_ip`
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

Invalid `status` returns `422`.

Response wrapper:

```json
{
  "items": [],
  "total": 0
}
```

Each item includes:

```text
id
device_id
source_ip
protocol
dest_port
action
status
reason
trigger_event_id
retry_count
last_error
last_attempted_at
next_retry_at
applied_at
released_at
created_at
updated_at
```

The backend only reads DB state. It does not run Firewall Worker logic or iptables.

## 현재 구현 상태

현재 backend에 구현된 조회 API는 다음과 같습니다.

```txt
GET /api/health
GET /api/dashboard/summary
GET /api/devices
GET /api/devices/{device_id}
GET /api/mqtt-logs
GET /api/feature-logs
GET /api/packet-feature-logs
GET /api/gateway-metrics
GET /api/detection-events
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
GET /api/isolation/history
GET /api/firewall-rules
```
