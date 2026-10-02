# API 명세

모든 API 경로는 `/api` prefix를 사용합니다. 백엔드는 SQLite를 조회해 대시보드용 JSON을 반환합니다. 탐지와 Trust Score 판단은 `edge/`에 둡니다.

Phase 8에서 추가할 기기 등록·정책 API의 구현 계약과 가상 응답은
[기기 정책 v1 계약](contracts/device-policy-v1.md)을 참고합니다.
해당 신규 경로는 아직 구현 전이며 아래 기존 엔드포인트와 구분합니다.

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
GET /api/trust-score/compensations
GET /api/isolation/history
GET /api/firewall-rules
POST /api/firewall-rules/{rule_id}/release-requests
GET /api/firewall-release-requests/{request_id}
POST /api/recovery/preflight
POST /api/recovery/execute
GET /api/recovery/history
GET /api/recovery/history/{operation_id}
```

## Packet Gateway Read APIs

### GET /api/packet-feature-logs

Query parameters:

- `session_id`
- `device_id`
- `peer_ip`
- `direction`: `INBOUND` or `OUTBOUND`
- `capture_eligible`: 현재 지원하지 않으며 전달 시 `422`를 반환
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

The API joins the source Capture Segment metadata and returns:

- `segment_status`
- `segment_error_code`
- `start_delay_seconds`
- `captured_duration_seconds`

It evaluates that metadata with the shared
`edge.packet.capture_policy.is_capture_eligible()` contract and returns:

```text
effective_packets_per_second = packet_count / captured_duration_seconds
effective_bytes_per_second = total_bytes / captured_duration_seconds
coverage_ratio = shared capture policy result
capture_eligible = shared capture policy eligibility result
capture_exclusion_reason = shared capture policy exclusion reason
```

If the duration is `NULL` or `0`, `effective_packets_per_second` and
`effective_bytes_per_second` are `null`. Missing or invalid Segment timing is
fail-closed by the shared policy, so `capture_eligible` is `false` and
`capture_exclusion_reason` contains the policy reason such as
`missing_timing_metadata`.

Exact server-side `capture_eligible` filtering is intentionally unsupported.
The endpoint returns `422` when that query parameter is supplied rather than
duplicating the policy in SQL or evaluating the entire result set outside the
paginated query. The Dashboard applies its Capture analysis status dropdown
only to the current API page and does not send this query parameter. Its
eligible/excluded/failed summary is also explicitly limited to the current page.

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

`GET /api/mqtt-logs`는 `id DESC`인 DB 수신·적재 순서로 반환합니다. 기존 Subscriber의
KST Local Naive 공백값과 SQLite `CURRENT_TIMESTAMP`의 UTC 공백값은 문자열만으로 구분할 수
없으므로 이 순서를 실제 Timestamp 순서라고 표현하지 않습니다. 응답의 `received_at` 원문은
변환하지 않습니다.

## Health 응답

```json
{
  "status": "ok",
  "database": "ok",
  "db_connected": true,
  "server_time": "2026-05-26T05:35:00Z"
}
```

DB 연결 오류 시 실제 DB 경로, SQL, stack trace, 환경변수, secret은 노출하지 않고 다음처럼 상태만 반환합니다.

```json
{
  "status": "degraded",
  "database": "error",
  "db_connected": false,
  "server_time": "2026-05-26T05:35:00Z"
}
```

`db_connected`와 `server_time`은 기존 Dashboard 호환성을 위해 유지합니다. `server_time`은 UTC `Z` 형식입니다.

API CORS 설정은 `.env.example`의 다음 값을 기준으로 합니다.

```text
API_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
API_ALLOW_CREDENTIALS=true
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

Input validation errors return `422`. Stored JSON or timestamp conversion errors return `500`; malformed stored rows are server data errors, not user request errors.

AI 관찰 완료 이벤트는 기존 응답 형식으로 `processing_reason=AI_OBSERVATION_ONLY`,
`processed_at`, `applied_to_score=0`, `score_delta=0`을 반환합니다. 처리 사유는 자유 문자열이며
같은 값으로 필터링할 수 있습니다. `evidence.trust_decision`에는 `ai_mode=observe`,
`policy_version=trust-ai-observation-v1`, 원래 저장값 `original_score_delta`, 공통 정책의
`policy_score_delta`, `actual_delta=0`, 처리 cutoff인 `processed_at`을 보존합니다.
Event 최상위 `policy_version`은 탐지 정책 버전으로 유지합니다. 이미 관찰 완료한 이벤트는
모드 전환 후에도 재감점하지 않습니다. `applied_to_score=0`은 처리 완료된 관찰·제외도
포함하므로 미처리 건수로 해석하지 않습니다. 자세한 적용 절차는
[AI 관찰 모드 운영 가이드](ai-observation-mode-runbook.md)를 참고합니다.

## Trust Score History

### GET /api/trust-score/{device_id}/history

Phase 4 reads from `trust_score_history`. It does not recalculate history by summing `detection_events.score_delta`.

Items are sorted by:

```text
analysis_window_end DESC, id DESC
```

`representative_event_ids_json` is parsed into `representative_event_ids`.

### GET /api/trust-score/compensations

Recovery Dashboard는 운영 DB를 직접 읽지 않고 승인형 Trust Score 보상 이력을 이
읽기 API로 조회합니다. 이 API는 `trust_score_compensations`만 조회하며 Detection
History나 Baseline Recovery Audit과 하나의 Timeline으로 합치지 않습니다.

관리자 헤더:

```text
X-Recovery-Admin-Key: <RECOVERY_ADMIN_API_KEY>
```

Query parameters:

- `device_id`
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

Response item:

```text
id
operation_id
device_id
source_event_id
source_trust_history_id
previous_score
compensation_delta
new_score
reason
approved_by
backup_reference
backup_sha256
created_at
```

`backup_reference`는 서버 내부 절대 경로가 아니라 파일명만 노출합니다.

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
  "created_at": "2026-05-26T05:35:00Z"
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

### POST /api/firewall-rules/{rule_id}/release-requests

관리자가 `APPLIED` Firewall Rule의 공식 Release를 요청하는 Command API입니다.
Backend는 `firewall_release_requests`에 `PENDING` 요청만 저장하며, sudo/iptables
또는 `release_rule()`을 직접 실행하지 않습니다. 실제 Release는 Firewall Worker가
공유 lock 아래에서 처리합니다.

관리자 헤더:

```text
X-Recovery-Admin-Key: <RECOVERY_ADMIN_API_KEY>
```

Request:

```json
{
  "reason": "official release approved",
  "confirm": "RELEASE-FIREWALL-RULE-12"
}
```

`confirm`은 Rule ID에 묶인 `RELEASE-FIREWALL-RULE-{rule_id}` 값이어야 합니다.
`requested_by`는 요청 Body가 아니라 인증된 관리자 principal에서 파생합니다.

Response `201`:

```json
{
  "item": {
    "id": 1,
    "firewall_rule_id": 12,
    "status": "PENDING",
    "requested_by": "recovery-admin",
    "reason": "official release approved",
    "requested_at": "2026-08-22T00:00:00Z",
    "processed_at": null,
    "last_error": null,
    "created_at": "2026-08-22T00:00:00Z",
    "updated_at": "2026-08-22T00:00:00Z"
  }
}
```

Error:

- `401`: 관리자 인증 실패
- `404`: 대상 Firewall Rule 없음
- `409`: 확인 문구 불일치, 대상 Rule이 `APPLIED`가 아님, 같은 Rule의 `PENDING` 요청 중복

### GET /api/firewall-release-requests/{request_id}

Firewall Release Request 처리 상태를 조회합니다. `PENDING`, `SUCCEEDED`, `FAILED`
중 하나를 반환합니다. `FAILED`인 경우 `last_error`에 Worker 실패 사유가 저장됩니다.

## Recovery Command APIs

Recovery API는 격리된 Device를 `normal`/`100` Baseline으로 되돌리는 관리 Command
어댑터입니다. 실제 상태 변경은 `edge.trust.baseline_recovery` 코어가 수행하며,
Backend는 직접 `devices`를 UPDATE하지 않습니다. 이 API는 systemd 제어, iptables
조회 계층 생성, Firewall Release 실행, Firewall Worker 실행을 하지 않습니다.

관리자 헤더:

```text
X-Recovery-Admin-Key: <RECOVERY_ADMIN_API_KEY>
```

`approved_by`와 `requested_by`는 요청 Body가 아니라 인증된 Recovery 관리자
principal(`RECOVERY_ADMIN_PRINCIPAL`)에서 파생합니다. Secret은 URL query parameter로
받지 않습니다.

환경변수:

```text
RECOVERY_ADMIN_API_KEY=
RECOVERY_ADMIN_PRINCIPAL=recovery-admin
RECOVERY_ARTIFACT_DIR=data/recovery/baseline
```

### POST /api/recovery/preflight

Request:

```json
{
  "device_id": "esp32_01",
  "expected_trust_score": 20
}
```

Preflight는 읽기 전용이며 Recovery artifact나 backup을 생성하지 않습니다. 검사 항목:

- Device 존재
- 현재 `devices.status='isolated'`
- 현재 Trust Score와 `expected_trust_score` 일치
- DB의 `PENDING`/`APPLIED` Firewall Rule 0건
- DB의 `PENDING` Firewall Release Request 0건
- Runtime Firewall verification
- `processed_at IS NULL` Detection Event 0건
- Backup artifact 경로 사용 가능성

현재 Backend가 소유한 안전한 runtime firewall read verifier가 없으면
`firewall_runtime_verification.status='UNAVAILABLE'`, `result='HOLD'`,
`can_execute=false`로 실패 폐쇄합니다. Backend가 새 subprocess/iptables 조회 계층을
만들어 PASS로 추정하지 않습니다.

설정된 Runtime Snapshot도 TTL뿐 아니라 마지막 차단·해제 동작 이후의 관측인지
확인합니다. 대상 Device 또는 같은 IP의 Firewall 시도·적용·해제·Release 처리와
동일한 초이거나 더 오래된 관측은 `UNAVAILABLE`/`HOLD`입니다.

Response:

```json
{
  "device_id": "esp32_01",
  "current_status": "isolated",
  "current_trust_score": 20,
  "can_execute": false,
  "result": "HOLD",
  "firewall_db_state": {
    "passed": true,
    "count": 0,
    "active_statuses": ["PENDING", "APPLIED"],
    "rules": []
  },
  "firewall_release_request_state": {
    "passed": true,
    "count": 0,
    "statuses": [],
    "request_ids": [],
    "requests": []
  },
  "firewall_runtime_verification": {
    "available": false,
    "passed": false,
    "status": "UNAVAILABLE",
    "rule_count": null,
    "details": "No backend-owned read-only runtime firewall verifier is configured."
  },
  "unprocessed_detection_count": 0,
  "backup_check": {
    "artifact_dir": "data/recovery/baseline",
    "available": true,
    "failure_reason": null
  },
  "failure_code": "FIREWALL_RUNTIME_UNAVAILABLE",
  "failure_reason": "No backend-owned read-only runtime firewall verifier is configured.",
  "preflight_errors": []
}
```

### POST /api/recovery/execute

Request:

```json
{
  "device_id": "esp32_01",
  "expected_trust_score": 20,
  "reason": "official firewall release completed",
  "confirm": "RESET-TO-NORMAL-100"
}
```

Execute는 승인·인증 후 preflight를 즉시 다시 수행합니다. 통과하지 못하면
`409`와 `DENIED` 또는 `HOLD` audit payload를 반환하고 baseline recovery core를
호출하지 않습니다. 성공 조건에서는 기존 baseline recovery core가 SQLite Backup API,
SHA256, integrity check, foreign key check, 조건부 UPDATE를 수행합니다.

Core는 Firewall Worker와 같은 잠금을 먼저 얻고 DB 쓰기 잠금을 획득한 뒤 Runtime
Snapshot을 재검증합니다. Backup 전과 Commit 직전에 모두 검증하므로 사전검사 통과
후 새 차단 시도가 생기거나 Snapshot이 만료되면 `409`/`HOLD`로 보류하며 점수·상태
변경을 Rollback합니다. 이때 응답과 Audit의 `firewall_release_status`는
`NOT_VERIFIED`입니다. 같은 Core를 사용하는 CLI에도 이 검사가 적용됩니다.

성공 Response:

```json
{
  "operation_id": "20260810T010000Z-abcdef123456",
  "result": "SUCCESS",
  "device_id": "esp32_01",
  "reason": "official firewall release completed",
  "requested_by": "recovery-admin",
  "approved_by": "recovery-admin",
  "requested_at": "2026-08-10T01:00:00Z",
  "before_status": "isolated",
  "before_trust_score": 20,
  "after_status": "normal",
  "after_trust_score": 100,
  "firewall_release_status": "VERIFIED_RELEASED",
  "backup_reference": "baseline-recovery-20260810T010000Z-abcdef123456.db",
  "backup_sha256": "..."
}
```

부분 실패나 사전 Gate 실패는 성공으로 반환하지 않습니다. Firewall Release 성공과
Baseline Recovery 성공은 별도 의미이며, 이 API는 Firewall Release 자체를 실행하지
않습니다.

### GET /api/recovery/history

Baseline Recovery JSON artifact와 Recovery Command denial/failure artifact를 읽어
정규화한 목록을 반환합니다. 서버 내부 절대 backup path는 노출하지 않고 파일명
`backup_reference`와 `backup_sha256`만 제공합니다.

동일 Recovery 요청에서 `baseline-recovery-*.json`과 `recovery-command-*.json`이
함께 생성되더라도 두 artifact는 하나의 `operation_id`를 공유해야 합니다.
History 응답은 `operation_id` 기준으로 정규화하여 Recovery 요청 1건을 operation
1건으로 노출합니다. DB commit 이후 JSON audit 저장 또는 사후 검증이 실패한 경우
fallback audit은 실제 DB의 Device 사후 상태와 생성된 backup 파일명/SHA256을
보존합니다.

Query parameters:

- `device_id`
- `result`: `SUCCESS`, `DENIED`, `HOLD`, or `FAILED`
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

### GET /api/recovery/history/{operation_id}

단일 Recovery audit item을 조회합니다. Detection Trust History, Trust Compensation,
Baseline Recovery는 P0에서 서로 다른 Source로 유지하며 통합 Timeline은 후속 P1
범위입니다.

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
GET /api/trust-score/compensations
GET /api/isolation/history
GET /api/firewall-rules
POST /api/recovery/preflight
POST /api/recovery/execute
GET /api/recovery/history
GET /api/recovery/history/{operation_id}
```
