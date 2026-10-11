# API 명세

모든 API 경로는 `/api` prefix를 사용합니다. 백엔드는 SQLite 조회와 보호된 관리자 명령을 제공합니다. 탐지와 Trust Score 판단은 `edge/`에 둡니다.

Phase 8 기기 등록·정책 API는 [기기 정책 v1 계약](contracts/device-policy-v1.md)을
따릅니다. Backend 구현과 로컬 검증은 운영 Pi 배포·Rule/Trust·화면 연동 완료와 구분합니다.

## 엔드포인트

```txt
GET /api/health
GET /api/dashboard/summary
GET /api/devices
GET /api/devices/{device_id}
POST /api/devices
GET /api/devices/{device_id}/policy
POST /api/devices/{device_id}/policy-revisions
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
POST /api/firewall-rules/{source_rule_id}/scope-extension-requests
POST /api/firewall-rules/{rule_id}/release-requests
GET /api/firewall-release-requests/{request_id}
POST /api/recovery/preflight
POST /api/recovery/execute
GET /api/recovery/history
GET /api/recovery/history/{operation_id}
```

## Device 등록·정책 APIs

두 POST는 기존 `X-Recovery-Admin-Key` 관리자 인증을 사용합니다. 정책 GET은 기존
Devices 조회와 동일한 읽기 경로이며 관리자 키를 요구하지 않습니다.

| 경로 | 요청·응답 |
| --- | --- |
| `POST /api/devices` | `device_id`, `ip_address`, `device_type`, `mqtt_principal`, 완전한 `policy`, `reason` 입력. 201 `{device,policy}` 반환 |
| `GET /api/devices/{device_id}/policy` | 200 `{device_id,server_time,latest_revision,current,pending}`. current/pending은 revision 객체 또는 null |
| `POST /api/devices/{device_id}/policy-revisions` | `expected_revision`, `registration_state`, 완전한 `policy`, `reason` 입력. 201로 정책 GET과 같은 구조 반환 |

`policy`의 여섯 필드는 `policy_profile`, `expected_publish_interval_seconds`,
`publish_count_max`, `payload_size_max_bytes`, `packet_rate_max_pps`,
`byte_rate_max_bytes_per_second`입니다. Publish Count는 10초당 메시지 수,
Payload는 원본 바이트, Packet/Byte Rate는 유효 캡처 초당 수치입니다.
센서 주기는 설명값이며 이 API가 센서 펌웨어를 변경하지 않습니다.
정확한 자료형·상한과 요청 예시는 [공유 계약](contracts/device-policy-v1.md)과
[JSON 예시](contracts/device-policy-v1.examples.json)를 따릅니다.

신규 등록은 서버가 `PENDING`, revision 1, `iot/{device_id}/sensor` Topic과
효력 시점을 생성합니다. 효력은 DB 쓰기 잠금 후 결정한 접수 시각의 **엄격히 다음 UTC
10초 경계**입니다. 두 POST의 `server_time`과 current/pending은 이 접수 시각을 기준으로
반환합니다. 응답 도착 전에 경계를 지났더라도 pending으로 표시될 수 있으므로,
저장 후와 효력 경계 이후에는 GET으로 재조회합니다. GET은 조회 시각을 기준으로 반환합니다.

상태는 PENDING→ACTIVE, PENDING/ACTIVE→DISABLED만 전환할 수 있습니다.
DISABLED 재활성화·편집, 기기 삭제, ID/IP/type/principal 변경, 부분 PATCH는 지원하지
않습니다. 적용 예정 revision이 있거나 값이 동일하면 409이며 자동 재전송하지 않습니다.
Broker 계정·ACL 생성과 센서 설정은 별도 운영 작업입니다.

기존 `GET /api/devices`의 `{items,total}` 및 Trust status 필터, 상세 DeviceItem의 기존
필드는 유지합니다. DeviceItem에는 다음 필드가 추가됩니다.

```text
device_type, mqtt_principal, mqtt_topic, registration_state,
registration_effective_from, current_policy_revision, pending_policy_revision,
auto_response_eligible, auto_response_exclusion_reason
```

`auto_response_eligible`은 등록 정책상 자격만 표시하며 실제 차단 권한이나 통신 정상성의
증거가 아닙니다. 초기 효력 대기는 GET 200/current=null/pending=1입니다. Migration 또는
정책이 누락·손상된 기존 기기는 목록/상세 GET 200에서 등록 상태 null·eligible=false·
`POLICY_UNAVAILABLE`로 표시하고, 정책 GET과 변경은 503으로 거부합니다.
기존 backfill 기기의 `registration_effective_from=null`은 그대로 보존합니다.

오류는 기존 인증 문자열, 업무 오류 객체 `{detail:{code,message,...}}`,
422 필드 오류 배열로 구분합니다. 422 항목에는 `type`, `loc`, `msg`만 포함하며 입력 원문을
돌려주지 않습니다. 잘못된 경로 ID의 loc는 `['path','device_id']`입니다.

| 상태 | 의미 |
| --- | --- |
| 401 | 관리자 키 불일치 |
| 404 | 미등록 기기 |
| 409 | 중복 ID/IP, revision 충돌, pending 존재, 변경 없음, 금지 상태 전환, Worker/DB busy |
| 422 | 잘못된 자료형·범위·필드·기기 IP |
| 503 | 관리자 키/허용 LAN 설정 미비, Migration 또는 정책 누락·손상 |

`REVISION_CONFLICT`, `PENDING_REVISION_EXISTS`는 `current_revision`, `pending_revision`,
`latest_revision`을 함께 제공합니다. 충돌이나 결과가 불명확한 네트워크 오류는 초안을
보존한 채 GET으로 먼저 확인합니다. 비활성화는 대상 ID 또는 같은 IP의 미완료 차단/해제,
다른 IP에 남은 해당 기기의 차단 이력, 마지막 시도 이후의 fresh Runtime 관측 부재가 있으면
409로 보류합니다. API가 차단을 자동 해제하거나 sudo/iptables를 실행하지 않습니다.

운영 활성화 전 Migration 007·실제 운영값 backfill과 PENDING/DISABLED의 Rule·Trust·Worker
보호를 함께 검증해야 합니다. 서버 `DEVICE_REGISTRATION_CIDR`은 기본 공란이며,
공란/잘못된 설정이면 두 POST 모두 503입니다. 실제 DHCP 예약 LAN 및 기존 보호 IP와
공용 Firewall lock 경로·권한을 확인한 뒤 활성화합니다. 관리자 키는 검증된 SSH 포워딩
loopback 또는 HTTPS 경로에서 전송합니다. 세부 절차는
[기기 정책 API 운영 확인](device-policy-api-runbook.md)을 따릅니다.

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

Migration 011의 두 scope는 `MQTT_IPV4_TCP_1883`(Pi INPUT의 TCP 1883)와
`PI_INPUT_IPV4_ALL`(같은 source IPv4의 Pi INPUT 전체 프로토콜·포트)입니다.
자동 격리는 기존 MQTT 1883을 유지하며 기존 ID의 범위를 확대하지 않습니다.
관리자 확장은 이미 `isolated`인 기기의 `APPLIED` MQTT 규칙에서 새 광역 행을 만드는
첫 경로만 구현했습니다. 운영 Pi migration/배포는 미적용 상태이며 실제 차단·DHCP/재부팅은
미검증입니다. 자동 신규 광역 격리 정책·광역 확장 승인 Frontend는 후속 미완료 범위입니다.

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
scope
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
source_rule_id
approved_policy_revision
requested_by
request_id
```

MQTT scope의 `protocol`/`dest_port`는 `tcp`/`1883`이고 광역 scope에서는 둘 다
`null`입니다. 새 승인 메타데이터 네 필드는 nullable이며 Migration 011 이전 행에는
`null`입니다. 완전한 pre-011 DB도 조회 시 MQTT scope와 null 메타데이터를 반환합니다.
scope 필터는 제공하지 않으며 `status`, `device_id`, `source_ip`로 조회합니다.

The backend only reads DB state. It does not run Firewall Worker logic or iptables.

### POST /api/firewall-rules/{source_rule_id}/scope-extension-requests

`X-Recovery-Admin-Key` 인증으로 기존 MQTT 규칙을 광역 scope로 확장 승인합니다.
`requested_by`는 서버 인증 principal에서 파생하며 요청 Body에는 허용하지 않습니다.
Backend는 Worker와 같은 파일 lock을 얻은 뒤 `BEGIN IMMEDIATE`에서 새 ID의 `PENDING`
행을 저장합니다. 기존 source 행을 수정·제거하거나 sudo/iptables를 실행하지 않습니다.
API의 `NoNewPrivileges=true`도 유지합니다.

Request (`source_rule_id=12` 예시):

```json
{
  "device_id": "pico_01",
  "source_ip": "192.168.0.31",
  "approved_policy_revision": 1,
  "scope": "PI_INPUT_IPV4_ALL",
  "reason": "operator approved Pi input isolation",
  "request_id": "6af7a972-a852-4e21-86f3-4632c68ea331",
  "confirm": "EXTEND-PI-INPUT-12-192.168.0.31-REV-1"
}
```

모든 필드가 필수이며 미지원 필드와 자료형 변환은 거부합니다. source ID는 양의
64비트 정수, 승인 revision은 `1..2147483647` 정수, `source_ip`는 정규 RFC1918 IPv4,
`request_id`는 소문자 정규 UUID4여야 합니다. `device_id`는 영숫자로 시작하는 1~64자
ASCII 영숫자·`_`·`-`이고, `reason`은 공백 제거 후 1~500자이며 제어 문자를 허용하지
않습니다. 확인 문자열은 `EXTEND-PI-INPUT-{source_rule_id}-{source_ip}-REV-{approved_policy_revision}`입니다.

첫 승인 시 source가 `APPLIED` MQTT 규칙이고 device/IP/사양이 요청과 일치해야 합니다.
기기의 현재 상태는 `isolated`, 소유 IPv4는 요청 값, 현재 적용 정책은 `ACTIVE`이며
승인 revision과 같아야 합니다. 적용 예정 DISABLED 정책, source의 해제 대기, 같은
device/IP의 미해결 광역 규칙이 있으면 거부합니다. 과거 광역 `REMOVED`도 정확한 성공
해제 감사가 해당 제거 시각을 포함해야 다음 새 승인을 허용합니다.

Response `201`의 `item`은 GET의 전체 FirewallRuleItem입니다. 예시에서는 주요 필드만
표시합니다.

```json
{
  "item": {
    "id": 13,
    "device_id": "pico_01",
    "source_ip": "192.168.0.31",
    "scope": "PI_INPUT_IPV4_ALL",
    "protocol": null,
    "dest_port": null,
    "action": "DROP",
    "status": "PENDING",
    "reason": "operator approved Pi input isolation",
    "source_rule_id": 12,
    "approved_policy_revision": 1,
    "requested_by": "recovery-admin",
    "request_id": "6af7a972-a852-4e21-86f3-4632c68ea331"
  },
  "created": true,
  "replayed": false,
  "runtime_verified": false
}
```

동일 UUID와 principal/source/device/IP/revision/scope/reason으로 재요청하면 상태가
`FAILED` 또는 `REMOVED`여도 같은 행을 반환합니다. 재요청도 `201`이며 `created=false`,
`replayed=true`입니다. 다른 바인딩은 `409 REQUEST_ID_BINDING_MISMATCH`입니다. 응답이
유실되면 같은 UUID와 같은 요청을 재사용합니다. 새 UUID로 이전 광역 FAILED/PENDING/APPLIED
또는 미감사 REMOVED를 우회할 수 없습니다. `runtime_verified`는 항상 false이며 현재
실제 적용을 인증하지 않습니다.

Worker는 적용·복원 직전에 source/device/IP/ACTIVE 정책 revision/해제 대기를 다시
확인합니다. 최초 PENDING 광역에는 source APPLIED가 필요합니다. 이미 APPLIED인 광역은
원본 MQTT를 별도로 감사 해제한 경우에도 복원할 수 있으나 정확한 source ID의 성공
해제, non-null `released_at`, `requested_at <= released_at <= processed_at`을 요구합니다.
원본 MQTT는 광역 확인 전후 모두 자동 제거하지 않습니다. 세부 범위·운영 순서는
[Pi 입력 격리](phase9-pi-input-isolation.md)를 따릅니다.

| 상태 | 의미 |
| --- | --- |
| 401 | 관리자 인증 실패 |
| 404 | source 규칙 없음 (`SOURCE_RULE_NOT_FOUND`) |
| 409 | 확인 불일치, source/IP/상태/정책 변경, 해제 대기, 이전 광역 미해결, UUID 바인딩 충돌, Worker/DB busy |
| 422 | 잘못된 필드·자료형·scope·IPv4·UUID·reason |
| 503 | 관리자 키·잠금·DB·정책 불가, 011 미적용 (`MIGRATION_011_REQUIRED`) 또는 schema 불일치 |

업무 오류는 `{detail:{result:"DENIED",failure_code,failure_reason}}`이며 두 failure
필드는 고정 코드입니다. 422는 입력 원문을 제외한 필드 오류 배열 또는 고정 오류
문자열입니다. 완전한 pre-011 DB에서는 기존 조회·해제를 유지하고 광역 승인만 거부합니다.

### POST /api/firewall-rules/{rule_id}/release-requests

관리자가 `APPLIED` 또는 `FAILED` Firewall Rule의 공식 Release를 요청하는 Command API입니다.
Backend는 `firewall_release_requests`에 `PENDING` 요청만 저장하며, sudo/iptables
또는 `release_rule()`을 직접 실행하지 않습니다. 실제 Release는 Firewall Worker가
공유 lock 아래에서 처리합니다. 요청 저장도 같은 파일 lock 뒤 `BEGIN IMMEDIATE`를
사용합니다. 두 scope 모두 정확한 Rule ID로 따로 해제하며 같은 IP의 다른 scope는 보존합니다.

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
FAILED의 런타임 잔여 DROP 정리는 정확한 ID의 PENDING 감사 요청이 있어야 Worker가
허용합니다. 정확한 scope/IP/ID 규칙의 삭제 후 부재를 확인해야 Rule을 REMOVED로 기록하고
요청을 SUCCEEDED로 완료합니다. 삭제·확인 실패는 성공으로 반환하지 않습니다. IP·정책·
보호 주소가 바뀌어도 과거 정확한 규칙의 확인·삭제는 허용합니다. REMOVED만 먼저 기록된
중단 상황은 다음 Worker cycle에서 부재 확인 후 요청을 수렴시킬 수 있습니다.

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
- `409`: 확인 문구 불일치, 대상 Rule이 `APPLIED`/`FAILED`가 아님, 같은 Rule의 `PENDING` 요청 중복, Worker/DB busy
- `422`: 필수 필드 누락·잘못된 자료형·빈 reason
- `503`: 관리자 키 또는 잠금/DB 불가

해제할 수 없는 상태의 기존 오류 코드는 호환을 위해 `FIREWALL_RULE_NOT_APPLIED`를
유지합니다. 해제 요청의 201은 실제 해제 성공과 별개입니다. Runtime DROP이 남아 있는
FAILED 규칙은 Baseline 복구를 통과하지 못하며 마지막 해제 시도 이후의 새 관측이 필요합니다.

### GET /api/firewall-release-requests/{request_id}

Firewall Release Request 처리 상태를 조회합니다. `PENDING`, `SUCCEEDED`, `FAILED`
중 하나를 반환합니다. `FAILED`인 경우 `last_error`에 Worker 실패 사유가 저장됩니다.
POST와 같은 관리자 헤더가 필요하며 정상 조회는 `200 {item: ...}`입니다.

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

현재 backend의 주요 API는 다음과 같습니다. 신규 API의 운영 배포 여부와
미구현 후속 범위는 각 계약을 참조합니다.

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
POST /api/firewall-rules/{source_rule_id}/scope-extension-requests
POST /api/firewall-rules/{rule_id}/release-requests
GET /api/firewall-release-requests/{request_id}
POST /api/recovery/preflight
POST /api/recovery/execute
GET /api/recovery/history
GET /api/recovery/history/{operation_id}
```
