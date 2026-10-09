# API 명세

모든 API 경로는 `/api` prefix를 사용합니다. 백엔드는 SQLite 조회와 보호된 관리자 명령을 제공합니다. 탐지와 Trust Score 판단은 `edge/`에 둡니다.

Phase 8 기기 등록·정책 API는 [기기 정책 v1 계약](contracts/device-policy-v1.md)을
따릅니다. Backend 구현과 로컬 검증은 운영 Pi 배포·Rule/Trust·화면 연동 완료와 구분합니다.

## 엔드포인트

```txt
GET /api/health
GET /api/models
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
POST /api/firewall-rules/{rule_id}/release-requests
GET /api/firewall-release-requests/{request_id}
POST /api/recovery/preflight
POST /api/recovery/execute
GET /api/recovery/history
GET /api/recovery/history/{operation_id}
POST /api/recovery/packet-pair/plans
GET /api/recovery/packet-pair/{plan_id}
POST /api/recovery/packet-pair/{plan_id}/verify
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

## 모델 정보 API

### GET /api/models

관리자 키를 요구하지 않는 공개 조회입니다. 서버에 설정된 Packet IF Artifact의
계약과 실제 실행 상태를 구분하며, 모델 활성화·역직렬화·추론은 실행하지 않습니다.
응답은 `200 {observed_at, models}`이고 `models`에는 `packet_if`, `mqtt_if`가 들어갑니다.
Artifact를 읽을 수 없거나 계약이 잘못된 경우도 해당 항목의 상태로 반환합니다.

| 항목 필드 | 의미 |
| --- | --- |
| `detector` | `packet_if` 또는 `mqtt_if` |
| `configured_model_version`, `configured_bundle_sha256` | API 서버의 설정값 또는 null. 실행 중 모델의 인증값이 아님 |
| `artifact_status` | 아래 Artifact 검사 상태 |
| `artifact` | 검증 성공 시 공개 Metadata 부분집합, 그 외 null |
| `checks` | Bundle·Metadata·Report 검사 여부와 미검증 항목 |
| `runtime` | 항상 `{status: "UNKNOWN", reason_code: "RUNTIME_MODEL_EVIDENCE_NOT_AVAILABLE"}` |
| `error_code` | 확인 불가·잘못된 계약 등의 안전한 오류 코드 또는 null |

| `artifact_status` | 의미 |
| --- | --- |
| `BUNDLE_METADATA_VERIFIED` | 외부 설정의 Bundle SHA·모델 Version, 개별 모델/Report SHA, Metadata 계약과 Report UTF-8 JSON 객체 형태 확인 |
| `UNCONFIGURED` | Packet Artifact 경로·기대 Version·기대 Bundle SHA 중 필수 설정 누락 |
| `UNAVAILABLE` | 필수 파일 누락 또는 읽기 권한/파일 접근 실패 |
| `INVALID` | Hash·Version·Metadata 계약 불일치, 잘못된 Report 형태, 크기 상한 초과 또는 안전하지 않은 경로 |
| `LEGACY_CONTRACT_UNAVAILABLE` | MQTT 기존 단일 Joblib 경로에 같은 외부 pin·Bundle·Metadata 계약이 준비되지 않음 |

공개 Metadata에는 모델·Feature·변환·Dataset·정상 정책 Version, Feature 순서,
Threshold와 비교 방향·출처, 생성 시각, Bundle/Dataset/Manifest SHA, 분할별 행 수와
정해진 CapturePolicy 필드만 포함합니다. 선택적인 `normal_policy_version`은 null일 수
있습니다. 내부 경로·임의 확장 필드·Report 원문과 평가 수치는 노출하지 않습니다.
MQTT 정책 Version을 모델 Version으로 표시하지 않습니다.

검증 성공 시 `bundle_sha256_verified`, `metadata_contract_verified`,
`report_sha256_verified`, `report_json_object_verified`는 true입니다.
`report_semantics_verified`, `model_deserialized`, `inference_verified`는 항상 false입니다.
Report의 내부 평가 수치 일치·학습 품질·공식 학습 승인·현재 Orchestrator의 라이브러리
호환성이나 로딩은 확인하지 않습니다. API 설정과 과거 탐지 이벤트도 실제 실행 증거를
대신하지 않습니다. 기기별 모델을 생성하는 API가 아닙니다.

파일당 **64 MiB**는 API가 읽는 세 Artifact 파일의 검사 상한입니다. 센서 Payload,
MQTT 학습 필터 또는 정상 허용 범위의 크기 제한과 관계없습니다.

## Packet Rule·IF 복구 관리 APIs

기존 단일 복구 엔진과 통합 관리자 CLI의 `COMPLETED` 원본 → 유일한 `RUNNING` 대상
Session 재개 경로를 조회하는 관리 API입니다. 위 모델 조회와 달리 아래 세 경로는 모두
`X-Recovery-Admin-Key`가 필요합니다. 키 미설정은 503 `RECOVERY_ADMIN_NOT_CONFIGURED`,
키 누락·불일치는 401 `RECOVERY_ADMIN_UNAUTHORIZED`입니다. `approved_by`는 서버
`RECOVERY_ADMIN_PRINCIPAL`에서 정하며 요청자가 지정하지 않습니다.

### POST /api/recovery/packet-pair/plans

다음 세 문자열만 받는 strict 요청입니다. 추가 필드·다른 자료형은 422입니다.
Session ID는 소문자 표준 UUID이고 서로 달라야 합니다. `reason`은 1~1000자이며
공백만인 값, ASCII 제어 문자와 DEL은 거부하고 앞뒤 공백을 제거합니다.

```json
{
  "source_session_id": "11111111-1111-4111-8111-111111111111",
  "target_session_id": "22222222-2222-4222-8222-222222222222",
  "reason": "완료된 수집 Session에서 현재 수집 Session으로 처리를 재개"
}
```

201 응답은 `plan_id`(Pair UUID), `plan_sha256`, source/target Session, 승인자·사유·
생성 시각, `can_execute`, `blocking_reasons`, `skips_processable`, `boundary`,
`children`, `apply_transport="ROOT_CLI"`, `runtime.status="UNKNOWN"`을 반환합니다.
`children`은 Rule/IF의 `detector`, `child_operation_id`, `checkpoint_before`,
`checkpoint_after`, 건너뛸 Session과 차단 사유를 포함합니다.

201은 새 계획 파일 저장 성공이며 복구 적용·완료가 아닙니다. `can_execute=false`인
계획도 차단 사유와 함께 저장될 수 있습니다. true여도 실제 실행 시 재검사가 필요합니다.
처리 가능 Session을 건너뛰면 기존 CLI의 같은 Plan SHA에 연결된 별도 skip 승인이
필요합니다. 승인자·DB/Artifact/출력 경로·Child ID·실행 옵션·확인 문자열은 Body에서
받지 않습니다. 원본 계획은 `<plan_id>.json`으로 새로 저장하며 기존 파일을 덮어쓰지
않습니다. 같은 Body의 반복 POST에 대한 중복 제거는 제공하지 않으며 새 계획을
만들 수 있으므로, 응답 유실을 기존 복구의 재실행 승인으로 해석하지 않습니다.

### GET /api/recovery/packet-pair/{plan_id}

서버에 저장한 표준 UUID 계획을 읽고 한 SQLite 읽기 Transaction에서 실제 Child 감사
존재와 현재 Checkpoint를 조회합니다. Backup·감사의 전체 계약 검증은 하지 않습니다.
200 응답 필드는 `plan_id`, `plan_sha256`, `observed_at`, `operation_status`,
`database_committed`, `children`, `verification`, `runtime`입니다.

`children`은 `packet_rule`/`packet_if`별 `state`, `audit_present`, `checkpoint`를
포함합니다. GET의 상태는 감사가 있으면 `COMMITTED_UNVERIFIED`, 없으면
`PENDING_UNVERIFIED`입니다. `database_committed`는 이 조회에서 감사가 하나라도
존재하는지를 표시하며 승인·Backup·실제 처리 전진까지 검증됐다는 뜻은 아닙니다.
GET의 `verification.status`는 `NOT_REQUESTED`입니다.

### POST /api/recovery/packet-pair/{plan_id}/verify

별도 Body 계약 없이 같은 계획의 Root Intent·실제 DB 감사·Before/After Checkpoint·
Backup/SHA와 기존 Root 진행 기록을 **읽기 전용**으로 대조합니다. 같은 승인 작업의
Child ID, 계획 원문·SHA, 현재 CAS와 Source ID 소비, DB/Backup integrity·FK 검증은
기존 Pair 엔진의 검증을 재사용합니다. 성공한 Child는 `APPLIED`, 미적용 Child는
`PENDING`으로 표시합니다. stdout이나 결과 파일의 `COMPLETE`만으로 Commit을
인정하지 않습니다.

| `operation_status` | 의미 |
| --- | --- |
| `PENDING` | Child 감사가 없거나 검증된 Child가 모두 미적용 |
| `COMMITTED_UNVERIFIED` | GET에서 두 Child 감사 존재를 확인했으나 전체 검증 전 |
| `PARTIAL_HOLD` | 한 Child만 적용/감사 존재. 전체 복구 완료가 아님 |
| `HOLD` | Root Intent 부재, 변경된 감사/Checkpoint/Backup 또는 잘못된 증거로 보류 |
| `APPLIED_VERIFY_REQUIRED` | verify에서 두 Child 적용을 검증했으나 현재 Runtime 전진은 미확인 |

`verification.status`는 `NOT_REQUESTED`, `VERIFIED_AUDITS`, `HOLD`, `UNKNOWN`입니다.
`VERIFIED_AUDITS`는 같은 계획의 감사와 미적용 Checkpoint 검사가 통과했다는 뜻이며
두 Child의 적용 여부는 별도 상태로 확인합니다. Root Intent가 없으면 200 HOLD/UNKNOWN,
증거가 잘못되면 200 HOLD입니다. 전체 감사가 검증됐지만 진행 파일이 없으면
`VERIFIED_AUDITS`를 유지하고 `root_progress_status="UNAVAILABLE"`로 구분합니다.
비공개 Root Artifact 읽기 권한이 없으면 503/UNKNOWN으로 반환합니다.

`root_progress_verified`는 기존 진행 파일의 SHA·승인·Checkpoint 연결을 확인했다는
뜻입니다. `root_progress_observed_at`, `root_progress_age_seconds`,
`root_progress_max_age_seconds=45`, `root_progress_fresh`로 원래 관측 시각과 최신성을
구분합니다. 선택적인 `<pair_id>.manager.json`과 연결된 Manager Journal까지 확인한
`root_completion_recorded=true`도 **과거 완료 기록**입니다. 현재 Boot·서비스 실행·모델
로딩이나 처리 전진을 인증하지 않습니다. 이 첫 API는 진행 파일이 fresh여도 현재
`COMPLETE`를 반환하지 않으며 모든 응답의 `runtime.status`는 `UNKNOWN`입니다.

### 서버 경로·권한과 구현 범위

| 설정 | 기본값 |
| --- | --- |
| `PACKET_PAIR_REPOSITORY_ROOT` | API 패키지가 있는 Repository Root |
| `DATABASE_URL` | 기존 SQLite DB 설정 |
| `PACKET_PAIR_PLAN_DIR` | `output/phase9-packet-pair-api/plans` |
| `PACKET_PAIR_ARTIFACT_DIR` | `data/recovery/packet-pair` |
| `PACKET_PAIR_MANAGER_PLAN_DIR` | `output/phase9-packet-pair-api/manager-plans` |

상대 경로는 Repository Root 기준이며 client가 경로를 지정할 수 없습니다.
Symlink/Junction을 거부하고 DB는 기존 파일을 `mode=ro`·`query_only`로 조회합니다.
계획 생성만 새 파일을 쓰며 세 API 모두 DB 감사·Checkpoint·Trust를 쓰지 않습니다.
GET/verify는 Lock·Root Progress·Journal·Backup을 갱신하지 않습니다.

적용·Resume·서비스 중단/원상복귀는 같은 Pair UUID·Plan SHA·DB·Artifact Root를 사용하는
Root 관리자 CLI로 수행합니다. HTTP apply 경로는 없습니다. API에서 sudo·서비스 제어·
Root 프로세스 시작을 하지 않으며 `iot-edge-api.service`의 `NoNewPrivileges=true`를
유지합니다. Manager Plan을 서버 설정 디렉토리의 `<pair_id>.manager.json`에 보관하는
선택 규약은 API의 과거 완료 증거 조회용이며 기존 CLI 파일명 규약을 바꾸지 않습니다.

잘못된 UUID/Body는 422, 계획 부재는 404, 서버 경로·DB·계획 생성/읽기 또는 비공개
증거 접근 불가는 503입니다. Pair 업무 오류는
`{detail:{code: "...", verification: "UNKNOWN"}}`이며 내부 경로·상세 OS 오류를
노출하지 않습니다. 인증 오류는 위 문자열 형식을 사용합니다.

현재 구현은 모델 원본 조회와 복구 계획/감사 검증의 첫 범위입니다. 운영 HTTP 서비스
배포·재시작은 하지 않았습니다. 별도 Pi 시험과 운영 Artifact의 Service 직접 읽기
확인을 운영 HTTP 검증이나 실제 실행 모델 인증으로 표시하지 않습니다. 실제 Runtime
발행, 기기별 OFF/OBSERVE 저장·적용, 모델 활성화·중단·후보 평가와 Frontend 연결은
후속이며 P9-06 전체 완료가 아닙니다. 검증 기록과 세부 계약은
[모델 정보·복구 관리 API](phase9-model-management-api.md)를 참조합니다.

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

현재 backend의 주요 API는 다음과 같습니다. 신규 API의 운영 배포 여부와
미구현 후속 범위는 각 계약을 참조합니다.

```txt
GET /api/health
GET /api/models
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
POST /api/recovery/packet-pair/plans
GET /api/recovery/packet-pair/{plan_id}
POST /api/recovery/packet-pair/{plan_id}/verify
```
