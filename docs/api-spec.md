# API 명세

모든 API 경로는 `/api` prefix를 사용합니다. 백엔드는 SQLite 조회와 보호된 관리자 명령을 제공합니다. 탐지와 Trust Score 판단은 `edge/`에 둡니다.

Phase 8 기기 등록·정책 API는 [기기 정책 v1 계약](contracts/device-policy-v1.md)을
따릅니다. Backend 구현과 로컬 검증은 운영 Pi 배포·Rule/Trust·화면 연동 완료와 구분합니다.

## 엔드포인트

```txt
GET /api/health
GET /api/models
GET /api/runtime-status
GET /api/ai-warnings
GET /api/dashboard/summary
GET /api/devices
GET /api/devices/{device_id}
POST /api/devices
GET /api/devices/{device_id}/policy
POST /api/devices/{device_id}/policy-revisions
GET /api/devices/{device_id}/ai-policy
POST /api/devices/{device_id}/ai-policy-revisions
GET /api/mqtt-logs
GET /api/feature-logs
GET /api/packet-feature-logs
GET /api/packet-capture-windows
GET /api/gateway-metrics
GET /api/detection-events
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
GET /api/trust-score/compensations
GET /api/isolation/history
GET /api/firewall-rules
GET /api/firewall-runtime-status
POST /api/firewall-rules/{source_rule_id}/scope-extension-requests
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
신규 등록에는 Migration 012가 필요하며, 초기 AI 모드 `OFF` revision을 기기·등록 정책과
같은 트랜잭션에 기록합니다. AI 정책 테이블이 없거나 필수 컬럼이 누락되면 503
`AI_POLICY_UNAVAILABLE`을 반환하고, AI 초기 기록 실패 시 기기·등록 정책을 포함한
전체 등록이 rollback됩니다.

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
| 503 | 관리자 키/허용 LAN 설정 미비, Migration 또는 정책 누락·손상, 신규 등록의 AI 정책 스키마 불가 (`AI_POLICY_UNAVAILABLE`) |

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

## Device AI 설정 APIs

Migration 012의 기기별 AI 설정을 읽고 새 revision으로 변경합니다. 기존 등록·Rule 정책
API와 응답은 유지합니다. 선택 모드 저장만 수행하며 Stage 활성화, 모델 로딩, 시작
Checkpoint 적용, 추론·Trust·방화벽 실행은 하지 않습니다. 실제 실행 상태와 구분해야 합니다.

| 경로 | 요청·응답 |
| --- | --- |
| `GET /api/devices/{device_id}/ai-policy` | 관리자 키 없이 200 `{device_id,server_time,latest_revision,current,pending}` |
| `POST /api/devices/{device_id}/ai-policy-revisions` | 기존 `X-Recovery-Admin-Key` 인증. 아래 세 필드만 입력하고 저장 후 201로 GET과 같은 구조 반환 |

```json
{
  "expected_revision": 1,
  "mode": "OBSERVE",
  "reason": "검토한 후보의 관찰 설정"
}
```

`expected_revision`은 양의 정수이며 숫자 문자열·실수·bool을 거부합니다. `mode`는
`OFF` 또는 `OBSERVE`만 허용합니다. 사유는 기존 정책과 동일하게 앞뒤 공백 제거 후
1~500자이며 제어 문자를 거부합니다. `created_by`, 효력 시각, 모델·Stage·기기 ID 등
추가 필드를 입력할 수 없습니다. 작성자는 서버의 인증 principal입니다.

current/pending은 null 또는 `device_id,revision,mode,effective_from,created_at,created_by,reason`
객체입니다. 등록 직후에는 current=null, pending=OFF revision 1일 수 있습니다. 누락되거나
손상된 AI 설정을 OFF로 만들어 반환하지 않습니다.

쓰기 잠금 후 정한 시각의 **엄격히 다음 UTC 10초 경계**에 효력이 시작됩니다. 공용
Firewall 파일 잠금 → DB 쓰기 잠금 순서를 기존 정책 명령과 공유하며 이전 revision은
변경하지 않습니다. POST의 server_time/current/pending은 접수 시각 기준이므로 저장 후와
효력 경계 이후에는 GET으로 확인합니다. 충돌·응답 유실 시 자동 재전송하지 않고 GET으로
실제 저장 여부를 확인합니다.

OBSERVE 변경은 `TRUST_AI_MODE=observe`일 때만 허용하고 DISABLED 기기는 거부합니다.
OFF 변경과 GET은 전역 enforce에서도 허용합니다. OFF 저장 역시 실행 중 Stage를 끄거나
즉시 처리를 중단하는 명령은 아닙니다. 기기별 설정의 Runtime 연결은 #118의 후속 통합입니다.

| 상태 | 의미 |
| --- | --- |
| 401 | 관리자 키 누락·불일치 |
| 404 | 미등록 기기 |
| 409 | `REVISION_CONFLICT`, `PENDING_REVISION_EXISTS`, `NO_POLICY_CHANGE`, `STATE_TRANSITION_BLOCKED`, `POLICY_WRITE_BUSY` |
| 422 | 잘못된 경로 ID·자료형·사유·모드 또는 추가 필드. ENFORCE 거부 |
| 503 | 관리자 인증 설정 없음, AI Migration·이관·설정 불가/손상 또는 OBSERVE의 전역 모드 조건 불충족 |

AI 설정 관련 503 코드는 `AI_POLICY_UNAVAILABLE`입니다. 기존 Rule 정책의 기반 스키마부터
없으면 공용 연결의 `POLICY_UNAVAILABLE`, 잠금 설정이 잘못되면 `DEVICE_POLICY_CONFIG_UNAVAILABLE`을
유지합니다. 409의 revision 충돌·예정 충돌은 기존 형식의 current_revision/pending_revision/latest_revision을
제공하고, 422는 입력 원문 없이 type/loc/msg만 반환합니다.

운영에서는 Migration 012와 기존 기기의 승인 목록 이관을 먼저 마쳐야 합니다. API 요청으로
Migration·이관을 실행하지 않으며, Pi 적용과 기기별 실제 추론·화면 연결은 별도 검증 대상입니다.

## 실제 실행 근거와 AI 경고 조회

두 API는 관리자 키 없는 읽기 전용입니다. Migration 014이 필요하며 요청 중 Migration·
모델 로딩·Stage 활성화·서비스 제어를 수행하지 않습니다. SQLite의 한 읽기 snapshot에서
실행 관측과 완료 기록 또는 경고 목록·total을 함께 읽습니다.

### GET /api/runtime-status

선택적인 `device_id`는 completion 목록만 필터링합니다. Stage 관측은 프로세스 전체 정보입니다.
기존 등록 API와 동일한 대소문자·숫자·밑줄·하이픈 ID를 허용합니다.

- `server_time`, `observed_at`, `run_id`, `boot_id`: 응답 시각과 실제 Orchestrator 관측의 출처.
- `status`: 같은 Boot에서 45초 이내에 관측한 STARTING/RUNNING/FAILED/STOPPED 또는 UNKNOWN.
  이는 마지막 관측 결과이며 현재 프로세스 생존을 보장하는 값이 아닙니다.
- `last_observation_status`: 만료되어도 보존하는 마지막 기록의 상태.
- `freshness`, `age_seconds`, `max_age_seconds`, `reason_code`: FRESH/STALE/MISSING/FUTURE/
  BOOT_MISMATCH/BOOT_UNAVAILABLE 구분. 미래·다른 Boot·Boot 확인 불가도 UNKNOWN입니다.
  Windows처럼 `/proc` Boot ID가 없는 환경에서 임의의 현재 Boot를 만들지 않습니다.
- `stages`: 실제 실행 프로세스의 enabled/required, 초기화·완료·무입력·실패 관측,
  실제 모델 version/hash, 마지막 완료 데이터 경계·입력 ID, 선택 행·이벤트 수.
  `trust_ai_mode`는 실행 Cycle의 전역 Trust 모드이며 기기별 AI 선택 모드와 다릅니다.
  `ai_device_policy_enabled`는 실제 Stage의 저장 정책 연결 사용 여부입니다. 과거 관측에는 null일 수 있습니다.
- `completions`: 기기·탐지기별 마지막 원본 Window의 입력/추론/정상/이상/사유별 제외 수,
  실제 모델·AI revision/mode와 run/Boot/관측 시각. CURRENT는 같은 최근 실행의 근거,
  HISTORICAL은 이전 실행·오래된 근거입니다. CURRENT도 해당 기기의 현재 추론 성공 보장은 아닙니다.

정상 추론은 `normal_count`로 확인하며 이벤트 없음·Checkpoint·API 설정으로 추정하지 않습니다.
무입력은 `device_id=null, window_start=null`의 Stage 기록으로만 남깁니다. 다른 기기 전진이나
빈 목록을 선택 기기의 정상으로 바꾸지 않습니다. 처리한 원본 Window 경계와 실제 관측 시각은
서로 다르며, 과거 자료 replay가 최근 실행됐더라도 최근 데이터 처리 완료를 뜻하지 않습니다.
현재 정책은 기존 `ai-policy` API에서 별도로 조회하며 완료 기록의 과거 revision을 덮지 않습니다.

저장소는 있으나 관측이 없으면 200 UNKNOWN/MISSING과 null 시각·빈 목록을 반환합니다.
스키마 누락·저장 자료 손상·DB 읽기 실패는 503 `RUNTIME_EVIDENCE_UNAVAILABLE`입니다.
마지막 성공 완료 자료는 이후 Stage 실패·프로세스 재시작으로 삭제하지 않습니다.

### GET /api/ai-warnings

`device_id`, timezone 포함 `from`/`to`, `limit`(기본100, 1~500), `offset`(기본0)을 받습니다.
한쪽 시각만 지정할 수 있고 UTC로 비교합니다. 기간에 완전히 포함되는 집계 bucket만 반환하며
경계는 포함합니다. 역순·timezone 누락·UTC 범위 초과는 422, 같은 시작/종료는 빈 기간입니다.
`bucket_start DESC,id DESC` 정렬과 같은 필터의 `{items,total}`을 제공합니다.

목록은 버전별 기준 N에 도달하고 경고 생성 결정 또는 cooldown 억제 이력이 있는 집계만 포함합니다.
N 미달 집계와 중단 뒤 지연 자료로만 N에 도달한 집계는 내부 보존하되 새 경고로 표시하지 않습니다.
항목에는 기기·탐지기·이벤트 유형·모델·경고 정책 버전, bucket 시작/끝, 중복 Window를 제외한 count,
최초/최근 Window, `notified_at`, `suppressed_count`, `closed`, `last_decision`, `updated_at`,
원본 `event_ids`/`analysis_windows`가 있습니다. `notified_at`은 집계기의 경고 생성 결정 시각이며
외부 알림 전송 성공을 뜻하지 않습니다. 이 변경은 외부 메시지를 전송하지 않습니다.

기기별 추론 0·명시적 제외 또는 Stage 전체 무입력은 열린 집계를 `INPUT_INTERRUPTED`로 닫습니다.
이후 같은 bucket의 지연 자료는 참조에 추가하되 새 경고를 만들지 않습니다. 다른 기기는 계속
입력되지만 특정 기기의 행만 누락된 경우에는 개별 무수신을 자동 판정하지 않습니다.

`server_time`, `observed_at`, `source_status`, `reason_code`로 자료 생성 상태를 함께 제공합니다.
FRESH/RUNNING 관측과 명시된 경고 정책이 있을 때 AVAILABLE, 기준이 미설정이면
POLICY_UNCONFIGURED, 관측 없음·만료·실패 등은 UNKNOWN입니다. 과거 집계는 그대로 조회하므로
AVAILABLE은 최근 관측과 정책 존재를 뜻하며 기기별 selector 연결·추론·알림 전송을 보장하지 않습니다.
실제 기기별 처리는 runtime-status의 완료 근거로 별도 확인합니다. 스키마·자료·DB 오류는
503 `AI_WARNING_DATA_UNAVAILABLE`이며 원본 SQL·설정 경로·예외 메시지를 노출하지 않습니다.

### 실행 기록 연결 범위

Migration 014 뒤 `RUNTIME_EVIDENCE_ENABLED=true`인 기존 Orchestrator에서만 기록을 발행합니다.
성공 Stage 관측·AI 완료·경고 저장은 기존 이벤트·Checkpoint와 같은 트랜잭션입니다.
저장 실패 시 함께 rollback하며 초기화·실행 실패는 rollback 후 별도 실패 관측을 시도합니다.
실패 기록도 저장하지 못하면 기존 관측의 만료로 확인 불가를 표시하고 원래 오류를 보존합니다.
새 상주 프로세스나 메시지별 상태 쓰기를 만들지 않습니다.

반복 경고는 `AI_WARNING_POLICY_VERSION`, `AI_WARNING_WINDOW_SECONDS`,
`AI_WARNING_COUNT_THRESHOLD`, `AI_WARNING_COOLDOWN_SECONDS`를 모두 명시해야 합니다.
운영 W/N/C 기본값은 없고 일부 설정만 있으면 Orchestrator 기동을 거부합니다. 실제 저장된
OBSERVE 이상 이벤트와 일치하는 완료 근거만 집계합니다. 저장된 기기별 OFF/OBSERVE 적용은
`AI_DEVICE_POLICY_ENABLED=true`와 Migration 015의 모델별 승인 시작 기록이 별도로 필요합니다.
[기기별 추론 연결 절차](phase9-ai-policy-runtime.md)를 따르며 조회 API나 관측 설정만으로
Stage·모델을 활성화하지 않습니다. 독립 detector runner의 관측 저장·실제 Pi·부하·화면 연결은
별도 검증 대상입니다.

## 모델 정보 API

### GET /api/models

관리자 키를 요구하지 않는 공개 조회입니다. 서버에 설정된 Packet IF·MQTT IF Bundle의
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
| `UNCONFIGURED` | 해당 Artifact 경로·기대 Version·기대 Bundle SHA 중 필수 설정 누락. MQTT는 세 설정 모두 비어 있으면 아래 legacy 상태 |
| `UNAVAILABLE` | 필수 파일 누락 또는 읽기 권한/파일 접근 실패 |
| `INVALID` | Hash·Version·Metadata 계약 불일치, 잘못된 Report 형태, 크기 상한 초과 또는 안전하지 않은 경로 |
| `LEGACY_CONTRACT_UNAVAILABLE` | MQTT Bundle 설정이 모두 비어 있어 기존 단일 Joblib 경로 사용. 해당 경로는 외부 pin·Bundle·Metadata 계약 없음 |

공개 Metadata에는 모델·Feature·변환·Dataset·정상 정책 Version, Feature 순서,
Threshold와 비교 방향·출처, 생성 시각, Bundle/Dataset/Manifest SHA, 분할별 행 수와
정해진 CapturePolicy 필드만 포함합니다. 선택적인 `normal_policy_version`은 null일 수
있습니다. 내부 경로·임의 확장 필드·Report 원문과 평가 수치는 노출하지 않습니다.
MQTT Bundle은 모델·Feature·변환 Version, 5개 Feature 순서, nominal 10초 Window,
`decision_function` 점수·낮을수록 이상인 방향·엄격한 `<` Threshold·출처와 Bundle SHA,
한 건 Window의 5.0초 대체 간격 의미를 반환합니다. MQTT 설정은
`MQTT_IF_ARTIFACT_DIR`, `MQTT_IF_EXPECTED_MODEL_VERSION`, `MQTT_IF_EXPECTED_BUNDLE_SHA256`입니다.
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

기존 live-resume 계획을 생성하고 실제 감사를 조회하는 관리 API입니다. 서버에 등록된
Root CLI의 bounded-replay 원본 계획도 조회할 수 있습니다. 위 모델 조회와 달리 아래 세 경로는 모두
`X-Recovery-Admin-Key`가 필요합니다. 키 미설정은 503 `RECOVERY_ADMIN_NOT_CONFIGURED`,
키 누락·불일치는 401 `RECOVERY_ADMIN_UNAUTHORIZED`입니다. `approved_by`는 서버
`RECOVERY_ADMIN_PRINCIPAL`에서 정하며 요청자가 지정하지 않습니다.

### POST /api/recovery/packet-pair/plans

다음 세 문자열만 받는 strict 요청입니다. 추가 필드·다른 자료형은 422입니다.
HTTP 계획 생성은 live-resume만 지원하며 mode와 FAILED 승인 옵션은 받지 않습니다.
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
`children`, `mode="live-resume"`, `replay_end=null`, `apply_transport="ROOT_CLI"`,
`runtime.status="UNKNOWN"`을 반환합니다.
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
`database_committed`, `children`, `verification`, `mode`, `replay_end`, `runtime`입니다.
`mode`는 `live-resume` 또는 `bounded-replay`이며 `replay_end`는 bounded 계획의
보존 데이터 처리 종점입니다. 이후 Session의 실시간 복구나 FAILED 끝 구간의 승인은 아닙니다.

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
진행 파일을 만들지 않는 bounded-replay는 `root_progress_status="NOT_APPLICABLE"`입니다.
비공개 Root Artifact 읽기 권한이 없으면 503/UNKNOWN으로 반환합니다.

`root_progress_verified`는 기존 진행 파일의 SHA·승인·Checkpoint 연결을 확인했다는
뜻입니다. `root_progress_observed_at`, `root_progress_age_seconds`,
`root_progress_max_age_seconds=45`, `root_progress_fresh`로 원래 관측 시각과 최신성을
구분합니다. 선택적인 `<pair_id>.manager.json`과 연결된 Manager Journal까지 확인한
`root_completion_recorded=true`도 **과거 완료 기록**입니다. 현재 Boot·서비스 실행·모델
로딩이나 처리 전진을 인증하지 않습니다. 이 첫 API는 진행 파일이 fresh여도 현재
`COMPLETE`를 반환하지 않으며 모든 응답의 `runtime.status`는 `UNKNOWN`입니다.

`historical_completion_status`는 원본 감사 검증을 통과한 과거 `COMPLETE` 또는
`REPLAY_COMPLETE` 기록이며, 근거가 없거나 검증에 실패하면 null입니다.
`historical_completion_source`는 직접 Root 진행 문서의 `ROOT_PROGRESS` 또는
연결된 Manager Journal의 `ROOT_MANAGER`, `historical_completion_recorded_at`은
당시 관측 또는 완료 Journal 보관 시각입니다. Manager 없이도 eligible=true·advances=2의
검증된 진행 문서로 과거 COMPLETE를 확인할 수 있지만 `root_completion_recorded`는
false로 유지합니다. 과거 완료와 현재 runtime UNKNOWN을 함께 표시해야 합니다.
후속 복구 등으로 원본 감사 검증이 HOLD면 과거 완료 문서로 우회하지 않습니다.
상세한 증명 범위는 [모델 정보·복구 관리 API](phase9-model-management-api.md)를 따릅니다.

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

현재 구현은 모델 원본 조회와 복구 계획/감사 검증의 첫 범위입니다. 2026/10/11의
운영 API 적용·HTTP 확인 기록은 아래 전용 문서를 참조합니다. 이후 manager 통합
후보의 운영 배포는 별도 검증 대상입니다. Artifact 검사나 정상 HTTP 응답을 실제
실행 모델 인증으로 표시하지 않습니다. 실제 Runtime
발행, 기기별 OFF/OBSERVE 저장·적용, 모델 활성화·중단·후보 평가와 Frontend 연결은
후속이며 P9-06 전체 완료가 아닙니다. 검증 기록과 세부 계약은
[모델 정보·복구 관리 API](phase9-model-management-api.md)를 참조합니다.

## Feature 및 Packet Gateway Read APIs

### GET /api/feature-logs

기존 MQTT Feature 목록에 선택적인 `from`·`to` 기간 필터를 제공합니다.

- `device_id`: 기존 기기 필터
- `from`, `to`: timezone이 있는 ISO 8601 시각. UTC로 비교하며 한쪽만 지정할 수 있습니다.
- `limit`: 기본 100, 1~500. `offset`: 기본 0, 0 이상
- `snapshot_max_id`: 첫 응답의 전역 Feature 최대 ID를 다음 페이지에 전달하는 선택 인자

`window_start >= from`이고 `window_end <= to`인 **완전히 포함된 Window**만 반환합니다.
경계와 같은 값은 포함하고, 일부만 겹치는 Window는 제외합니다. 기간의 끝과 시작이 같으면
일반적인 10초 Window는 포함되지 않습니다. 잘못된 시각·timezone 누락·역순 기간은 422입니다.

```text
/api/feature-logs?device_id=esp32_01&from=2026-10-01T00:00:00Z&to=2026-10-01T01:00:00Z
```

응답은 `{items,total,snapshot_max_id}`입니다. 기존 `window_start DESC,id DESC` 정렬,
페이지 처리와 응답의 저장 시각 원문은 유지합니다. total에도 동일한 기간·기기·최대 ID 필터가
적용됩니다. 기존 Feature writer의 Window 경계는
UTC 정수 초이며, 공백/T/Z/명시적 UTC offset 형식을 UTC 초로 비교합니다. 분수 초 요청은
시작 경계를 올림·종료 경계를 내림하여 정수 초 Window의 포함 여부를 정확하게 판단합니다.
기간을 생략하면 기존 조회와 같습니다.

페이지 기준과 별도 Capture 관측은 [그래프용 읽기 API](phase9-graph-read-api.md)를 참조합니다.
이 기준은 새로운 ID의 유입만 막으며 요청 사이 기존 행 수정·삭제까지 동결하지 않습니다.
원본 MQTT 로그의 `received_at` 해석, 새 그래프·집계는 변경하지 않습니다. Feature 응답의
단일 메시지 간격 값만으로 실제 송신 주기를 판정하지 않습니다.

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
- `snapshot_max_id`: optional insertion watermark returned by the first page

Response wrapper:

```json
{
  "items": [],
  "total": 0,
  "snapshot_max_id": 0
}
```

Each item also returns nullable `broker_target_ip`, `broker_target_port`, and
`broker_target_syn_count` from the stored row. Migration 013 records the verified
IPv4 destination, TCP port 1883, and inbound SYN=1/ACK=0 packet count in the
original 10-second window (including retransmissions). Historical or unconfigured
rows return all three as `null`; a measured zero is `0`. Current environment
settings never rewrite the meaning of historical rows.

The existing Packet time filter uses `window_start >= from` and `window_start <= to`.
This differs from MQTT's complete-window containment. The separate bounded
`GET /api/packet-capture-windows` requires `session_id`, `from`, and `to`, returns at
most one hour/360 fully contained windows, and distinguishes stored READY, EMPTY,
FAILED, PROCESSED and absent records. See [graph read API](phase9-graph-read-api.md)
for pagination and capture-state semantics.

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

### GET /api/mqtt-logs 원본 기간 조회

기간을 생략한 `GET /api/mqtt-logs`는 기존 `id DESC`인 DB 수신·적재 순서로 반환합니다. 기존 Subscriber의
KST Local Naive 공백값과 SQLite `CURRENT_TIMESTAMP`의 UTC 공백값은 문자열만으로 구분할 수
없으므로 이 순서를 실제 Timestamp 순서라고 표현하지 않습니다. 응답의 `received_at` 원문은
변환하지 않습니다.

- `from`·`to`: timezone이 있는 ISO 8601. 시작 포함·종료 제외 `[from,to)`를 UTC 마이크로초로 비교합니다. 한쪽만 지정할 수 있고 역순·timezone 누락은 422입니다.
- `limit`: 기본100, 1~500. `offset`: 0~100000. `snapshot_max_id`: 첫 페이지의 전역 원본 최대 ID를 다음 페이지에도 전달합니다.
- 기간 조회 정렬은 실제 시각 내림차순, 동률이면 ID 내림차순입니다. timezone 없는 과거 원본은 기간에 추정 배치하지 않습니다.
- 기존 `items,total`에 `snapshot_max_id,offset,limit,has_more`를 추가합니다. `total`에도 동일한 기간·기기·유효성·최대 ID 필터를 적용합니다.
- `timestamp_unavailable_count`는 첫 페이지에서 요청 기기 스냅샷의 시각 불명 행 수를 반환합니다. 뒤 페이지에서는 null이며 `timestamp_unavailable_count_scope=device_snapshot_first_page`입니다. 이 수는 해당 기간에 누락됐다는 판정이 아닙니다.
- `source_span_count`는 첫 페이지에서 전체 기간 일치 집합의 최소~최대 ID 사이에 저장된 같은 기기 원본 수를 셉니다. 시각·JSON·Topic 유효 여부로 중간 원본을 빼지 않습니다. 빈 집합은0, 뒤 페이지는 null이며 `source_span_count_scope=selected_source_ids_first_page`입니다.
- 기간 없는 조회는 위 두 감사 수가 null이고 scope는 `not_evaluated`입니다. `interval_predecessor_policy=within_range_only`이며 기간 밖 선행 메시지는 가져오지 않습니다.

화면은 크기에 원래 `payload_size` 바이트를 사용합니다. 간격은 전체 페이지를 받아 `rows.length=total=source_span_count`이고 시간순 ID가 증가할 때만 같은 기기의 연속 시각 차이를 표시합니다. 첫 메시지·누락·순서 역전은 값 없음이며 임의5초를 넣지 않습니다. 5000건 화면 한도·잘린 페이지·스냅샷 불일치는 불완전으로 표시하고 간격을 숨깁니다. 과거 시각 불명 행은 그대로 보존합니다. ID watermark는 새 삽입을 차단하지만 페이지 사이의 기존 행 수정·삭제를 동결하는 장기 스냅샷은 아닙니다.

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

AI OBSERVE 처리는 전역 `TRUST_AI_MODE=observe`가 명시적인 enforce 요청보다 우선합니다. 이미 격리됨·늦은 이벤트·등록 제외 등 처리 경로에도 같은 관찰 정책을 기록합니다. Rule의 기존 감점·격리 판단은 유지합니다.

`score_delta`는 원본 저장값이며 새 관찰 처리에서0으로 덮어쓰지 않습니다. 과거 이미0으로 저장된 행도 재작성하지 않습니다. `evidence.trust_decision`에 observe 정책·원래 값·정책 감점·실제0·처리 시각을 기록하며 기존 탐지 근거와 기존 감사 결정도 보존합니다. 최상위 `policy_version`은 탐지 정책 버전입니다.

추가 응답 필드는 다음과 같습니다.

| 필드 | 의미 |
| --- | --- |
| `policy_score_delta` | 규칙/AI 정책상의 감점 값. 실제 적용과 구분 |
| `actual_score_delta` | 관찰·이미 격리·처리 제외는0. 검증된 단일 대표 이력은 실제 점수 차이. 미처리·감사 근거 불명은 null |
| `score_effect_reason` | 실제 적용·관찰·처리 제외·근거 불명 사유 |
| `trust_score_history_id` | 연결이 검증된 신뢰점수 이력 ID 또는 null |
| `window_actual_delta` | 연결 이력의 해당 구간 실제 총변화. 여러 이벤트의 개별 감점으로 분배하지 않음 |

목록은 실제 변화와 미반영 사유를 표시하고 원본·정책 감점은 별도로 보존합니다. 여러 이벤트가 묶인 구간의 총변화를 각 이벤트의 실제 감점으로 주장하지 않습니다. `applied_to_score=0`에는 처리 완료된 관찰·제외도 포함하므로 미처리 건수로 해석하지 않습니다. 과거 조회는 원본 이벤트와 감사 이력을 변경하지 않습니다. 자세한 운영 절차는 [AI 관찰 모드 운영 가이드](ai-observation-mode-runbook.md)를 참고합니다.

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
기본 자동 격리는 MQTT 1883이며 기존 ID의 범위를 변경하지 않습니다.
운영자 설정 `FIREWALL_AUTO_SCOPE=PI_INPUT_IPV4_ALL`과 migration 018에서는 Trust의 최초
격리 결정으로 광역 규칙 한 개를 예약합니다. MQTT 선행 규칙을 만들지 않으며 기존 MQTT
규칙을 Worker가 자동 확장하지 않습니다. 직접 생성한 광역 규칙은 `source_rule_id=null`,
`requested_by=system:trust-score-v2`와 실제 감점의 `trigger_event_id`를 기록합니다.
관리자 확장 API와 과거 규칙의 정확한 ID별 해제는 유지합니다. 과거 두 규칙이 남아 있으면
각각 해제해야 하며, 새 방식으로 생성한 규칙은 한 ID를 해제합니다.
설정은 이후 생성에만 적용되며 기존 규칙의 범위·이력을 바꾸지 않습니다.
[단일 규칙 운영 절차](direct-ipv4-isolation.md)를 참고합니다. 2026/10/25~26의
[실물 검증 기록](phase9-pi-input-isolation-validation-20261026.md)은 당시 두 규칙 방식의 결과입니다.

### GET /api/firewall-rules
GET /api/firewall-runtime-status

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

### GET /api/firewall-runtime-status

공개 읽기 전용 API로 기존 5초 Firewall runtime Snapshot과 현재 DB fingerprint를
확인합니다. `MATCH`, `MISMATCH`, `WAITING`, `UNKNOWN`과 `warnings`/`waiting` 목록,
경고의 최초·최신 관측시각 및 관측 간 지속시간을 반환합니다. PENDING 작업·해제와
관측 이후 DB 변경은 `WAITING`, stale/future/boot·스키마·관측 오류는 `UNKNOWN`입니다.
자동 repair나 sudo/iptables 실행, DB 쓰기는 하지 않습니다. `MATCH`는 Recovery 승인과
다르며 기존 대상별 Recovery Gate는 유지됩니다. 응답 필드와 Pi 검증 범위는
[Phase 9 방화벽 주기 대조](phase9-firewall-consistency.md)를 참조합니다.

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
어댑터입니다. 일반 복구의 실제 상태 변경과 성공 감사 저장은
`edge.trust.device_recovery.execute_device_recovery`가 같은 SQLite 트랜잭션에서
수행합니다. Backend 어댑터는 직접 `devices`를 UPDATE하지 않습니다. 이 API는 systemd 제어, iptables
조회 계층 생성, Firewall Release 실행, Firewall Worker 실행을 하지 않습니다.

일반 복구는 전체 DB 백업·전체 DB 무결성 검사를 실행하지 않습니다. 별도 수동 명령
`edge.trust.run_baseline_recovery execute`는 기존 전체 백업·검사·복구 경로를 유지하며,
**백업만 만드는 명령이 아닙니다.** 정기 백업 스케줄은 추가하지 않습니다.

새 API를 사용하기 전에 Migration 017 (`device_recovery_audits`)을 적용해야 합니다.
운영 DB 변경 전 별도 전체 백업과 사본 적용 검증이 필요합니다. 현재 문서는 PR #146의
구현 계약이며, 해당 코드·017의 실제 Pi 적용 및 실기 검증이 완료됐다는 의미는 아닙니다.

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

`RECOVERY_ARTIFACT_DIR`는 과거 JSON 이력 조회와 DB에 저장하지 못한 실패·거부 기록의
파일 저장에 사용합니다. 신규 일반 복구의 성공은 이 디렉터리나 백업 파일 생성에 의존하지 않습니다.
Preflight·Execute·History 조회 네 경로 모두 동일한 관리자 인증을 요구합니다.

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
- Migration 017의 감사 테이블·필수 컬럼 준비 상태 (`audit_check`)

`audit_check.available`은 읽기 전용 스키마 점검 결과입니다. 실제 INSERT가 성공한다는
보장은 아니며, Execute에서 성공 감사 저장이 실패하면 기기 상태 변경도 함께 Rollback합니다.
감사 스키마 문제로 보류된 요청은 `AUDIT_STORAGE_UNAVAILABLE`·`HOLD`로 닫습니다.
`backup_check` 필드는 이전 호출부와의 호환을 위해 유지하되, 일반 복구에서는
`required=false`, `available=null`, `status=NOT_REQUIRED`입니다. 백업 경로는 실행 Gate가 아닙니다.

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
    "required": false,
    "available": null,
    "status": "NOT_REQUIRED"
  },
  "audit_check": {
    "storage": "database",
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
`409`와 `DENIED` 또는 `HOLD` audit payload를 `detail`에 반환하고 복구 코어를
호출하지 않습니다. 통과한 요청은 대상 Device 하나만 조건부 UPDATE하여 `normal`·`100`으로
바꾸고, 변경 전후 상태·승인자·사유·Runtime 점검 근거가 있는 성공 감사를 함께 저장합니다.
성공 감사는 `device_recovery_audits`에 저장하며, 기기 변경과 감사 중 하나만 확정하지 않습니다.

Core는 수동 Baseline CLI와 같은 DB별 복구 잠금으로 명령을 직렬화합니다. 최초 상태를
읽은 뒤 읽기 트랜잭션을 해제하고, Firewall Worker와 같은 잠금을 얻은 다음 짧은 DB 쓰기
트랜잭션을 시작합니다. Firewall 잠금 대기 중에는 DB 쓰기 잠금을 유지하지 않습니다.
WAL 모드 DB만 실행을 허용하고 원본의 Journal 모드를 바꾸지 않습니다.

최초 검사·최종 잠금 안의 검사·Commit 직전에 Runtime Snapshot을 검증합니다. 현재 IP·미해제
규칙·미처리 이벤트·관측 최신성 중 실행 조건을 충족하지 못하면 실행을 거부하며 점수·상태
변경을 Rollback합니다. 이때 응답과 Audit의 `firewall_release_status`는
Runtime 검증 실패인 경우 `NOT_VERIFIED`입니다. 공식 해제된 방화벽 규칙을 자동으로
다시 추가하는 의미는 아닙니다. 과거 탐지·Trust·격리·방화벽·수집 이력은 보존합니다.

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
  "backup_reference": null,
  "backup_sha256": null,
  "audit_reference": "device_recovery_audits:20260810T010000Z-abcdef123456",
  "failure_code": null,
  "failure_reason": null
}
```

부분 실패나 사전 Gate 실패는 성공으로 반환하지 않습니다. Firewall Release 성공과
Baseline Recovery 성공은 별도 의미이며, 이 API는 Firewall Release 자체를 실행하지
않습니다.

실패·결과 불확정의 처리:

| HTTP | `detail.result` | 의미와 재실행 기준 |
| --- | --- | --- |
| 409 | `DENIED` / `HOLD` | 확인 문구·상태·점수·미처리 이벤트·Runtime·잠금 등 실행 조건을 충족하지 못함. 원인을 해소하고 새 Preflight 필요 |
| 500 | `FAILED` | 복구 코어가 저장 확정 전 실패한 경우. 상태 변경·성공 감사는 Rollback되며 실패 기록 저장을 시도 |
| 500 | `HOLD` | `failure_code=BASELINE_RECOVERY_COMMITTED_UNVERIFIED`. Commit 결과를 감사에서 확인할 수 없어 변경 후 상태를 단정하지 않음 |

Commit 응답이 끊겨도 같은 작업의 확정된 DB 성공 감사를 읽을 수 있으면 그 성공을 반환합니다.
확정 여부를 확인할 수 없는 경우에는 `after_status`·`after_trust_score`가 `null`이며,
성공을 `FAILED` 감사로 덮거나 복구 코어를 다시 실행하지 않습니다. 대시보드도 이 오류 코드를
결과 불확정으로 분류해 실제 기기·남은 방화벽 상태를 조회하고 중복 실행을 차단합니다.
HTTP 500을 미변경의 증거로 해석하지 말고 `operation_id`로 이력과 실제 상태를 확인해야 합니다.

실패·거부·보류 기록은 DB에 우선 저장하며, 감사 DB 읽기·쓰기가 실패하면 기존 JSON 방식으로
저장을 시도합니다. 파일 기록까지 실패할 수 있으므로 오류 응답이 모든 실패 증거의 저장을
보장하지는 않습니다. 저장 결과 불확정 응답은 기존 성공을 보호하기 위해 새 실패 감사를 저장하지 않습니다.

### GET /api/recovery/history

`device_recovery_audits`의 DB 감사와 과거 Baseline Recovery·Recovery Command JSON
artifact를 함께 읽어 정규화한 목록을 반환합니다. 서버 내부 절대 backup path는 노출하지 않고,
과거 백업이 있는 이력에만 파일명 `backup_reference`와 `backup_sha256`를 제공합니다.

동일 Recovery 요청에서 `baseline-recovery-*.json`과 `recovery-command-*.json`이
함께 생성됐던 과거 이력도 하나의 `operation_id`로 정규화합니다. 동일 작업의 DB 감사가
있으면 JSON과 필드별로 합치지 않고 DB 기록을 우선합니다. 신규 일반 복구의 `null` 백업
필드를 오래된 JSON의 백업 값으로 채우지 않습니다.

항목은 성공 응답 필드와 `log_reference`를 포함합니다. 신규 DB 감사의 `audit_reference`와
`log_reference`는 `device_recovery_audits:<operation_id>`이며 파일 경로가 아닙니다.
DB 내부 JSON에 보존한 전체 Preflight·Runtime·기기 스냅샷은 이 API의 평탄한 응답에
자동으로 노출되지 않습니다. 이전 JSON에 `audit_reference`가 없으면 `null`로 반환합니다.
정규화한 항목을 `requested_at`·`operation_id` 내림차순으로 정렬하고, 필터 후 페이지를 나눕니다.

Query parameters:

- `device_id`
- `result`: `SUCCESS`, `DENIED`, `HOLD`, or `FAILED`
- `limit`: default `100`, minimum `1`, maximum `500`
- `offset`: default `0`, minimum `0`

응답은 `{"items": [...], "total": <필터 후 전체 건수>}`입니다.

### GET /api/recovery/history/{operation_id}

단일 Recovery audit item을 조회합니다. Detection Trust History, Trust Compensation,
Baseline Recovery는 P0에서 서로 다른 Source로 유지하며 통합 Timeline은 후속 P1
범위입니다.
해당 `operation_id`가 없으면 404입니다. DB 감사가 있으면 같은 작업의 JSON보다 우선합니다.

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
GET /api/firewall-runtime-status
POST /api/firewall-rules/{source_rule_id}/scope-extension-requests
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
