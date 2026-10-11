# DB Schema

SQLite를 MVP 데이터베이스로 사용합니다. 생성된 DB 파일은 `backend/data/iot_security.db`에 저장되며 Git에는 올리지 않습니다. 실행 가능한 schema는 `db/migrations/` 아래 migration 파일입니다.

DB 생성과 seed:

```bash
python db/create_tables.py
python db/seed_devices.py
```

SQLite 동시 접근 설정:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout = 5000;
```

## schema_migrations

Migration 005 (`packet_checkpoint_recovery`)는 운영 적용과 Recovery Execute를 분리한다.
Migration 006 (`firewall_release_requests`)는 관리자 승인 Firewall Release 요청을
DB queue로 저장하고 Worker가 실제 iptables release를 처리하도록 분리한다.
Migration 007 (`device_policy_revisions`)은 기기 등록 메타데이터와 불변 정책 Revision 이력을
추가한다(device-policy-v1). 기존 `devices`의 Trust 필드와 이력은 변경하지 않는다. 기존 `devices`에
같은 IP가 둘 이상 있으면 007은 유일 인덱스 생성에서 실패하고 전체가 rollback되므로, 적용 전에
`edge.policy.device_policy_repository.diagnose_device_ip_conflicts`로 진단한다.
Migration 008 (`packet_segment_gap_recovery`)은 같은 Capture Session 안의 손실 Window를
관리자 승인으로 재개한 감사 기록을 추가한다. 실패 Segment·기존 이력과 Migration 005는 보존한다.
Migration 009 (`mqtt_raw_payload`)는 `mqtt_logs`에 수신 원본 바이트(`payload_raw`)와 UTF-8 해석
결과(`payload_decode_status`)를 추가한다. 기존 row는 원본이 없어 NULL로 남으며 backfill하지 않는다.
**009를 적용한 뒤에 Subscriber를 재시작한다.** 새 Subscriber는 이 컬럼에 저장하므로 009가 없는 DB에서는
저장이 실패하고(오류 로그만 남고 해당 메시지는 저장되지 않는다) 수신 증적이 유실된다. 009는 컬럼 추가와
Trigger만 포함하고 기존 컬럼의 값은 바꾸지 않는다.

Migration 011 (`pi_input_isolation`)은 `firewall_rules`에 scope와 관리자 확장 승인
메타데이터를 추가한다. 기존 행은 MQTT TCP 1883과 기존 ID·열 값을 유지하고 새 광역
행만 별도 ID로 생성한다. Runner는 FK를 잠시 끄는 재구성 경로에서 011 전체를 원자적으로
적용하고 `foreign_key_check`/`integrity_check` 후 commit한다. 오류면 테이블·행·인덱스·
`sqlite_sequence`·011 완료 기록이 rollback되며 원래 FK 설정도 복구한다. 삭제된 높은 ID의
sequence와 기존 Release FK를 보존한다. 완료 뒤 되돌리는 down Migration은 제공하지
않으므로 운영 적용 전 일관된 백업과 사본 검증이 필요하다. 운영 DB의 011 적용/배포는 아직
미실행 상태이며 로컬 검증을 운영 적용으로 표시하지 않는다.

Migration 012 (`device_ai_policy_revisions`)는 기기별 AI 모드(OFF/OBSERVE) 불변 이력 테이블을
추가한다. 기존 기기의 모드는 만들지 않으며, 운영자 승인 목록으로
`python -m db.backfill_device_ai_policies --db <복사본> --manifest <목록.json>`(기본 dry-run)을
실행하기 전까지 기존 기기는 AI 설정 누락 상태다. 배포 순서는 012 적용 → 승인 목록 이관 →
이 설정을 읽는 API·탐지기 배포다. 012만 적용해서는 기존 동작이 바뀌지 않는다.

적용과 복구: 007은 컬럼 추가를 포함하며 되돌리는(down) Migration이 없다. 운영 DB에는 먼저
일관된 백업(SQLite backup API 등, 쓰기 중 파일 하나만 복사하지 않는다)을 만든 뒤 **복사본에서**
Migration과 backfill dry-run을 확인하고 적용한다. 적용 중 오류가 나면 Migration 전체가 rollback되어
007 이전 상태로 남는다. 적용이 끝난 뒤 문제가 있으면 서비스를 멈추고 백업을 복원한다.
`edge/policy`의 쓰기 함수는 **트랜잭션이 열려 있지 않은 연결**이 필요하다. Backend는 SQLAlchemy
세션의 연결을 재사용하기보다 `db.migration_runner.connect_database`로 연 별도 연결을 쓰는 것이 안전하다
(세션이 이미 쓰기를 시작한 연결은 `RuntimeError`로 거부된다).

## packet_checkpoint_recoveries

Detector별 Packet Checkpoint Gap Recovery 감사 Row를 저장한다. `operation_id`와 `(detector_name, source_table, target_capture_session_id)`는 각각 UNIQUE이며 Detector는 `packet_rule`/`packet_if`, Source는 `packet_feature_logs`만 허용한다. 현재·대상 Capture Session과 Detector Checkpoint는 `ON DELETE RESTRICT` FK로 연결되고 `last_processed_id_before IS last_processed_id_after`, Skip count 비음수, SHA256 길이를 검사한다.

`db/migration_runner.py`가 적용한 migration을 기록합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| version | INTEGER | migration version, primary key |
| name | TEXT | migration 이름 |
| applied_at | DATETIME | 적용 시각, 기본 current timestamp |

## packet_segment_gap_recoveries

정확히 한 `FAILED/PARTIAL_CAPTURE` Window에 대한 승인이다. Packet Rule·Packet IF의
완료 경계를 **한 트랜잭션**에서 함께 이동하고, 두 Stage의 변경 전/후 Checkpoint를 Plan에
저장한다. `last_processed_id`는 유지한다. 실패 Segment는 변경하지 않는다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id / operation_id | INTEGER / TEXT | PK / 유일 작업 ID |
| capture_session_id | TEXT | Session UUID, `packet_capture_sessions.session_id` FK |
| failed_segment_id | INTEGER | 원본 실패 Segment FK, 같은 Segment 중복 승인 금지 |
| window_start / window_end | TEXT | 승인한 10초 손실 구간, UTC `Z` |
| plan_sha256 / plan_json | TEXT | 실패 Row·두 Checkpoint·승인·증거를 묶은 SHA256 및 Plan |
| approved_by / reason | TEXT | 명시적 승인자와 재개 사유 |
| repository_commit / database_path | TEXT | 승인 시 코드 Commit과 DB 경로 |
| backup_path / backup_sha256 | TEXT | 실행 직전 검증된 SQLite 백업 |
| preserved_pcap_path / pcap_sha256 | TEXT | 보존한 실패 PCAP와 SHA256 |
| created_at | TEXT | 감사 Row 생성 시각 |

Readiness는 감사 Row와 Plan·원본 실패 상태·Feature 부재가 일치할 때만 해당 손실 구간을
통과한다. 다음 미승인 손실·누락·중복 Window는 계속 탐지를 막는다. 008이 없는 DB에서는
기존 Gate를 유지한다. 적용·HOLD·복구 절차는
[Packet 손실 구간 승인 복구](packet-segment-gap-recovery-runbook.md)를 따른다.

## devices

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| device_id | TEXT | primary key, 기본 seed `esp32_01`, `esp32_02` |
| ip_address | TEXT | 기기 IP |
| status | TEXT | `normal`, `warning`, `danger`, `isolated` |
| trust_score | INTEGER | 기본값 `100` |
| last_seen_at | DATETIME | 마지막 MQTT 수신 시각. 신규 Subscriber는 UTC `YYYY-MM-DDTHH:MM:SSZ` 저장 |
| created_at | DATETIME | 생성 시각(등록 시각), 기본 current timestamp. 관리자 등록은 UTC `Z` 정수 초로 저장 |
| device_type | TEXT | Migration 007. 표시용 `SENSOR`/`CAMERA`/`ACTUATOR`/`OTHER`. NULL 허용 |
| mqtt_principal | TEXT | Migration 007. Broker Principal 이름(1~128자). 비밀번호는 저장하지 않음. NULL 허용 |
| registration_effective_from | TEXT | Migration 007. 등록 효력 시작 시각(UTC `Z`, 10초 경계). NULL은 정책 도입 전부터 있던 기존 기기 |

`devices.status`는 Trust 상태(`normal/warning/danger/isolated`)이며 등록 상태(PENDING/ACTIVE/DISABLED)와
별개다. 등록 상태는 `device_policy_revisions`에만 저장한다. `registration_effective_from`은 한 번
정해지면 트리거로 수정을 막는다(값이 없던 기존 기기에 처음 채우는 것만 허용). Device ID·IP·유형·Principal의
수정 금지는 DB가 아니라 서비스/API가 담당하며 수정 경로를 제공하지 않는다. 등록된 기기의 IP를 직접 바꾸면
과거 Window의 IP 귀속이 달라지므로 운영에서 바꾸지 않는다.
IP는 정규 dotted-decimal 형태만 저장하며(앞자리 0 거부) 비어 있지 않은 IP는 유일 인덱스로 중복을 막는다.
octet 범위와 사설/LAN 대역 검사는 서비스(`edge/policy`)가 담당한다.

## device_policy_revisions

기기별 정책 Revision을 쌓는 불변 이력이다. 행을 수정하거나 삭제할 수 없고(트리거), 변경은 새 revision으로만 한다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | `devices(device_id)` FK, `ON DELETE RESTRICT` |
| revision | INTEGER | 기기별 1부터 연속 증가(이전 revision + 1) |
| effective_from | TEXT | 효력 시작 시각. UTC `YYYY-MM-DDTHH:MM:SSZ`, 정수 초, 10초 경계. 이전 revision보다 커야 함 |
| registration_state | TEXT | `PENDING`/`ACTIVE`/`DISABLED` |
| policy_profile | TEXT | 첫 버전은 `periodic-sensor-v1`(서비스가 검사) |
| expected_publish_interval_seconds | REAL | 설명용 주기. 0 초과 86400 이하 |
| publish_count_max | INTEGER | 10초당 메시지 수 상한. 1~10000 |
| payload_size_max_bytes | INTEGER | MQTT Payload 바이트 상한. 1~1048576 |
| packet_rate_max_pps | REAL | packets/second 상한. 0 초과 100000 이하 |
| byte_rate_max_bytes_per_second | REAL | bytes/second 상한. 0 초과 125000000 이하 |
| created_at | TEXT | 작성 시각(UTC `Z`, 소수 초 허용) |
| created_by | TEXT | 서버 인증 결과의 작성자(1~128자). 현재 공용 관리자 키는 개인 신원을 증명하지 않음 |
| reason | TEXT | 변경 사유 1~500자 |

`UNIQUE(device_id, revision)`, `UNIQUE(device_id, effective_from)`를 둔다. 상태 전이는
PENDING→ACTIVE, PENDING/ACTIVE→DISABLED만 허용하며 DISABLED 이후 revision은 만들 수 없다(트리거).
0·음수·범위 초과 임계값은 저장할 수 없고, 0을 "탐지 끄기"로 해석하지 않는다.
숫자 문자열·bool 같은 묵시 변환과 "예정 revision이 이미 있음(`PENDING_REVISION_EXISTS`)"은
서버 시각이 필요하므로 `edge/policy`가 검사한다. 시각 비교는 정수 초 UTC 문자열의 사전식 비교다.

기존 기기의 초기 revision은 Migration이 만들지 않는다. 확인된 운영값으로
`python -m db.backfill_device_policies --db <복사본> --manifest <manifest.json>`(기본 dry-run)을 실행해
ACTIVE revision 1을 만든다. 이때 `registration_effective_from`은 NULL로 두어 이관 이전 Window의 기존
등록 판정을 바꾸지 않고, 그 Window의 정책은 추정하지 않는다(`POLICY_UNAVAILABLE`).
새 개발 DB는 `python db/create_tables.py` 뒤 `python db/seed_devices.py`가 기기와 초기 revision을
한 트랜잭션으로 만든다.

## device_ai_policy_revisions

기기별 AI 모드 Revision을 쌓는 불변 이력이다. 등록 상태·정책 값(`device_policy_revisions`)과 별개의
설정이며 행을 수정하거나 삭제할 수 없다(트리거). 변경은 새 revision으로만 한다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | `devices(device_id)` FK, `ON DELETE RESTRICT` |
| revision | INTEGER | 기기별 1부터 연속 증가(이전 revision + 1) |
| mode | TEXT | `OFF` 또는 `OBSERVE`. ENFORCE는 저장할 수 없음 |
| effective_from | TEXT | 효력 시작 시각. UTC `YYYY-MM-DDTHH:MM:SSZ`, 정수 초, 10초 경계. 이전 revision보다 커야 함 |
| created_at | TEXT | 작성 시각(UTC `Z`, 소수 초 허용) |
| created_by | TEXT | 서버 인증 결과의 작성자(1~128자) |
| reason | TEXT | 변경 사유 1~500자 |

`UNIQUE(device_id, revision)`, `UNIQUE(device_id, effective_from)`를 둔다. 신규 등록은 기기·정책
revision 1과 같은 트랜잭션에서 **OFF revision 1**을 같은 효력 시각으로 만든다. 예정 revision은
기기당 최대 1개이고 효력은 엄격히 다음 UTC 10초 경계다. 이 규칙과 "DISABLED 기기를 OBSERVE로 바꿀 수
없음"은 서버 시각이나 다른 테이블이 필요해 `edge/policy`가 검사한다. 전역 `TRUST_AI_MODE` 확인은
설정을 변경하는 API의 책임이다.

설정이 없거나 손상된 기기는 OFF로 간주하지 않는다. 저장소는 `AI_POLICY_UNAVAILABLE`(API 503)을 알리고
`resolve_ai_mode`는 그 Window의 AI를 제외할 근거를 반환한다. 다른 기기와 Raw·Feature·Rule 처리에는
영향이 없다. Window 시작 시각에 효력이 있던 revision을 사용하므로 OFF→OBSERVE 전환이 과거 OFF
구간을 되살리지 않는다.

기존 기기의 초기 모드는 승인 목록(`device-ai-policy-backfill-v1`)으로만 만든다. DB의 모든 기기가 목록에
있어야 하며 하나라도 빠지면 아무것도 변경하지 않는다. 이미 revision이 있는 기기는 건너뛰므로 재실행해도
덮어쓰지 않는다. 이관 효력 시각 이전 Window는 설정 누락으로 남는다.

## mqtt_logs

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | topic 또는 payload에서 얻은 device ID |
| topic | TEXT | MQTT topic |
| payload | TEXT | 수신 payload를 UTF-8로 해석한 문자열. 잘못된 UTF-8 바이트는 U+FFFD로 치환돼 있어 원본 바이트와 같지 않음 |
| payload_size | INTEGER | 수신 원본 payload의 byte 크기(문자 수나 치환 후 크기가 아님) |
| payload_raw | BLOB | Migration 009. 수신한 payload 바이트 원본. 009 이전 row는 NULL. 저장 후 변경 불가(API로 노출하지 않음) |
| payload_decode_status | TEXT | Migration 009. 원본을 엄격한 UTF-8로 해석할 수 있으면 `OK`, 아니면 `INVALID_UTF8`. 009 이전 row는 NULL(알 수 없음) |
| received_at | DATETIME | 수신 시각. 신규 Subscriber는 UTC `YYYY-MM-DDTHH:MM:SSZ`, DB 기본값은 `CURRENT_TIMESTAMP` |
| is_json_valid | INTEGER | `0` 또는 `1`. 수신 원본 바이트가 UTF-8 JSON 객체이고 `device_id`가 있을 때만 `1` |
| is_topic_valid | INTEGER | `0` 또는 `1` |
| error_message | TEXT | 검증 오류 상세 |

저장된 `payload` 문자열은 치환된 값일 수 있어 다시 JSON으로 읽으면 정상처럼 보입니다. 그래서
Subscriber(`last_seen_at` 갱신)와 Feature 집계는 `is_json_valid = 0`인 메시지에서 Payload Device ID를
추출하지 않고 Topic으로만 귀속하며, 이런 메시지는 `last_seen_at`을 갱신하지 않습니다.
MQTT Rule의 Identity 판정은 아직 이 해석을 쓰지 않습니다(P8-05).

`payload_raw`와 `payload_decode_status`는 함께 저장하며(둘 다 NULL이거나 둘 다 값이 있음), `payload_raw`는
BLOB이고 길이가 `payload_size`와 같아야 합니다. 어긋난 값은 Trigger가 거부합니다.
`payload_decode_status`는 JSON 유효성(`is_json_valid`)과 별개입니다. 정상 UTF-8이지만 JSON이 아닌
메시지도 `OK`입니다.

신규 Subscriber는 한 메시지에서 생성한 UTC `Z` 문자열 하나를 `mqtt_logs.received_at`과
`devices.last_seen_at`에 동일하게 저장합니다. 기존 DB의 공백 형식에는 서로 다른 의미가
공존할 수 있습니다. Pi가 `Asia/Seoul`인 상태에서 기존 Subscriber가 생성한 값은 KST Local
Naive Timestamp이고, SQLite `CURRENT_TIMESTAMP`가 생성한 값은 UTC입니다. 문자열 형식만으로
둘을 구분할 수 없으므로 모든 공백값을 UTC 또는 KST로 일괄 변환하지 않습니다.

Phase 4의 기존 `parse_db_utc()` Naive 호환 동작은 유지하지만 실제 Timestamp 출처를 증명하지는
않습니다. 운영 DB 보정은 출처가 검증된 Row만 별도 승인·백업 절차로 수행합니다.

## feature_logs

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | device ID |
| window_start | DATETIME | 10초 window 시작 시각 |
| window_end | DATETIME | 10초 window 종료 시각 |
| publish_count | INTEGER | window 내 publish 수 |
| avg_payload_size | REAL | 평균 payload 크기 |
| max_payload_size | INTEGER | 최대 payload 크기 |
| avg_message_interval | REAL | 평균 메시지 간격, 초 단위 |
| min_message_interval | REAL | 최소 메시지 간격, 초 단위 |
| topic_count | INTEGER | 고유 topic 수 |
| abnormal_topic_count | INTEGER | 비정상 topic 수 |
| malformed_payload_count | INTEGER | 깨진 JSON 또는 `device_id` 필수 필드 누락 payload 수 |

`feature_logs`는 `(device_id, window_start, window_end)` 조합을 unique key로 가집니다.

## detection_events

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| feature_log_id | INTEGER | 관련 feature window |
| mqtt_log_id | INTEGER | 관련 원본 로그 |
| detector_type | TEXT | `RULE` 또는 `AI` |
| event_type | TEXT | MVP event type |
| severity | TEXT | 심각도 |
| score_delta | INTEGER | Trust Score 감점값 |
| applied_to_score | INTEGER | Trust Score updater 처리 완료 여부. `1`이면 처리 완료를 의미하며, `isolated` 이후 이벤트는 정책상 `score_delta = 0`으로 마감될 수 있음 |
| packet_feature_log_id | INTEGER | 관련 packet feature row |
| analysis_window_start | DATETIME | packet 분석 window 시작 |
| analysis_window_end | DATETIME | packet 분석 window 종료 |
| incident_family | TEXT | Phase 4 incident family |
| subject_ip | TEXT | 탐지 대상 IP |
| evidence_json | TEXT | 탐지 근거 JSON |
| evidence_schema_version | INTEGER | evidence schema version |
| processed_at | DATETIME | 후속 처리 완료 시각 |
| processing_reason | TEXT | 후속 처리 사유 |
| dedupe_key | TEXT | Phase 4 detector 중복 이벤트 방지 key |
| policy_version | TEXT | 이벤트 생성 정책 version |
| description | TEXT | 사람이 읽을 설명 |
| detected_at | DATETIME | 탐지 시각, 기본 current timestamp |

`dedupe_key`는 NULL을 허용합니다. NULL이 아닌 값은 `idx_detection_events_dedupe_key` partial unique index로 중복 저장을 방지합니다.

기존 `detection_events` row는 002·003 migration 적용 시 backfill하지 않습니다. `incident_family`, `processed_at`, `processing_reason`, `applied_to_score`, `dedupe_key`, `policy_version` 값은 기존 의미를 유지합니다.

## isolation_history

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| action | TEXT | 격리 이력 action 코드, 기본값 `ISOLATED` |
| reason | TEXT | 격리 이유 |
| trust_score | INTEGER | action 당시 점수 |
| trigger_event_id | INTEGER | action을 유발한 이벤트 |
| trust_score_history_id | INTEGER | Phase 4 격리 결정을 만든 `trust_score_history.id` |
| created_at | DATETIME | 생성 시각, 기본 current timestamp |

`devices.status`는 현재 기기 상태를 나타내므로 `isolated`를 사용합니다.
`isolation_history.action`은 격리 이력에 저장되는 action 코드이므로 `ISOLATED`를 사용합니다.
`trust_score_history_id`는 NULL을 허용해 기존 이력을 보존합니다. NULL이 아닌 값은 `idx_isolation_history_trust_score_history_id` partial unique index로 한 Trust History가 중복 Isolation History를 만들지 못하게 합니다.

TODO: 향후 격리 해제 기능을 추가하면 `RELEASED`를 action 값으로 사용할 수 있습니다.

## packet_capture_sessions

Packet capture session 단위입니다. DB 내부 join에는 `id`를 사용하고, API/CSV/pcap 파일명에는 UUIDv4 문자열인 `session_id`를 사용합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| session_id | TEXT | 엄격한 UUIDv4 문자열, unique. 16진수 문자, version 4, RFC variant를 DB에서 검증 |
| capture_interface | TEXT | capture interface |
| started_at | DATETIME | capture 시작 시각 |
| first_window_start | DATETIME | 첫 10초 window 시작 |
| ended_at | DATETIME | capture 종료 시각 |
| capture_gap_start | DATETIME | capture gap 시작 |
| capture_gap_end | DATETIME | capture gap 종료 |
| status | TEXT | `RUNNING`, `COMPLETED`, `FAILED` |
| created_at | DATETIME | 생성 시각 |
| updated_at | DATETIME | 수정 시각 |

## packet_capture_segments

pcap segment 파일 단위입니다. Window는 `[window_start, window_end)` 반개방 구간입니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| capture_session_id | INTEGER | `packet_capture_sessions.id` 참조 |
| file_name | TEXT | segment 파일명, unique. `READY`, `PROCESSED`, `EMPTY`는 필수이며 파일 미생성 `FAILED`는 NULL 허용 |
| capture_interface | TEXT | capture interface |
| window_start | DATETIME | window 시작 |
| window_end | DATETIME | window 종료 |
| status | TEXT | `READY`, `PROCESSED`, `EMPTY`, `FAILED` |
| packet_count | INTEGER | packet 수. `READY` 또는 `FAILED`에서는 NULL 가능 |
| processed_at | DATETIME | 처리 완료 시각 |
| error_code | TEXT | 오류 코드 |
| error_message | TEXT | 오류 메시지 |
| actual_capture_started_at | DATETIME | 실제 capture process 시작 시각 |
| capture_stop_requested_at | DATETIME | capture stop 요청 시각 |
| capture_process_exited_at | DATETIME | capture process 종료 시각 |
| start_delay_seconds | REAL | window 시작 대비 capture 시작 지연. NULL 또는 0 이상 |
| captured_duration_seconds | REAL | 실제 capture duration. NULL 또는 0 이상 10 이하 |
| created_at | DATETIME | 생성 시각 |
| updated_at | DATETIME | 수정 시각 |

`file_name`은 NULL이 아닌 경우 중복될 수 없습니다. `(capture_interface, window_start, window_end)`는 중복될 수 없습니다.
`window_start`, `window_end`는 정수 초 UTC 경계의 `YYYY-MM-DDTHH:MM:SSZ` 형식이어야 하며, `window_end`는 `window_start`로부터 정확히 10초 후여야 합니다. 소수점 이하 초가 포함된 시각은 저장하지 않습니다.
`error_code='LATE_CAPTURE'`인 row는 `status='FAILED'`, `file_name IS NULL`, capture timing 시각 NULL, `captured_duration_seconds=0`이어야 합니다. 003 migration은 기존 segment id, feature FK, unique/check/index 계약을 보존하기 위해 `packet_capture_segments`를 재구성합니다.

## packet_feature_logs

Packet segment에서 추출한 peer/direction별 feature row입니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| capture_segment_id | INTEGER | `packet_capture_segments.id` 참조 |
| device_id | TEXT | IP 매핑 실패 시 NULL 허용 |
| peer_ip | TEXT | 통신 peer IP |
| direction | TEXT | `INBOUND`, `OUTBOUND` |
| window_start | DATETIME | window 시작 |
| window_end | DATETIME | window 종료 |
| packet_count | INTEGER | packet 수 |
| total_bytes | INTEGER | 총 byte 수 |
| avg_packet_size | REAL | 평균 packet 크기 |
| max_packet_size | INTEGER | 최대 packet 크기 |
| mean_inter_arrival_time | REAL | 평균 inter-arrival time. packet 2개 미만이면 `0.0` |
| distinct_dest_port_count | INTEGER | 고유 목적지 port 수 |
| tcp_syn_count | INTEGER | TCP SYN 수 |
| mqtt_related_packet_count | INTEGER | MQTT 관련 packet 수 |
| non_mqtt_tcp_udp_packet_count | INTEGER | MQTT 외 TCP/UDP packet 수 |
| capture_scope | TEXT | capture scope |
| created_at | DATETIME | 생성 시각 |

`(capture_segment_id, peer_ip, direction)`은 중복될 수 없습니다. `window_start`, `window_end`는 정수 초 UTC 경계의 `YYYY-MM-DDTHH:MM:SSZ` 형식이어야 하며, feature window는 정확히 10초여야 합니다. 소수점 이하 초가 포함된 시각은 저장하지 않습니다. 격리 상태 기기의 feature 저장을 막는 DB 제약은 두지 않습니다.

## gateway_metrics

Gateway 시스템 자원 metric 저장용 테이블입니다. 기본 수집 주기는 10초이며, 실제 sample 간격은 `sample_interval_seconds`에 저장합니다. 이번 단계에서는 구조만 생성하고 Collector, Repository, API는 구현하지 않습니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| collected_at | DATETIME | Collector가 생성한 UTC metric 수집 시각 |
| sample_interval_seconds | REAL | 실제 sample 간격. 최초 sample 또는 유효한 이전 sample이 없으면 NULL 가능. 저장 값은 0 이상이어야 하며 음수는 거부 |
| cpu_percent | REAL | CPU 사용률. 최초 sample 또는 비정상 delta에서는 NULL 가능 |
| memory_percent | REAL | Memory 사용률 |
| disk_percent | REAL | Disk 사용률 |
| disk_used_mb | REAL | Disk 사용량 MB, 선택 필드 |
| network_rx_bytes | INTEGER | 선택적 top-level RX byte 합계 |
| network_tx_bytes | INTEGER | 선택적 top-level TX byte 합계 |
| temperature_c | REAL | 온도. 센서 미지원 또는 읽기 실패 시 NULL 가능 |
| interface_metrics_json | TEXT | 역할별 interface metric JSON |
| created_at | DATETIME | 생성 시각 |

`interface_metrics_json`은 `internal_lan`, `usb_lan` 같은 역할명을 top-level key로 사용합니다. 실제 인터페이스 이름, 존재 여부, UP/DOWN 상태, IP, 누적 RX/TX, RX/TX bytes/sec는 JSON 객체에 저장합니다. 최초 sample, missing/down interface, counter reset, 비정상 delta에서는 JSON 내부 rate가 NULL일 수 있습니다. 후속 FastAPI 단계에서 이 JSON을 객체로 파싱할 예정입니다.

PR #14 Gateway Metrics Collector의 `GatewayMetricsSample`은 `collected_at`, `sample_interval_seconds`, `cpu_percent`, `memory_percent`, `disk_percent`, `disk_used_mb`, `temperature_c`, `interface_metrics`를 이 테이블에 저장할 수 있습니다. `disk_total_mb`는 현재 DB/API 계약에 없으므로 저장 컬럼으로 추가하지 않습니다.

## detector_checkpoints

Detector별 처리 지점을 저장하기 위한 Phase 4용 테이블입니다. 003 이후 `edge.detection.checkpoint_repository`와 `initialize_phase4_cutover()`가 cutover snapshot에 사용하고, runtime에서는 `edge.detection.runtime_checkpoint_repository`가 SQLAlchemy `Session` 기반으로 같은 테이블을 갱신합니다. Repository는 `last_completed_window_end`와 `last_processed_id`가 기존 checkpoint보다 과거로 역행하는 update를 거부하며, `last_completed_window_end`는 UTC 정수 초 10초 Window 경계만 허용합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| detector_name | TEXT | detector 이름 |
| source_table | TEXT | detector 입력 source table |
| last_processed_id | INTEGER | 마지막 처리 row id |
| last_completed_window_end | DATETIME | 마지막 완료 window 종료 시각 |
| updated_at | DATETIME | 수정 시각 |

`(detector_name, source_table)`은 primary key입니다. Checkpoint 대상 이름은 향후 확장을 막지 않도록 DB CHECK로 고정하지 않습니다.

Phase 4 cutover initializer가 생성하는 공통 checkpoint key는 다음 7개입니다.

```text
mqtt_feature_builder+mqtt_logs
mqtt_feature_rule+feature_logs
mqtt_message_rule+mqtt_logs
mqtt_if+feature_logs
packet_rule+packet_feature_logs
packet_if+packet_feature_logs
trust_score_v2+detection_events
```

Source row가 없으면 `last_processed_id`는 NULL로 유지합니다. Legacy DB에 MQTT
Producer 완료 watermark가 없으면 `phase4_cutover_at`을 MQTT Producer와 MQTT
Detector의 시작 경계로 저장합니다. Packet 완료 watermark가 없으면 Packet 관련
`last_completed_window_end`는 NULL을 유지합니다. `updated_at`은 UTC `Z` 형식으로
저장합니다. `initialize_phase4_cutover()`는 정수 초 UTC
`phase4_cutover_at`만 허용하며, 기존 MQTT/Packet 완료 watermark가 cutover 시각을
초과하면 실패합니다.

## trust_score_history

Phase 4용 Trust Score window history 테이블입니다. Window별 실제 점수 변화 결과를 저장하기 위한 구조입니다. `edge.trust.trust_score_v2.apply_trust_score_v2_until()`이 detection event 처리, device score 변경, isolation 기록, firewall PENDING 생성과 같은 transaction 안에서 row를 생성합니다. `GET /api/trust-score/{device_id}/history`는 Phase 4 DB에서 이 테이블을 원본으로 조회하며 `detection_events.score_delta`를 재합산하지 않습니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| analysis_window_start | DATETIME | 분석 window 시작 |
| analysis_window_end | DATETIME | 분석 window 종료 |
| previous_score | INTEGER | 적용 전 Trust Score |
| calculated_delta | INTEGER | 계산된 총 변화량 |
| capped_delta | INTEGER | 정책 cap 적용 후 변화량 |
| actual_delta | INTEGER | 실제 적용된 변화량 |
| new_score | INTEGER | 적용 후 Trust Score |
| representative_event_ids_json | TEXT | 대표 detection event id JSON 배열 |
| policy_version | TEXT | Trust Score 정책 version |
| created_at | DATETIME | 생성 시각 |

`(device_id, analysis_window_start, analysis_window_end)`는 중복될 수 없습니다.

## trust_score_compensations

운영자가 승인한 단일 Trust Score 보상의 불변 감사 기록입니다. Source Detection
Event와 Source Trust History를 수정하지 않고, 어떤 감점을 어떤 Backup 근거로
되돌렸는지 기록합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| operation_id | TEXT | 실행별 고유 식별자 |
| device_id | TEXT | 대상 Device |
| source_event_id | INTEGER | 보상 근거 Detection Event, unique |
| source_trust_history_id | INTEGER | 보상 근거 Trust History, unique |
| previous_score | INTEGER | 보상 전 점수 |
| compensation_delta | INTEGER | 양수 보상량 |
| new_score | INTEGER | 보상 후 점수 |
| reason | TEXT | 운영 승인 사유 |
| approved_by | TEXT | 승인자 식별 정보 |
| backup_path | TEXT | 실행 전 SQLite Backup 경로 |
| backup_sha256 | TEXT | Backup SHA256 소문자 64자리 |
| created_at | DATETIME | 감사 Row 생성 시각 |

`new_score = previous_score + compensation_delta`를 검사합니다. Event와 History는 각각
한 번만 보상할 수 있고 모든 외래 키는 `ON DELETE RESTRICT`입니다. v1 CLI는
`devices.trust_score`만 조건부 갱신하며 `devices.status`는 변경하지 않습니다.

## firewall_rules

Firewall 요청/상태 테이블입니다. 격리 진입 시 Trust Score v2 transaction은 기존 MQTT
scope의 `PENDING` 행을 만들고, Migration 011 관리 API는 기존 isolated/APPLIED MQTT
규칙에 연결된 새 광역 PENDING 행을 만듭니다. Worker가 실제 iptables 적용·해제와
reconciliation을 담당합니다. Repository는 `PENDING -> APPLIED`, `PENDING -> PENDING/FAILED`,
`APPLIED/FAILED -> REMOVED`, 관리자 재시도용 `FAILED -> PENDING`을 지원합니다.
FAILED 정리는 정확한 PENDING 해제 감사 요청과 실제 규칙 부재 확인이 필요합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 `devices.device_id` FK, NULL 허용, `ON DELETE SET NULL` |
| source_ip | TEXT | 차단 대상 IPv4, NOT NULL |
| scope | TEXT | 011. NOT NULL, 기본 `MQTT_IPV4_TCP_1883`, 또는 `PI_INPUT_IPV4_ALL` |
| protocol | TEXT | 기본 `tcp`; MQTT scope는 `tcp`, 광역 scope는 NULL |
| dest_port | INTEGER | 기본 `1883`; MQTT scope는 `1883`, 광역 scope는 NULL |
| action | TEXT | NOT NULL, 기본 `DROP`, `DROP`만 허용 |
| status | TEXT | `PENDING`, `APPLIED`, `FAILED`, `REMOVED` |
| reason | TEXT | 요청 사유 |
| trigger_event_id | INTEGER | `detection_events.id` FK, NULL 허용, `ON DELETE SET NULL` |
| applied_at | DATETIME | 적용 시각 |
| released_at | DATETIME | 해제 시각 |
| last_error | TEXT | 마지막 오류 메시지 |
| retry_count | INTEGER | firewall 적용 재시도 횟수, 기본 0, 0 이상 |
| last_attempted_at | DATETIME | 마지막 적용 시도 시각 |
| next_retry_at | DATETIME | 다음 재시도 가능 시각 |
| created_at | DATETIME | 요청 생성 시각 |
| updated_at | DATETIME | 수정 시각 |
| source_rule_id | INTEGER | 011. 원본 `firewall_rules.id` FK, `ON DELETE RESTRICT`; 광역은 양수 필수, MQTT는 NULL |
| approved_policy_revision | INTEGER | 011. 승인한 현재 ACTIVE policy revision; 광역은 양수 필수, MQTT는 NULL |
| requested_by | TEXT | 011. 광역은 서버 인증 principal, 공백 제외 비어 있지 않아야 함; 기존 행은 NULL |
| request_id | TEXT | 011. UNIQUE nullable; 광역은 소문자 정규 UUID4 필수, MQTT는 NULL |

011 CHECK는 scope별 protocol/port/승인 메타데이터 조합을 강제합니다. MQTT는 `tcp`/`1883`,
NULL source/revision/request ID이고 광역은 NULL protocol/port, 양의 source/revision, 정규 UUID4,
비어 있지 않은 actor/reason이어야 합니다. `approved_policy_revision`은 별도 FK가 아니라
승인값이며 현재 적용 정책과의 동일성은 API/Worker에서 다시 검사합니다.

011부터 `PENDING`/`APPLIED`는 `(source_ip, scope)`가 유일합니다. 같은 IP의 MQTT와 광역
규칙은 공존할 수 있으나 같은 scope의 활성 중복은 거부합니다. 기존 status/IP 인덱스는
재생성됩니다. 자동 신규 규칙은 MQTT scope 기본값을 사용하며 기존 ID를 광역으로 바꾸지
않습니다. 최초 광역에는 source APPLIED·현재 isolated 기기·동일 소유 IPv4·현재 ACTIVE
revision·해제 대기 없음이 필요합니다. source ID/사양/device/IP 연결과 승인 revision은
실제 적용·재시도·복원 직전 다시 검사합니다.

동일 `request_id`의 동일 principal/source/device/IP/revision/scope/reason 재요청은 FAILED/
REMOVED에서도 같은 행을 반환합니다. 다른 바인딩은 거부하며 새 UUID도 미해결 이전 광역을
우회하지 못합니다. 기존 광역 REMOVED의 새 승인과 이미 APPLIED인 광역의 source REMOVED
복원에는 정확한 ID의 SUCCEEDED 해제 감사, non-null `released_at`,
`requested_at <= released_at <= processed_at`을 요구합니다. 최초 PENDING 광역은 source
REMOVED에서 적용할 수 없고, 원본 MQTT는 자동 제거하지 않습니다.

완전한 pre-011 DB는 기존 열과 `(source_ip, protocol, dest_port)` 활성 유일성을 유지합니다.
조회와 Release JOIN은 MQTT scope/NULL 승인 메타데이터로 읽기 호환하며 기존 자동·해제
경로를 유지합니다. 광역 승인에는 011이 필요하고 부분 열/완료 버전 불일치는 거부합니다.

## firewall_release_requests

Phase 6-B용 관리자 승인 Firewall Release 요청 queue입니다. Backend API는 이 테이블에
`PENDING` 요청을 생성할 뿐 sudo/iptables를 실행하지 않습니다. Firewall Worker가 공유
lock 아래에서 `release_rule()`을 호출하고 요청을 `SUCCEEDED` 또는 `FAILED`로 종료합니다.
API는 APPLIED 또는 FAILED 규칙에 대해 요청을 저장합니다. Worker의 FAILED 잔여 정리는
정확한 rule ID의 PENDING 요청으로만 허용하고 scope/IP/ID를 모두 맞춰 삭제·부재 확인합니다.
다른 scope는 제거하지 않으며 IP·정책·보호 목록 변경 후에도 정확한 과거 규칙 정리는 허용합니다.
Recovery Preflight는 대상 Device/IP에 연결된 `PENDING` release request가 있으면
Baseline Recovery를 거부합니다. `FAILED` release request는 감사 이력으로 보존하며,
실제 Recovery에는 대상 Device/같은 IP에 연결된 모든 scope의 활성 PENDING/APPLIED 규칙과
PENDING 해제 요청이 없어야 하고 마지막 Firewall 시도/해제 처리 이후 fresh runtime
`VERIFIED_RELEASED` 관측이 필요합니다.
REMOVED 상태만으로 성공을 증명하지 않으며 FAILED 규칙의 runtime DROP이 남아 있어도 HOLD합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| firewall_rule_id | INTEGER | 대상 `firewall_rules.id`, `ON DELETE RESTRICT` |
| status | TEXT | `PENDING`, `SUCCEEDED`, `FAILED` |
| requested_by | TEXT | 인증된 관리자 principal |
| reason | TEXT | 요청 사유 |
| requested_at | TEXT | 요청 시각, UTC `Z` |
| processed_at | TEXT | Worker 처리 완료 시각 |
| last_error | TEXT | 실패 사유. `FAILED`일 때 필수 |
| created_at | TEXT | 생성 시각 |
| updated_at | TEXT | 수정 시각 |

동일 `firewall_rule_id`에는 `status = 'PENDING'` 요청이 하나만 존재할 수 있습니다.
`SUCCEEDED` 또는 `FAILED`로 종료된 뒤에는 새 요청을 만들 수 있습니다. `PENDING`은
`processed_at`과 `last_error`가 없어야 하며, `SUCCEEDED`는 `last_error`가 없어야 합니다.
요청 생성에는 대상 Rule이 APPLIED/FAILED여야 합니다. Rule REMOVED commit 뒤 Request 완료
전에 중단되면 Worker는 다음 cycle에서 정확한 규칙 부재를 재확인하고 SUCCEEDED로 수렴시킵니다.
`processed_at`은 실제 요청 완료 시각을 유지하므로 Rule의 `released_at`보다 늦을 수 있습니다.

## planned_maintenance_operations / planned_maintenance_resumes

010 migration은 계획 종료 승인과 원자적 Packet 재개의 감사 기록을 추가합니다.
실제 장애·손실 구간의 기존 Recovery 승인 조건은 변경하지 않습니다.

`planned_maintenance_operations`의 상태는 `REQUESTED → READY → RESUMED`이며,
종료 준비 실패 시 `REQUESTED` 또는 `READY`에서 `CANCELLED`로 종료합니다.
활성 `REQUESTED`/`READY` 승인은 전체 DB에 하나만 존재할 수 있습니다.

| 주요 컬럼 | 설명 |
| --- | --- |
| operation_id | 계획 종료·다음 재개를 연결하는 고유 UUID |
| approved_by / reason / requested_at | 관리자 식별 정보·사유·승인 시각; 생성 후 불변 |
| source_session_id / source_boot_id | 승인 당시 RUNNING Capture Session과 OS boot UUID |
| required_checkpoints_json | 필수 처리 6개; MQTT IF가 필수로 활성화된 구성은 7개 |
| source_final_boundary | 정상 종료 Session의 마지막 10초 Window 종료 경계 |
| source_snapshot_json | 완료 Session·Segment/Feature 개수와 SHA256·Capture Policy |
| checkpoint_snapshot_json | READY 시점의 참여 Checkpoint 전체 Snapshot |
| ready_at / expires_at | 처리가 완료된 준비 시각과 7일 재개 승인 만료 시각 |
| target_session_id / target_boot_id | 승인 한 번으로 연결된 새 Session·새 boot UUID |
| maintenance_start / maintenance_end | 원본을 보존하는 MQTT·Packet 제외 범위 `[시작, 끝)` |
| resumed_at | 원자적 재개가 적용된 시각 |
| cancelled_at / cancellation_reason | 실패한 종료 준비를 재사용하지 않도록 취소한 감사 정보 |

READY는 source가 실제 `COMPLETED`이고, 전체 Segment가 연속·정상으로 처리됐으며,
필수 Producer·Detector·Trust Checkpoint와 종료 전 미처리 Event가 모두 처리된 경우에만
기록합니다. 참여 Checkpoint의 완료 경계는 모두 source의 마지막 경계와 같아야 합니다.
단순 Session 종료나 `SIGTERM`은 다음 부팅의 재개 승인이 아닙니다.

재개는 source의 불변 증적과 Packet pair Snapshot을 다시 확인하고, 다른 boot의
유일한 새 RUNNING Session의 첫 정상 Packet Feature까지 확인합니다. 승인되지 않은
중간 Session·FAILED 구간·기존 미처리 데이터를 건너뛰지 않습니다. 정상 MQTT 추가나
새 Session의 정상 Capture tail 추가는 전체 DB 변경으로 취급하지 않습니다.
종료 전 시각에 뒤늦게 추가된 미처리 Source Row나 유지보수 구간과 겹치는 기존
Detection Event가 있으면 자동 재개를 보류합니다. 이미 반영된 감점도 삭제·보상하지
않으며 기존 장애 Recovery에서 별도로 판단합니다.

`planned_maintenance_resumes`는 operation당 하나의 불변 Audit이며 target Session도
중복 사용할 수 없습니다. Plan SHA256·JSON, 검증된 Backup 경로·SHA256, 재개 시각을
보존합니다. 두 Packet Checkpoint의 Window 경계 변경, 승인 소비, 이 Audit 생성은
같은 Transaction에서 이뤄지며 기존 처리 ID·MQTT/Trust Checkpoint·기기 점수·격리를
수정하지 않습니다. 동일 실행을 재시도하면 기존 Audit을 확인하고 추가 이동하지
않습니다. 승인 및 Audit의 삭제·재작성은 Trigger로 금지합니다.

READY를 기록하는 Transaction부터 source Session·Segment·Packet Feature의
추가·변경·삭제를 Seal Trigger가 차단합니다. 이미 READY였던 승인을 취소해도 이
원본 봉인은 유지합니다. 새 Session의 Capture/Feature 추가 및 MQTT 수신은 허용하며,
봉인 전에 실패했던 Session의 기존 장애 Recovery 경로에는 적용하지 않습니다.
재개 처리는 Migration 010의 Table·Index·Trigger 선언을 검사하며, 봉인 Trigger가
없거나 다른 선언으로 대체된 경우 보류합니다.

승인이 소비된 유지보수 제외 범위는 이후 target Session의 종료·장애나 Checkpoint
전진 이후에도 보존합니다. Runtime은 불변 Approval/Plan과 Session·첫 Window 연결을
검사합니다. 전체 완료 Session의 증적 Hash는 Capture가 멈춘 종료 준비 및 Read-only
재개 검사에서 확인하고, 실제 재개 Write Transaction은 검증된 봉인과 대상 경계를
재검증하여 기존 Session 전체를 다시 Hash하지 않습니다.

## 주요 Index

002 migration은 다음 조회를 위해 index를 추가합니다.

| Index | 대상 |
| --- | --- |
| `idx_packet_capture_sessions_status` | session 상태 조회 |
| `idx_packet_capture_segments_session_window` | session별 segment window 조회 |
| `idx_packet_capture_segments_status` | segment 상태 조회 |
| `idx_packet_feature_logs_device_window` | 기기별 packet feature window 조회 |
| `idx_packet_feature_logs_peer_window` | peer IP별 packet feature window 조회 |
| `idx_gateway_metrics_collected_at` | gateway metric 시각 조회 |
| `idx_detection_events_packet_feature_log_id` | packet feature 기반 detection event 조회 |
| `idx_detection_events_incident_family_detected_at` | incident family별 event 조회 |
| `idx_detection_events_subject_ip_detected_at` | subject IP별 event 조회 |
| `idx_detection_events_dedupe_key` | Phase 4 detection event dedupe |
| `idx_isolation_history_trust_score_history_id` | Trust History 기반 isolation exactly-once |
| `idx_trust_score_history_window` | window 기반 Trust Score history 조회 |
| `idx_firewall_rules_status` | firewall status 조회 |
| `idx_firewall_rules_source_ip` | source IP별 firewall rule 조회 |
| `idx_firewall_rules_active_unique` | PENDING/APPLIED `(source_ip, scope)` 유일성(011); pre-011은 `(source_ip, protocol, dest_port)` |
| `uq_firewall_release_requests_pending_rule` | Rule별 PENDING release request 중복 방지 |
| `idx_firewall_release_requests_status_requested` | Worker의 PENDING release request 조회 |
