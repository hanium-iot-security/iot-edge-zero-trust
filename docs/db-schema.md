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

`db/migration_runner.py`가 적용한 migration을 기록합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| version | INTEGER | migration version, primary key |
| name | TEXT | migration 이름 |
| applied_at | DATETIME | 적용 시각, 기본 current timestamp |

## devices

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| device_id | TEXT | primary key, 기본 seed `esp32_01`, `esp32_02` |
| ip_address | TEXT | 기기 IP |
| status | TEXT | `normal`, `warning`, `danger`, `isolated` |
| trust_score | INTEGER | 기본값 `100` |
| last_seen_at | DATETIME | 마지막 MQTT 수신 시각. 신규 Subscriber는 UTC `YYYY-MM-DDTHH:MM:SSZ` 저장 |
| created_at | DATETIME | 생성 시각, 기본 current timestamp |

## mqtt_logs

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | topic 또는 payload에서 얻은 device ID |
| topic | TEXT | MQTT topic |
| payload | TEXT | 원본 payload |
| payload_size | INTEGER | payload byte 크기 |
| received_at | DATETIME | 수신 시각. 신규 Subscriber는 UTC `YYYY-MM-DDTHH:MM:SSZ`, DB 기본값은 `CURRENT_TIMESTAMP` |
| is_json_valid | INTEGER | `0` 또는 `1` |
| is_topic_valid | INTEGER | `0` 또는 `1` |
| error_message | TEXT | 검증 오류 상세 |

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

## firewall_rules

Phase 4용 firewall 요청/상태 테이블입니다. 이번 PR은 DB repository와 조회 API만 구현합니다. 격리 진입 시 Trust Score v2 transaction에서 `PENDING` row를 만들 수 있지만, 실제 iptables 실행과 worker reconciliation은 다른 담당 범위입니다. Repository는 `PENDING -> APPLIED`, `PENDING -> PENDING/FAILED`, `APPLIED -> REMOVED`, 관리자 재시도용 `FAILED -> PENDING`만 허용합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| source_ip | TEXT | 차단 대상 IP |
| protocol | TEXT | protocol, 기본 `tcp`, 1차 계약은 `tcp`만 허용 |
| dest_port | INTEGER | destination port, 1차 계약은 `1883`만 허용 |
| action | TEXT | firewall action, 1차 계약은 `DROP`만 허용 |
| status | TEXT | `PENDING`, `APPLIED`, `FAILED`, `REMOVED` |
| reason | TEXT | 요청 사유 |
| trigger_event_id | INTEGER | 관련 detection event |
| applied_at | DATETIME | 적용 시각 |
| released_at | DATETIME | 해제 시각 |
| last_error | TEXT | 마지막 오류 메시지 |
| retry_count | INTEGER | firewall 적용 재시도 횟수, 기본 0, 0 이상 |
| last_attempted_at | DATETIME | 마지막 적용 시도 시각 |
| next_retry_at | DATETIME | 다음 재시도 가능 시각 |
| created_at | DATETIME | 요청 생성 시각 |
| updated_at | DATETIME | 수정 시각 |

`PENDING`, `APPLIED` 상태에서는 `(source_ip, protocol, dest_port)` 조합이 중복될 수 없습니다.

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
| `idx_firewall_rules_active_unique` | 활성 firewall rule 중복 방지 |
