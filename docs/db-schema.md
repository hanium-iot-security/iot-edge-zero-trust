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
| last_seen_at | DATETIME | 마지막 MQTT 수신 시각 |
| created_at | DATETIME | 생성 시각, 기본 current timestamp |

## mqtt_logs

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | topic 또는 payload에서 얻은 device ID |
| topic | TEXT | MQTT topic |
| payload | TEXT | 원본 payload |
| payload_size | INTEGER | payload byte 크기 |
| received_at | DATETIME | 수신 시각, 기본 current timestamp |
| is_json_valid | INTEGER | `0` 또는 `1` |
| is_topic_valid | INTEGER | `0` 또는 `1` |
| error_message | TEXT | 검증 오류 상세 |

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
| description | TEXT | 사람이 읽을 설명 |
| detected_at | DATETIME | 탐지 시각, 기본 current timestamp |

기존 `detection_events` row는 002 migration 적용 시 backfill하지 않습니다. `incident_family`, `processed_at`, `processing_reason`, `applied_to_score` 값은 기존 의미를 유지합니다.

## isolation_history

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| action | TEXT | 격리 이력 action 코드, 기본값 `ISOLATED` |
| reason | TEXT | 격리 이유 |
| trust_score | INTEGER | action 당시 점수 |
| trigger_event_id | INTEGER | action을 유발한 이벤트 |
| created_at | DATETIME | 생성 시각, 기본 current timestamp |

`devices.status`는 현재 기기 상태를 나타내므로 `isolated`를 사용합니다.
`isolation_history.action`은 격리 이력에 저장되는 action 코드이므로 `ISOLATED`를 사용합니다.

TODO: 향후 격리 해제 기능을 추가하면 `RELEASED`를 action 값으로 사용할 수 있습니다.

## packet_capture_sessions

Packet capture session 단위입니다. DB 내부 join에는 `id`를 사용하고, API/CSV/pcap 파일명에는 UUIDv4 문자열인 `session_id`를 사용합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| session_id | TEXT | UUIDv4 문자열, unique |
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
| file_name | TEXT | segment 파일명, unique |
| capture_interface | TEXT | capture interface |
| window_start | DATETIME | window 시작 |
| window_end | DATETIME | window 종료 |
| status | TEXT | `READY`, `PROCESSED`, `EMPTY`, `FAILED` |
| packet_count | INTEGER | packet 수. `READY` 또는 `FAILED`에서는 NULL 가능 |
| processed_at | DATETIME | 처리 완료 시각 |
| error_code | TEXT | 오류 코드 |
| error_message | TEXT | 오류 메시지 |
| created_at | DATETIME | 생성 시각 |
| updated_at | DATETIME | 수정 시각 |

`file_name`과 `(capture_interface, window_start, window_end)`는 중복될 수 없습니다.

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

`(capture_segment_id, peer_ip, direction)`은 중복될 수 없습니다. 격리 상태 기기의 feature 저장을 막는 DB 제약은 두지 않습니다.

## gateway_metrics

Gateway 상태 metric 저장용 테이블입니다. 이번 단계에서는 구조만 생성하고 row 생성 로직은 구현하지 않습니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| collected_at | DATETIME | metric 수집 시각 |
| capture_interface | TEXT | capture interface |
| active_session_count | INTEGER | 활성 session 수 |
| ready_segment_count | INTEGER | READY segment 수 |
| processed_segment_count | INTEGER | PROCESSED segment 수 |
| failed_segment_count | INTEGER | FAILED segment 수 |
| details_json | TEXT | 추가 metric JSON |
| created_at | DATETIME | 생성 시각 |

## detector_checkpoints

Detector별 처리 지점을 저장하기 위한 Phase 4용 테이블입니다. 이번 단계에서는 갱신 로직을 구현하지 않습니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| detector_name | TEXT | detector 이름 |
| checkpoint_key | TEXT | checkpoint key |
| last_processed_id | INTEGER | 마지막 처리 row id |
| last_processed_at | DATETIME | 마지막 처리 시각 |
| updated_at | DATETIME | 수정 시각 |

`(detector_name, checkpoint_key)`는 중복될 수 없습니다.

## trust_score_history

Phase 4용 Trust Score window history 테이블입니다. 이번 단계에서는 row를 자동 생성하지 않으며, 기존 `GET /api/trust-score/{device_id}/history`는 계속 `detection_events`를 원본으로 사용합니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| packet_feature_log_id | INTEGER | 관련 packet feature row |
| detection_event_id | INTEGER | 관련 detection event |
| analysis_window_start | DATETIME | 분석 window 시작 |
| analysis_window_end | DATETIME | 분석 window 종료 |
| score_before | INTEGER | 적용 전 Trust Score |
| score_delta | INTEGER | 변화량 |
| score_after | INTEGER | 적용 후 Trust Score |
| status_before | TEXT | 적용 전 상태 |
| status_after | TEXT | 적용 후 상태 |
| reason | TEXT | 변경 사유 |
| created_at | DATETIME | 생성 시각 |

`(device_id, analysis_window_start, analysis_window_end)`는 중복될 수 없습니다.

## firewall_rules

Phase 4용 firewall 요청/상태 테이블입니다. 이번 단계에서는 row 생성이나 iptables 실행을 구현하지 않습니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| source_ip | TEXT | 차단 대상 IP |
| protocol | TEXT | protocol, 기본 `TCP` |
| dest_port | INTEGER | destination port |
| action | TEXT | firewall action, 기본 `DROP` |
| status | TEXT | `PENDING`, `APPLIED`, `FAILED`, `REMOVED` |
| reason | TEXT | 요청 사유 |
| trigger_event_id | INTEGER | 관련 detection event |
| requested_at | DATETIME | 요청 시각 |
| applied_at | DATETIME | 적용 시각 |
| released_at | DATETIME | 해제 시각 |
| last_error | TEXT | 마지막 오류 메시지 |
| created_at | DATETIME | 생성 시각 |
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
| `idx_trust_score_history_event` | event 기반 Trust Score history 조회 |
| `idx_trust_score_history_window` | window 기반 Trust Score history 조회 |
| `idx_firewall_rules_status` | firewall status 조회 |
| `idx_firewall_rules_source_ip` | source IP별 firewall rule 조회 |
| `idx_firewall_rules_active_unique` | 활성 firewall rule 중복 방지 |
