# DB Schema

SQLite를 MVP 데이터베이스로 사용합니다. 생성된 DB 파일은 `backend/data/iot_security.db`에 저장되며 Git에는 올리지 않습니다. 실행 가능한 schema는 `db/migrations/001_init.sql`입니다.

DB 생성과 seed:

```bash
python db/create_tables.py
python db/seed_devices.py
```

SQLite 동시 접근 설정:

```sql
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout = 5000;
```

## devices

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| device_id | TEXT | primary key, 기본 seed `esp32_01` |
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
| malformed_payload_count | INTEGER | JSON 파싱 실패 수 |

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
| applied_to_score | INTEGER | `0` 또는 `1` |
| description | TEXT | 사람이 읽을 설명 |
| detected_at | DATETIME | 탐지 시각, 기본 current timestamp |

## isolation_history

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER | primary key autoincrement |
| device_id | TEXT | 대상 기기 |
| action | TEXT | 기본값 `isolate` |
| reason | TEXT | 격리 이유 |
| trust_score | INTEGER | action 당시 점수 |
| trigger_event_id | INTEGER | action을 유발한 이벤트 |
| created_at | DATETIME | 생성 시각, 기본 current timestamp |

TODO: 수동 또는 자동 격리 해제 기능을 추가하면 `release`를 action 값으로 사용합니다.
