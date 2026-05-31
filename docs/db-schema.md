# DB Schema Draft

This project uses SQLite for the MVP. The actual database file is stored locally under `backend/data/iot_security.db` and is not committed to Git.

SQLite does not use a `jsonb` column type; JSON payloads should be stored as `TEXT` containing a JSON string unless the implementation later introduces SQLite JSON functions explicitly.

## devices

| Column | Type | Note |
| --- | --- | --- |
| id | integer | primary key autoincrement |
| device_id | text | unique device identifier |
| expected_device_id | text | expected ID for mismatch checks |
| status | text | `NORMAL`, `SUSPICIOUS`, `ISOLATED` |
| trust_score | integer | default 100 |
| last_seen_at | text | latest MQTT receive time, ISO-8601 string |
| created_at | text | created time |
| updated_at | text | updated time |

## mqtt_logs

| Column | Type | Note |
| --- | --- | --- |
| id | integer | primary key autoincrement |
| device_id | text | reported device ID |
| topic | text | MQTT topic |
| payload | text | JSON string payload |
| payload_size | integer | raw payload size |
| qos | integer | MQTT QoS |
| received_at | text | broker receive time, ISO-8601 string |

## feature_logs

| Column | Type | Note |
| --- | --- | --- |
| id | integer | primary key autoincrement |
| device_id | text | device ID |
| window_start | text | 10 second window start, ISO-8601 string |
| window_end | text | 10 second window end, ISO-8601 string |
| message_count | integer | count in window |
| avg_payload_size | real | average payload size |
| max_payload_size | integer | max payload size |
| malformed_count | integer | malformed payload count |
| abnormal_topic_count | integer | abnormal topic count |
| created_at | text | created time |

## detection_events

| Column | Type | Note |
| --- | --- | --- |
| id | integer | primary key autoincrement |
| device_id | text | target device |
| feature_log_id | integer | nullable FK to feature_logs |
| event_type | text | `FLOODING`, `LARGE_PAYLOAD`, `MALFORMED_PAYLOAD`, `ABNORMAL_TOPIC`, `UNKNOWN_DEVICE`, `DEVICE_ID_MISMATCH`, `AI_ANOMALY` |
| severity | text | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| reason | text | human-readable reason |
| raw_data | text | JSON string event details |
| applied_to_score | integer | 0 or 1, default 0 |
| detected_at | text | detection time, ISO-8601 string |

## isolation_history

| Column | Type | Note |
| --- | --- | --- |
| id | integer | primary key autoincrement |
| device_id | text | target device |
| previous_status | text | before transition |
| new_status | text | after transition |
| reason | text | reason for isolation/recovery |
| trust_score | integer | score at transition |
| changed_at | text | transition time, ISO-8601 string |
