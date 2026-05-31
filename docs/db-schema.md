# DB Schema Draft

This file is the source of truth for table responsibilities during MVP development.

## devices

| Column | Type | Note |
| --- | --- | --- |
| id | bigint | primary key |
| device_id | varchar | unique device identifier |
| expected_device_id | varchar | expected ID for mismatch checks |
| status | varchar | `NORMAL`, `SUSPICIOUS`, `ISOLATED` |
| trust_score | integer | default 100 |
| last_seen_at | timestamp | latest MQTT receive time |
| created_at | timestamp | created time |
| updated_at | timestamp | updated time |

## mqtt_logs

| Column | Type | Note |
| --- | --- | --- |
| id | bigint | primary key |
| device_id | varchar | reported device ID |
| topic | varchar | MQTT topic |
| payload | jsonb | parsed payload |
| payload_size | integer | raw payload size |
| qos | integer | MQTT QoS |
| received_at | timestamp | broker receive time |

## feature_logs

| Column | Type | Note |
| --- | --- | --- |
| id | bigint | primary key |
| device_id | varchar | device ID |
| window_start | timestamp | 10 second window start |
| window_end | timestamp | 10 second window end |
| message_count | integer | count in window |
| avg_payload_size | float | average payload size |
| max_payload_size | integer | max payload size |
| malformed_count | integer | malformed payload count |
| abnormal_topic_count | integer | abnormal topic count |
| created_at | timestamp | created time |

## detection_events

| Column | Type | Note |
| --- | --- | --- |
| id | bigint | primary key |
| device_id | varchar | target device |
| feature_log_id | bigint | nullable FK to feature_logs |
| event_type | varchar | `FLOODING`, `LARGE_PAYLOAD`, `MALFORMED_PAYLOAD`, `ABNORMAL_TOPIC`, `UNKNOWN_DEVICE`, `DEVICE_ID_MISMATCH`, `AI_ANOMALY` |
| severity | varchar | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| reason | text | human-readable reason |
| raw_data | jsonb | event details |
| applied_to_score | boolean | default false |
| detected_at | timestamp | detection time |

## isolation_history

| Column | Type | Note |
| --- | --- | --- |
| id | bigint | primary key |
| device_id | varchar | target device |
| previous_status | varchar | before transition |
| new_status | varchar | after transition |
| reason | text | reason for isolation/recovery |
| trust_score | integer | score at transition |
| changed_at | timestamp | transition time |

