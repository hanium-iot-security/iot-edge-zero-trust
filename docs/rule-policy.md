# 규칙 기반 탐지 정책

규칙 기반 탐지는 `edge/detection`에서 실행되며, `detector_type = RULE`로 `detection_events`에 저장합니다.

| 이벤트 타입 | 기준 |
| --- | --- |
| `ABNORMAL_PUBLISH_RATE` | 10초 동안 `publish_count > 15` 또는 `min_message_interval < 1.0` |
| `LARGE_PAYLOAD` | `max_payload_size > 5120` bytes |
| `MALFORMED_PAYLOAD` | `malformed_payload_count >= 3` |
| `ABNORMAL_TOPIC` | `abnormal_topic_count >= 3` |
| `DEVICE_ID_MISMATCH` | topic device_id와 payload device_id가 모두 존재하지만 서로 다름 |
| `UNKNOWN_DEVICE` | `devices`에 등록되지 않은 device_id |

`UNKNOWN_DEVICE`는 점수를 적용할 등록 기기가 없으므로 Trust Score 계산 대상이 아닙니다.

TODO: 위 기준을 사용해 `edge/detection/rule_detector.py`의 실제 판정 함수를 구현합니다.
