# 규칙 기반 탐지 정책

규칙 기반 탐지는 `edge/detection`에서 실행되며, `detector_type = RULE`로 `detection_events`에 저장합니다.

| 이벤트 타입 | 기준 |
| --- | --- |
| `ABNORMAL_PUBLISH_RATE` | 10초 동안 `publish_count > 15` |
| `LARGE_PAYLOAD` | `max_payload_size > 5120` bytes |
| `MALFORMED_PAYLOAD` | `malformed_payload_count >= 3` |
| `ABNORMAL_TOPIC` | `abnormal_topic_count >= 3` |
| `DEVICE_ID_MISMATCH` | topic device_id와 payload device_id가 모두 존재하지만 서로 다름 |
| `UNKNOWN_DEVICE` | `devices`에 등록되지 않은 device_id |

`MALFORMED_PAYLOAD`는 깨진 JSON 또는 `device_id` 필수 필드가 누락된 payload가 10초 window 기준 3회 이상 발생하면 기록합니다.
`UNKNOWN_DEVICE`는 점수를 적용할 등록 기기가 없으므로 Trust Score 계산 대상이 아닙니다.

`min_message_interval`은 Feature로 계속 수집·저장하며 AI·Dataset·실험 Evidence에서
사용할 수 있습니다. 다만 전달 지연 또는 Subscriber backlog로 정상 메시지의
수신시각이 압축될 수 있으므로, 짧은 `min_message_interval` 값만으로는
`ABNORMAL_PUBLISH_RATE` Rule Event나 Trust Score 감점을 생성하지 않습니다.

## 판정 우선순위

`UNKNOWN_DEVICE`는 `DEVICE_ID_MISMATCH`보다 우선합니다. topic 또는 payload 중 하나라도 미등록 기기이면 `UNKNOWN_DEVICE`로 처리합니다.

## 이벤트 저장 기준

| 이벤트 분류 | 참조 ID |
| --- | --- |
| Feature 기반 (`ABNORMAL_PUBLISH_RATE`, `LARGE_PAYLOAD`, `MALFORMED_PAYLOAD`, `ABNORMAL_TOPIC`) | `feature_log_id` |
| MQTT 원본 기반 (`UNKNOWN_DEVICE`, `DEVICE_ID_MISMATCH`) | `mqtt_log_id` |
| AI 탐지 (`AI_ANOMALY`) | `feature_log_id` |

탐지 실행:

```bash
python -m edge.detection.run_rule_detector
python -m edge.detection.run_ai_detector
```
