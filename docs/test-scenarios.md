# 테스트 시나리오

## 정상 Telemetry

- 유효한 JSON을 `iot/esp32_01/sensor`로 publish합니다.
- `mqtt_logs`에 `is_json_valid = 1`, `is_topic_valid = 1`인 row가 1개 생겨야 합니다.
- detection event는 없어야 합니다.

## 비정상 Publish Rate

- `attacks/flooding_attack.py`를 실행합니다.
- DB event type은 `ABNORMAL_PUBLISH_RATE`여야 합니다.
- 공격 스크립트 이름을 event type으로 저장하지 않습니다.

## 잘못된 Payload

- `tests/samples/malformed_payload.txt`를 publish합니다.
- `MALFORMED_PAYLOAD`가 발생해야 합니다.

## Device ID 불일치

- `iot/esp32_01/sensor`로 publish하되 payload의 `device_id`는 `esp32_99`로 보냅니다.
- `DEVICE_ID_MISMATCH`가 발생해야 합니다.

## 알 수 없는 기기

- `iot/esp32_99/sensor`로 publish합니다.
- `UNKNOWN_DEVICE`가 발생해야 합니다.
- 등록되지 않은 기기이므로 Trust Score를 적용하지 않습니다.

## 격리

- 충분한 감점을 적용해 `trust_score < 30` 상태를 만듭니다.
- device status는 `isolated`가 되어야 합니다.
- `isolation_history`에 row가 생겨야 합니다.
