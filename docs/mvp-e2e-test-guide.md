# MVP E2E 테스트 가이드

이 문서는 MVP E2E 테스트를 재현하기 위한 실행 가이드이다. 실제 장비 기반 테스트와 로컬 사전 테스트 모두 같은 흐름을 기준으로 한다.

## 목적

다음 MVP E2E 흐름의 실행 절차를 정리한다.

```txt
ESP32
-> MQTT Publish
-> Raspberry Pi Mosquitto Broker
-> Python MQTT Subscriber
-> SQLite mqtt_logs 저장
-> 10초 window feature_logs 생성
-> Rule-based 탐지
-> Isolation Forest AI 탐지
-> Trust Score 계산
-> 격리 상태 변경
-> FastAPI API 응답
-> React Dashboard 표시
```

## 테스트 환경

| 항목 | 값 |
| --- | --- |
| Gateway | Raspberry Pi |
| Gateway IP | `192.168.0.20` |
| MQTT Broker | Mosquitto |
| MQTT Port | `1883` |
| DB | SQLite |
| Backend | FastAPI |
| Frontend | React Dashboard |
| 정상 기기 | `esp32_01` |
| 공격 테스트 기기 | `esp32_02` |
| Dashboard | `http://localhost:5173` |

## 사전 조건

Mosquitto 실행 상태를 확인한다.

```bash
sudo systemctl status mosquitto
```

MQTT 1883 포트가 열려 있는지 확인한다.

```bash
ss -lntp | grep 1883
```

DB 초기화 전에는 Subscriber, Feature Collector, FastAPI를 모두 종료한다.

## DB 초기화

프로젝트 디렉터리로 이동하고 가상환경을 활성화한다.

```bash
cd ~/iot-edge-zero-trust
source venv/bin/activate
```

기존 SQLite DB 파일을 제거한다.

```bash
rm -f backend/data/iot_security.db
rm -f backend/data/iot_security.db-wal
rm -f backend/data/iot_security.db-shm
```

DB schema를 생성하고 기본 기기를 seed한다.

```bash
python -m db.create_tables
python -m db.seed_devices
```

기본 등록 기기를 확인한다.

```bash
sqlite3 backend/data/iot_security.db "
SELECT device_id, status, trust_score
FROM devices;
"
```

기대 결과:

```txt
esp32_01|normal|100
esp32_02|normal|100
```

## 환경 변수 주의사항

Abnormal Topic 공격을 수신하려면 Subscriber가 전체 topic을 구독해야 한다.

```env
MQTT_SUBSCRIBE_TOPIC=#
```

`.env`를 수정한 뒤에는 Subscriber를 재시작해야 한다.

운영 기준 정상 구독 범위는 `iot/+/sensor`이고, Abnormal Topic 테스트 시에만 `#` 사용을 권장한다.

## 실행 터미널 구성

### 터미널 1: MQTT Subscriber

```bash
cd ~/iot-edge-zero-trust
source venv/bin/activate
python -m edge.mqtt.subscriber
```

### 터미널 2: Feature Collector

```bash
cd ~/iot-edge-zero-trust
source venv/bin/activate
python -m edge.features.collect_feature_logs --loop --interval 5
```

### 터미널 3: 공격 및 탐지 실행

아래 명령은 필요한 시나리오별로 순서대로 실행한다.

## Rule-based 테스트

### Malformed Payload

```bash
python -m attacks.malformed_payload_attack --device_id esp32_02 --count 5 --interval 1.5
sleep 15
python -m edge.detection.run_rule_detector
```

확인 SQL:

```bash
sqlite3 backend/data/iot_security.db "
SELECT id, device_id, detector_type, event_type, severity, score_delta,
       applied_to_score, feature_log_id, mqtt_log_id, detected_at
FROM detection_events
WHERE event_type='MALFORMED_PAYLOAD'
ORDER BY id DESC
LIMIT 10;
"
```

### Abnormal Topic

```bash
python -m attacks.abnormal_topic_attack --device_id esp32_02 --count 5 --interval 1.5
sleep 15
python -m edge.detection.run_rule_detector
```

확인 SQL:

```bash
sqlite3 backend/data/iot_security.db "
SELECT id, device_id, detector_type, event_type, severity, score_delta,
       applied_to_score, feature_log_id, mqtt_log_id, detected_at
FROM detection_events
WHERE event_type='ABNORMAL_TOPIC'
ORDER BY id DESC
LIMIT 10;
"
```

### Device ID Mismatch

```bash
python -m attacks.device_id_mismatch_attack --count 4 --interval 2.0
sleep 3
python -m edge.detection.run_rule_detector
```

확인 SQL:

```bash
sqlite3 backend/data/iot_security.db "
SELECT id, device_id, detector_type, event_type, severity, score_delta,
       applied_to_score, feature_log_id, mqtt_log_id, detected_at
FROM detection_events
WHERE event_type='DEVICE_ID_MISMATCH'
ORDER BY id DESC
LIMIT 10;
"
```

Device ID Mismatch 공격은 topic 기준 device_id에 따라 `esp32_01`과 `esp32_02` 이벤트가 모두 생성될 수 있다.

## AI Anomaly 테스트

AI 모델 파일은 아래 경로에 있어야 한다.

```txt
ai/models/isolation_forest.joblib
```

모델 파일은 Git에 커밋하지 않는다.

Flooding 공격을 실행하고 AI detector를 실행한다.

```bash
python -m attacks.flooding_attack --count 30 --interval 0.2
sleep 15
python -m edge.detection.run_ai_detector
```

확인 SQL:

```bash
sqlite3 backend/data/iot_security.db "
SELECT id, device_id, detector_type, event_type, severity, score_delta,
       applied_to_score, feature_log_id, mqtt_log_id, description, detected_at
FROM detection_events
WHERE event_type='AI_ANOMALY'
ORDER BY id DESC
LIMIT 10;
"
```

## Trust Score 반영

Trust Score update를 실행한다.

```bash
python -m edge.trust.run_trust_score_update
```

기기 상태를 확인한다.

```bash
sqlite3 backend/data/iot_security.db "
SELECT device_id, status, trust_score, last_seen_at
FROM devices;
"
```

이벤트 반영 상태를 확인한다.

```bash
sqlite3 backend/data/iot_security.db "
SELECT id, device_id, event_type, score_delta, applied_to_score,
       feature_log_id, mqtt_log_id
FROM detection_events
ORDER BY id;
"
```

`applied_to_score=0`은 점수 미반영, `applied_to_score=1`은 점수 반영 완료를 의미한다.

`UNKNOWN_DEVICE`는 등록 기기의 Trust Score 감점 대상이 아니므로 `score_delta=0`으로 처리된다.

동일 feature window에서 이미 다른 이벤트가 점수에 반영된 경우 일부 이벤트는 `Applied=no` 상태로 남을 수 있다.

## FastAPI 실행

Raspberry Pi에서 FastAPI를 실행한다.

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Windows PC 또는 다른 장비에서 API를 확인한다.

```bash
curl.exe http://192.168.0.20:8000/api/health
curl.exe "http://192.168.0.20:8000/api/devices"
curl.exe "http://192.168.0.20:8000/api/detection-events?limit=50"
curl.exe "http://192.168.0.20:8000/api/feature-logs?limit=50"
```

## React Dashboard 확인

Frontend `.env`는 아래처럼 설정한다.

```env
VITE_API_BASE_URL=http://192.168.0.20:8000/api
VITE_USE_MOCK=false
```

React Dashboard를 실행한다.

```bash
cd frontend
npm run dev
```

확인 페이지:

```txt
Dashboard: Summary, Recent Events, Feature Graph
Devices: device status, trust_score
MQTT Logs: 원본 MQTT 로그
Events: Rule / AI detection events
Isolation: 격리 이력
```

## 주의사항

- DB 초기화 전에는 Subscriber, Feature Collector, FastAPI를 종료한다.
- `.env`에서 `MQTT_SUBSCRIBE_TOPIC=#`를 설정한 뒤에는 Subscriber를 재시작해야 Abnormal Topic을 수신할 수 있다.
- Device ID Mismatch 공격은 `esp32_01`과 `esp32_02` 양쪽 이벤트를 만들 수 있다.
- AI Detector는 전체 `feature_logs`를 조회하므로 이전 feature window에서도 `AI_ANOMALY`가 생성될 수 있다.
- 격리 상태가 된 기기는 이후 `feature_logs` 생성 대상에서 제외된다.
- Dashboard Events Page가 제한된 개수만 표시하면 이전 이벤트가 화면에서 밀릴 수 있으므로 필요 시 API에서 `limit` 값을 늘려 확인한다.
