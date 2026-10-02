# Demo Guide

## 목표

정상 MQTT 수집, feature 생성, 탐지, Trust Score 감소, 격리, 대시보드 API 조회 흐름을 보여줍니다.

## 명령어

### 로컬 개발

```bash
sudo systemctl start mosquitto
python db/create_tables.py
python db/seed_devices.py
python edge/mqtt/subscriber.py
python -m edge.features.run_mqtt_feature_builder \
  --bootstrap --confirm BOOTSTRAP-MQTT-FEATURE-CHECKPOINT
python -m edge.features.run_mqtt_feature_builder --loop
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Bootstrap은 신규 DB에서 최초 1회만 실행합니다. 기존 운영 DB는 Phase 4
Cutover 절차를 사용합니다.

### Pi 운영

Pi에서는 개발용 `--reload` 대신 설치된 Backend 서비스를 사용합니다.

```bash
sudo systemctl start mosquitto
sudo systemctl start iot-edge-api.service
systemctl is-active iot-edge-api.service
curl --fail http://127.0.0.1:8000/api/health
```

최초 설치와 CORS·재부팅 검증은 `docs/phase4-api-deployment-runbook.md`를
따릅니다.

탐지 및 Trust Score 실행:

```bash
python -m edge.orchestration.run_detection_orchestrator --once
```

Windows 가상환경 활성화:

```powershell
venv\Scripts\activate
```

프론트엔드:

```bash
cd frontend
npm install
npm run dev
```

실제 API 기반 시연 시 `frontend/.env`에서 `VITE_USE_MOCK=false`로 설정합니다.

## MQTT 확인

```bash
mosquitto_sub -h localhost -t 'iot/+/sensor'
mosquitto_pub -h localhost -t 'iot/esp32_01/sensor' -m '{"device_id":"esp32_01","temperature":25.3}'
```

## 시연 순서

1. Mosquitto를 시작합니다.
2. `esp32_01`, `esp32_02`가 들어간 DB를 생성하고 seed합니다.
3. FastAPI를 실행하고 `/api/health`를 확인합니다.
4. 구현된 edge worker를 실행합니다.
5. 정상 telemetry를 `iot/esp32_01/sensor`로 publish합니다.
6. `attacks/`의 공격 스크립트 하나를 실행합니다.
7. `detection_events.event_type`을 확인합니다.
8. Trust Score와 `devices.status`를 확인합니다.
9. `trust_score < 30`이 되면 `isolation_history`를 확인합니다.
