# Raspberry Pi 설정

권장 환경:

- Raspberry Pi OS 64-bit
- Python 3.11+
- 프로젝트 가상환경
- `apt`로 설치한 Mosquitto broker

## 네트워크 정보

| 항목 | 값 |
| --- | --- |
| 공유기 관리자 주소 | `http://192.168.0.1` |
| Raspberry Pi hostname | `iot-gateway` |
| Raspberry Pi username | `pi` |
| Raspberry Pi 고정 IP | `192.168.0.20` |
| MQTT Broker 주소 | `192.168.0.20` |
| MQTT Port | `1883` |
| FastAPI 주소 | `http://192.168.0.20:8000` |
| 정상 MQTT Topic | `iot/esp32_01/sensor` |

Raspberry Pi 내부에서 subscriber를 실행할 때는 Mosquitto가 같은 장비에서 실행되므로 `MQTT_HOST=localhost`를 사용할 수 있습니다. Windows PC나 ESP32처럼 외부 장비에서 broker에 접근할 때는 `192.168.0.20`을 사용합니다.

SSH 접속 예시:

```bash
ssh pi@192.168.0.20
```

비밀번호는 Git에 기록하지 않고 팀 내부에서 별도로 공유합니다.

## Mosquitto

```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

## MQTT Topic

```txt
구독: iot/+/sensor
예시: iot/esp32_01/sensor
```

## MQTT 테스트

```bash
mosquitto_sub -h localhost -t 'iot/+/sensor'
mosquitto_pub -h localhost -t 'iot/esp32_01/sensor' -m '{"device_id":"esp32_01","temperature":25.3}'
```

## Python 설정

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows:

```powershell
venv\Scripts\activate
```

## 데이터베이스

```bash
python db/create_tables.py
python db/seed_devices.py
```

## 백엔드

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
