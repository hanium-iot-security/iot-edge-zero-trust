# Raspberry Pi 설정

권장 환경:

- Raspberry Pi OS 64-bit
- Python 3.11+
- 프로젝트 가상환경
- `apt`로 설치한 Mosquitto broker

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
