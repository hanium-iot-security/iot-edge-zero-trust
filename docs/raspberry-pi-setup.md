# Raspberry Pi Setup

## Role

Raspberry Pi is the edge gateway for the MVP.

It can run:

- Mosquitto MQTT Broker
- FastAPI backend
- SQLite local database
- MQTT subscriber worker
- Feature extraction worker
- Rule-based and AI anomaly detection

## Install Mosquitto

```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

## Test MQTT

Terminal 1:

```bash
mosquitto_sub -h localhost -t 'devices/+/telemetry'
```

Terminal 2:

```bash
mosquitto_pub -h localhost -t 'devices/esp32-001/telemetry' -m '{"device_id":"esp32-001","temperature":25.3}'
```

## Run Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## SQLite

Default DB path:

```txt
backend/data/iot_security.db
```

The `.db` file is generated locally and should not be committed.
