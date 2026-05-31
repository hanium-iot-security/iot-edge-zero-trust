# Demo Scenario

## Goal

Show that the system can collect normal ESP32 MQTT traffic on a Raspberry Pi edge gateway, detect abnormal behavior, lower Trust Score, isolate suspicious devices, and visualize the result in React.

## Suggested Order

1. Start Mosquitto on Raspberry Pi.
2. Run FastAPI backend on Raspberry Pi or a development PC.
3. Run React dashboard.
4. Send normal ESP32 telemetry.
5. Show `mqtt_logs` and `feature_logs` updating in SQLite.
6. Run one attack scenario with an ESP32 attack mode or Python attack script.
7. Show `detection_events` being created.
8. Show Trust Score decreasing.
9. Show device status changing to `SUSPICIOUS` or `ISOLATED`.
10. Show `isolation_history` being saved.

## Attack Scenarios

- Flooding
- Large Payload
- Malformed Payload
- Abnormal Topic
- Unknown Device
- Device ID Mismatch
- AI Anomaly

## Raspberry Pi Commands

```bash
sudo systemctl start mosquitto
sudo systemctl status mosquitto
```

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

