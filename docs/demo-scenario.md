# Demo Scenario

## Goal

Show that the system can collect normal ESP32 MQTT traffic, detect abnormal behavior, lower Trust Score, isolate suspicious devices, and visualize the result in React.

## Suggested Order

1. Start PostgreSQL and Mosquitto with `docker compose up -d`.
2. Run FastAPI backend.
3. Run React dashboard.
4. Send normal ESP32 telemetry.
5. Show `mqtt_logs` and `feature_logs` updating.
6. Run attack script for one scenario.
7. Show `detection_events` being created.
8. Show Trust Score decreasing.
9. Show device status changing to `SUSPICIOUS` or `ISOLATED`.
10. Explain rule-based and AI-based detection paths.

## Attack Scenarios

- Flooding
- Large Payload
- Malformed Payload
- Abnormal Topic
- Unknown Device
- Device ID Mismatch
- AI Anomaly

