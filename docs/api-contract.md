# API Contract Draft

All API paths use `/api` prefix.

## Health

```http
GET /api/health
```

Response:

```json
{
  "status": "ok"
}
```

## MQTT Logs

```http
GET /api/mqtt-logs?device_id=esp32-001&limit=100
```

## Feature Logs

```http
GET /api/feature-logs?device_id=esp32-001&limit=100
```

## Recent Dashboard Data

```http
GET /api/dashboard/recent
```

Expected sections:

```json
{
  "devices": [],
  "mqtt_logs": [],
  "feature_logs": [],
  "detection_events": []
}
```

## Detection Events

```http
GET /api/detection-events?device_id=esp32-001&limit=100
```

## Devices

```http
GET /api/devices
```

## Dashboard Summary

```http
GET /api/dashboard/summary
```

Expected sections:

```json
{
  "total_devices": 0,
  "normal_devices": 0,
  "suspicious_devices": 0,
  "isolated_devices": 0,
  "recent_event_count": 0
}
```

## Trust Score

```http
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
```

## Isolation

```http
GET /api/isolation/history
```

