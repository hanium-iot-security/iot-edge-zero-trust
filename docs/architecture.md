# Architecture

## MVP Flow

```txt
ESP32
  -> Mosquitto MQTT Broker
  -> Python MQTT Subscriber
  -> mqtt_logs
  -> 10 second feature window
  -> feature_logs
  -> rule-based detection / Isolation Forest
  -> detection_events
  -> trust score update
  -> device isolation status
  -> FastAPI
  -> React dashboard
```

## Backend Modules

```txt
app/main.py                 # FastAPI entrypoint
app/core/                   # config and common settings
app/db/                     # DB connection/session
app/models/                 # ORM models
app/schemas/                # API request/response schemas
app/routers/                # API endpoints
app/services/               # detection, trust score, isolation logic
app/workers/                # MQTT subscriber, feature extraction worker
```

## Integration Priority

1. DB schema and migrations
2. MQTT normal data collection
3. Feature window creation
4. Rule-based attack detection
5. Isolation Forest inference
6. Trust Score and isolation status
7. Dashboard API integration

