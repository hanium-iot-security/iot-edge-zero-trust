# Architecture

## MVP Flow

```txt
ESP32
  -> Raspberry Pi
  -> Mosquitto MQTT Broker
  -> Python MQTT Subscriber
  -> SQLite mqtt_logs
  -> 10 second feature window
  -> SQLite feature_logs
  -> rule-based detection / Isolation Forest
  -> SQLite detection_events
  -> trust score update
  -> device isolation status
  -> FastAPI
  -> React dashboard
```

## Edge Gateway

Raspberry Pi is the MVP edge gateway.

Responsibilities:

- Run Mosquitto MQTT Broker.
- Run FastAPI backend.
- Store local logs in SQLite.
- Run MQTT subscriber and feature extraction workers.
- Run rule-based detection and Isolation Forest inference.
- Update Trust Score and device isolation status.

## Backend Modules

```txt
app/main.py                 # FastAPI entrypoint
app/core/                   # config and common settings
app/db/                     # SQLite connection/session
app/models/                 # ORM models
app/schemas/                # API request/response schemas
app/routers/                # API endpoints
app/services/               # detection, trust score, isolation logic
app/workers/                # MQTT subscriber, feature extraction worker
data/                       # local SQLite database file
```

## Scope Split

MVP:

1. MQTT traffic collection from ESP32.
2. SQLite log storage.
3. 10 second feature window generation.
4. Rule-based attack detection.
5. Isolation Forest anomaly detection.
6. Trust Score and isolation status.
7. React dashboard API integration.

Future expansion:

- Packet capture beyond MQTT.
- eBPF-based kernel monitoring.
- Software Defined Perimeter.
- Advanced model optimization for edge devices.

