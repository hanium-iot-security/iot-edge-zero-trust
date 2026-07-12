# 아키텍처

## 경계

```txt
ESP32가 iot/{device_id}/sensor로 publish
  -> Mosquitto
  -> edge worker
  -> SQLite
  -> FastAPI 조회 API
  -> React + Vite Dashboard
```

## Edge 계층

`edge/`는 Raspberry Pi에서 실행되는 판단 로직을 담당합니다.

- `iot/+/sensor` MQTT 구독
- topic 및 payload 검증
- 10초 feature window 생성
- rule-based 탐지
- Isolation Forest 추론
- Trust Score 변경
- isolation history 저장

## 백엔드 계층

`backend/`는 `/api` 아래에 FastAPI 조회 API를 제공합니다. 백엔드 service 파일은 `*_query_service.py`로 이름을 맞춰, 탐지나 Trust Score 계산 로직이 backend에 중복되지 않도록 합니다.

## 데이터 계층

SQLite schema는 `db/migrations/001_init.sql`에 둡니다. 생성된 DB 파일은 `backend/data/iot_security.db`에 위치하며 Git에 올리지 않습니다.

## 프론트엔드 계층

`frontend/`는 React + Vite 기반 대시보드입니다. FastAPI의 `/api` 조회 API를 호출해 기기 상태, MQTT 로그, feature 로그, 탐지 이벤트, Trust Score, 격리 이력을 표시합니다.
