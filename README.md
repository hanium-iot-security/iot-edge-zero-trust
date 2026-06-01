# IoT Edge Zero Trust MVP

Hanium 프로젝트용 MQTT 기반 제로 트러스트 IoT 엣지 보안 MVP입니다. ESP32가 Mosquitto로 센서 데이터를 발행하면, Raspberry Pi의 edge worker가 트래픽을 SQLite에 저장하고 분석합니다. FastAPI는 저장된 데이터를 조회 API로 제공하고, 향후 React + Vite 기반 대시보드가 기기 상태를 표시합니다.

## 1. 프로젝트 개요

이 MVP는 MQTT 트래픽으로 범위를 제한합니다. 백엔드는 판단 엔진이 아닙니다. 탐지, Trust Score 갱신, 격리 판단은 `edge/`에서 담당하고, FastAPI는 SQLite를 조회해 대시보드용 JSON을 반환합니다.

## 2. MVP 전체 흐름

```txt
ESP32 -> iot/{device_id}/sensor
  -> Raspberry Pi의 Mosquitto
  -> edge/mqtt subscriber
  -> mqtt_logs
  -> edge/features 10초 window
  -> feature_logs
  -> edge/detection rule 또는 AI 탐지
  -> detection_events
  -> edge/trust 점수 및 격리 정책
  -> devices / isolation_history
  -> FastAPI /api/*
  -> React + Vite dashboard 예정
```

기본 MQTT 값:

```txt
정상 topic: iot/{device_id}/sensor
구독 topic: iot/+/sensor
기본 device_id: esp32_01
```

## 3. 폴더 구조

```txt
backend/     FastAPI 조회 API
edge/        Raspberry Pi worker와 판단 로직
attacks/     MQTT 공격 시나리오 스크립트
ai/          Isolation Forest export/train/predict 스크립트
db/          SQLite schema, create, seed, reset 스크립트
data/        학습 데이터와 export 데이터
tests/       backend/integration 테스트와 작은 샘플
frontend/    React + Vite 대시보드 예약 구조
docs/        아키텍처, API, DB, 정책, 시나리오 문서
infra/       Mosquitto 참고 설정
firmware/    ESP32 펌웨어 자리
```

## 4. 역할 분담

| 영역 | 경로 |
| --- | --- |
| MQTT 수집과 feature window | `edge/mqtt`, `edge/features` |
| Rule 탐지와 공격 스크립트 | `edge/detection`, `attacks` |
| AI 모델 학습과 추론 | `ai`, `edge/detection/ai_detector.py` |
| Trust Score와 격리 | `edge/trust` |
| API와 대시보드 데이터 조회 | `backend/app/routers`, `backend/app/services` |
| 대시보드 UI 예정 | `frontend` |
| 문서와 시연 흐름 | `docs`, `README.md` |

## 5. 실행 방법

Python 가상환경:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

DB 생성:

```bash
python db/create_tables.py
python db/seed_devices.py
```

Edge 진입점 실행:

```bash
python edge/mqtt/subscriber.py
python edge/features/collect_feature_logs.py
```

탐지 및 Trust Score 실행 진입점은 구현 단계에서 확정합니다. 실제 진입점이 정해지면 `edge/scripts/run_detector.sh` 또는 `edge/detection/rule_detector.py` 기준으로 갱신합니다.

FastAPI 실행:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

프론트엔드:

현재 `frontend/`는 예약 구조만 유지합니다. JavaScript 또는 TypeScript 사용 여부를 확정한 뒤 `frontend/README.md` 기준으로 Vite 스캐폴딩을 생성합니다.

## 6. API 목록

모든 API는 `/api` prefix를 사용합니다.

```txt
GET /api/health
GET /api/dashboard/summary
GET /api/dashboard/recent
GET /api/devices
GET /api/devices/{device_id}
GET /api/devices/{device_id}/features
GET /api/devices/{device_id}/events
GET /api/mqtt-logs
GET /api/feature-logs
GET /api/detection-events
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
GET /api/isolation/history
```

## 7. DB schema 요약

| Table | 목적 |
| --- | --- |
| `devices` | 기기 상태, IP, Trust Score, 마지막 수신 시각 |
| `mqtt_logs` | 원본 MQTT payload와 검증 flag |
| `feature_logs` | 10초 트래픽 feature window |
| `detection_events` | Rule 및 AI 탐지 이벤트 |
| `isolation_history` | Trust Score로 발생한 격리 action |

실제 SQLite DB 파일은 기본적으로 `backend/data/iot_security.db`에 생성됩니다. 이 파일은 Git에 포함하지 않습니다.
실행 가능한 schema는 `db/migrations/001_init.sql`입니다.

## 8. 규칙 기반 탐지 기준

| 이벤트 타입 | 기준 |
| --- | --- |
| `ABNORMAL_PUBLISH_RATE` | 10초 동안 `publish_count > 15` 또는 `min_message_interval < 1.0` |
| `LARGE_PAYLOAD` | `max_payload_size > 5120` bytes |
| `MALFORMED_PAYLOAD` | `malformed_payload_count >= 3` |
| `ABNORMAL_TOPIC` | `abnormal_topic_count >= 3` |
| `UNKNOWN_DEVICE` | 등록되지 않은 device_id |
| `DEVICE_ID_MISMATCH` | topic의 device_id와 payload의 device_id가 다름 |

flooding 공격 스크립트 이름은 DB event type이 아닙니다. DB에는 `ABNORMAL_PUBLISH_RATE`를 저장합니다.

## 9. Trust Score 기준

```txt
초기값: 100
최소값: 0
최대값: 100

80-100: normal
60-79: warning
30-59: danger
0-29: isolated
격리 기준: trust_score < 30
```

같은 feature window에서 여러 이벤트가 발생하면 가장 큰 감점 하나만 반영합니다.

## 10. 공격 시나리오

```txt
attacks/flooding_attack.py
attacks/large_payload_attack.py
attacks/malformed_payload_attack.py
attacks/abnormal_topic_attack.py
attacks/unknown_device_attack.py
attacks/device_id_mismatch_attack.py
```

## 11. Git 브랜치

```txt
main
develop
feature/woomin-mqtt-feature-api
feature/sunwoo-rule-attack
feature/jongmin-ai-detector
feature/hyunsu-trust-isolation-api
feature/soyou-dashboard
docs/project-docs
```

## 12. Commit Message 규칙

```txt
feat: 새로운 기능 추가
fix: 버그 수정
docs: 문서 수정
refactor: 코드 구조 개선
test: 테스트 코드 추가
chore: 설정 파일 수정
style: 코드 포맷 수정
```
