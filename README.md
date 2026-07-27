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
  -> React + Vite Dashboard
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
frontend/    React + Vite 대시보드
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
| 대시보드 UI | `frontend` |
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

탐지 및 Trust Score 실행:

```bash
python -m edge.detection.run_rule_detector
python -m edge.detection.run_ai_detector
python -m edge.trust.run_trust_score_update
```

FastAPI 로컬 개발 실행:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

`--reload`는 로컬 개발용입니다. Raspberry Pi 운영 환경에서는 전체 Backend
API를 `iot-edge-api.service` 하나로 실행합니다.

```bash
sudo systemctl enable --now iot-edge-api.service
systemctl is-active iot-edge-api.service
curl --fail http://127.0.0.1:8000/api/health
```

설치, CORS, 재시작·재부팅 및 Rollback 절차는
`docs/phase4-api-deployment-runbook.md`를 따릅니다.

프론트엔드 실행:

```bash
cd frontend
npm install
npm run dev
```

실제 API 기반으로 실행할 때는 `frontend/.env`에서 아래 값을 사용합니다.

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api
VITE_USE_MOCK=false
```

## 6. API 목록

모든 API는 `/api` prefix를 사용합니다.

```txt
GET /api/health
GET /api/dashboard/summary
GET /api/devices
GET /api/devices/{device_id}
GET /api/mqtt-logs
GET /api/feature-logs
GET /api/detection-events
GET /api/trust-score/summary
GET /api/trust-score/{device_id}/history
GET /api/isolation/history
```

기기별 feature/event 조회는 중복 endpoint를 만들지 않고 query parameter로 처리합니다.

```txt
/api/feature-logs?device_id=esp32_01
/api/detection-events?device_id=esp32_01
```

## 7. DB schema 요약

| Table | 목적 |
| --- | --- |
| `devices` | 기기 상태, IP, Trust Score, 마지막 수신 시각 |
| `mqtt_logs` | 원본 MQTT payload와 검증 flag |
| `feature_logs` | 10초 트래픽 feature window |
| `detection_events` | Rule 및 AI 탐지 이벤트 |
| `isolation_history` | Trust Score로 발생한 격리 action |
| `packet_capture_sessions` | Packet capture session |
| `packet_capture_segments` | pcap segment window |
| `packet_feature_logs` | Packet 기반 feature window |
| `gateway_metrics` | Gateway metric |
| `detector_checkpoints` | Detector 처리 지점 |
| `trust_score_history` | Phase 4용 Trust Score window history |
| `firewall_rules` | Phase 4용 firewall rule 상태 |

실제 SQLite DB 파일은 기본적으로 `backend/data/iot_security.db`에 생성됩니다. 이 파일은 Git에 포함하지 않습니다.
실행 가능한 schema는 `db/migrations/`와 `db/migration_runner.py`로 관리합니다.

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

```txt
Device status: normal, warning, danger, isolated
isolation_history.action: ISOLATED
```

같은 feature window에서 여러 이벤트가 발생하면 가장 큰 감점 하나만 반영합니다.

## 10. 공격 시나리오

MVP에서는 실제 악성코드 기반 공격이 아니라, MQTT 통신 행위 기반의 통제 가능한 공격 시나리오를 사용한다.

각 공격 스크립트는 Raspberry Pi의 Mosquitto Broker로 비정상 MQTT 메시지를 publish한다.  
수신 메시지는 우선 `mqtt_logs`에 저장한다. Rule 기준을 충족하거나 정책 위반이 확인된 경우 `detection_events`에 기록한다. 등록된 기기 기준으로 10초 window 집계가 가능한 메시지만 `feature_logs`에 반영한다.

| 공격 시나리오 | 스크립트 | 저장 event_type | 탐지 기준 |
| --- | --- | --- | --- |
| Flooding Attack | `attacks/flooding_attack.py` | `ABNORMAL_PUBLISH_RATE` | 10초 동안 `publish_count > 15` 또는 `min_message_interval < 1.0` |
| Large Payload Attack | `attacks/large_payload_attack.py` | `LARGE_PAYLOAD` | `max_payload_size > 5120` bytes |
| Malformed Payload Attack | `attacks/malformed_payload_attack.py` | `MALFORMED_PAYLOAD` | 깨진 JSON 또는 `device_id` 누락 payload 3회 이상 |
| Abnormal Topic Attack | `attacks/abnormal_topic_attack.py` | `ABNORMAL_TOPIC` | 허용되지 않은 topic 형식 3회 이상 |
| Unknown Device Attack | `attacks/unknown_device_attack.py` | `UNKNOWN_DEVICE` | 등록되지 않은 `device_id` 사용 |
| Device ID Mismatch Attack | `attacks/device_id_mismatch_attack.py` | `DEVICE_ID_MISMATCH` | topic의 device_id와 payload의 device_id 불일치 |

`UNKNOWN_DEVICE`는 등록 기기의 Trust Score 감점 대상이 아니라, 미등록 기기 접근 이벤트로 기록하고 즉시 차단 또는 메시지 무시 처리한다.

`DEVICE_ID_MISMATCH`는 topic과 payload의 device_id가 모두 존재하지만 서로 다른 경우에만 적용한다. 단, 미등록 device_id가 포함된 경우에는 `UNKNOWN_DEVICE`를 우선 적용한다.

**Abnormal Topic 테스트 시 subscriber 구독 범위 설정**

`admin/system/control`, `cmd/exec` 등 비정상 topic은 subscriber가 `iot/+/sensor`만 구독하면 수신되지 않아 탐지가 동작하지 않는다.  
Abnormal Topic 공격 테스트 시에는 `.env`에 아래 설정을 적용해야 한다.

```env
MQTT_SUBSCRIBE_TOPIC=#
```

기본값(`iot/+/sensor`)은 정상 운영 구독 범위이며, 통합 테스트 완료 후 되돌린다.

## 11. Git 브랜치 운영 규칙

현재 원격 저장소의 기본 브랜치는 `develop`이며, MVP 개발은 `develop`을 기준으로 진행한다.

원격 저장소 기준 `main` 브랜치는 현재 사용하지 않는다.  
MVP가 시연 가능한 안정 버전이 되었을 때 `develop`을 기준으로 `main`을 생성하거나 갱신하고, 이후 `main`은 제출, 시연, 릴리즈용 안정 브랜치로 관리한다.

브랜치 운영 기준은 다음과 같다.

```txt
develop
- 현재 기본 개발 브랜치
- 각 기능 브랜치에서 작업한 내용을 PR로 통합하는 기준 브랜치

main
- MVP 완성 후 사용 예정
- 시연/제출/릴리즈용 안정 브랜치
- MVP 완성 시 v1.0.0-mvp 태그를 함께 생성 예정

feature/woomin-mqtt-feature-api
- MQTT 수집, 10초 window feature 추출, FastAPI 기본 API 작업

feature/sunwoo-rule-attack
- Rule-based 탐지 로직 및 MQTT 공격 시나리오 스크립트 작업

feature/jongmin-ai-detector
- Isolation Forest 학습, 모델 저장, AI 이상 탐지 추론 작업

feature/hyunsu-trust-isolation-api
- Trust Score 계산, 기기 상태 변경, 격리 이력, 관련 API 작업

feature/soyou-dashboard
- React 대시보드 UI 및 API 연동 작업

docs/project-docs
- 코드 변경 없이 README, API 명세, DB 명세, 공격 시나리오, 시연 흐름 등 공통 문서만 크게 정리할 때 필요 시 생성
```

기능 구현과 직접 관련된 문서 수정은 해당 `feature/*` 브랜치에서 함께 수정할 수 있다.

예를 들어 Rule 탐지 코드를 수정하면서 공격 시나리오 문서를 함께 수정하거나, FastAPI API를 추가하면서 API 명세를 함께 수정하는 방식은 허용한다.

단, README 전체 구조 변경이나 공통 문서 대규모 정리는 충돌 방지를 위해 작업 전에 팀원들에게 공유한 뒤 진행한다.

기본 작업 흐름은 다음과 같다.

```txt
1. develop 브랜치 최신화
2. 본인 담당 feature 브랜치 생성
3. 기능 구현 및 관련 문서 수정
4. commit / push
5. Pull Request 생성
6. 리뷰 후 develop에 merge
7. MVP 안정화 후 main 생성 또는 갱신 및 태그 부여
```

## 12. Commit Message 규칙

커밋 메시지는 아래 형식을 사용한다.

```txt
type: 작업 내용 요약
```

사용 가능한 type은 다음과 같다.

| type | 의미 | 예시 |
| --- | --- | --- |
| `feat` | 새로운 기능 추가 | `feat: MQTT subscriber DB 저장 기능 추가` |
| `fix` | 버그 수정 또는 명세 불일치 수정 | `fix: feature window 중복 저장 오류 수정` |
| `docs` | 문서 수정 | `docs: Git 브랜치 운영 규칙 보강` |
| `refactor` | 동작 변경 없는 코드 구조 개선 | `refactor: detection service 모듈 분리` |
| `test` | 테스트 코드 추가 또는 수정 | `test: mqtt_logs 저장 테스트 추가` |
| `chore` | 설정, 패키지, 빌드 관련 작업 | `chore: requirements.txt 패키지 추가` |
| `style` | 포맷팅, 들여쓰기 등 동작 변화 없는 수정 | `style: 코드 포맷 정리` |

## MVP E2E Test

실제 Raspberry Pi + ESP32 기반 MVP E2E 테스트 절차와 결과는 아래 문서를 참고합니다.

- [MVP E2E 테스트 가이드](docs/mvp-e2e-test-guide.md)
- [MVP E2E 테스트 결과 - 2026-07-02](docs/mvp-e2e-test-results-2026-07-02.md)
- [Packet Isolation Forest Core 가이드](docs/packet-if-runbook.md)
