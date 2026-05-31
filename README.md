# Hanium MQTT Security MVP

제로 트러스트 기반 IoT 엣지 보안을 위한 동적 위협 탐지 및 자동 격리 시스템 MVP입니다.

ESP32가 MQTT 메시지를 보내면 Raspberry Pi가 엣지 게이트웨이 역할을 하며 Mosquitto, FastAPI, SQLite 기반 로그 저장, 이상 탐지, Trust Score 계산, 격리 상태 관리를 수행합니다. React 대시보드는 FastAPI를 호출해 기기 상태, MQTT 로그, feature 로그, 탐지 이벤트, Trust Score, 격리 이력을 보여줍니다.

## 1. MVP 목표

계획서의 큰 방향은 패킷 수집, AI 이상 탐지, 제로 트러스트 신뢰 점수, 자동 격리, 대시보드입니다. 현재 MVP에서는 이를 MQTT 기반으로 단순화합니다.

```txt
ESP32 정상/공격 MQTT 송신
  -> Raspberry Pi의 Mosquitto MQTT Broker
  -> Python MQTT Subscriber
  -> SQLite mqtt_logs 저장
  -> 10초 단위 feature_logs 생성
  -> Rule-based 탐지 / Isolation Forest 탐지
  -> detection_events 저장
  -> Trust Score 감점
  -> devices.status 변경
  -> isolation_history 저장
  -> FastAPI API 제공
  -> React Dashboard 표시
```

## 2. 기술 스택

| 영역 | 기술 |
| --- | --- |
| IoT Device | ESP32 |
| Edge Gateway | Raspberry Pi |
| MQTT Broker | Mosquitto |
| Backend API | FastAPI |
| Backend Language | Python |
| Database | SQLite |
| AI Detection | scikit-learn Isolation Forest |
| Frontend | React, Vite, TypeScript |
| Collaboration | Git, GitHub, Pull Request |

## 3. 폴더 구조

```txt
haniot-mqtt-security/
+-- backend/
|   +-- app/
|   |   +-- core/          # 환경 설정
|   |   +-- db/            # SQLite 연결/session
|   |   +-- models/        # ORM 모델
|   |   +-- routers/       # FastAPI 라우터
|   |   +-- schemas/       # API request/response schema
|   |   +-- services/      # 탐지, Trust Score, 격리 로직
|   |   +-- workers/       # MQTT subscriber, feature extractor
|   +-- data/              # SQLite DB 파일 위치, 실제 .db 파일은 Git 제외
|   +-- migrations/        # DB migration 또는 schema 변경 기록
|   +-- tests/             # backend tests
|   +-- requirements.txt
+-- frontend/
|   +-- src/
|       +-- api/           # FastAPI 호출 client
|       +-- components/    # dashboard components
|       +-- pages/         # dashboard pages
|       +-- types/         # TypeScript types
+-- firmware/
|   +-- esp32/             # ESP32 정상/공격 펌웨어
+-- scripts/
|   +-- mqtt_attack/       # MQTT 공격 테스트 스크립트
|   +-- export_training_csv.py
|   +-- train_isolation_forest.py
+-- models/                # 학습된 모델 파일, 실제 모델 파일은 Git 제외
+-- sample-data/           # 정상/공격 샘플 데이터
+-- docs/                  # DB/API/아키텍처/시연 문서
+-- infra/                 # Raspberry Pi/Mosquitto 설정 참고 자료
+-- .github/               # PR template
```

## 4. 팀원 역할

| 담당자 | 역할 | 주요 경로 |
| --- | --- | --- |
| 원우민 | 정상 데이터, MQTT 수집, DB 저장, Feature 추출, FastAPI 기본 구조 | `backend/app/workers`, `backend/app/routers`, `scripts/export_training_csv.py` |
| 정선우 | Rule-based 탐지, 공격 테스트 | `backend/app/services/rule_detection.py`, `scripts/mqtt_attack` |
| 정종민 | Isolation Forest 학습, 추론 | `scripts/train_isolation_forest.py`, `backend/app/services/ai_detection.py`, `models` |
| 정현수 | Trust Score, 격리, 상태 API, 탐지 이벤트 API | `backend/app/services/trust_score.py`, `backend/app/routers` |
| 박소유 | React 대시보드, 문서, 시연 화면 구성 | `frontend`, `docs`, `README.md` |

## 5. Git 브랜치 전략

```txt
main        # 발표/시연 가능한 안정 버전
develop     # 기능 통합 브랜치
feature/*   # 개인 기능 개발 브랜치
```

추천 브랜치 이름:

```txt
feature/wumin-mqtt-feature-api
feature/sunwoo-rule-detection
feature/jongmin-isolation-forest
feature/hyunsu-trust-isolation-api
feature/soyou-dashboard-docs
```

작업 흐름:

```txt
develop에서 feature 브랜치 생성
  -> 기능 구현
  -> 로컬 테스트
  -> GitHub Pull Request 생성
  -> 코드 리뷰
  -> develop merge
  -> Raspberry Pi 또는 로컬 PC에서 통합 테스트
  -> main merge
```

## 6. Raspberry Pi 실행 준비

### 6.1 Mosquitto 설치

Raspberry Pi에서 MQTT Broker를 직접 실행합니다.

```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

상태 확인:

```bash
sudo systemctl status mosquitto
```

테스트:

```bash
mosquitto_sub -h localhost -t 'devices/+/telemetry'
mosquitto_pub -h localhost -t 'devices/esp32-001/telemetry' -m '{"device_id":"esp32-001","temperature":25.3}'
```

### 6.2 환경 변수 준비

```bash
cp .env.example .env
```

Windows PowerShell에서는 다음 명령을 사용할 수 있습니다.

```powershell
Copy-Item .env.example .env
```

기본 SQLite DB 위치:

```txt
backend/data/iot_security.db
```

실제 `.db` 파일은 Git에 올리지 않습니다.

### 6.3 Backend 실행

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend URL:

```txt
http://localhost:8000
```

Health check:

```txt
http://localhost:8000/api/health
```

### 6.4 Frontend 실행

```bash
cd frontend
npm install
npm run dev
```

Frontend URL:

```txt
http://localhost:5173
```

Raspberry Pi에서 backend를 띄우고 노트북에서 frontend를 실행하는 경우, frontend의 API 주소를 Raspberry Pi IP로 맞춰야 합니다.

```txt
VITE_API_BASE_URL=http://<RASPBERRY_PI_IP>:8000/api
```

## 7. 주요 API

모든 API는 `/api` prefix를 사용합니다. 주요 API 구현은 원우민과 정현수가 담당하고, 박소유는 이 API들을 호출해 대시보드 화면에 표시합니다.

| Method | Path | 담당 | 설명 |
| --- | --- | --- | --- |
| GET | `/api/health` | 원우민 | 서버 상태 확인 |
| GET | `/api/mqtt-logs` | 원우민 | MQTT 수신 로그 조회 |
| GET | `/api/feature-logs` | 원우민 | 10초 window feature 로그 조회 |
| GET | `/api/dashboard/recent` | 원우민 | 최근 MQTT 로그, feature 로그, 탐지 이벤트 요약 |
| GET | `/api/detection-events` | 정현수 | 탐지 이벤트 조회 |
| GET | `/api/devices` | 정현수 | 기기 상태와 Trust Score 조회 |
| GET | `/api/dashboard/summary` | 정현수 | 대시보드 상단 요약 지표 |
| GET | `/api/trust-score/summary` | 정현수 | 전체 Trust Score 요약 |
| GET | `/api/trust-score/{device_id}/history` | 정현수 | 특정 기기 Trust Score 이력 |
| GET | `/api/isolation/history` | 정현수 | 격리 및 상태 변경 이력 |

자세한 API 계약은 `docs/api-contract.md`를 기준으로 관리합니다.

## 8. DB 테이블

SQLite를 사용합니다.

| Table | 설명 |
| --- | --- |
| `devices` | 기기 ID, 상태, Trust Score, 마지막 접속 시각 |
| `mqtt_logs` | MQTT topic, payload, payload size, 수신 시각 |
| `feature_logs` | 10초 window 기반 통계 feature |
| `detection_events` | rule-based / AI 탐지 결과 |
| `isolation_history` | 기기 상태 변경 및 격리 이력 |

자세한 schema는 `docs/db-schema.md`를 기준으로 관리합니다.

## 9. 탐지 시나리오

Rule-based 탐지 대상:

| Event Type | 설명 |
| --- | --- |
| `FLOODING` | 짧은 시간 동안 과도한 MQTT 메시지 송신 |
| `LARGE_PAYLOAD` | 비정상적으로 큰 payload 송신 |
| `MALFORMED_PAYLOAD` | JSON 파싱 실패 등 잘못된 payload |
| `ABNORMAL_TOPIC` | 허용되지 않은 topic으로 송신 |
| `UNKNOWN_DEVICE` | 등록되지 않은 device_id 사용 |
| `DEVICE_ID_MISMATCH` | topic의 device_id와 payload의 device_id 불일치 |

AI 탐지 대상:

| Event Type | 설명 |
| --- | --- |
| `AI_ANOMALY` | 정상 feature 기반 Isolation Forest가 이상 window로 판단 |

## 10. Trust Score 규칙 초안

초기 점수는 `100`점입니다.

| Severity | 예시 감점 |
| --- | --- |
| `LOW` | -5 |
| `MEDIUM` | -10 |
| `HIGH` | -20 |
| `CRITICAL` | -30 |

주의할 점:

- 같은 feature window에서 중복 감점되지 않도록 `detection_events.applied_to_score`를 사용합니다.
- Trust Score가 격리 기준 이하로 떨어지면 `devices.status`를 `ISOLATED`로 변경합니다.
- 상태 변경은 `isolation_history`에 저장합니다.

최종 감점 정책은 구현 중 팀 합의에 따라 조정할 수 있습니다.

## 11. 문서 관리 규칙

중요한 변경은 코드와 문서를 함께 수정합니다.

| 변경 내용 | 수정해야 할 문서 |
| --- | --- |
| DB column 추가/변경 | `docs/db-schema.md` |
| API path 또는 response 변경 | `docs/api-contract.md` |
| Raspberry Pi 실행 방식 변경 | `docs/raspberry-pi-setup.md` |
| 시연 순서 변경 | `docs/demo-scenario.md` |
| 팀 작업 규칙 변경 | `docs/team-rules.md` |

## 12. PR 규칙

PR을 만들 때는 `.github/pull_request_template.md`를 기준으로 작성합니다.

확인할 것:

- 작업 내용이 명확한가?
- 로컬 테스트 방법이 적혀 있는가?
- DB 변경 여부가 적혀 있는가?
- API 변경 여부가 적혀 있는가?
- Frontend 영향 여부가 적혀 있는가?

커밋 메시지 예시:

```txt
feat: mqtt subscriber stores normal telemetry
feat: rule detection saves flooding events
feat: train isolation forest model
feat: apply trust score penalty
feat: dashboard shows detection events
fix: handle malformed mqtt payload
docs: update demo scenario
```

## 13. 시연 흐름

1. Raspberry Pi에서 Mosquitto를 실행합니다.
2. FastAPI backend를 실행합니다.
3. React dashboard를 실행합니다.
4. ESP32에서 정상 MQTT telemetry를 송신합니다.
5. Dashboard에서 `mqtt_logs`, `feature_logs` 갱신을 확인합니다.
6. 공격 스크립트 또는 ESP32 공격 모드를 실행합니다.
7. `detection_events`에 탐지 결과가 저장되는지 확인합니다.
8. Trust Score가 감소하는지 확인합니다.
9. 기준 이하 기기가 `SUSPICIOUS` 또는 `ISOLATED`로 변경되는지 확인합니다.
10. 격리 이력이 `isolation_history`에 저장되는지 확인합니다.

## 14. 현재 상태

현재 repository는 MVP 협업을 위한 초기 구조만 세팅된 상태입니다.

완료된 것:

- 모노레포 폴더 구조 생성
- Raspberry Pi + SQLite 기준 구조 정리
- FastAPI 기본 entrypoint 생성
- `/api/health` 기본 API 생성
- React/Vite 기본 구조 생성
- DB/API/시연/팀 규칙 문서 초안 생성
- PR template 생성
- `main`, `develop` 브랜치 생성

앞으로 구현할 것:

- SQLite ORM model과 schema 작성
- MQTT subscriber 구현
- 10초 feature window 생성
- rule-based 탐지 구현
- Isolation Forest 학습/추론 구현
- Trust Score 및 격리 로직 구현
- React dashboard 화면 구현
- Raspberry Pi 통합 시연 데이터 준비

