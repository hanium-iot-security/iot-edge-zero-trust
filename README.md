# Hanium MQTT Security MVP

ESP32 MQTT 데이터를 수집하고, rule-based 탐지와 Isolation Forest 이상 탐지, Trust Score 기반 격리 상태를 대시보드로 보여주는 한이음 MVP 프로젝트입니다.

## Repository Structure

```txt
haniot-mqtt-security/
├─ backend/       # FastAPI, DB models, MQTT subscriber, detection services
├─ frontend/      # React dashboard
├─ firmware/      # ESP32 normal/attack firmware
├─ scripts/       # attack scripts, CSV export, model training
├─ models/        # trained ML model files
├─ sample-data/   # normal/attack sample data
├─ docs/          # API contract, DB schema, architecture, demo docs
└─ .github/       # PR template and GitHub collaboration files
```

## Branch Strategy

```txt
main        # stable demo/release branch
develop     # integration branch
feature/*   # member work branches
```

Recommended member branches:

```txt
feature/wumin-mqtt-feature-api
feature/sunwoo-rule-detection
feature/jongmin-isolation-forest
feature/hyunsu-trust-isolation-api
feature/soyou-dashboard-docs
```

## Owners

| Owner | Area | Main Paths |
| --- | --- | --- |
| 원우민 | 정상 데이터, MQTT 수집, DB 저장, Feature 추출, FastAPI 기본 구조 | `backend/app/workers`, `backend/app/routers`, `scripts/export_training_csv.py` |
| 정선우 | Rule-based 탐지, 공격 테스트 | `backend/app/services/rule_detection.py`, `scripts/mqtt_attack` |
| 정종민 | Isolation Forest 학습, 추론 | `scripts/train_isolation_forest.py`, `backend/app/services/ai_detection.py`, `models` |
| 정현수 | Trust Score, 격리, 상태 API, 탐지 이벤트 API | `backend/app/services/trust_score.py`, `backend/app/routers` |
| 박소유 | React 대시보드, 문서, 시연 | `frontend`, `docs`, `README.md` |

## First Setup

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Infra:

```bash
docker compose up -d
```

## Team Rule

DB schema and API response shape should be updated in `docs/db-schema.md` and `docs/api-contract.md` before implementation PRs are merged.

