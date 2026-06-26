# IoT Edge Zero Trust - Frontend

React + Vite 기반 Dashboard입니다.

Frontend는 SQLite DB를 직접 조회하지 않고 FastAPI Backend REST API를 호출하여 Dashboard를 구성합니다.

---

# Requirements

* Node.js 18+
* npm

---

# Install

```bash
cd frontend
npm install
```

---

# Environment Variables

프로젝트 실행 전 `frontend/.env` 파일을 생성하거나 `.env.example`을 복사하여 사용합니다.

예시:

```env
VITE_API_BASE_URL=http://localhost:8000/api
VITE_USE_MOCK=false
```

| 변수                  | 설명                                         |
| ------------------- | ------------------------------------------ |
| `VITE_API_BASE_URL` | FastAPI API 서버 주소                          |
| `VITE_USE_MOCK`     | `true` : mockData 사용 / `false` : 실제 API 사용 |

---

# Run

```bash
npm run dev
```

기본 개발 서버

```
http://localhost:5173
```

---

# Backend API

Frontend는 아래 FastAPI API를 사용합니다.

* `/api/dashboard/summary`
* `/api/devices`
* `/api/mqtt-logs`
* `/api/feature-logs`
* `/api/detection-events`
* `/api/trust-score/summary`
* `/api/trust-score/{device_id}/history`
* `/api/isolation/history`

---

# Polling

실시간 Dashboard를 위해 Polling 방식을 사용합니다.

기본 갱신 주기

* Dashboard Summary : 3초
* Devices : 3초
* MQTT Logs : 3초
* Detection Events : 3초
* Trust Score Summary : 3초
* Isolation : 3초

---

# Mock Mode

UI 테스트를 위해 Mock Data를 사용할 수 있습니다.

```env
VITE_USE_MOCK=true
```

실제 FastAPI API를 사용할 경우

```env
VITE_USE_MOCK=false
```

---

# Project Structure

```
frontend
├── src
│   ├── api
│   ├── pages
│   ├── styles
│   └── mockData.js
├── .env.example
├── package.json
└── vite.config.js
```
