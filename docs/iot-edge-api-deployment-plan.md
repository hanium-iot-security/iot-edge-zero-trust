# IoT Edge API systemd Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raspberry Pi에서 전체 FastAPI Backend를 `iot-edge-api.service`로 안정적으로 실행하고 사설 LAN Health·CORS 검증과 복구 절차를 문서화한다.

**Architecture:** systemd가 필수 `.env`를 읽고 프로젝트 가상환경의 Python으로 Uvicorn을 직접 실행한다. 기존 FastAPI App과 CORS 설정을 재사용하며 새로운 API Runtime 코드는 추가하지 않는다.

**Tech Stack:** systemd, Uvicorn, FastAPI, Pydantic Settings, pytest, Raspberry Pi OS

> **상태:** 로컬 구현·자동 검증 완료. 실제 Pi 설치·재시작·재부팅 검증은 미실행이며 PR과 Notion에 실행 결과를 별도로 기록한다.

## Global Constraints

- 서비스 이름은 `iot-edge-api.service`로 고정한다.
- 하나의 서비스가 MQTT·Packet·Gateway·Detection·Trust·Isolation·Firewall API를 모두 제공한다.
- 운영 명령에는 `--reload`를 사용하지 않는다.
- `.env`는 필수이며 Credential 허용 상태에서 CORS Wildcard를 금지한다.
- API는 사설 LAN에서만 사용하고 공인망·Port Forwarding으로 노출하지 않는다.
- 실제 Pi 설치·재부팅 검증은 로컬 구현과 자동 검증 이후 별도로 수행한다.

---

### Task 1: systemd·Runbook 계약 테스트

**Files:**
- Create: `tests/test_iot_edge_api_deployment.py`
- Create: `infra/systemd/iot-edge-api.service`
- Create: `docs/phase4-api-deployment-runbook.md`

**Interfaces:**
- Consumes: `backend.app.main:app`, `.env`의 `API_HOST`, `API_PORT`, `API_ALLOWED_ORIGINS`
- Produces: Pi에 설치 가능한 Unit과 운영·복구 절차

- [x] **Step 1: 실패하는 Unit 계약 테스트 작성**

`tests/test_iot_edge_api_deployment.py`에 Unit이 필수 환경 파일, 가상환경 Python,
Uvicorn App, Host·Port, 재시작, SIGTERM, Journal, 자동 시작을 포함하고
`--reload`를 포함하지 않는지 검사한다.

- [x] **Step 2: RED 확인**

Run:

```bash
python -m pytest tests/test_iot_edge_api_deployment.py -q
```

Expected: `infra/systemd/iot-edge-api.service`가 없어 실패한다.

- [x] **Step 3: 최소 Unit 구현**

`infra/systemd/iot-edge-api.service`에 설계 문서의 systemd 계약을 반영한다.

- [x] **Step 4: Unit 테스트 GREEN 확인**

Run:

```bash
python -m pytest tests/test_iot_edge_api_deployment.py -q
```

Expected: Unit 계약 테스트가 통과한다.

- [x] **Step 5: 실패하는 Runbook 계약 테스트 작성**

Runbook에 설치, `.env`, 내부·LAN Health, CORS, Journal, 재시작, 재부팅,
Rollback, 공인망 노출 금지 절차가 모두 있는지 검사한다.

- [x] **Step 6: RED 확인**

Run:

```bash
python -m pytest tests/test_iot_edge_api_deployment.py -q
```

Expected: `docs/phase4-api-deployment-runbook.md`가 없어 실패한다.

- [x] **Step 7: Runbook 구현**

검증 가능한 명령과 기대 결과를 포함한 운영 Runbook을 작성한다.

- [x] **Step 8: GREEN 확인**

Run:

```bash
python -m pytest tests/test_iot_edge_api_deployment.py -q
```

Expected: Unit·Runbook 계약 테스트가 모두 통과한다.

### Task 2: 환경 예제와 기존 문서의 개발·운영 구분

**Files:**
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `docs/raspberry-pi-setup.md`
- Modify: `docs/demo-guide.md`
- Test: `tests/test_iot_edge_api_deployment.py`

**Interfaces:**
- Consumes: `iot-edge-api.service`, `docs/phase4-api-deployment-runbook.md`
- Produces: 로컬 개발과 Pi 운영을 혼동하지 않는 문서 계약

- [x] **Step 1: 실패하는 문서 계약 테스트 작성**

`.env.example`이 CORS 실제 Origin 지침을 제공하고, 세 문서가 로컬 `--reload`
실행과 Pi `iot-edge-api.service` 운영 실행을 명확히 구분하는지 검사한다.

- [x] **Step 2: RED 확인**

Run:

```bash
python -m pytest tests/test_iot_edge_api_deployment.py -q
```

Expected: Pi 운영 서비스 안내가 없어 실패한다.

- [x] **Step 3: 최소 문서 수정**

로컬 개발 명령은 유지하고 Pi 운영 섹션에 서비스 설치·실행과 Runbook 링크를 추가한다.
`.env.example`에는 실제 Dashboard Origin을 정확히 추가하라는 주석을 넣는다.

- [x] **Step 4: GREEN 확인**

Run:

```bash
python -m pytest tests/test_iot_edge_api_deployment.py -q
```

Expected: 모든 API 배포 계약 테스트가 통과한다.

### Task 3: 전체 검증

**Files:**
- Verify: 전체 변경 파일

**Interfaces:**
- Consumes: Task 1·2 결과
- Produces: PR 검토 가능한 로컬 검증 증적

- [x] **Step 1: 관련 테스트 실행**

```bash
venv/Scripts/python -m pytest tests/test_iot_edge_api_deployment.py backend/tests/test_health.py backend/tests/test_phase4_backend_api.py -q
```

- [x] **Step 2: 전체 회귀 테스트 실행**

```bash
venv/Scripts/python -m pytest -q
```

- [x] **Step 3: 정적 검증 실행**

```bash
venv/Scripts/python -m compileall backend tests
git diff --check
```

- [x] **Step 4: 변경 검토**

`git status --short`, `git diff --stat`, `git diff`로 범위 밖 변경이 없는지 확인한다.

- [x] **Step 5: 구현 커밋**

```bash
git add infra/systemd/iot-edge-api.service docs/phase4-api-deployment-runbook.md \
  docs/iot-edge-api-deployment-design.md docs/iot-edge-api-deployment-plan.md \
  README.md docs/raspberry-pi-setup.md docs/demo-guide.md .env.example \
  tests/test_iot_edge_api_deployment.py
git commit -m "feat: IoT Edge API systemd 배포 자산 추가"
```
