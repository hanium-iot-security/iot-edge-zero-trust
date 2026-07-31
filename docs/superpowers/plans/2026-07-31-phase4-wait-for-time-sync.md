# Phase 4 Wait for Time Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raspberry Pi 부팅 시 최초 NTP 동기화가 끝난 뒤에만 시간 기반 수집·탐지 systemd 서비스가 시작되도록 한다.

**Architecture:** 각 시간 의존 Unit이 `systemd-time-wait-sync.service`를 직접 `Wants=` 및 `After=`로 참조한다. 기존 서비스 실행 경로와 의존성은 유지하고, FastAPI와 Firewall Worker는 이번 변경 범위에서 제외한다.

**Tech Stack:** systemd Unit, Python pytest, Raspberry Pi OS, systemd-timesyncd

## Global Constraints

- 기준 브랜치는 `develop`이다.
- 작업 브랜치는 `fix/phase4-wait-for-time-sync`이다.
- 수정 대상은 Packet Capture, Gateway Metrics, MQTT Feature Builder, Detection Orchestrator Unit 4개로 제한한다.
- `iot-edge-api.service`와 `firewall-worker.service`는 수정하지 않는다.
- 테스트를 먼저 실패시키고 최소 Unit 변경으로 통과시킨다.
- Raspberry Pi 운영 Unit 설치 전 기존 파일을 반드시 백업한다.
- 실제 운영 DB Cutover, Firewall 설치, ESP32 공격 실행은 이번 작업에 포함하지 않는다.

---

### Task 1: Time Sync Unit 계약 테스트 추가

**Files:**
- Create: `tests/test_systemd_time_sync_dependencies.py`
- Read: `infra/systemd/packet-capture.service`
- Read: `infra/systemd/gateway-metrics.service`
- Read: `infra/systemd/mqtt-feature-builder.service`
- Read: `infra/systemd/detection-orchestrator.service`
- Read: `infra/systemd/iot-edge-api.service`
- Read: `infra/systemd/firewall-worker.service`

**Interfaces:**
- Consumes: systemd Unit `[Unit]` 섹션의 `After`, `Wants`
- Produces: 시간 동기화 의존성 회귀를 방지하는 pytest 계약

- [ ] **Step 1: 실패하는 계약 테스트 작성**

```python
from configparser import ConfigParser
from pathlib import Path


SYSTEMD_DIR = Path("infra/systemd")
TIME_WAIT_UNIT = "systemd-time-wait-sync.service"


def read_unit(name: str) -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(SYSTEMD_DIR / name, encoding="utf-8")
    return parser


def tokens(parser: ConfigParser, key: str) -> set[str]:
    return set(parser["Unit"][key].split())


def test_time_window_services_wait_for_initial_time_sync() -> None:
    for name in (
        "packet-capture.service",
        "gateway-metrics.service",
        "mqtt-feature-builder.service",
    ):
        unit = read_unit(name)
        assert TIME_WAIT_UNIT in tokens(unit, "After")
        assert TIME_WAIT_UNIT in tokens(unit, "Wants")


def test_detection_orchestrator_keeps_builder_and_waits_for_time_sync() -> None:
    unit = read_unit("detection-orchestrator.service")

    assert {
        "network-online.target",
        TIME_WAIT_UNIT,
        "mqtt-feature-builder.service",
    }.issubset(tokens(unit, "After"))
    assert {
        "network-online.target",
        TIME_WAIT_UNIT,
        "mqtt-feature-builder.service",
    }.issubset(tokens(unit, "Wants"))


def test_non_window_services_are_not_broadened_by_this_fix() -> None:
    for name in ("iot-edge-api.service", "firewall-worker.service"):
        unit = read_unit(name)
        assert TIME_WAIT_UNIT not in tokens(unit, "After")
        assert TIME_WAIT_UNIT not in tokens(unit, "Wants")
```

- [ ] **Step 2: 테스트가 기존 Unit에서 실패하는지 확인**

Run:

```bash
python -m pytest tests/test_systemd_time_sync_dependencies.py -q
```

Expected: 첫 두 테스트가 `systemd-time-wait-sync.service` 누락으로 FAIL하고, 제외 범위 테스트는 PASS한다.

- [ ] **Step 3: 테스트 파일 커밋**

```bash
git add tests/test_systemd_time_sync_dependencies.py
git commit -m "test: require time sync before time-based services"
```

---

### Task 2: 시간 기반 systemd Unit 의존성 수정

**Files:**
- Modify: `infra/systemd/packet-capture.service:1-5`
- Modify: `infra/systemd/gateway-metrics.service:1-5`
- Modify: `infra/systemd/mqtt-feature-builder.service:1-5`
- Modify: `infra/systemd/detection-orchestrator.service:1-5`
- Test: `tests/test_systemd_time_sync_dependencies.py`

**Interfaces:**
- Consumes: `systemd-time-wait-sync.service`, 기존 `network-online.target`, 기존 `mqtt-feature-builder.service`
- Produces: NTP 최초 동기화 이후 시작되는 Unit 계약

- [ ] **Step 1: Packet Capture Unit 최소 수정**

```ini
After=network-online.target systemd-time-wait-sync.service
Wants=network-online.target systemd-time-wait-sync.service
```

- [ ] **Step 2: Gateway Metrics Unit 최소 수정**

```ini
After=network-online.target systemd-time-wait-sync.service
Wants=network-online.target systemd-time-wait-sync.service
```

- [ ] **Step 3: MQTT Feature Builder Unit 최소 수정**

```ini
After=network-online.target systemd-time-wait-sync.service
Wants=network-online.target systemd-time-wait-sync.service
```

- [ ] **Step 4: Detection Orchestrator 기존 의존성을 유지하며 수정**

```ini
After=network-online.target systemd-time-wait-sync.service mqtt-feature-builder.service
Wants=network-online.target systemd-time-wait-sync.service mqtt-feature-builder.service
```

- [ ] **Step 5: 계약 테스트 통과 확인**

Run:

```bash
python -m pytest tests/test_systemd_time_sync_dependencies.py -q
```

Expected: `3 passed`.

- [ ] **Step 6: 기존 Unit 관련 테스트 실행**

Run:

```bash
python -m pytest \
  tests/test_systemd_time_sync_dependencies.py \
  tests/test_gateway_metrics_runner.py \
  tests/test_iot_edge_api_deployment.py \
  tests/test_phase4_cutover_workflow.py \
  -q
```

Expected: 수정된 계약에 맞춰 모든 테스트 PASS. 기존 테스트가 정확한 문자열을 고정하고 있어 실패하면 해당 테스트를 의미 보존 방식으로 갱신한다.

- [ ] **Step 7: Unit 수정 커밋**

```bash
git add \
  infra/systemd/packet-capture.service \
  infra/systemd/gateway-metrics.service \
  infra/systemd/mqtt-feature-builder.service \
  infra/systemd/detection-orchestrator.service \
  tests/test_systemd_time_sync_dependencies.py
git commit -m "fix: wait for initial time sync before detectors"
```

---

### Task 3: 운영 Runbook에 NTP 대기 계약 반영

**Files:**
- Modify: `docs/packet-capture-runbook.md`
- Modify: `docs/gateway-metrics-runbook.md`
- Modify: `docs/phase4-cutover-runbook.md`
- Test: `tests/test_systemd_time_sync_dependencies.py`

**Interfaces:**
- Consumes: Unit의 `systemd-time-wait-sync.service` 의존성
- Produces: 설치 전 점검, 오프라인 주의사항, 부팅 검증 절차

- [ ] **Step 1: Packet Capture Runbook에 사전 확인 추가**

다음 명령과 판정 기준을 설치 절차 전에 추가한다.

```bash
systemctl show systemd-time-wait-sync.service \
  --property=LoadState \
  --property=FragmentPath \
  --no-pager
```

정상 기준:

```text
LoadState=loaded
FragmentPath=/usr/lib/systemd/system/systemd-time-wait-sync.service
```

- [ ] **Step 2: Gateway Metrics Runbook에 동일 계약 추가**

`systemd-time-wait-sync.service`가 설치되어 있지 않으면 Unit 설치를 중단하고 OS 시간 동기화 구성을 먼저 해결하도록 명시한다.

- [ ] **Step 3: Phase 4 Cutover Runbook에 오프라인 정책 추가**

다음 내용을 명시한다.

```text
NTP 서버에 도달할 수 없는 환경에서는 시간 기반 Runtime이 대기 상태로 남을 수 있다.
잘못된 시각으로 Window와 Checkpoint를 생성하는 것보다 시작을 보류하는 것을 안전 정책으로 사용한다.
```

- [ ] **Step 4: 문서 계약 테스트 확장**

`tests/test_systemd_time_sync_dependencies.py`에 다음 테스트를 추가한다.

```python
def test_runbooks_explain_time_sync_preflight_and_offline_policy() -> None:
    packet = Path("docs/packet-capture-runbook.md").read_text(encoding="utf-8")
    gateway = Path("docs/gateway-metrics-runbook.md").read_text(encoding="utf-8")
    cutover = Path("docs/phase4-cutover-runbook.md").read_text(encoding="utf-8")

    assert "systemd-time-wait-sync.service" in packet
    assert "systemd-time-wait-sync.service" in gateway
    assert "NTP" in cutover
    assert "대기" in cutover
```

- [ ] **Step 5: 문서 계약 테스트 실행**

Run:

```bash
python -m pytest tests/test_systemd_time_sync_dependencies.py -q
```

Expected: `4 passed`.

- [ ] **Step 6: 문서 커밋**

```bash
git add \
  docs/packet-capture-runbook.md \
  docs/gateway-metrics-runbook.md \
  docs/phase4-cutover-runbook.md \
  tests/test_systemd_time_sync_dependencies.py
git commit -m "docs: document time sync startup requirement"
```

---

### Task 4: 로컬 전체 검증 및 Draft PR 생성

**Files:**
- Verify: entire repository

**Interfaces:**
- Consumes: Tasks 1-3의 Unit·테스트·문서
- Produces: 검증 증거가 포함된 Draft PR

- [ ] **Step 1: Python 정적 컴파일 확인**

```bash
python -m compileall -q backend edge tests
```

Expected: exit code `0`.

- [ ] **Step 2: 의존성 상태 확인**

```bash
python -m pip check
```

Expected: `No broken requirements found.`

- [ ] **Step 3: 전체 회귀 테스트 실행**

```bash
python -m pytest -q --ignore=tests/test_firewall_rule_wrapper.py
```

Expected: 모든 실행 테스트 PASS.

- [ ] **Step 4: Diff 형식 확인**

```bash
git diff --check origin/develop...HEAD
```

Expected: 출력 없음, exit code `0`.

- [ ] **Step 5: Draft PR 생성**

PR 제목:

```text
fix: NTP 동기화 후 시간 기반 Runtime 시작
```

PR 본문에는 다음을 포함한다.

```text
원인: 부팅 초기 과거 시각으로 서비스가 시작된 뒤 최초 NTP 동기화 시 약 8시간 시각 점프
수정: 시간 기반 Unit 4개가 systemd-time-wait-sync.service 완료 후 시작
제외: FastAPI, Firewall Worker, 운영 DB Cutover, ESP32 공격 실행
검증: 계약 테스트, 전체 회귀 테스트, Pi systemd-analyze verify 예정
```

---

### Task 5: Raspberry Pi 정적 검증 및 설치 준비

**Files:**
- Read: `infra/systemd/*.service`
- Backup: `/etc/systemd/system/packet-capture.service`
- Backup: `/etc/systemd/system/gateway-metrics.service`

**Interfaces:**
- Consumes: Draft PR 브랜치의 Unit 파일
- Produces: 설치 전 검증 증거와 복구 가능한 백업

- [ ] **Step 1: Pi에서 브랜치와 SHA 확인**

```bash
git status -sb
git branch --show-current
git rev-parse HEAD
```

Expected: `fix/phase4-wait-for-time-sync`, 깨끗한 작업 트리.

- [ ] **Step 2: Unit 정적 검증**

```bash
sudo systemd-analyze verify \
  infra/systemd/packet-capture.service \
  infra/systemd/gateway-metrics.service \
  infra/systemd/mqtt-feature-builder.service \
  infra/systemd/detection-orchestrator.service
```

Expected: 변경 Unit에 대한 오류 없음.

- [ ] **Step 3: 현재 설치 Unit SHA256 기록**

```bash
sha256sum \
  /etc/systemd/system/packet-capture.service \
  /etc/systemd/system/gateway-metrics.service
```

- [ ] **Step 4: timestamp 포함 백업 생성**

```bash
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -m 0644 \
  /etc/systemd/system/packet-capture.service \
  "/etc/systemd/system/packet-capture.service.${STAMP}.bak"
sudo install -m 0644 \
  /etc/systemd/system/gateway-metrics.service \
  "/etc/systemd/system/gateway-metrics.service.${STAMP}.bak"
```

- [ ] **Step 5: 백업 원본 일치 확인**

```bash
sudo cmp -s \
  /etc/systemd/system/packet-capture.service \
  "/etc/systemd/system/packet-capture.service.${STAMP}.bak"
sudo cmp -s \
  /etc/systemd/system/gateway-metrics.service \
  "/etc/systemd/system/gateway-metrics.service.${STAMP}.bak"
```

Expected: 두 명령 exit code `0`.

---

### Task 6: Raspberry Pi Unit 설치 및 재부팅 검증

**Files:**
- Install: `infra/systemd/packet-capture.service`
- Install: `infra/systemd/gateway-metrics.service`

**Interfaces:**
- Consumes: Task 5의 백업과 검증된 Unit
- Produces: NTP 동기화 후 서비스 시작 증거

- [ ] **Step 1: 수정 Unit 설치**

```bash
sudo install -m 0644 \
  infra/systemd/packet-capture.service \
  /etc/systemd/system/packet-capture.service
sudo install -m 0644 \
  infra/systemd/gateway-metrics.service \
  /etc/systemd/system/gateway-metrics.service
sudo systemctl daemon-reload
```

- [ ] **Step 2: 설치본과 저장소 원본 일치 확인**

```bash
sudo cmp -s infra/systemd/packet-capture.service /etc/systemd/system/packet-capture.service
sudo cmp -s infra/systemd/gateway-metrics.service /etc/systemd/system/gateway-metrics.service
```

Expected: 두 명령 exit code `0`.

- [ ] **Step 3: 재부팅 전 안전 상태 확인**

```bash
systemctl is-enabled packet-capture.service
systemctl is-enabled gateway-metrics.service
systemctl is-active packet-capture.service || true
systemctl is-active gateway-metrics.service || true
```

Expected: enabled, inactive.

- [ ] **Step 4: Raspberry Pi 재부팅**

```bash
sudo reboot
```

- [ ] **Step 5: 재접속 후 시작 순서 확인**

```bash
journalctl -b \
  -u systemd-timesyncd.service \
  -u systemd-time-wait-sync.service \
  -u packet-capture.service \
  -u gateway-metrics.service \
  --no-pager \
  -o short-precise
```

Expected: 최초 NTP 동기화와 `systemd-time-wait-sync.service` 완료 이후 Packet Capture와 Gateway Metrics가 시작된다.

- [ ] **Step 6: 첫 Window와 Capture Gap 확인**

```bash
journalctl -b -u packet-capture.service --no-pager -n 120
```

Expected:

```text
첫 Window가 실제 현재 UTC 10초 경계에 정렬
부팅 시각과 무관한 수 시간 규모 LATE_CAPTURE 없음
수 시간 규모의 가짜 Capture Gap 없음
```

- [ ] **Step 7: DB 무결성 확인**

```bash
python - <<'PY'
import sqlite3
from pathlib import Path

path = Path("backend/data/iot_security.db")
connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
try:
    print("INTEGRITY_CHECK=", connection.execute("PRAGMA integrity_check").fetchone()[0], sep="")
    print("FOREIGN_KEY_VIOLATIONS=", len(connection.execute("PRAGMA foreign_key_check").fetchall()), sep="")
finally:
    connection.close()
PY
```

Expected:

```text
INTEGRITY_CHECK=ok
FOREIGN_KEY_VIOLATIONS=0
```

- [ ] **Step 8: 실패 시 Rollback**

```bash
sudo systemctl stop packet-capture.service gateway-metrics.service
sudo install -m 0644 \
  "/etc/systemd/system/packet-capture.service.${STAMP}.bak" \
  /etc/systemd/system/packet-capture.service
sudo install -m 0644 \
  "/etc/systemd/system/gateway-metrics.service.${STAMP}.bak" \
  /etc/systemd/system/gateway-metrics.service
sudo systemctl daemon-reload
```

서비스 재시작은 로그와 Unit 복원 확인 후 별도로 결정한다.

---

### Task 7: Pi 검증 결과 반영 및 병합 준비

**Files:**
- Update: Draft PR body

**Interfaces:**
- Consumes: Task 6의 Pi 실기기 증거
- Produces: 병합 판단 가능한 PR

- [ ] **Step 1: PR 본문에 정확한 증거 추가**

다음을 실제 출력값으로 기록한다.

```text
Windows 전체 테스트 결과
Pi 관련 테스트 결과
systemd-analyze verify 결과
NTP 최초 동기화 시각
systemd-time-wait-sync 완료 시각
Packet Capture 시작 시각
첫 Window 경계
LATE_CAPTURE 재발 여부
DB integrity_check 및 FK 결과
```

- [ ] **Step 2: 성공 조건 충족 시 Draft 해제 판단**

다음이 모두 충족되어야 한다.

```text
모든 회귀 테스트 PASS
systemd 정적 검증 PASS
NTP 동기화 이후 서비스 시작 확인
잘못된 과거 Window 생성 없음
대규모 LATE_CAPTURE·Capture Gap 없음
DB 무결성 정상
Rollback 파일 보존
```

- [ ] **Step 3: 코드 리뷰 후 develop 병합**

병합 후 PR #38 브랜치에는 최신 `develop`을 다시 반영하고, 운영 Cutover 및 ESP32 #2 E2E 준비를 재개한다.
