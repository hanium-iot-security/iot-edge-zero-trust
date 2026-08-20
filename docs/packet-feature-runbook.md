# Packet Feature Pipeline 운영 가이드

pcap → Packet Feature 추출 파이프라인의 수동 실행, Session 한정 복구, Phase 6-B systemd 자동화 운영 기준을 설명합니다.

## 환경 설정

### 필수 환경 변수

`CAPTURE_INTERFACE_IP`: pcap을 캡처한 Pi의 IPv4 주소입니다. Feature 추출 시 INBOUND/OUTBOUND 방향 분류에 사용합니다.

```bash
CAPTURE_INTERFACE_IP=192.168.0.20
```

운영 Raspberry Pi에서는 `/home/pi/iot-edge-zero-trust/.env`와 프로젝트 venv를 사용합니다.

```bash
/home/pi/iot-edge-zero-trust/venv/bin/python
```

---

## Feature Extractor 기본 계약

READY 상태의 PCAP Segment를 읽어 `packet_feature_logs`에 저장합니다.

기본 수동 실행:

```bash
cd /home/pi/iot-edge-zero-trust
./venv/bin/python -m edge.features.run_packet_feature_extractor
```

주요 옵션:

| 옵션 | 기본값 | 설명 |
|---|---:|---|
| `--ready-dir` | `data/pcap/ready` | READY PCAP 위치 |
| `--processed-dir` | `data/pcap/processed` | 정상 terminal PCAP 이동 위치 |
| `--failed-dir` | `data/pcap/failed` | 실패 PCAP 이동 위치 |
| `--session-id` | 없음 | 지정한 COMPLETED Capture Session만 처리 |
| `--limit` | `10` | 한 실행에서 처리할 READY Segment 최대 개수 |
| `--capture-scope` | `PI1_INTERNAL_LAN` | DB Capture Scope |
| `--lock-path` | `data/pcap/.extractor.lock` | 중복 실행 방지 lock |

예시:

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor --limit 20
```

`--limit`은 **READY Segment 처리 시도 수**를 제한합니다. Reconciliation 자체의 파일시스템 스캔 개수를 제한하는 옵션은 아닙니다.

### Reconciliation 계약

Extractor는 Segment 처리 전에 `data/pcap/ready/*.pcap`을 확인하여, 이전 실행에서 **DB commit은 성공했지만 파일 이동이 실패한 경우**를 복구합니다.

현재 구현은 다음과 같습니다.

1. `ready/`의 PCAP 파일명 목록을 한 번 스캔합니다.
2. DB 상태 조회는 파일마다 SELECT하지 않고 최대 500개 파일명씩 batch 조회합니다.
3. DB 상태가 `PROCESSED`/`EMPTY`이면 `processed/`로 이동합니다.
4. DB 상태가 `FAILED`이면 `failed/`로 이동합니다.
5. `READY` 또는 DB에 없는 파일은 이동하지 않습니다.

따라서 `--limit 20`이어도 `ready/`에 과거 파일이 수천 개 남아 있으면 파일명 스캔은 계속 발생합니다. 다만 기존 N개 파일 → N번 DB SELECT 구조는 사용하지 않습니다.

SQLite `locked/busy`로 개별 Segment 처리가 실패하면 READY를 유지하고 다음 실행에서 재시도합니다. 영구 오류는 `FAILED`로 남기며 정상 Window처럼 건너뛰지 않습니다.

---

## Capture Session 한정 수동 실행

Pilot, 과거 Session 점검, 장애 분석처럼 특정 Capture Session만 처리할 때는 canonical UUIDv4 `--session-id`를 사용합니다.

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor \
  --session-id 08822cbd-8b33-4568-a759-7ecf1bc808cd \
  --limit 70
```

사전 조건:

- `packet_capture_sessions`에 해당 `session_id`가 존재해야 합니다.
- Session 상태가 `COMPLETED`여야 합니다. `RUNNING`/`FAILED`는 거부합니다.
- Capture 종료와 ready PCAP 배치가 완료되어야 합니다.
- `packet-capture.service`의 의도한 상태를 먼저 확인합니다.

Session 한정 모드에서는 READY 조회와 Reconciliation이 해당 Session으로 제한됩니다. 다른 Session의 Row/PCAP은 변경하지 않습니다.

Session ID 형식 오류, 존재하지 않는 Session, 부적격 Session 상태, `limit < 1`은 Reconciliation 전에 non-zero로 종료합니다.

### Session 상태 확인 SQL

```sql
SELECT id, session_id, capture_interface, status, started_at, ended_at
FROM packet_capture_sessions
WHERE session_id = '08822cbd-8b33-4568-a759-7ecf1bc808cd';

SELECT pcsg.status, pcsg.error_code, COUNT(*) AS segment_count
FROM packet_capture_segments pcsg
JOIN packet_capture_sessions pcs
  ON pcs.id = pcsg.capture_session_id
WHERE pcs.session_id = '08822cbd-8b33-4568-a759-7ecf1bc808cd'
GROUP BY pcsg.status, pcsg.error_code
ORDER BY pcsg.status, pcsg.error_code;
```

---

## Global READY 모드 계약

`--session-id`를 생략하면 모든 Capture Session의 `READY` Segment를 `window_start ASC, id ASC` 순서로 처리합니다.

중요한 현재 코드 계약:

- 부모 Capture Session이 `COMPLETED`인지 `FAILED`인지 Global 조회에서 필터링하지 않습니다.
- 따라서 FAILED 부모 Session 아래 남은 READY도 처리 대상이 될 수 있습니다.
- 이미 `FAILED`인 Segment 자체는 READY 조회 대상이 아니므로 그대로 유지합니다.
- Packet Detector 앞 `PacketFeatureReadyStage`는 READY/FAILED/누락 Window를 정상 Window처럼 건너뛰지 않습니다.

이 동작을 Raw SQL이나 파일 삭제로 우회하지 않습니다. 과거 FAILED Session의 READY가 처리되면서 새 `FAILED`가 발생하면 원인을 분류하고 Evidence로 보존합니다.

---

# Phase 6-B systemd 자동화

## Unit 구성

저장소 원본:

```text
infra/systemd/packet-feature-extractor.service
infra/systemd/packet-feature-extractor.timer
```

운영 흐름:

```text
packet-feature-extractor.timer
        │ 최초 활성화 10초 후
        │ 이후 5초 기준
        ▼
packet-feature-extractor.service (Type=oneshot)
        │
        ▼
venv/bin/python -m edge.features.run_packet_feature_extractor --limit 20
```

Timer 계약:

```ini
OnActiveSec=10s
OnUnitActiveSec=5s
AccuracySec=1s
```

`OnActiveSec=10s`는 Pi 부팅 후 자동 활성화와 수동 Cutover 모두 **Timer가 실제 활성화된 시점 기준 10초 후 첫 실행**이라는 같은 의미를 갖게 합니다.

Service 안전 경계:

```ini
TimeoutStartSec=120
TimeoutStopSec=15
```

한 번의 oneshot이 120초를 넘기면 정상 Steady-state가 아니므로 timeout으로 실패 처리하고 Journal을 조사합니다. Timer가 active인 것만 보고 Extractor가 정상 반복 중이라고 판정하지 않습니다.

---

## 1. Cutover 전 Packet Stage 비활성화

Extractor 자동화 검증이 끝나기 전에는 Packet Rule / Packet IF를 Orchestrator에서 제외합니다.

```bash
ORCHESTRATOR_ENABLED_STAGES=mqtt_feature_rule,mqtt_message_rule
ORCHESTRATOR_REQUIRED_STAGES=mqtt_feature_rule,mqtt_message_rule
```

`.env` 수정 후 `detection-orchestrator.service`를 재시작하고 **실제 실행 프로세스 환경**을 확인합니다. `.env` 전체는 출력하지 않습니다.

`packet-capture.service`도 과거 READY Backlog 배출 중에는 `inactive` 상태를 유지합니다.

---

## 2. 설치 전 검증

```bash
cd /home/pi/iot-edge-zero-trust

./venv/bin/python -m pytest -q \
  tests/test_packet_feature_extractor_systemd.py \
  tests/test_packet_feature_extractor.py \
  tests/test_packet_feature_extractor_phase6b.py \
  tests/test_detection_orchestrator_runner.py

systemd-analyze verify \
  infra/systemd/packet-feature-extractor.service \
  infra/systemd/packet-feature-extractor.timer

git diff --check
```

실제 실행 결과를 확인하기 전에는 PASS로 기록하지 않습니다.

---

## 3. Pi에 Unit 설치

```bash
sudo install -m 0644 \
  infra/systemd/packet-feature-extractor.service \
  /etc/systemd/system/packet-feature-extractor.service

sudo install -m 0644 \
  infra/systemd/packet-feature-extractor.timer \
  /etc/systemd/system/packet-feature-extractor.timer

sudo systemctl daemon-reload
```

저장소 원본과 설치본은 `sha256sum`으로 동일성을 확인합니다.

---

## 4. 통제된 Timer Smoke

처음부터 enable하지 않습니다.

```bash
sudo systemctl start packet-feature-extractor.timer
systemctl status packet-feature-extractor.timer --no-pager
systemctl list-timers packet-feature-extractor.timer --no-pager
```

짧은 구간에서 다음을 확인합니다.

- READY 감소량 = `PROCESSED + EMPTY + 신규 FAILED` 증가량인지 확인
- `ready/` 감소 및 terminal 디렉터리 이동 확인
- 예상하지 못한 FAILED가 증가하지 않는지 확인
- 반복 `database is locked/busy`, timeout, traceback이 없는지 확인
- 한 Cycle 실행시간이 5초 반복 운용에 비해 과도하지 않은지 확인

Smoke 종료 시 Timer뿐 아니라 이미 실행 중인 oneshot도 명시적으로 정리합니다.

```bash
sudo systemctl stop packet-feature-extractor.timer
sudo systemctl stop packet-feature-extractor.service
```

그 후 DB/PCAP 상태와 Journal을 판정합니다.

---

## 5. 과거 READY Backlog Drain

현재처럼 수천 건의 과거 READY가 존재하는 상태에서는 신규 Capture와 10초 SLO 검증을 동시에 시작하지 않습니다.

Backlog Drain 동안:

```text
packet-capture.service                  = inactive
Packet Rule / Packet IF                = disabled
Detection Orchestrator                 = MQTT-only
packet-feature-extractor.timer         = controlled operation
```

Global mode는 오래된 READY부터 처리하므로, 과거 Backlog가 존재하는 동안 새 READY를 만들면 신규 Segment가 뒤에서 대기할 수 있습니다.

Backlog 진행 상황은 DB 상태, `ready/processed/failed` 파일 수, Journal을 함께 확인합니다. `--limit 20`은 Segment 처리량만 제한하며 Reconciliation의 파일명 스캔 자체를 20개로 제한하지 않습니다.

FAILED 부모 Session의 READY와 DB/file mismatch를 임의 삭제하거나 Raw SQL로 정상 상태처럼 바꾸지 않습니다. 처리 중 발생한 `PCAP_FILE_MISSING` 등은 기존 증적과 대조해 분류합니다.

---

## 6. Steady-state Cutover Gate

**신규 READY 10초 SLO를 평가하거나 `packet-capture.service`를 다시 시작하기 전에 다음 Gate를 모두 충족해야 합니다.**

```text
packet-capture.service = inactive
READY Backlog = 0
미분류 신규 FAILED = 0
Extractor 반복 timeout = 0
반복 SQLite busy/locked = 0
Timer / Service Journal에 구조적 오류 = 0
```

`READY Backlog = 0`은 `packet_capture_segments.status='READY'` 기준입니다. `ready/`에 terminal 상태 파일이 남아 있다면 Reconciliation 불일치이므로 원인을 확인하고 Gate를 통과시키지 않습니다.

Gate 확인 예시:

```sql
SELECT status, error_code, COUNT(*)
FROM packet_capture_segments
GROUP BY status, error_code
ORDER BY status, error_code;
```

```bash
find data/pcap/ready -maxdepth 1 -type f ! -name '.gitkeep' | wc -l
journalctl -u packet-feature-extractor.service -n 200 --no-pager
```

과거 FAILED Row가 존재한다는 이유만으로 삭제하지 않습니다. **Gate의 `미분류 신규 FAILED = 0`은 기존에 이미 분류된 역사적 FAILED를 지우라는 의미가 아닙니다.**

---

## 7. 신규 Capture 자동 처리 SLO 검증

Steady-state Cutover Gate를 통과한 뒤에만 통제된 `packet-capture.service`를 시작합니다.

```text
Packet Capture
  ↓ 10초 PCAP
READY
  ↓ Timer
PROCESSED / EMPTY
```

초기 SLO:

> **새 READY Segment는 READY 생성 후 10초 이내 `PROCESSED` 또는 `EMPTY`에 도달한다.**

한 번의 SQLite busy가 다음 Cycle에서 자동 회복하면 허용할 수 있지만, 반복 busy·timeout·Backlog 재증가는 HOLD입니다.

신규 Segment가 수동 Extractor 없이 여러 Window 연속 terminal 상태에 도달하는 것을 확인한 뒤에만 Packet Rule을 `enabled + required`로 Cutover합니다. Packet IF는 새 Artifact 확정 이후 별도로 활성화합니다.

---

## 8. 정식 Timer 활성화

Backlog Drain, Steady-state Gate, 신규 자동 처리 검증을 통과한 후 정식 활성화합니다.

```bash
sudo systemctl enable --now packet-feature-extractor.timer
```

상태 확인:

```bash
systemctl is-enabled packet-feature-extractor.timer
systemctl is-active packet-feature-extractor.timer
systemctl list-timers packet-feature-extractor.timer --no-pager
journalctl -u packet-feature-extractor.service -n 100 --no-pager
```

---

## 9. Rollback / 비상 중단

자동화를 즉시 중단할 때는 Timer 예약만 없애지 말고 **현재 실행 중인 oneshot Service도 중지**합니다.

```bash
sudo systemctl disable --now packet-feature-extractor.timer
sudo systemctl stop packet-feature-extractor.service

systemctl is-active packet-feature-extractor.timer || true
systemctl is-active packet-feature-extractor.service || true
journalctl -u packet-feature-extractor.service -n 100 --no-pager
```

Service 중지 시 현재 DB transaction이 아직 commit 전이면 rollback되고 READY가 유지됩니다. 이미 DB commit이 끝나고 PCAP 이동 전에 중지되었다면 다음 실행의 Reconciliation 계약으로 복구합니다. 따라서 중지 후 DB/PCAP 상태를 확인한 뒤 수동 실행 여부를 결정합니다.

수동 fallback:

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor --limit 20
```

Timer/Service가 모두 중지된 것을 확인하기 전에는 수동 Extractor를 동시에 실행하지 않습니다.

---

## Segment 상태

| 상태 | 의미 |
|---|---|
| `READY` | 추출 대기 |
| `PROCESSED` | Feature 생성 완료 |
| `EMPTY` | 정상 terminal, 생성할 Pi 관련 Feature 없음 |
| `FAILED` | 영구 실패. `error_code` 확인 필요 |

주요 `FAILED error_code`:

| error_code | 의미 |
|---|---|
| `PCAP_FILE_MISSING` | `ready_dir`에서 PCAP을 찾지 못함 |
| `PCAP_PARSE_ERROR` | PCAP 파싱 실패 |
| `PARTIAL_CAPTURE` | 일부 패킷 파싱 실패 |
| `UNSUPPORTED_FORMAT` | 지원하지 않는 Datalink 타입 |
| `WINDOW_MISMATCH` | PCAP packet timestamp와 Segment Window 불일치 |

---

## 동명 파일 충돌

`processed/` 또는 `failed/`에 이름은 같지만 내용이 다른 파일이 있으면 기존 파일을 보존하고 자동 복구하지 않습니다. 두 파일을 비교하기 전에는 READY PCAP을 삭제하거나 덮어쓰지 않습니다.

---

## DB 확인

```sql
SELECT status, error_code, COUNT(*)
FROM packet_capture_segments
GROUP BY status, error_code;

SELECT COUNT(*)
FROM packet_feature_logs;
```

READY Backlog 증가, 미분류 FAILED, timeout 또는 반복 DB busy가 발생하면 Packet Detector를 활성화하지 않고 원인을 먼저 확인합니다.

---

## CSV Export

```bash
./venv/bin/python -m edge.features.export_packet_features
```

주요 옵션:

| 옵션 | 설명 |
|---|---|
| `--output PATH` | 출력 CSV 경로 |
| `--session-id UUID` | 특정 Capture Session Feature만 조회 |
| `--from DATETIME` | `window_start` 시작 범위 |
| `--to DATETIME` | `window_start` 종료 범위 |
