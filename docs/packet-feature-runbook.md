# Packet Feature Pipeline 운영 가이드

pcap → Packet Feature 추출 파이프라인의 수동 실행, Session 한정 복구, Phase 6-B systemd 상시 운영 기준을 설명합니다.

## 환경 설정

### 필수 환경 변수

`CAPTURE_INTERFACE_IP`: pcap 캡처를 수행한 Pi의 IPv4 주소입니다. Feature 추출 시 INBOUND/OUTBOUND 방향 분류에 사용됩니다.

`.env` 예시:

```bash
CAPTURE_INTERFACE_IP=192.168.0.20
```

운영 Raspberry Pi에서는 `/home/pi/iot-edge-zero-trust/.env`를 사용합니다.

### 의존성

```bash
pip install -r requirements.txt
```

운영에서는 프로젝트 venv의 Python을 사용합니다.

```bash
/home/pi/iot-edge-zero-trust/venv/bin/python
```

---

## Feature 추출 (Extractor)

READY 상태의 pcap Segment를 읽어 `packet_feature_logs`에 저장합니다.

### 기본 수동 실행

프로젝트 루트에서:

```bash
python -m edge.features.run_packet_feature_extractor
```

운영 Pi에서는 Python 환경 혼동을 피하기 위해 다음 형식을 권장합니다.

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor
```

### 주요 옵션

| 옵션 | 기본값 | 설명 |
|---|---:|---|
| `--ready-dir` | `data/pcap/ready` | READY pcap 파일 위치 |
| `--processed-dir` | `data/pcap/processed` | 처리 완료 파일 이동 위치 |
| `--failed-dir` | `data/pcap/failed` | 처리 실패 파일 이동 위치 |
| `--session-id` | 없음 | 지정한 COMPLETED Capture Session만 처리 |
| `--limit` | `10` | 한 번에 처리할 최대 Segment 수 |
| `--capture-scope` | `PI1_INTERNAL_LAN` | DB에 기록할 Capture Scope |
| `--lock-path` | `data/pcap/.extractor.lock` | 중복 실행 방지 lock 파일 경로 |

예시:

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor \
  --ready-dir data/pcap/ready \
  --limit 20
```

`--limit`은 1 이상의 정수만 허용합니다. `0` 또는 음수는 DB 조회와 Reconciliation 전에 거부됩니다.

---

## Capture Session 한정 수동 실행

Pilot, 과거 Session 점검, 장애 복구처럼 특정 Capture Session만 의도적으로 처리할 때는 canonical UUIDv4 형식의 `--session-id`를 사용합니다.

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor \
  --session-id 08822cbd-8b33-4568-a759-7ecf1bc808cd \
  --limit 70
```

사전 조건:

- `packet_capture_sessions`에 해당 `session_id`가 존재해야 합니다.
- Session 상태가 `COMPLETED`여야 합니다. `RUNNING`과 `FAILED`는 거부합니다.
- Capture 종료와 ready PCAP 배치가 완료되어야 합니다.
- 운영 실행 전 `packet-capture.service`가 의도한 상태인지 확인합니다.

Session 한정 모드에서는 다음 작업이 모두 지정 Session 범위로 제한됩니다.

- `status='READY'` Segment 조회
- `--limit` 적용
- 이전 DB Commit 후 파일 이동 실패를 복구하는 Reconciliation
- `processed/` 또는 `failed/`로의 PCAP 이동

다른 Session의 Row와 PCAP은 변경하지 않습니다. 지정 Session 안의 `PROCESSED`, `EMPTY`, `FAILED` Row에 대응하는 파일이 `ready/`에 남아 있으면 기존 Reconciliation 계약에 따라 올바른 디렉터리로 이동합니다.

Session ID 형식 오류, 존재하지 않는 Session, 부적격 Session 상태 또는 1보다 작은 limit은 Reconciliation 전에 non-zero로 종료합니다. 검증 통과 후 개별 Segment 처리 중 PCAP 누락·파싱 오류가 발생하면 해당 Row는 기존 계약대로 `FAILED`가 됩니다.

### Session 한정 실행 전·후 검증 SQL

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

SELECT pcsg.id, pcsg.file_name, pcsg.window_start, pcsg.window_end
FROM packet_capture_segments pcsg
JOIN packet_capture_sessions pcs
  ON pcs.id = pcsg.capture_session_id
WHERE pcs.session_id = '08822cbd-8b33-4568-a759-7ecf1bc808cd'
  AND pcsg.status = 'READY'
ORDER BY pcsg.window_start, pcsg.id;
```

실행 후 Feature 연결 확인:

```sql
SELECT COUNT(DISTINCT pcsg.id) AS feature_segment_count,
       COUNT(pfl.id) AS feature_row_count
FROM packet_capture_segments pcsg
JOIN packet_capture_sessions pcs
  ON pcs.id = pcsg.capture_session_id
LEFT JOIN packet_feature_logs pfl
  ON pfl.capture_segment_id = pcsg.id
WHERE pcs.session_id = '08822cbd-8b33-4568-a759-7ecf1bc808cd'
  AND pfl.id IS NOT NULL;
```

---

## Global READY 모드 계약

`--session-id`를 생략하면 모든 Capture Session의 READY Segment를 `window_start ASC, id ASC` 순서로 처리하고 전역 Reconciliation을 수행합니다. 실행 시 WARNING이 출력됩니다.

Global 모드는 **Phase 6-B 상시 자동화의 정상 Steady-state 모드**이지만, 다음 조건을 충족하기 전에 무조건 활성화하면 안 됩니다.

- 과거 READY Backlog 수량과 Session 상태를 먼저 조회합니다.
- DB READY와 `ready/` PCAP 파일 수·위치 불일치를 확인합니다.
- Packet Rule / Packet IF를 먼저 비활성화합니다.
- 운영 SQLite DB를 SQLite Backup API로 백업하고 `integrity_check`, Foreign Key 검증을 수행합니다.
- 수동 소량 Smoke로 `READY → PROCESSED/EMPTY`, PCAP 이동, 신규 FAILED 증가 여부를 확인합니다.
- 과거 READY Backlog를 임의 삭제하거나 Raw SQL로 정상 상태처럼 변경하지 않습니다.

과거 Session을 선별적으로 조사하거나 복구해야 하는 경우에는 계속 `--session-id` 수동 모드를 사용합니다. 상시 Timer와 수동 Extractor를 동시에 운영하지 않습니다.

---

## Segment 상태

| 상태 | 의미 |
|---|---|
| `READY` | 추출 대기 중 |
| `PROCESSED` | 정상 처리 완료 |
| `EMPTY` | Pi 관련 Feature가 생성되지 않은 정상 terminal 상태 |
| `FAILED` | 처리 실패. `error_code` 확인 필요 |

### 주요 FAILED error_code

| error_code | 원인 |
|---|---|
| `PCAP_FILE_MISSING` | pcap 파일이 ready_dir에 없음 |
| `PCAP_PARSE_ERROR` | pcap Reader 초기화 실패 또는 패킷 파싱 실패 |
| `PARTIAL_CAPTURE` | 일부 패킷 파싱 실패 |
| `UNSUPPORTED_FORMAT` | 지원하지 않는 Datalink 타입 |
| `WINDOW_MISMATCH` | pcap의 패킷이 Segment Window와 맞지 않음 |

`FAILED`를 정상 Window처럼 Skip해서 Packet Detector Checkpoint를 진행하지 않습니다.

---

## Phase 6-B systemd 상시 자동화

### Unit 구성

저장소 원본:

```text
infra/systemd/packet-feature-extractor.service
infra/systemd/packet-feature-extractor.timer
```

운영 구조:

```text
packet-feature-extractor.timer
        │ 5초
        ▼
packet-feature-extractor.service (Type=oneshot)
        │
        ▼
venv/bin/python -m edge.features.run_packet_feature_extractor --limit 20
```

Service는 `--session-id`를 사용하지 않는 Global READY 모드입니다. 기존 `data/pcap/.extractor.lock`의 `fcntl.flock()`이 중복 실행을 방지합니다.

Timer는 `OnActiveSec=5s`, `OnUnitActiveSec=5s`를 사용합니다. 따라서 Timer를 수동으로 시작한 경우에도 첫 Extractor 실행은 활성화 약 5초 뒤에 시작합니다.

### Cutover 전 Packet Stage 비활성화

Extractor 자동화가 안정화되기 전에는 Packet Rule / Packet IF를 Orchestrator에서 제외합니다.

```bash
ORCHESTRATOR_ENABLED_STAGES=mqtt_feature_rule,mqtt_message_rule
ORCHESTRATOR_REQUIRED_STAGES=mqtt_feature_rule,mqtt_message_rule
```

실제 `.env`를 수정한 뒤에는 `detection-orchestrator.service`를 재시작하고 실행 프로세스의 환경을 확인합니다. Secret이 포함될 수 있으므로 `.env` 전체를 출력하지 않습니다.

### 설치 전 검증

```bash
cd /home/pi/iot-edge-zero-trust

./venv/bin/python -m pytest -q \
  tests/test_packet_feature_extractor_systemd.py \
  tests/test_packet_feature_extractor.py

systemd-analyze verify \
  infra/systemd/packet-feature-extractor.service \
  infra/systemd/packet-feature-extractor.timer
```

### Pi에 Unit 설치

```bash
sudo install -m 0644 \
  infra/systemd/packet-feature-extractor.service \
  /etc/systemd/system/packet-feature-extractor.service

sudo install -m 0644 \
  infra/systemd/packet-feature-extractor.timer \
  /etc/systemd/system/packet-feature-extractor.timer

sudo systemctl daemon-reload
```

저장소 원본과 `/etc/systemd/system` 설치본은 `sha256sum`으로 동일성을 확인합니다.

### 통제된 Timer Smoke

초기 Pi Cutover에서는 곧바로 enable하지 않습니다.

```bash
sudo systemctl start packet-feature-extractor.timer
systemctl status packet-feature-extractor.timer --no-pager
systemctl list-timers packet-feature-extractor.timer --no-pager
```

짧은 통제 구간에서 다음을 확인합니다.

- READY가 감소합니다.
- `PROCESSED + EMPTY`가 처리 수만큼 증가합니다.
- 예상하지 못한 신규 FAILED가 증가하지 않습니다.
- `ready/` 파일이 감소하고 `processed/` 파일이 동일 수만큼 증가합니다.
- `journalctl -u packet-feature-extractor.service`에 반복 오류나 DB busy가 누적되지 않습니다.

Smoke 종료:

```bash
sudo systemctl stop packet-feature-extractor.timer
```

Timer를 정지한 뒤 이미 실행 중인 oneshot이 있다면 terminal 상태가 될 때까지 기다린 후 DB/PCAP 상태를 판정합니다.

### 정식 활성화

Backlog 정책과 Smoke 결과를 검토한 후에만 정식으로 활성화합니다.

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

신규 READY Segment는 READY 생성 후 10초 이내 `PROCESSED` 또는 `EMPTY`에 도달하는 것을 초기 SLO로 합니다. DB busy가 한 Cycle 발생해도 다음 Timer에서 자동 회복하면 허용하지만, 반복 busy 또는 READY Backlog 지속 증가는 HOLD 조건입니다.

Packet Rule / Packet IF는 Extractor Timer의 신규 Segment 자동 처리가 안정적으로 검증된 뒤 단계적으로 다시 활성화합니다.

### Rollback

Extractor 자동화를 즉시 중단할 때:

```bash
sudo systemctl disable --now packet-feature-extractor.timer
```

필요하면 실행 중인 oneshot 상태와 Journal을 확인합니다.

```bash
systemctl status packet-feature-extractor.service --no-pager
journalctl -u packet-feature-extractor.service -n 100 --no-pager
```

Rollback 후에는 기존 one-shot CLI를 이용한 수동 처리 경로를 유지할 수 있습니다. Timer가 중지된 것을 확인한 뒤 수동 명령을 실행합니다.

```bash
./venv/bin/python -m edge.features.run_packet_feature_extractor --limit 20
```

---

## 동명 파일 충돌

`data/pcap/processed/` 또는 `data/pcap/failed/`에 이름은 같지만 내용이 다른 파일이 있으면 `_move_pcap`은 기존 파일을 보존하고 `FileExistsError`를 발생시킵니다. Reconciliation도 이 경우 자동 복구하지 않습니다.

두 파일을 실제로 비교하기 전에는 READY PCAP을 삭제하거나 덮어쓰지 않습니다.

---

## DB에서 처리 결과 확인

```sql
SELECT status, error_code, COUNT(*)
FROM packet_capture_segments
GROUP BY status, error_code;

SELECT COUNT(*)
FROM packet_feature_logs;
```

READY Backlog가 지속 증가하거나 FAILED가 발생하면 Packet Detector를 활성화하지 않고 원인을 먼저 확인합니다.

---

## CSV Export

`packet_feature_logs`를 CSV로 추출합니다.

```bash
python -m edge.features.export_packet_features
```

주요 옵션:

| 옵션 | 설명 |
|---|---|
| `--output PATH` | 출력 CSV 경로 |
| `--session-id UUID` | 특정 Capture Session Feature만 조회 |
| `--from DATETIME` | `window_start` 시작 범위 |
| `--to DATETIME` | `window_start` 종료 범위 |

예시:

```bash
python -m edge.features.export_packet_features \
  --session-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --output data/exports/session_a.csv
```
