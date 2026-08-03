# Packet Feature Pipeline 운영 가이드

Phase 3-B에서 구현한 pcap → Feature 추출 파이프라인의 실행 방법과 설정을 설명합니다.

## 환경 설정

### 필수 환경 변수

`CAPTURE_INTERFACE_IP`: pcap 캡처를 수행한 Pi의 IPv4 주소입니다. feature 추출 시 INBOUND/OUTBOUND 방향 분류에 사용됩니다.

`.env` 파일에 추가하거나 직접 export합니다:

```bash
export CAPTURE_INTERFACE_IP=192.168.0.20
```

`.env.example`에 예시가 포함되어 있습니다.

### 의존성

```bash
pip install -r requirements.txt   # dpkt==1.9.8 포함
```

---

## Feature 추출 (Extractor)

READY 상태의 pcap segment를 읽어 `packet_feature_logs`에 저장합니다.

### 기본 실행

프로젝트 루트에서:

```bash
python -m edge.features.run_packet_feature_extractor
```

### 주요 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--ready-dir` | `data/pcap/ready` | READY pcap 파일 위치 |
| `--processed-dir` | `data/pcap/processed` | 처리 완료 파일 이동 위치 |
| `--failed-dir` | `data/pcap/failed` | 처리 실패 파일 이동 위치 |
| `--session-id` | 없음 | 지정한 COMPLETED Capture Session만 처리 |
| `--limit` | `10` | 한 번에 처리할 최대 segment 수 |
| `--capture-scope` | `PI1_INTERNAL_LAN` | DB에 기록할 캡처 범위 레이블 |
| `--lock-path` | `data/pcap/.extractor.lock` | 중복 실행 방지 lock 파일 경로 |

```bash
python -m edge.features.run_packet_feature_extractor \
  --ready-dir data/pcap/ready \
  --limit 20
```

`--limit`은 1 이상의 정수만 허용합니다. `0` 또는 음수는 DB 조회와
Reconciliation 전에 거부되므로 DB Row와 PCAP 파일을 변경하지 않습니다.

### Capture Session 한정 실행

Phase 5 Pilot처럼 특정 Capture Session만 처리할 때는 canonical UUIDv4 형식의
`--session-id`를 사용합니다.

```bash
python -m edge.features.run_packet_feature_extractor \
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

다른 Session의 `READY`, `PROCESSED`, `EMPTY`, `FAILED` Row와 PCAP은 변경하지
않습니다. 단, 지정 Session 안의 `PROCESSED`, `EMPTY`, `FAILED` Row에 대응하는
파일이 `ready/`에 남아 있으면 기존 복구 계약에 따라 Reconciliation이 올바른
디렉터리로 이동합니다. `--limit`은 READY 처리 개수에 적용되며 이 복구 파일
개수를 제한하지 않습니다.

Session ID 형식 오류, 존재하지 않는 Session, 부적격 Session 상태 또는 1보다
작은 limit은 Reconciliation 전에 non-zero로 종료합니다. 이 사전 검증 실패는
DB Row와 PCAP 파일을 변경하지 않습니다. 반면 검증 통과 후 개별 Segment 처리
중 PCAP 누락·파싱 오류가 발생하면 지정 Session의 해당 Row만 기존 계약대로
`FAILED`가 됩니다.

### Session 한정 실행 전·후 검증 SQL

실행 전 Session 상태와 대상 Segment 분포를 확인합니다.

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

실행 후 지정 Session의 상태와 Feature 연결을 확인합니다.

```sql
SELECT pcsg.status, pcsg.error_code, COUNT(*) AS segment_count
FROM packet_capture_segments pcsg
JOIN packet_capture_sessions pcs
  ON pcs.id = pcsg.capture_session_id
WHERE pcs.session_id = '08822cbd-8b33-4568-a759-7ecf1bc808cd'
GROUP BY pcsg.status, pcsg.error_code
ORDER BY pcsg.status, pcsg.error_code;

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

실행 전·후 다른 Session별 상태 집계도 비교합니다.

```sql
SELECT pcs.session_id, pcsg.status, COUNT(*) AS segment_count
FROM packet_capture_segments pcsg
JOIN packet_capture_sessions pcs
  ON pcs.id = pcsg.capture_session_id
WHERE pcs.session_id != '08822cbd-8b33-4568-a759-7ecf1bc808cd'
GROUP BY pcs.session_id, pcsg.status
ORDER BY pcs.session_id, pcsg.status;
```

### Session ID 생략 시 전역 모드

`--session-id`를 생략하면 하위 호환성을 위해 기존처럼 모든 Capture Session의
READY backlog를 시간순으로 처리하고 전역 Reconciliation을 수행합니다. 실행 시
강한 WARNING을 출력합니다. 과거 READY backlog가 있는 운영 환경에서는 전역 모드
대신 Session 한정 모드를 사용합니다.

### Segment 상태

| 상태 | 의미 |
|------|------|
| `READY` | 추출 대기 중 |
| `PROCESSED` | 정상 처리 완료 |
| `EMPTY` | Pi 관련 트래픽 없음 (window 내 패킷 없음 또는 방향 불명) |
| `FAILED` | 처리 실패 (error_code 참고) |

### FAILED error_code 목록

| error_code | 원인 |
|------------|------|
| `PCAP_FILE_MISSING` | pcap 파일이 ready_dir에 없음 |
| `PCAP_PARSE_ERROR` | pcap Reader 초기화 실패 또는 모든 패킷 파싱 실패 |
| `PARTIAL_CAPTURE` | 일부 패킷 파싱 실패 (정상 패킷도 포함됨) |
| `UNSUPPORTED_FORMAT` | Ethernet(DLT=1) 이외의 Datalink 타입 |
| `WINDOW_MISMATCH` | pcap 내 모든 패킷이 segment window 범위 밖 |

---

## CSV Export

`packet_feature_logs`를 CSV로 추출합니다.

### 기본 실행

```bash
python -m edge.features.export_packet_features
```

기본 출력 파일: `data/exports/packet_features.csv`

### 주요 옵션

| 옵션 | 설명 |
|------|------|
| `--output PATH` | 출력 CSV 경로 지정 |
| `--session-id UUID` | 이미 생성된 특정 캡처 세션의 feature만 CSV로 조회·출력 |
| `--from DATETIME` | window_start 시작 범위 (ISO 8601) |
| `--to DATETIME` | window_start 종료 범위 (ISO 8601) |

```bash
# 특정 세션 export
python -m edge.features.export_packet_features \
  --session-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --output data/exports/session_a.csv

# 시간 범위 export
python -m edge.features.export_packet_features \
  --from 2026-07-16T10:00:00Z \
  --to 2026-07-16T11:00:00Z
```

---

## Raspberry Pi 운영 예시

### cron으로 주기적 실행

```bash
# 로그 디렉터리 사전 생성
mkdir -p /home/pi/iot-edge-zero-trust/data/logs
```

```cron
# 1분마다 Extractor 실행 (가상환경 Python 사용)
* * * * * cd /home/pi/iot-edge-zero-trust && venv/bin/python -m edge.features.run_packet_feature_extractor >> data/logs/extractor.log 2>&1
```

fcntl 기반 lock이 중복 실행을 방지하므로 짧은 간격으로 등록해도 안전합니다.

### 동명 파일 충돌 (수동 조치 필요)

`data/pcap/processed/` 또는 `data/pcap/failed/`에 이름은 같지만 내용이 다른 파일이 있을 때, `_move_pcap`은 기존 파일을 보존하고 `FileExistsError`를 발생시킵니다. `reconcile_orphaned_files`도 이 경우 **자동 복구를 시도하지 않습니다.**

로그에 `충돌 — 수동 조치가 필요합니다`가 출력되면 두 파일을 모두 보존하면서 이동합니다:

```bash
# 기존 파일을 타임스탬프 접미사로 백업 후 ready 파일을 이동
mv data/pcap/processed/seg.pcap data/pcap/processed/seg.pcap.bak-$(date +%s)
mv data/pcap/ready/seg.pcap data/pcap/processed/
```

내용이 다른 파일이므로 ready 파일을 임의로 삭제하지 않습니다. 두 파일을 비교한 뒤 불필요한 것을 판단하여 수동으로 제거하세요.

### DB에서 처리 결과 확인

```sql
SELECT status, error_code, COUNT(*) FROM packet_capture_segments GROUP BY status, error_code;
SELECT COUNT(*) FROM packet_feature_logs;
```
