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
| `--limit` | `10` | 한 번에 처리할 최대 segment 수 |
| `--capture-scope` | `PI1_INTERNAL_LAN` | DB에 기록할 캡처 범위 레이블 |
| `--lock-path` | `data/pcap/.extractor.lock` | 중복 실행 방지 lock 파일 경로 |

```bash
python -m edge.features.run_packet_feature_extractor \
  --ready-dir data/pcap/ready \
  --limit 20
```

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
| `--session-id UUID` | 특정 캡처 세션의 feature만 추출 |
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
