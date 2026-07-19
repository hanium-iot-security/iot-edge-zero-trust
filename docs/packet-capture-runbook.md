# Packet Capture Runbook

Packet Capture Runtime(`edge/packet/`)의 실행 방법과, 병렬 개발·회귀 테스트용
Test Pack(`tests/fixtures/packet/pcap/`) 수집 절차·검증 기준을 정리합니다.

> 이 문서는 Capture Wrapper 담당 기준 초안입니다. 실제 Raspberry Pi·ESP32에서의
> 수집·systemd 검증은 따로 진행해야 하며, 결과를 반영해 이 문서를 갱신합니다.

## 1. Capture 대상

세부 계획 5.1절 기준입니다.

| 항목 | 값 |
| --- | --- |
| Capture 장비 | Raspberry Pi #1 |
| Capture 인터페이스 | `eth0` (내부 LAN) |
| 제외 대상 | USB LAN(`eth1`)의 관리자 SSH·API 트래픽 |
| BPF Filter | `tcp or udp` |
| 관심 Port | TCP `1883` (MQTT) — 그 외 TCP/UDP는 Non-MQTT 트래픽 후보로 기록 |
| Window 길이 | 10초 고정 (UTC 정수 초 경계) |

`eth0`, `192.168.0.20`은 [raspberry-pi-setup.md](./raspberry-pi-setup.md)에 기록된 실제 배포
환경과 동일하며, Gateway Metrics 실기기 검증(PR #14, 2026-07-16)에서 재확인됐습니다.

## 2. 환경 변수

`backend/app/config.py`에 정의되어 있고 `.env`로 오버라이드할 수 있습니다.

| 환경 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `CAPTURE_INTERFACE` | `eth0` | tcpdump가 리스닝할 인터페이스 |
| `PCAP_WINDOW_SECONDS` | `10` | Window 길이 (DB CHECK 제약상 10 고정, 다른 값은 실행 즉시 오류) |
| `PCAP_CAPTURE_FILTER` | `tcp or udp` | tcpdump에 넘기는 BPF filter |
| `PCAP_INCOMING_DIR` | `data/pcap/incoming` | 작성 중 `.pcap.tmp` |
| `PCAP_READY_DIR` | `data/pcap/ready` | 캡처 완료, Extractor 대기 |
| `PCAP_PROCESSED_DIR` | `data/pcap/processed` | Extractor 처리 완료 (Extractor 담당) |
| `PCAP_FAILED_DIR` | `data/pcap/failed` | Partial Capture 등 실패 |
| `PCAP_SAMPLES_DIR` | `data/pcap/samples` | 대표 pcap 장기 보관 |
| `PCAP_RETENTION_HOURS` / `PCAP_MAX_STORAGE_MB` | `1` / `1024` | `processed` 보관 정책 (정리 로직은 별도 구현 필요) |
| `FAILED_PCAP_RETENTION_HOURS` / `FAILED_PCAP_MAX_STORAGE_MB` / `FAILED_PCAP_MAX_FILES` | `24` / `256` / `20` | `failed` 보관 정책 (정리 로직은 별도 구현 필요) |

## 3. 실행 방법

### 3.1 수동 실행 (개발/검증용)

```bash
# 1개 Window만 캡처하고 종료 (동작 확인용)
python -m edge.packet.run_packet_capture --windows 1

# 무한 반복 (Ctrl+C로 종료 -- 현재 Window를 마치고 정상 종료됨)
python -m edge.packet.run_packet_capture
```

tcpdump는 raw socket 권한이 필요합니다. 로컬에서 sudo 없이 테스트하려면 다음 중 하나가
필요합니다.

```bash
# 옵션 A: 실행 파일에 capability 직접 부여 (권장, 매 실행 sudo 불필요)
sudo setcap cap_net_raw,cap_net_admin+eip "$(which tcpdump)"

# 옵션 B: sudo로 직접 실행 (Capture Wrapper 자체는 sudo를 사용하지 않으므로 개발 중 확인용)
sudo python -m edge.packet.run_packet_capture --windows 1
```

### 3.2 systemd (운영)

```bash
chmod +x edge/scripts/run_packet_capture.sh
sudo cp infra/systemd/packet-capture.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable packet-capture.service
sudo systemctl start packet-capture.service

# 상태 확인
sudo systemctl status packet-capture.service
sudo journalctl -u packet-capture.service -f

# 재시작/중지 (중지는 현재 Window를 마치고 정상 종료 -> 자동 재시작 안 됨)
sudo systemctl restart packet-capture.service
sudo systemctl stop packet-capture.service
```

`AmbientCapabilities`가 tcpdump 자식 프로세스까지 실제로 상속되는지는 다음으로 확인합니다.

```bash
PID=$(pgrep -f "tcpdump -i eth0")
cat /proc/$PID/status | grep Cap
```

### 3.3 예상 결과

정상 동작 시 `journalctl -u packet-capture.service`에서 아래와 같은 로그가 10초 간격으로
반복되어야 합니다.

```
새 Capture Session 시작: session_id=<uuid> first_window_start=2026-07-15T00:00:10Z
READY segment 생성: capture_<uuid>_eth0_1752537610_1752537620.pcap
READY segment 생성: capture_<uuid>_eth0_1752537620_1752537630.pcap
```

`data/pcap/ready/`에 10초 간격 파일명의 `.pcap`이 계속 쌓이고, `data/pcap/incoming/`에는
찰나(1초 미만)를 제외하면 `.pcap.tmp`가 남아있지 않아야 합니다.

## 4. Test Pack (`tests/fixtures/packet/pcap/`)

Extractor(정종민) 및 Capture 자체 개발·회귀 테스트가 실제 장비 없이도 병렬로 진행될 수
있도록 공유하는 대표 pcap 5종입니다.

| 파일 | 수집 방식 | 담당 |
| --- | --- | --- |
| `normal_mqtt.pcap` | 실제 Pi #1 + ESP32 | (실기기) |
| `port_scan.pcap` | 실제 Pi #1 + 공격 노드 | (실기기) |
| `packet_flood.pcap` | 실제 Pi #1 + 공격 노드 | (실기기) |
| `empty_window.pcap` | 합성 생성 스크립트 | (완료) |
| `partial_capture.pcap` | 합성 생성 스크립트 | (완료) |

### 4.1 `normal_mqtt.pcap` — 정상 MQTT 트래픽

**목적**: 정상 상태에서 Packet Feature가 올바르게 계산되는지 검증하는 기준(baseline) 샘플.

**수집 절차**:

1. Pi #1에서 Mosquitto broker와 ESP32(`iot/esp32_01/sensor`)가 정상 동작 중인지 확인합니다
   ([raspberry-pi-setup.md](./raspberry-pi-setup.md) 참고).
2. ESP32가 4~6초 간격으로 정상 발행 중인 상태에서 아래 명령으로 60~90초간 캡처합니다.

```bash
sudo tcpdump -i eth0 -w tests/fixtures/packet/pcap/normal_mqtt.pcap "tcp or udp"
# 60~90초 대기 후 Ctrl+C
```

**검증 기준**:

- 전체 Packet 수 > 0, MQTT(TCP 1883) 관련 Packet 비중이 대부분일 것
- Packet Drop 0개 (`tcpdump` 종료 로그의 `X packets dropped by kernel` 확인)
- `mqtt_related_packet_count`가 0보다 크고 `non_mqtt_tcp_udp_packet_count`는 낮을 것
- `tcp_syn_count`는 TCP 연결 수립 시점(초반)에만 소수 존재

### 4.2 `port_scan.pcap` — Port Scan 공격 시나리오

**목적**: `distinct_dest_port_count`, `tcp_syn_count` 같은 Rule/AI 판단 근거 Feature가
공격 상황에서 정상 트래픽과 다르게 나오는지 검증.

**수집 절차**: 기존 `attacks/` 폴더의 Port Scan 스크립트(Phase 3-A)를 Pi #1 대상으로
실행하면서 동시에 캡처합니다.

```bash
sudo tcpdump -i eth0 -w tests/fixtures/packet/pcap/port_scan.pcap "tcp or udp" &
TCPDUMP_PID=$!
# 공격 노드(Pi #2 또는 관리자 노트북)에서 Port Scan 스크립트 실행
sleep 30
sudo kill -TERM $TCPDUMP_PID
```

**검증 기준**:

- 같은 `peer_ip`에서 짧은 시간 안에 `distinct_dest_port_count`가 비정상적으로 높음
- `tcp_syn_count`가 정상 트래픽 대비 훨씬 높음 (완료되지 않은 연결 다수)
- 방향은 INBOUND 기준 (5.2절: "PORT_SCAN 후보 Feature는 INBOUND를 기준으로 한다")

### 4.3 `packet_flood.pcap` — Packet/Byte Rate 이상 시나리오

**목적**: `packets_per_second`/`bytes_per_second` 급증 상황의 Feature 값 검증.

**수집 절차**: Port Scan과 동일한 방식으로, 공격 노드에서 짧은 시간에 다량의 패킷을
Pi #1로 전송하면서 캡처합니다 (예: `hping3` 또는 유사 트래픽 생성 도구).

**검증 기준**:

- 특정 10초 Window의 `packet_count`/`total_bytes`가 `normal_mqtt.pcap` 대비 현저히 높음
- API에서 파생 계산되는 `packets_per_second`, `bytes_per_second`가 급증

### 4.4 `empty_window.pcap` — 빈 Window (합성 생성, 완료)

**목적**: 정상적으로 닫혔지만 대상 Packet이 없는 경우, Segment가 `EMPTY`로 처리되고
`packet_feature_logs` row가 생성되지 않는지 검증.

**생성 방법**: 실제 네트워크에서 "정확히 0개"를 안정적으로 재현하기 어려워 합성
생성 스크립트를 사용합니다.

```bash
python tests/fixtures/packet/generate_synthetic_pcaps.py
```

**검증 기준**: `tests/test_generate_synthetic_pcaps.py`가 구조를 고정 검증합니다
(24바이트 global header만 있고 패킷 레코드 0개). Extractor 쪽 검증(Segment EMPTY 처리)은
`tests/test_packet_feature_extractor.py`(정종민 담당)에서 이 파일을 입력으로 사용합니다.

### 4.5 `partial_capture.pcap` — 손상/중단된 Capture (합성 생성, 완료)

**목적**: 재시작 시 `.pcap.tmp`가 `PARTIAL_CAPTURE`로 처리되는 시나리오, 그리고 Extractor가
잘린 pcap을 만났을 때 파싱 오류로 처리하는 시나리오 둘 다에서 재사용 가능한 샘플.

**생성 방법**: `empty_window.pcap`과 같은 스크립트로 함께 생성됩니다. 정상 레코드 1개 +
"헤더에는 54바이트라고 선언했지만 실제로는 20바이트만 존재하는" 잘린 레코드로 구성됩니다.

```bash
python tests/fixtures/packet/generate_synthetic_pcaps.py
```

**검증 기준**: `tests/test_generate_synthetic_pcaps.py`가 첫 레코드는 온전하고 마지막
레코드는 선언된 길이만큼 실제로 존재하지 않음(잘림)을 고정 검증합니다.

## 5. 참고 문서

- [`db-schema.md`](./db-schema.md) — `packet_capture_sessions`/`packet_capture_segments`/`packet_feature_logs` 스키마
- [`raspberry-pi-setup.md`](./raspberry-pi-setup.md) — Pi 네트워크·계정 정보
- [`db-backup-restore.md`](./db-backup-restore.md) — DB 백업/복구 절차 (Migration 관련)