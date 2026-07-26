# Packet Capture Runbook

Phase 3-B Packet Capture Runtime(`edge/packet/`)의 실행 방법과, 병렬 개발·회귀 테스트용
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
환경과 동일하며, 원우민의 Gateway Metrics 실기기 검증(PR #14, 2026-07-16)에서 재확인됐습니다.

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
# 시스템 python이 아니라 Pi 가상환경의 python을 명시적으로 지정한다.
# (systemd에는 로그인 셸 환경이 없어 venv가 PATH에 안 잡히는 문제와 동일한 이유 --
#  `sudo python`은 venv 밖의 시스템 python을 부를 위험이 있다.)
sudo /home/pi/iot-edge-zero-trust/venv/bin/python -m edge.packet.run_packet_capture --windows 1
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

시스템 부하 등으로 Window를 놓치면(대기 전 또는 대기 후 모두), 다음과 같이 현재 Session이
종료되고 새 Session이 시작되는 로그가 남습니다. 같은 Session 안에서 계속 이어지지 않는 것이
정상입니다 (Capture Gap이 새 Session에 기록되어야 연속성 조회가 그 지점에서 멈추지 않습니다).

```
Window 2026-07-15T00:00:20Z~2026-07-15T00:00:30Z는 캡처 시작 전에 만료됨 (capture_started_at=2026-07-15T00:00:31Z); Session을 종료하고 다음 경계에서 새 Session을 시작
새 Capture Session 시작: session_id=<new-uuid> first_window_start=2026-07-15T00:00:40Z
```

## 4. Test Pack (`tests/fixtures/packet/pcap/`)

Extractor(정종민) 및 Capture 자체 개발·회귀 테스트가 실제 장비 없이도 병렬로 진행될 수
있도록 공유하는 대표 pcap 5종입니다.

| 파일 | 수집 방식 | 담당 |
| --- | --- | --- |
| `normal_mqtt.pcap` | 실제 Pi #1 + ESP32 | 원우민 (실기기) |
| `port_scan.pcap` | 실제 Pi #1 + 공격 노드 | 원우민 (실기기) |
| `packet_flood.pcap` | 실제 Pi #1 + 공격 노드 | 원우민 (실기기) |
| `empty_window.pcap` | 합성 생성 스크립트 | 정선우 (완료) |
| `partial_capture.pcap` | 합성 생성 스크립트 | 정선우 (완료) |

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

> `attacks/` 폴더에는 Port Scan 스크립트가 없습니다 (MQTT 레벨 공격 시나리오만 있음).
> 대신 범용 도구인 `nmap`으로 실제 포트 스캔 트래픽을 발생시킵니다.

**대상 및 조건**:

| 항목 | 값 |
| --- | --- |
| 대상 IP | Pi #1의 `eth0` IP (`192.168.0.20`) |
| 스캔 Port 범위 | `1-2000` (MQTT 1883 포함) |
| 스캔 노드 | Pi #2 또는 관리자 노트북 (Pi #1과 같은 내부 LAN) |
| 캡처 시간 | 스캔 시작 5초 전부터 스캔 종료 5초 후까지 (여유 포함 약 30~40초) |
| 반복 횟수 | 1회 (재현성 확인용으로 2회차를 별도 파일로 추가 수집해도 무방) |

**수집 절차**:

```bash
# Pi #1에서: 캡처 먼저 시작
sudo tcpdump -i eth0 -w tests/fixtures/packet/pcap/port_scan.pcap "tcp or udp" &
TCPDUMP_PID=$!
sleep 5

# 공격 노드(Pi #2 또는 관리자 노트북)에서: Pi #1의 1~2000번 포트를 SYN 스캔
nmap -sS -p 1-2000 --min-rate 500 192.168.0.20

# Pi #1에서: 스캔 종료 후 5초 더 대기하고 캡처 종료
sleep 5
sudo kill -TERM $TCPDUMP_PID
```

**예상 결과**: `nmap` 실행 후 몇 초 안에 "Nmap scan report for 192.168.0.20" 이하 포트별
open/closed/filtered 목록이 출력되면 스캔 자체는 정상 완료된 것입니다. tcpdump 종료 로그의
`X packets captured`가 최소 수백~수천 개 수준으로 나와야 합니다 (SYN 패킷 다수).

**검증 기준**:

- 같은 `peer_ip`(스캔 노드 IP)에서 `distinct_dest_port_count`가 수백 단위로 비정상적으로 높음
- `tcp_syn_count`가 정상 트래픽 대비 훨씬 높음 (완료되지 않은 연결 다수, 대부분 SYN만 있고 응답 없음)
- 방향은 INBOUND 기준 (5.2절: "PORT_SCAN 후보 Feature는 INBOUND를 기준으로 한다")

### 4.3 `packet_flood.pcap` — Packet/Byte Rate 이상 시나리오

**목적**: `packets_per_second`/`bytes_per_second` 급증 상황의 Feature 값 검증.

**대상 및 조건**:

| 항목 | 값 |
| --- | --- |
| 대상 | Pi #1의 MQTT Broker (`192.168.0.20:1883`) |
| 방식 | 기존 `attacks/flooding_attack.py`로 MQTT Publish를 짧은 간격으로 반복 발행 |
| 발행 횟수 | 30회 (`--count 30`) |
| 발행 간격 | 0.1초 (`--interval 0.1`, 기본 발행 간격 4~6초 대비 현저히 빠름) |
| 캡처 시간 | 공격 스크립트 실행 5초 전부터 종료 5초 후까지 (여유 포함 약 15~20초) |

**수집 절차**:

```bash
# Pi #1에서: 캡처 먼저 시작
sudo tcpdump -i eth0 -w tests/fixtures/packet/pcap/packet_flood.pcap "tcp or udp" &
TCPDUMP_PID=$!
sleep 5

# 공격 노드에서 (또는 Pi #1 자체에서): 기존 flooding_attack.py 실행
python -m attacks.flooding_attack --host 192.168.0.20 --count 30 --interval 0.1

# Pi #1에서: 종료 후 5초 더 대기하고 캡처 종료
sleep 5
sudo kill -TERM $TCPDUMP_PID
```

**예상 결과**: `flooding_attack.py` 실행 로그에 30건의 Publish 성공 메시지가 3초 안팎으로
빠르게 출력되어야 합니다. tcpdump 종료 로그의 `X packets captured`가 `normal_mqtt.pcap`
대비 같은 시간 동안 훨씬 많아야 합니다.

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
(24바이트 global header만 있고 패킷 레코드 0개).

**Extractor 테스트와의 연결 상태 (2026-07-20 기준)**: `tests/test_packet_feature_extractor.py`는
현재 이 파일을 직접 사용하지 않습니다. 대신 `_write_pcap()` 헬퍼로 자체 fixture를 그때그때
만들어서 EMPTY 케이스(`test_empty_when_no_pi_related_packets` 등)를 검증하고 있습니다 —
정확히는 "패킷이 0개"가 아니라 "패킷은 있지만 Pi #1과 무관한 경우"를 EMPTY로 처리하는지
보는 테스트라, 이 파일이 표현하는 "패킷 레코드 자체가 0개"인 시나리오와는 조건이 다릅니다.
`empty_window.pcap`을 Extractor 테스트에 실제로 연결할지, 지금처럼 각자 fixture를 따로
쓸지는 정종민님과 협의해서 추후 결정합니다.

**커밋된 파일과의 일치 확인**: 생성 스크립트는 랜덤 요소가 전혀 없는 결정적(deterministic)
스크립트이므로, 재생성한 파일과 저장소에 커밋된 파일의 SHA256은 항상 동일해야 합니다.

```bash
python tests/fixtures/packet/generate_synthetic_pcaps.py /tmp/regenerated
diff <(sha256sum tests/fixtures/packet/pcap/empty_window.pcap | cut -d' ' -f1) \
     <(sha256sum /tmp/regenerated/empty_window.pcap | cut -d' ' -f1)
# 출력이 없으면(diff 없음) 일치하는 것
```

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

**커밋된 파일과의 일치 확인**: `empty_window.pcap`과 동일하게, 재생성 결과와 SHA256을
비교해 확인합니다.

```bash
python tests/fixtures/packet/generate_synthetic_pcaps.py /tmp/regenerated
diff <(sha256sum tests/fixtures/packet/pcap/partial_capture.pcap | cut -d' ' -f1) \
     <(sha256sum /tmp/regenerated/partial_capture.pcap | cut -d' ' -f1)
```

**Extractor 테스트와의 연결 상태 (2026-07-20 기준)**: `test_packet_feature_extractor.py`의
`test_failed_partial_capture_when_some_packets_corrupted` 등도 이 파일을 직접 쓰지 않고
자체 fixture로 손상 시나리오를 검증하고 있습니다. `empty_window.pcap`과 마찬가지로,
Capture Wrapper의 재시작 복구(`.pcap.tmp` → `PARTIAL_CAPTURE`) 테스트도 별도의 임시 바이트
파일로 동일한 실패 시나리오를 검증하며, 커밋된 이 파일을 직접 사용하지는 않습니다.
Extractor 쪽 연결은 추후 정종민 님과 협의해서 결정합니다.

## 5. 참고 문서

- [`db-schema.md`](./db-schema.md) — `packet_capture_sessions`/`packet_capture_segments`/`packet_feature_logs` 스키마
- [`raspberry-pi-setup.md`](./raspberry-pi-setup.md) — Pi 네트워크·계정 정보
- [`db-backup-restore.md`](./db-backup-restore.md) — DB 백업/복구 절차 (Migration 관련)

---

## Capture 입력 적격 Policy·LATE_CAPTURE (P4-1-01)

담당: 정선우

### 6.1 새 환경값

Pi Pilot 측정 근거 없이 임의로 바꾸지 않는다. 바꿀 경우 `CAPTURE_POLICY_VERSION`도
함께 올려서 Evidence에 어떤 정책 버전으로 판정됐는지 남긴다.

| 환경변수 | 기본값 | 의미 |
|---|---|---|
| `PCAP_MAX_START_DELAY_SECONDS` | `1.0` | 이 값을 넘는 지연으로 캡처가 시작되면 tcpdump를 아예 실행하지 않고 `LATE_CAPTURE`로 처리한다 |
| `PACKET_MIN_CAPTURE_DURATION_SECONDS` | `9.0` | `10.0 - PCAP_MAX_START_DELAY_SECONDS`로 유도된 값. 두 값을 따로 바꾸면 어긋나므로 항상 함께 조정한다 |
| `CAPTURE_TIME_EPSILON_SECONDS` | `0.01` | 부동소수점 경계 오차 허용치 |
| `CAPTURE_POLICY_VERSION` | `packet-capture-policy-v1` | Evidence·Model Metadata에 기록되는 Policy 식별자 |

공통 판정 로직은 `edge/packet/capture_policy.py`의 `is_capture_eligible()`이다.
Packet Rule Detector, Packet Behavior Isolation Forest(Train/Validation/Test/
Inference), Dataset Export는 모두 이 함수를 그대로 호출해야 하며, 별도의 적격
판정식을 새로 작성하지 않는다.

### 6.2 Capture 경계 상태표 실기기 재현 절차

세부계획 2.1 절 표와 동일하게, 아래 다섯 가지 상황을 실기기에서 재현하고 결과를
`Phase 4 실기기 테스트 및 검증 결과` 문서에 기록한다.

**(1) 정상 실행 (`start_delay_seconds <= 1.0`)**
1. `packet-capture.service`를 정상 기동한다.
2. 몇 개 Window가 지난 뒤 `packet_capture_segments`를 조회해 `status=READY`,
   `start_delay_seconds`가 1.0 이하, `captured_duration_seconds`가 9~10초
   범위인지 확인한다.
3. `coverage_ratio = captured_duration_seconds / 10.0`이 표시값으로만 쓰이고
   판정에는 원본 값이 쓰였는지 확인한다 (반올림된 coverage_ratio 기준으로
   적격 판정하지 않는다).

**(2) 지연 1초 초과, Window는 아직 안 끝남 (Capture Process 미실행, `LATE_CAPTURE`)**
1. Pi에서 인위적 부하(`stress-ng` 등)를 걸어 캡처 루프가 예정 시각보다 1초
   넘게 늦게 깨어나도록 유도하거나, 테스트 환경에서 `run_capture_loop`를
   직접 호출해 재현한다.
2. 해당 Window가 `status=FAILED`, `error_code=LATE_CAPTURE`, `file_name=NULL`,
   `actual_capture_started_at=NULL`, `capture_stop_requested_at=NULL`,
   `capture_process_exited_at=NULL`, `captured_duration_seconds=0`으로
   기록됐는지 확인한다. `start_delay_seconds`만 감사용으로 실제 관측된 지연
   값이 남는다.
3. 부모 `packet_capture_sessions`가 `FAILED`로 마감되고, 다음 정수 10초
   경계에서 새 Session이 시작됐는지(`session_id`가 바뀜) 확인한다.

**(3) Window 대기 중 완전히 만료 (`actual_start >= window_end`)**
1. Pi를 `SIGSTOP`으로 멈췄다가 수십 초 뒤 `SIGCONT`로 재개해, 캡처 루프가
   현재 대기 중이던 Window의 window_end까지 지나버린 상태로 깨어나게 한다.
2. 이 경우도 (2)와 동일하게 **딱 하나의** `FAILED/LATE_CAPTURE` Segment만
   남아야 한다 (실행 중 놓친 현재 Window 한 건은 감사용으로 남긴다).

**(4) 서비스 재시작 시 여러 과거 Window 만료 (Session Gap, 소급 Segment 없음)**
1. `packet-capture.service`를 1분 이상 멈췄다가 재시작한다.
2. `packet_capture_sessions.capture_gap_start`/`capture_gap_end`에 정지~재시작
   구간이 **하나의 범위**로만 기록되고, 그 사이 개별 Window에 대한 가짜
   Segment가 전혀 생성되지 않는지 확인한다.
3. `capture_gap_start`가 직전 마지막 Segment(있다면 LATE_CAPTURE 감사 Segment
   포함)의 `window_end` 기준으로 계산됐는지 확인한다.

**(5) Capture 시작 후 중간 종료 (`PARTIAL_CAPTURE`, 기존 동작 유지)**
1. 캡처 도중 `pkill -TERM tcpdump`로 강제 종료한다.
2. `status=FAILED`, `error_code=PARTIAL_CAPTURE`로 기록되고, 파일이 실제
   생성됐다면 `file_name`에 남는지 확인한다. 지연 초과가 아니므로 Session은
   FAILED로 전환되지 않고 같은 Session에서 다음 Window로 계속 진행되는지
   확인한다.

### 6.3 pcap 자동 삭제

pcap 자동 Cleanup은 구현하지 않는다 (원본 pcap은 Feature 오류·오탐·미탐을 재현하는 근거다. 백업과 보관 기간이 합의되기 전에는 자동 삭제하지 않는다).