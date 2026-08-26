# Phase 6-B Packet Runtime Validation

## 1. 결론

2026-08-25 실기기 환경에서 Packet Rule v3와 Packet IF의 30분 Combined Normal Soak, 그리고 Packet Rule v3의 4종 Physical Smoke를 검증했다.

Combined Normal Soak에서는 Packet Rule 오탐과 `AI_PACKET_ANOMALY`가 발생하지 않았고, 등록 기기의 Trust·Isolation·Firewall 상태도 변하지 않았다. 이후 미등록 Pi4 Attack/Test Node에서 Packet Rate, Byte Rate v2, Port Scan, Broker DoS 시나리오를 각각 정확히 1회 실행해 목표 Packet Rule Event를 모두 확인했다.

이 문서는 승인된 실기기 검증 중 확보한 read-only DB 조회와 systemd/runtime 확인 결과를 요약한다. Raw DB, PCAP, 대용량 로그, Credential 및 `.env` 내용은 포함하지 않는다. 모든 `Z` 시각은 UTC다.

## 2. 검증 기준과 범위

| 항목 | 기준 |
| --- | --- |
| 검증일 | 2026-08-25 |
| Packet Rule Policy | `packet-rule-policy-v3` |
| Management Peer exclusion | `192.168.0.3` |
| Packet IF | 운영 활성화된 검증 Artifact 및 기존 Runtime 계약 |
| 정상 트래픽 Device | `esp32_01` |
| Attack/Test Node | Pi4 `192.168.0.30`, 미등록 상태 유지 |
| Gateway | Pi5 `192.168.0.20` |

검증 수치는 해당 시점의 운영 DB와 Runtime에서 read-only로 확인했다. 30분 Soak와 Physical Smoke는 같은 장기 실행 Capture Session에 속하지만, Soak의 Segment·Feature 집계는 **30분으로 고정한 Soak 구간만** 나타낸다. Physical Smoke 이후의 Post-flight 상태와 누적 집계로 해석하면 안 된다.

## 3. Combined Normal Soak

### 3.1 Capture 및 Feature

- 검증 시간: 약 30분
- Capture Session: `727ae40b-ba0e-43bd-8651-4646ad4f81e1`
- Segment: 총 180
  - `PROCESSED`: 180
  - `EMPTY`: 0
  - `READY`: 0
  - `FAILED`: 0
- Packet Feature: 총 654 rows
- Soak 구간 내부 Capture Gap: 없음

### 3.2 Packet Rule

| 항목 | Row 수 |
| --- | ---: |
| INBOUND 및 Capture eligible | 327 |
| Management Peer `192.168.0.3` 제외 | 146 |
| 실제 Rule 평가 | 181 |
| Rule Event / False Positive | 0 |

Management Peer 제외는 Packet Rule scope에만 적용했다. `device_id`가 없다는 이유로 benign unregistered INBOUND를 일괄 제외하지 않았다.

### 3.3 Packet IF

| 항목 | 결과 |
| --- | ---: |
| Source rows | 654 |
| `esp32_01` eligible rows | 180 |
| `AI_PACKET_ANOMALY` | 0 |

Packet IF는 새 Capture 범위만 처리했다. 과거 Packet Feature를 다시 추론하는 historical reinference는 없었다.

### 3.4 Trust, Isolation 및 Firewall

- `esp32_01` Trust: `100 -> 100`
- 신규 Isolation: 0
- 신규 Firewall Rule: 0
- Packet Rule 또는 Packet IF 원인의 Trust 감점: 없음

### 3.5 Checkpoint 및 DB

- Packet Rule / Packet IF 최종 동일 boundary: `2026-08-25T10:21:20Z`
- SQLite `integrity_check`: `ok`
- Foreign key violations: 0

**COMBINED_NORMAL_SOAK = PASS**

## 4. Packet Rule v3 Physical Smoke

### 4.1 배포 기준

- PR #78 merge SHA: `291db5b0a3141a7be9e9aa1c097206de3133c5e1`
- Pi4:
  - `develop`을 위 merge SHA로 fast-forward
  - working tree clean
  - 운영 `devices`에 등록하지 않은 Attack/Test Node 유지
- Pi5 Runtime:
  - repository SHA: `687b7601130141fa012ce17fe93b60020b15ff59`
  - working tree clean

PR #78은 Pi4용 Broker DoS Attack/Test generator, Scenario 정의와 테스트를 추가했다. Pi5의 Packet Rule Detector, Threshold, Packet IF 및 Trust Runtime은 바꾸지 않았으므로, Physical Smoke 당시 Pi5는 기존 Runtime SHA를 유지했다. Pi5가 PR #78 merge SHA의 최신 `develop`이었다고 해석하지 않는다.

모든 Physical Smoke는 정확히 1회만 실행했으며 실패 시 자동 재시도를 허용하지 않았다. 서로 독립적인 Packet Rule이 같은 Window에서 동시에 성립하면 부가 Event가 함께 발생할 수 있다. 각 시나리오의 PASS는 명시한 핵심 Event를 기준으로 판정했고, Byte Rate v2는 Packet Rate와 분리되는 계약까지 확인했다.

### 4.2 Packet Rate

- 판정: PASS
- 실행: 1회, 자동 재시도 없음
- 전송: 953 packets
- 실제 `packets_per_second`: 38.37 / 49.54
- 핵심 Event: `PACKET_RATE_ANOMALY`
- 부가 Event: `BYTE_RATE_ANOMALY`

| Feature ID | Window (UTC) | packet_count | captured duration (s) | packets/s | total bytes | bytes/s | Event ID |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 20244 | `11:09:40Z` - `11:09:50Z` | 381 | 9.928513 | 38.37 | 35,052 | 3,530.44 | #41 Packet Rate, #42 Byte Rate |
| 20245 | `11:09:50Z` - `11:10:00Z` | 492 | 9.930739 | 49.54 | 45,264 | 4,557.97 | #43 Packet Rate, #44 Byte Rate |

Packet Rate 시나리오의 핵심 Event가 두 Window에서 발생했음을 확인했다.

### 4.3 Byte Rate v2

- 판정: PASS
- 실행: 1회, 자동 재시도 없음
- 조건: duration 12s, rate 4pps, UDP payload 1,200B
- 실제 `packets_per_second`: 2.11 / 2.31
- 실제 `bytes_per_second`: 2,596.54 / 2,834.90
- 발생: `BYTE_RATE_ANOMALY`
- 미발생: `PACKET_RATE_ANOMALY`

| Feature ID | Window (UTC) | packet_count | captured duration (s) | packets/s | bytes/s | Event ID |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 20254 | `11:11:30Z` - `11:11:40Z` | 21 | 9.931680 | 2.11 | 2,596.54 | #45 Byte Rate |
| 20255 | `11:11:40Z` - `11:11:50Z` | 23 | 9.962947 | 2.31 | 2,834.90 | #46 Byte Rate |

Packet Rate 임계값을 넘지 않으면서 Byte Rate만 탐지되는 독립 Rule 동작을 확인했다.

### 4.4 Port Scan

- 판정: PASS
- 실행: 1회, 자동 재시도 없음
- 조건: TCP ports 1-256, timeout 150ms
- Feature ID: 20264
- Window: `2026-08-25T11:13:10Z` - `2026-08-25T11:13:20Z`
- `packet_count`: 262
- `captured_duration_seconds`: 9.963331
- `packets_per_second`: 26.30
- `total_bytes`: 15,660
- `bytes_per_second`: 1,571.76
- `distinct_dest_port_count`: 256
- `tcp_syn_count`: 256
- `mqtt_related_packet_count`: 0
- 핵심 Event: #48 `PORT_SCAN`
- 부가 Event: #47 `PACKET_RATE_ANOMALY`

짧은 burst로 Packet Rate 조건도 함께 충족했지만, Port Scan의 strict AND 조건인 `distinct_dest_port_count > 5`와 `tcp_syn_count > 5` 및 핵심 Event를 확인했다.

### 4.5 Broker DoS

- 판정: PASS
- 실행: 1회, 자동 재시도 없음
- 조건: 24 connections, 8cps, connect timeout 200ms, TCP port 1883
- 연결 성공: 24/24
- Feature ID: 20278
- Window: `2026-08-25T11:14:30Z` - `2026-08-25T11:14:40Z`
- `packet_count`: 84
- `captured_duration_seconds`: 9.962739
- `packets_per_second`: 8.43
- `total_bytes`: 4,536
- `bytes_per_second`: 455.30
- `distinct_dest_port_count`: 1
- `tcp_syn_count`: 21
- `mqtt_related_packet_count`: 84
- 발생: #49 `BROKER_DOS_SUSPECTED`
- 미발생: `PACKET_RATE_ANOMALY`, `BYTE_RATE_ANOMALY`

Extractor의 `mqtt_related_packet_count`는 MQTT payload decode가 아니라 TCP source/destination port 1883 패킷 수다. 실측값은 Packet Rule v3의 strict 조건인 `tcp_syn_count > 10 AND mqtt_related_packet_count > 20`을 모두 충족했다.

### 4.6 Event 요약

| Event | 건수 | Event ID |
| --- | ---: | --- |
| `PACKET_RATE_ANOMALY` | 3 | #41, #43, #47 |
| `BYTE_RATE_ANOMALY` | 4 | #42, #44, #45, #46 |
| `PORT_SCAN` | 1 | #48 |
| `BROKER_DOS_SUSPECTED` | 1 | #49 |

**PACKET_RULE_V3_PHYSICAL_SMOKE = PASS**

## 5. Unregistered Attack Node 안전성

모든 Physical Smoke Event에서 다음을 확인했다.

- `device_id = NULL`
- `applied_to_score = 0`
- `processing_reason = UNMAPPED_DEVICE`
- Pi4 `192.168.0.30`의 `devices` 등록: 0건

등록 Device 상태는 변하지 않았다.

| Device | 검증 후 상태 / Trust |
| --- | --- |
| `esp32_01` | `normal / 100` |
| `esp32_02` | 기존 `warning / 70` 유지 |

Firewall 검증 결과:

- Active Firewall DB Rule: 0
- Runtime iptables INPUT policy: `ACCEPT`

따라서 Pi4 트래픽은 `DETECTION_ONLY`로 처리됐고 Trust 감점, Isolation 또는 Firewall 자동 차단 side effect가 없었다.

## 6. Post-flight

- Capture Session `727ae40b-ba0e-43bd-8651-4646ad4f81e1`: `RUNNING`
- Capture Segment `READY`: 0
- Capture Segment `FAILED`: 0
- Packet Rule / Packet IF checkpoint 동일 boundary: `2026-08-25T11:15:40Z`
- 주요 서비스: 모두 `active`
- SQLite `integrity_check`: `ok`
- Foreign key violations: 0
- Pi4/Pi5 working tree: clean
- 추가 공격: 실행하지 않고 중지

Packet Rule과 Packet IF의 `last_processed_id`는 각 detector가 소비하는 적격 row 범위 때문에 다를 수 있다. Post-flight에서는 두 detector의 완료 시각 boundary가 동일하고 퇴행 또는 divergence가 없는지를 기준으로 정렬을 확인했다.

## 7. 제한 사항과 증적 보존

- 이 문서는 승인된 검증 결과를 전사한 docs-only 기록이며, 문서 작성 과정에서 Pi에 다시 접속하거나 Soak·공격을 재실행하지 않았다.
- Raw DB, PCAP 및 대용량 로그는 Git에 추가하지 않았다.
- 측정값을 재생성하거나 사후 보정하지 않았다.
- Password, API key, MQTT Credential 및 `.env` 값은 기록하지 않았다.
- 정상 Soak와 4종 Physical Smoke 이외의 공격·격리 E2E 완료를 의미하지 않는다.

## 8. 최종 판정

```text
COMBINED_NORMAL_SOAK = PASS
PACKET_RULE_V3_PHYSICAL_SMOKE = PASS
PHASE_6B_PACKET_RUNTIME_VALIDATION = PASS
```
