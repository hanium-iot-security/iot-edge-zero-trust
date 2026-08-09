# Phase 5 실기기 E2E 마감 기록

> 기준일: 2026-08-09
>
> 이 문서는 Phase 5에서 실제 수행한 Packet IF Dataset/Artifact/Runtime 및 신규 실기기 Holdout E2E 결과를 마감 정리한다. 실제 확인한 결과와 Phase 6-A 이관 항목을 분리하며, Session 56을 Clean Holdout `valid_run=PASS`로 과장하지 않는다.

## 1. Phase 5 종료 요약

Phase 5에서는 Dataset 밖 신규 실기기 Session 56으로 다음 기능 흐름을 실제 장비에서 검증했다.

```text
Packet Traffic
→ Packet Feature
→ Packet Rule / Packet IF
→ Detection Event
→ Trust Score
→ Device Isolation
→ Firewall PENDING
→ Firewall APPLIED
→ 실제 iptables TCP/1883 DROP
→ 실제 ESP32 MQTT Block
→ Firewall Release
→ 실제 MQTT Recovery
→ Baseline Recovery
→ normal / 100
```

기능적 FULL E2E는 PASS다. 다만 Session 56의 두 번째 Packet Rate Burst에서 Sender 실행 저하가 있었고, Trust Score 적용 순서가 분석 Window 시간순이 아니라 Event ID 삽입 순서의 영향을 받는 Audit 정합성 이슈가 확인되어 Clean Holdout `valid_run`은 HOLD로 남기고 Phase 6-A에서 수정 후 신규 Session으로 재검증한다.

## 2. Packet IF Dataset v2 및 Artifact

```text
Package ID      = packet-if-v2-verified-001
Dataset Version = packet-if-dataset-v2
Train           = 8 Sessions / 647 Rows
Validation      = 4 Sessions / 329 Rows
Test            = 5 Sessions / 331 Rows
Test Normal     = 329 Rows
Test Attack     = 2 Rows
```

```text
Dataset CSV SHA256
100fde678b953f408a4a977ad67af73b4580e777380250b9d125166f90dbb446

Dataset Manifest SHA256
e2caf8a45daa71d6bd42d21610eb2485c483ec1a811342f2fc88983c7c1953d9
```

```text
Model Version = packet-if-v2-verified-001-p99-py310
Threshold     = 0.1629224401608304
Bundle SHA256 = 1a567511b5ff4f90b14176ce017f77cf74fa5ea1ead6908b8e5a482333681a48
Pi Path       = /home/pi/iot-edge-zero-trust/ai/models/packet_if/packet-if-v2-verified-001-p99-py310
```

고정 Test Split 결과는 Normal FP 14/329, FPR 4.255%, Attack Test 2 Rows 중 2 Rows 탐지다. 공격 결과는 "고정 Test Split의 공격 2개 Row를 모두 탐지했다"로 한정하며 일반화된 Attack TPR 100%로 표현하지 않는다.

## 3. 신규 실기기 Holdout — Session 56

```text
Session UUID  = 89534c55-9e22-48ca-a832-80f59ae3f16e
DB Session ID = 56
Device        = esp32_02
Source IP     = 192.168.0.5
Status        = COMPLETED
Total Windows = 43
Packet Feature Rows = 8 (4769~4776)
Extractor     = PROCESSED 6 / EMPTY 37 / FAILED 0 / READY 0
```

첫 번째 Burst는 80 PPS, 15초, 64 bytes 조건에서 attempted=1200, sent=1200, failed=0으로 종료됐다. 두 번째 Burst는 attempted=1200, sent=747, failed=453, average≈49.8 PPS였으며 실행 저하 원인은 확정하지 않는다.

## 4. Detection 결과

| Event | Detector | Event Type | Delta | Feature | Processing |
| --- | --- | --- | ---: | ---: | --- |
| 27 | RULE | `PACKET_RATE_ANOMALY` | -20 | 4772 | `APPLIED_TO_TRUST` |
| 28 | AI | `AI_PACKET_ANOMALY` | -15 | 4771 | `APPLIED_TO_TRUST` |
| 29 | AI | `AI_PACKET_ANOMALY` | -15 | 4772 | `NOT_REPRESENTATIVE` |
| 30 | AI | `AI_PACKET_ANOMALY` | -15 | 4773 | `APPLIED_TO_TRUST` |
| 31 | AI | `AI_PACKET_ANOMALY` | -15 | 4774 | `ALREADY_ISOLATED` |

Event 29는 동일 Window의 Packet Rule이 대표 Event로 적용되어 Rule+AI 중복 감점을 방지했다. Event 31은 이미 격리된 Device에 추가 감점을 적용하지 않은 결과다.

## 5. Trust Score 및 Isolation

```text
65 → 45   Event 27 / -20
45 → 30   Event 28 / -15
30 → 15   Event 30 / -15
```

```text
esp32_02
trust_score = 15
status      = isolated
```

```text
Isolation History ID = 5
Action               = ISOLATED
Trust Score          = 15
Trigger Event        = 30
Trust History ID     = 14
```

## 6. Firewall 실제 적용

```text
Rule ID     = 3
Device      = esp32_02
Source IP   = 192.168.0.5
Protocol    = TCP
Destination = 1883
Action      = DROP
Trigger     = Event 30
```

초기 `PENDING`에서 Firewall Worker 단발 실행 후 `APPLIED`로 전이했다. 실제 Raspberry Pi iptables에서도 다음 Rule을 확인했다.

```text
-A INPUT -s 192.168.0.5/32 -p tcp -m tcp --dport 1883 -m comment --comment "hanium-firewall:3" -j DROP
```

적용 시각은 `2026-08-09T02:21:55Z`다.

현재 구조는 2-NIC Inline Gateway가 아니므로 이 격리는 "격리 대상 Source IP의 Raspberry Pi MQTT Broker TCP/1883 접근 차단"으로 표현한다. LAN 전체 통신 격리로 표현하지 않는다.

## 7. 실제 ESP32 MQTT Block

차단 검증 전 Raspberry Pi에서 `mosquitto.service=active`, TCP/1883 LISTEN, Pi Local TCP/1883 PASS를 확인했다.

실제 ESP32 #2 Serial:

```text
wifi_connected ip=192.168.0.5
mqtt_connect_started client_id=p5-esp32_02-v1
mqtt_connect_failed state=-2
mqtt_connect_started client_id=p5-esp32_02-v1
mqtt_connect_failed state=-2
mqtt_connect_started client_id=p5-esp32_02-v1
mqtt_connect_failed state=-2
```

따라서 Broker 장애가 아닌 상태에서 `192.168.0.5 → Raspberry Pi TCP/1883` 접근 차단을 실기기로 확인했다.

## 8. Firewall Release 및 실제 통신 복구

공식 Firewall Release 후 Rule 3은 `REMOVED`로 전이했다.

```text
applied_at  = 2026-08-09T02:21:55Z
released_at = 2026-08-09T02:34:43Z
```

Release 후 iptables는 `-P INPUT ACCEPT`만 남았다. 실제 ESP32 #2에서도 `mqtt_connected`와 `mqtt_publish_succeeded sequence=1~4`를 확인했다. 따라서 Firewall 적용 → 실제 MQTT 차단 → 공식 Release → 실제 MQTT 통신 복구의 가역성을 확인했다.

## 9. Baseline Recovery

Firewall Release 이후에도 Device 정책 상태는 의도적으로 `isolated / 15`를 유지했다. Raw SQL UPDATE를 사용하지 않고 승인된 Baseline Recovery CLI를 사용했다.

Dry-run:

```text
database_changed = false
can_execute      = true
preflight_errors = []
active firewall rules = 0
pending trust events  = 0
```

Execute:

```text
isolated / 15 → normal / 100
operation_id = 20260809T023809Z-35eacd8a4d3f
```

Backup SHA256:

```text
0c5685dc35ca7c4b0b3c0374910e282e3f73fd2808a73c4dcff932042fc363a3
```

Backup·운영 DB 모두 integrity_check=ok, FK 위반 0을 확인했다. Detection Events 27~31, Trust History 12~14, Isolation History 5, Firewall Rule 3이 그대로 보존됐다.

최종 운영 상태:

```text
esp32_02 = normal / 100
Firewall Rule 3 = REMOVED
iptables project DROP Rule = 없음
unprocessed detection events = 0
DB integrity_check = ok
ESP32 #2 MQTT = 정상 연결·Publish
```

## 10. Known Issues / Phase 6-A Carry-over

### 10.1 Trust Event 시간순 처리 정합성

Session 56에서 Trust Score 자체는 `65 → 45 → 30 → 15`로 격리까지 이어졌지만, Detection Event 생성 순서 때문에 분석 Window 시간순과 Trust History 적용 순서가 일치하지 않는 사례를 확인했다. 현재 후보 처리 순서가 Event ID 삽입 순서의 영향을 받을 수 있으므로 Phase 6-A에서 `analysis_window` 기반 chronological ordering 수정 → 회귀 테스트 → 신규 Clean Holdout 재검증을 수행한다. 기존 Session 56 Event·History는 수정하지 않고 Audit 증적으로 보존한다.

### 10.2 Packet Sender 두 번째 Burst 실행 저하

```text
첫 번째 Burst: attempted=1200 / sent=1200 / failed=0
두 번째 Burst: attempted=1200 / sent=747 / failed=453 / average≈49.8 PPS
```

원인은 현재 확정하지 않는다. Sender 안정성과 재현성을 Phase 6-A에서 확인한 뒤 신규 Session으로 Clean Holdout을 수행한다.

## 11. Phase 5 최종 판정

| 항목 | 판정 |
| --- | --- |
| Packet IF Dataset / Artifact / Runtime | PASS |
| Packet Rule / Packet IF Detection | PASS |
| Detection → Trust → Isolation | PASS |
| Firewall `PENDING → APPLIED` | PASS |
| 실제 iptables TCP/1883 DROP | PASS |
| 실제 ESP32 MQTT Block | PASS |
| Firewall Release | PASS |
| 실제 MQTT Recovery | PASS |
| Baseline Recovery | PASS |
| 증적 보존 / DB 무결성 | PASS |
| Phase 5 Functional E2E | PASS |
| Session 56 Clean Holdout `valid_run` | HOLD → Phase 6-A |

## 12. Phase 6-A 인계 기준선

```text
esp32_02         = normal / 100
Firewall         = clean
MQTT             = 정상 Publish
Mosquitto        = 정상
Packet IF Model  = 배치 완료
Phase 5 Evidence = 보존
Recovery Backup  = 보존
```

Phase 6-A 우선 작업은 Trust Score Event 처리 순서 보정, 회귀 테스트, Packet Sender 실행 저하 확인, 신규 Clean Holdout E2E, MQTT Credential/ACL, Recovery Backend API, Dashboard Recovery Control 및 최종 증적이다.

Phase 5의 Dataset·Model Artifact·Session·Detection·Trust·Isolation·Firewall·Recovery 증적은 삭제하거나 덮어쓰지 않는다.
