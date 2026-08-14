# Phase 5 실기기 E2E 마감 기록

> 기준일: 2026-08-09
>
> 이 문서는 Phase 5에서 실제 수행한 Packet IF Dataset/Artifact/Runtime 및 실기기 E2E 결과를 마감 정리한다. 실제 확인한 결과와 Phase 6-A 이관 항목을 분리하며, Session 56 단독 실행을 Baseline→Isolation 재현 PASS 또는 Clean Holdout PASS로 과장하지 않는다.

## 1. Phase 5 종료 요약

Phase 5의 물리 E2E는 **Session 55와 Session 56의 연속된 운영 상태**를 기준으로 다음 흐름까지 확인했다.

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

최종 판정은 다음과 같이 구분한다.

```text
Phase 5 누적 Session 55+56 Functional E2E      = PASS
Session 56 단독 Baseline→Isolation 재현        = 미검증 / HOLD
Session 56 Clean Holdout 판정                  = HOLD
```

Session 55 종료 시 `esp32_02`는 이미 `warning / 65`였고, Session 56은 그 상태를 그대로 보존한 채 시작했다. Session 56에서 실제 Trust 적용 Delta는 `-20, -15, -15`, 총 `-50`이므로 `normal / 100`에서 Session 56만 단독 실행했다고 가정하면 최종 점수는 50이며 격리 임계치(<30)에 도달하지 않는다. 따라서 **Session 56 하나만으로 Baseline→Isolation 전체 경로를 재현했다고 표현하지 않는다.**

반면 Phase 5 누적 관점에서는 Session 55에서 Detection→Trust까지 검증한 뒤 상태를 임의 초기화하지 않고 Session 56에서 Detection→Trust→Isolation→Firewall→실제 MQTT Block→Release→Recovery까지 연결했으므로 기능적 전체 체인은 PASS로 마감한다.

또한 Session 56의 두 번째 Packet Rate Burst에서 Sender 실행 저하가 있었고, Trust Score 적용 순서가 분석 Window 시간순이 아니라 Event ID 삽입 순서의 영향을 받는 정합성 문제가 확인됐다. 이 두 항목은 Phase 6-A에서 수정·재검증한다.

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

## 3. 실행·Artifact Provenance

Session 55·56 및 Packet IF Runtime을 재현할 때 기준으로 남겨야 하는 Provenance는 다음과 같다.

```text
Runtime Source Commit = 5834a386ea7bbee908af0bd0e2cbad53e6446c39
Model Version         = packet-if-v2-verified-001-p99-py310
Training Python       = 3.10.20
Pi Runtime Python     = 3.10.11
scikit-learn          = 1.6.1
joblib                = 1.4.2
numpy                 = 2.0.2
pandas                = 2.2.3
Bundle SHA256         = 1a567511b5ff4f90b14176ce017f77cf74fa5ea1ead6908b8e5a482333681a48
```

Packet IF 학습 환경은 Python 3.10.20이고 Pi Runtime은 Python 3.10.11로 major.minor 호환을 확인했다. Session 56 Packet Checkpoint Gap Recovery Plan에도 Repository Commit `5834a386...`와 clean worktree 상태가 기록됐다.

## 4. Session 55 — Phase 5 누적 E2E의 선행 상태

```text
Session UUID = 5565afde-a76c-4659-a76f-fefa5d22dfc3
Status       = COMPLETED
Device       = esp32_02
Final Trust  = 65
Final Status = warning
```

실제 Commit된 Detection Event:

| Event | Detector | Event Type | Delta | Feature | Processing |
| --- | --- | --- | ---: | ---: | --- |
| 24 | RULE | `PACKET_RATE_ANOMALY` | -20 | 4752 | `APPLIED_TO_TRUST` |
| 25 | AI | `AI_PACKET_ANOMALY` | -15 | 4749 | `APPLIED_TO_TRUST` |
| 26 | AI | `AI_PACKET_ANOMALY` | -15 | 4752 | `NOT_REPRESENTATIVE` |

Session 55에서는 Packet Attack → Detection → Trust까지 실기기에서 확인했으며 최종 `warning / 65`였다. 이 Session에서는 Isolation, Firewall, 실제 MQTT Block이 발생하지 않았다.

중요하게도 Session 56 시작 전 이 상태를 Raw SQL 등으로 `normal / 100`으로 초기화하지 않고 그대로 보존했다.

## 5. 신규 실기기 Holdout 후보 — Session 56

```text
Session UUID  = 89534c55-9e22-48ca-a832-80f59ae3f16e
DB Session ID = 56
Device        = esp32_02
Source IP     = 192.168.0.5
Status        = COMPLETED
Start Trust   = 65
Start Status  = warning
Total Windows = 43
Packet Feature Rows = 8 (4769~4776)
Extractor     = PROCESSED 6 / EMPTY 37 / FAILED 0 / READY 0
```

첫 번째 Burst는 80 PPS, 15초, 64 bytes 조건에서 attempted=1200, sent=1200, failed=0으로 종료됐다. 두 번째 Burst는 attempted=1200, sent=747, failed=453, average≈49.8 PPS였으며 실행 저하 원인은 확정하지 않는다.

Session 56은 `warning / 65`에서 시작했으므로 **Phase 5 누적 E2E의 후반부를 완결한 Session**으로 기록한다. Session 56 단독으로 normal/100 Baseline부터 격리까지 재현한 Run으로 분류하지 않는다.

## 6. Session 56 Packet Checkpoint Gap Recovery

Session 55 종료(`2026-08-08T15:30:50Z`)와 Session 56 첫 Window(`2026-08-09T00:58:40Z`) 사이에는 Capture Gap이 존재했다. 이미 Packet Layer가 초기화된 상태였으므로 이 Gap을 정상 연속 구간으로 자동 연결하지 않고 공식 Packet Checkpoint Gap Recovery 절차를 사용했다.

Raw SQL로 Detector Checkpoint를 수정하지 않았다.

### Packet Rule Recovery

```text
Plan SHA256
0936dc90793c834979b6ef6398f193e00aeaab1d8a783f141f933c76aec27bb2

Operation ID
fbe0ecca-14c4-486c-b35b-715e8b930f18

Backup SHA256
942ebdc6a2220d0cfd3733685738cb1b92be6e6529fcd7b29d8690440d5feaaf

Artifact
/home/pi/iot-edge-zero-trust-artifacts/phase5-official-e2e-session56/
  packet-rule-recovery/fbe0ecca-14c4-486c-b35b-715e8b930f18/
```

### Packet IF Recovery

```text
Plan SHA256
cc1215ca385e063b66a64670a81d20b549879866c8e75937f40d3aa8228a6ddc

Operation ID
a3d7d525-9cd4-4673-a345-4bbc4ea9248e

Backup SHA256
ac43806b14ee6cb8bfdc22a45f6e4427d6a2298d3d5133da9aa376ab30ce182c

Artifact
/home/pi/iot-edge-zero-trust-artifacts/phase5-official-e2e-session56/
  packet-if-recovery/a3d7d525-9cd4-4673-a345-4bbc4ea9248e/
```

두 Recovery 모두 `database_committed=true`, `transaction_total_changes_delta=2`, Post-commit Verification PASS를 확인했다. Detector `last_processed_id`는 유지하고 `last_completed_window_end`만 Session 56 시작 경계 `00:58:40Z`로 이동했다.

초기 Execute 시 Artifact 하위 Directory가 존재하지 않아 `database_committed=false`로 거부된 시도가 있었으며 DB 변경은 없었다. Directory 생성 후 공식 Execute가 성공했다.

## 7. Session 56 Detection 결과

| Event | Detector | Event Type | Delta | Feature | Processing |
| --- | --- | --- | ---: | ---: | --- |
| 27 | RULE | `PACKET_RATE_ANOMALY` | -20 | 4772 | `APPLIED_TO_TRUST` |
| 28 | AI | `AI_PACKET_ANOMALY` | -15 | 4771 | `APPLIED_TO_TRUST` |
| 29 | AI | `AI_PACKET_ANOMALY` | -15 | 4772 | `NOT_REPRESENTATIVE` |
| 30 | AI | `AI_PACKET_ANOMALY` | -15 | 4773 | `APPLIED_TO_TRUST` |
| 31 | AI | `AI_PACKET_ANOMALY` | -15 | 4774 | `ALREADY_ISOLATED` |

Event 29는 동일 Window의 Packet Rule이 대표 Event로 적용되어 Rule+AI 중복 감점을 방지했다. Event 31은 이미 격리된 Device에 추가 감점을 적용하지 않은 결과다.

## 8. Session 56 Trust Score 및 Isolation

실제 DB 처리 순서의 Score 전이는 다음과 같다.

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

이 결과는 **Session 56 시작점이 65였을 때의 실제 상태 전이**다. normal/100 Baseline부터 Session 56만으로 격리됐다는 뜻이 아니다.

## 9. Firewall 실제 적용

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

## 10. 실제 ESP32 MQTT Block

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

## 11. Firewall Release 및 실제 통신 복구

공식 Firewall Release 후 Rule 3은 `REMOVED`로 전이했다.

```text
applied_at  = 2026-08-09T02:21:55Z
released_at = 2026-08-09T02:34:43Z
```

Release 후 iptables는 `-P INPUT ACCEPT`만 남았다. 실제 ESP32 #2에서도 `mqtt_connected`와 `mqtt_publish_succeeded sequence=1~4`를 확인했다. 따라서 Firewall 적용 → 실제 MQTT 차단 → 공식 Release → 실제 MQTT 통신 복구의 가역성을 확인했다.

## 12. Baseline Recovery

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

## 13. `valid_run` / Clean Holdout 판정 계약

Session 56 마감 증적에서는 공식 Phase 5 Evaluator가 생성한 Evaluation Row를 근거로 `valid_run` 값을 확정하지 않았다. 따라서 이 문서에서는 **`valid_run=HOLD`라는 비정상 타입 표기를 사용하지 않는다.**

현재 판정은 다음처럼 문장 수준으로 구분한다.

```text
Session 56 Clean Holdout 판정 = HOLD
```

Phase 5 Evaluator 계약상 `valid_run`은 Boolean이다. 향후 공식 Evaluator에서 Data Status가 `HOLD`로 평가되는 Run이라면 다음 관계를 사용한다.

```text
data_status                  = HOLD
valid_run                    = false
success_denominator_included = false
```

공식 Run Manifest / Scenario Result / Evaluation Export를 생성하지 않은 수동 실기기 실행에 대해 존재하지 않는 `run_id`, `scenario_id`, `evaluation_scope`, Evaluation SHA256을 임의로 만들지 않는다. Phase 6-A 신규 Clean Holdout에서 공식 평가 산출물을 생성하면 그때 Provenance를 함께 기록한다.

## 14. Known Issues / Phase 6-A Carry-over

### 14.1 Trust Event 시간순 처리 정합성

Session 56에서 Trust Score 자체는 `65 → 45 → 30 → 15`로 격리까지 이어졌지만, Detection Event 생성 순서 때문에 분석 Window 시간순과 Trust History 적용 순서가 일치하지 않는 사례를 확인했다. 현재 후보 처리 순서가 Event ID 삽입 순서의 영향을 받을 수 있으므로 Phase 6-A에서 `analysis_window` 기반 chronological ordering 수정 → 회귀 테스트 → 신규 Clean Holdout 재검증을 수행한다. 기존 Session 56 Event·History는 수정하지 않고 Audit 증적으로 보존한다.

### 14.2 Packet Sender 두 번째 Burst 실행 저하

```text
첫 번째 Burst: attempted=1200 / sent=1200 / failed=0
두 번째 Burst: attempted=1200 / sent=747 / failed=453 / average≈49.8 PPS
```

원인은 현재 확정하지 않는다. Sender 안정성과 재현성을 Phase 6-A에서 확인한 뒤 신규 Session으로 Clean Holdout을 수행한다.

### 14.3 Sender 성공 수 ↔ Gateway 관측 수 Gap

Sender `sent`는 ESP32의 WiFiUDP API 성공 조건을 만족한 횟수이며 Gateway Packet Feature Count와 동일한 의미가 아니다. Session 53·55·56에서 관측량 차이가 반복됐지만 원인을 네트워크 Packet Loss라고 단정하지 않는다. Phase 6에서 필요 시 Sender → Raw PCAP → Packet Feature 계측을 보강한다.

## 15. Phase 5 최종 판정

| 항목 | 판정 |
| --- | --- |
| Packet IF Dataset / Artifact / Runtime | PASS |
| Packet Rule / Packet IF Detection | PASS |
| Phase 5 누적 Detection → Trust → Isolation | PASS |
| Firewall `PENDING → APPLIED` | PASS |
| 실제 iptables TCP/1883 DROP | PASS |
| 실제 ESP32 MQTT Block | PASS |
| Firewall Release | PASS |
| 실제 MQTT Recovery | PASS |
| Baseline Recovery | PASS |
| 증적 보존 / DB 무결성 | PASS |
| **Phase 5 누적 Session 55+56 Functional E2E** | **PASS** |
| **Session 56 단독 Baseline→Isolation 재현** | **미검증 / HOLD** |
| **Session 56 Clean Holdout 판정** | **HOLD → Phase 6-A** |

## 16. Phase 6-A 인계 기준선

```text
esp32_02         = normal / 100
Firewall         = clean
MQTT             = 정상 Publish
Mosquitto        = 정상
Packet IF Model  = 배치 완료
Phase 5 Evidence = 보존
Recovery Backup  = 보존
```

Phase 6-A 우선 작업은 Trust Score Event chronological ordering 보정과 회귀 테스트, Packet Sender 반복 Burst 실패 원인 확인, Sender↔Gateway 관측 Gap 계측, 신규 Clean Holdout E2E다. 이후 MQTT Credential/ACL, Recovery Backend API, Dashboard Recovery Control 및 최종 증적을 기존 Phase 6-A 계획에 따라 진행한다.

Phase 5의 Dataset·Model Artifact·Session·Detection·Trust·Isolation·Firewall·Recovery 증적은 삭제하거나 덮어쓰지 않는다.
