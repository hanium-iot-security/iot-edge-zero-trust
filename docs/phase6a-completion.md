# Phase 6-A 실기기 완료 보고

## 1. 결론

Phase 6-A의 핵심 실기기 흐름을 Raspberry Pi와 ESP32 2대로 검증했다.

MQTT Principal별 인증·ACL, Application Identity mismatch 탐지, Trust Score 하락, Device Isolation, 실제 iptables DROP, 차단 대상 MQTT 실패, 승인된 Firewall Release, Runtime Firewall Snapshot 검증, Recovery Preflight/Execute, DB Backup 무결성 검증, 정상 MQTT/Feature 재개까지 하나의 신규 E2E Session에서 확인했다.

Phase 6-A P0 흐름은 완료로 판정한다. 단, `esp32_02`의 정상 sparse cadence가 현재 Packet IF 임계값을 근소하게 초과한 사례는 Runtime 결함이 아닌 모델 보정 후속 작업으로 확인했으며 Phase 6-B로 이관한다. 이 보정 전까지 Packet Capture 상시 운영은 활성화하지 않는다.

## 2. 검증 기준

- 검증일: 2026-08-15 ~ 2026-08-16 KST
- Raspberry Pi repository: `/home/pi/iot-edge-zero-trust`
- Branch: `develop`
- HEAD: `2e3de9f7711a32df33d4c506a381205da0d27725`
- 공식 E2E Session DB ID: `59`
- 공식 E2E Session UUID: `3c7e875d-2b7c-4a5e-923e-878e0f399f14`
- Packet capture interface: `eth0`
- Session status: `COMPLETED`
- Processed windows: `19/19`
- Window range: `2026-08-15T14:34:50Z` ~ `2026-08-15T14:38:00Z`

Session 53은 재사용하지 않았으며, Phase 6-A 공식 검증을 위한 신규 Session 59만 사용했다.

## 3. MQTT Identity 및 ACL

Strict-test TCP 18831에서 다음 ACL Test Pack을 모두 통과했다.

| 항목 | 결과 |
| --- | --- |
| `esp32_01` 자기 Topic Publish | PASS |
| `esp32_02` 자기 Topic Publish | PASS |
| Cross-topic Publish | DENY |
| Wrong password CONNECT | DENY |
| Anonymous CONNECT | DENY |
| Edge Subscriber read | PASS |
| Edge Subscriber write | DENY |

운영 1883 Strict 전환 후 `esp32_01`, `esp32_02`, `edge_subscriber`가 각 Credential로 정상 연결되는 것을 확인했다. 실제 Password, password hash, API key 및 로컬 Credential 파일은 Git·문서·PR에 포함하지 않았다.

Application Identity 검증에서는 Topic의 Device ID와 Payload의 Device ID가 다른 메시지 2건이 `DEVICE_ID_MISMATCH`로 탐지됐다.

- MQTT log ID: `16162`, `16168`
- Topic device: `esp32_01`
- Payload device: `esp32_02`
- Detection event ID: `35`, `36`
- Trust delta: 각 `-25`
- 정상 Device `last_seen_at` 오염 없음
- 정상 MQTT Feature 혼입 없음
- Raw MQTT 증적 보존

Broker ACL과 Application Detection은 서로 다른 계층으로 검증했다. Cross-topic 요청은 Broker에서 차단했고, 허용된 Test Tool Principal의 Payload mismatch는 Application에서 탐지했다.

## 4. Trust, Isolation 및 Firewall Enforcement

Session 59에서 확인한 Trust 변화는 다음과 같다.

- `esp32_01`: `100 → 75 → 50 → 25`
- `esp32_02`: `100 → 85 → 70`

`esp32_01`은 Trust Score가 격리 기준 미만으로 내려가 격리됐다.

- Isolation History ID: `6`
- Firewall Rule ID: `4`
- Trigger Event ID: `36`
- Protocol: TCP
- Destination port: `1883`
- Action: `DROP`

Isolation History와 Firewall Rule은 Device ID로 추측 연결하지 않고 동일한 `trigger_event_id=36`으로 연결되는 것을 API와 Dashboard Modal에서 모두 확인했다.

실제 Runtime에서는 다음을 확인했다.

- iptables에 `esp32_01` TCP 1883 DROP 적용
- 격리된 `esp32_01` MQTT 연결 실패
- 비격리 `esp32_02` MQTT Publish 지속
- 승인된 Firewall Release 후 Rule DB 상태 `REMOVED`
- Runtime wrapper에서 해당 DROP rule 제거
- Runtime Firewall Snapshot 결과 `VERIFIED_RELEASED`

## 5. Recovery

- Recovery operation ID: `20260815T145926Z-218f60fba943`
- Result: `SUCCESS`
- Before: `isolated / 25`
- After: `normal / 100`
- Runtime gate: `VERIFIED_RELEASED`
- Backup file: `baseline-recovery-20260815T145926Z-218f60fba943.db`
- Backup SHA256: `7157d7b84bb59bae3f79cc292cb5aa9940dfa2819aa34e5d21943bf15a817b38`
- Live/Backup DB integrity: `ok`
- Foreign key violation: `0`

기존 Detection, Trust, Isolation, Firewall 및 Recovery History가 보존되는 것을 확인했다. 동일 Device에 대한 중복 Recovery Preflight는 `INVALID_DEVICE_STATUS`로 거부됐다.

Writer 복구 후 다음 신규 데이터가 생성됐다.

- 새 MQTT log: `esp32_01` 6건, `esp32_02` 6건
- 새 MQTT Feature: `esp32_01` 3건, `esp32_02` 3건
- 신규 보안 Event: 0건
- Active Firewall Rule: 0건

## 6. Dashboard 실제 화면 검증

Frontend는 Mock이 아닌 실제 Raspberry Pi API를 사용해 `http://localhost:5173`에서 확인했다.

- Dashboard 요약: 전체 2, 정상 1, 주의 1, 격리 0, Firewall 적용 0
- API Health: API `ok`, Database `ok`, DB 연결됨
- Device 상태: `esp32_01 normal/100`, `esp32_02 warning/70`
- Devices Modal: Firewall Port `1883` 표시
- Isolation History ID 6 상세:
  - Trust History ID `19`
  - Trigger Event ID `36`
  - Firewall Rule ID `4`
  - Port `1883`
  - Firewall 상태 `차단 해제`
- MQTT Logs: 최신 정상 메시지 JSON Valid / Topic Valid / Error 없음
- Events: `DEVICE_ID_MISMATCH`와 `AI_PACKET_ANOMALY`의 Device, Delta 및 Trust 반영 결과 표시
- Browser console error/warning 없음

현재 격리 Device가 없기 때문에 Recovery Execute Panel이 표시되지 않는 것은 정상이다. 완료된 Recovery operation은 Backend History API로 확인했다.

## 7. 최종 Runtime 상태

- Active:
  - `mqtt-subscriber.service`
  - `mqtt-feature-builder.service`
  - `detection-orchestrator.service`
  - `firewall-worker.service`
  - `gateway-metrics.service`
  - `iot-edge-api.service`
  - `mosquitto.service`
  - `firewall-runtime-snapshot.timer`
- Inactive by design: `packet-capture.service`
- Runtime managed firewall rule: 없음
- Runtime Snapshot: fresh, `available=true`, `managed_rules=[]`
- 운영 Mosquitto: TCP 1883 / WebSocket 9001 LISTEN
- 사전 검증용 Strict-test Broker: 종료, 18831 / 18901 listener 없음
- Pi working tree: clean

## 8. Packet IF 정상 오탐 분석과 Phase 6-B 이관

Session 59에서 `esp32_02` 정상 Packet Feature 2건이 Packet IF anomaly로 판정돼 Trust Score가 `100 → 70`으로 내려갔다.

배포 Artifact와 Runtime 계산을 다시 검증했다.

- Artifact: `packet-if-v2-verified-001-p99-py310`
- Bundle SHA256: `1a567511b5ff4f90b14176ce017f77cf74fa5ea1ead6908b8e5a482333681a48`
- Threshold: `0.1629224401608304`
- Operator: `>`
- Threshold source: normal validation percentile 99
- Runtime Feature 순서, normalization 및 manifest 일치

Artifact 평가에서도 정상 오탐이 존재한다.

- Validation normal: 329건 중 4건 anomaly (`1.2158%`)
- Test normal: 329건 중 14건 anomaly (`4.2553%`)
- Test attack: 2건 중 2건 탐지

Session 59 재계산 결과는 다음과 같다.

- `esp32_01`: eligible inbound 19건, anomaly 0건
- `esp32_02`: eligible inbound 19건, anomaly 2건
- 최대 score: `0.1649766935`
- Threshold 초과 폭: 약 `0.00205425336`
- anomaly window: packet count 1, total bytes 117, 약 9.96초 coverage
- 인접 정상 row score: `0.1619540605`

`esp32_02`의 single-packet window는 약 30초 주기로 반복됐다. Capture 누락, parser 오류, Artifact 손상 또는 Runtime 계약 불일치는 확인되지 않았다. 정상 firmware/client cadence와 10초 window 경계가 만든 sparse 패턴이 현재 p99 경계에 걸린 모델 데이터 커버리지·보정 문제로 판정한다.

### Phase 6-B 필수 후속 작업

1. `esp32_02`의 정상 sparse cadence를 별도 정상 Holdout으로 추가 수집한다.
2. 기존 고정 Dataset과 구분된 새 Dataset/Artifact Version을 사용한다.
3. 정상 오탐률과 기존 공격 탐지율을 함께 재평가한다.
4. Test 결과를 본 뒤 기존 Artifact나 Threshold를 덮어쓰지 않는다.
5. 승인된 새 Artifact로 두 ESP32 장시간 신규 Session 회귀를 수행한다.
6. 정상 오탐 누적이 해소된 뒤 Packet Capture 상시 운영을 검토한다.
7. 현재 운영 DB의 `esp32_02 warning/70`을 결과에 맞추기 위해 Raw SQL로 임의 복구하지 않는다.

## 9. 제외 범위 및 보안 통제

- 코드, API, DB Schema, Migration, systemd unit 및 모델 변경 없음
- 실제 Credential, `.env`, Local Secret Header 및 password file 미포함
- 운영 DB 또는 Backup DB 파일 미포함
- PCAP, Model 및 대용량 수집 Artifact 미포함
- Recovery/Firewall 결과에 맞추기 위한 운영 DB 수동 수정 없음
- Evidence 수집 후 추가 Recovery Execute 또는 iptables 변경 없음
- 실기기 화면에 노출 가능성이 있었던 로컬 Wi-Fi Credential은 문서와 PR에 기록하지 않았으며 검증 종료 후 교체를 권고한다.

## 10. 관련 PR

- PR #58: Recovery Dashboard
- PR #63: MQTT Identity / ACL
- PR #64: Runtime Firewall Verifier
- PR #65: Mosquitto listener별 인증 설정 보완

이 문서는 위 구현 PR을 변경하지 않고 실제 통합 배포·검증 결과와 남은 후속 작업을 고정한다.
