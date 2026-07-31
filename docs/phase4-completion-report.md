# Phase 4 완료 보고

## 1. 문서 목적

이 문서는 Phase 4에서 구현·통합한 MQTT 기반 탐지, Trust Score v2, Firewall 자동 격리 Runtime과 Raspberry Pi 실기기 운영 검증 결과를 고정합니다.

- 검증 일자: 2026-08-01 KST
- 적용 브랜치: `develop`
- 적용 Commit: `9bd9478f23f24e960b70bbfe61cf2d54af3a8a94`
- 검증 장비: Raspberry Pi #1, ESP32 #1·#2
- 운영 DB와 `.env`, 인증정보, 비밀키는 저장소에 포함하지 않습니다.

## 2. Phase 4 완료 범위

Phase 4에서는 다음 범위를 완료했습니다.

- ESP32 MQTT Publish 수신과 SQLite 저장
- 10초 MQTT Feature Window 생성
- Detection Orchestrator 기반 탐지 Stage 실행
- Required Detector Barrier와 Checkpoint 처리
- Trust Score v2 계산과 격리 상태 전이
- Firewall Worker 기반 MQTT TCP 1883 자동 차단·해제
- FastAPI 운영 Runtime
- Packet Capture와 Gateway Metrics 기반 Runtime
- systemd 상시 실행, 서비스 재시작, Pi 재부팅 후 자동 복구 검증
- 제한형 MQTT Flood를 이용한 ESP32 실기기 E2E 검증

## 3. 최종 운영 구조

```text
ESP32 #1·#2
→ Mosquitto
→ mqtt-subscriber.service
→ mqtt-feature-builder.service
→ detection-orchestrator.service
  → MQTT Rule Detection
  → Required Detector Barrier
  → Trust Score v2
  → Trust Checkpoint
→ firewall-worker.service
→ iot-edge-api.service
→ React Dashboard
```

Trust Score v2는 별도의 `trust-score.service`로 실행하지 않습니다. Phase 4 운영 경로에서는 `detection-orchestrator.service`가 `edge.orchestration.run_detection_orchestrator --loop`를 실행하고, 탐지 Stage 완료 후 Trust Score v2까지 같은 Cycle 안에서 처리합니다.

수동 실행용 `edge.trust.run_trust_score_update`는 저장소에 존재하지만 Phase 4 상시 운영 Runtime으로 사용하지 않습니다. Orchestrator와 수동 Trust Runner를 동시에 실행하지 않습니다.

## 4. 상시 Runtime 서비스

재부팅 후 다음 8개 서비스가 모두 `enabled`와 `active` 상태임을 확인했습니다.

| 서비스 | 역할 | 재부팅 후 상태 |
| --- | --- | --- |
| `mosquitto.service` | MQTT Broker | `enabled / active` |
| `mqtt-subscriber.service` | MQTT 수신·DB 저장 | `enabled / active` |
| `mqtt-feature-builder.service` | MQTT Feature Window 생성 | `enabled / active` |
| `detection-orchestrator.service` | 탐지·Trust Score v2 통합 Cycle | `enabled / active` |
| `firewall-worker.service` | 승인된 Firewall Rule 적용·해제 | `enabled / active` |
| `packet-capture.service` | Packet Capture Runtime | `enabled / active` |
| `gateway-metrics.service` | Gateway Metrics 수집 | `enabled / active` |
| `iot-edge-api.service` | FastAPI 운영 API | `enabled / active` |

- Failed Unit: 없음
- Pi Timezone: `Asia/Seoul`
- NTP 동기화: `yes`

## 5. MQTT Subscriber 정식 배포 결과

### 5.1 저장소 갱신

Pi 저장소를 병합된 `develop`로 Fast-forward 갱신했습니다.

```text
기존 HEAD: d6772656f691cbd813c818519626632e695edde3
최종 HEAD: 9bd9478f23f24e960b70bbfe61cf2d54af3a8a94
브랜치: develop
상태: origin/develop과 일치
```

### 5.2 Unit Backup과 설치

기존 설치 Unit을 UTC Timestamp Backup으로 보존했습니다.

```text
/etc/systemd/system/mqtt-subscriber.service.20260731T162952Z.bak
```

저장소 Unit을 `/etc/systemd/system/mqtt-subscriber.service`에 설치하고 `systemctl daemon-reload`, `systemd-analyze verify`를 수행했습니다.

저장소본과 설치본 SHA256은 다음과 같이 일치했습니다.

```text
697cc28b1f6cf0863b6a7e2e87def93c856a0a0689e6eeba196564fc88d03723
```

설치 직후 상태:

```text
mqtt-subscriber.service: enabled / active
```

### 5.3 재시작 검증

서비스 재시작 전후 MQTT Row 수를 비교했습니다.

```text
BEFORE=7037
AFTER=7043
MQTT_ROW_INCREASE=PASS
```

재시작 후 확인 결과:

- 새 Main PID로 정상 기동
- `NRestarts=0`
- `localhost:1883`, Topic `#`로 Broker 재연결
- `esp32_01`, `esp32_02` Row 저장 재개
- 반복 Traceback, DB 오류, Broker 연결 실패 없음

## 6. Pi 재부팅 후 자동 복구 검증

Pi를 재부팅한 뒤 다음 항목을 확인했습니다.

- 부팅 시각: `2026-08-01 01:37:20 KST`
- Git HEAD: `9bd9478f23f24e960b70bbfe61cf2d54af3a8a94`
- Runtime 서비스 8개: 모두 `enabled / active`
- Failed Unit: 없음
- MQTT Subscriber 저장소본·설치본 SHA256 일치
- API Health 정상
- MQTT Row 증가
- SQLite 무결성 정상

API Health 응답:

```json
{"status":"ok","database":"ok","db_connected":true,"server_time":"2026-07-31T16:38:37Z"}
```

재부팅 후 MQTT Row 검증:

```text
BEFORE=7196
AFTER=7202
MQTT_ROW_INCREASE=PASS
```

최신 Row에서 `esp32_01`, `esp32_02`의 정상 MQTT Publish를 모두 확인했습니다.

DB 검사:

```text
integrity_check=ok
foreign_key_violations=0
```

부팅 로그의 ALSA udev 규칙 경고와 NFS `blkmapd` 경고는 프로젝트 Runtime 실패로 판정하지 않았습니다. Failed Unit이 없고 MQTT·API·DB Runtime이 정상임을 우선 근거로 삼았습니다.

## 7. ESP32 등록 기기 자동 격리 E2E

공식 Run ID:

```text
esp32-attack-e2e-20260731T132407Z
```

관측 결과:

| 항목 | 실제 결과 |
| --- | --- |
| 공격 대상 | ESP32 #2, `192.168.0.5` |
| 제한형 MQTT Flood | 40건 × 4 Burst |
| 공격 구간 MQTT Row | 162건, 관측 Probe 포함 |
| Feature Window | 4개, `publish_count` 40·40·40·41 |
| Detection Event | `ABNORMAL_PUBLISH_RATE` 4건 |
| Trust Score | `100 → 80 → 60 → 40 → 20` |
| Firewall | Rule ID `1`, TCP 1883 DROP, `APPLIED` |
| 격리 관측 | 기존 연결 단절과 신규 연결 실패 확인 |
| 공식 Release | Firewall Rule `REMOVED`, iptables Rule 제거 확인 |
| 정상 복구 | 정상 Firmware 복구 후 MQTT Publish 재개 |
| Run 최종 상태 | `HOLD` |

`HOLD`는 탐지·격리 실패가 아닙니다. 승인된 Trust Score·Device Status Baseline Recovery 절차가 아직 없기 때문에 다음 반복 Run의 Baseline Gate를 충족하지 못한 상태입니다. 운영 DB를 임의 SQL로 `trust_score=100`, `status=normal`로 되돌리지 않았습니다.

## 8. 검증 중 확인된 식별 오귀속 위험

ESP32 #2에 `esp32_01` 식별자를 잘못 업로드한 과정에서 논리 Device `esp32_01`에 탐지·감점·격리가 귀속되는 현상을 확인했습니다.

- 직접적인 촉발 원인: 운영자의 Firmware `DEVICE_ID` 설정 실수
- 구조적 위험: Source IP, MQTT Client ID, Topic·Payload의 Device ID가 강하게 바인딩되지 않음
- 조치: 생성된 Firewall Rule을 공식 Release하고 정상 Firmware와 Publish를 복구
- 후속 범위: Source IP ↔ MQTT Client ID ↔ Device ID 바인딩 강화

Firmware 업로드 전 다음 네 항목을 대조합니다.

1. Arduino IDE COM Port와 물리 장비
2. Firmware `DEVICE_ID`
3. MQTT Topic
4. Serial Monitor 실제 IP와 DB `devices.ip_address`

## 9. Phase 4 최종 판정

**Phase 4 구현·통합·실기기 운영 검증 완료**

완료 근거:

- MQTT 수신·Feature·탐지·Trust Score v2·Firewall 자동 격리 연결
- ESP32 실기기 공격 E2E 관측
- MQTT Subscriber systemd 배포 자산 저장소 반영
- Pi 서비스 재시작 후 데이터 적재 복구
- Pi 재부팅 후 Runtime 자동 시작
- API Health와 SQLite 무결성 확인
- 실제 수행 결과와 미검증 범위를 문서로 분리

## 10. Phase 5 인계 범위

다음 항목은 Phase 4 미완료가 아니라 Phase 5 또는 후속 보안 고도화 범위로 인계합니다.

- 승인된 Trust Score·Device Status Baseline Recovery 정책
- Source IP·MQTT Client ID·Device ID 바인딩
- Packet Rule 공식 실기기 시나리오와 반복 평가
- Packet Isolation Forest 최종 학습·Artifact·Metadata 검증
- Packet Stage Required 활성화와 Packet 기반 Trust 반영
- Packet 이상 → Firewall 자동 격리 E2E
- Capture Session Gap 운영 복구 절차
- Threshold 정량 보정과 3회 이상 반복 성능 평가

Packet Capture와 Gateway Metrics Runtime이 `active`인 사실과 Packet Detector가 운영 Trust Cycle에서 Required로 활성화된 사실은 구분합니다. Phase 4의 공식 자동 격리 E2E는 MQTT Detection·Trust Score v2·Firewall 경로를 기준으로 완료했습니다.

## 11. 관련 문서와 PR

- `docs/phase4-esp32-attack-test-runbook.md`
- `docs/mqtt-subscriber-deployment-runbook.md`
- PR #38: ESP32 공격 테스트 모드와 실기기 E2E 결과
- PR #43: MQTT Subscriber systemd 배포 자산
