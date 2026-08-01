# Phase 5 정상 데이터 수집 Firmware 설계

## 1. 목적

Phase 5 정책 v1.0 Pilot에서 ESP32 두 대의 정상 MQTT·Packet 분포를 재현 가능하게 수집할 수 있는 전용 Firmware를 추가한다. 기존 `firmware/esp32/normal_sender/`는 MVP 증적으로 보존하되 새 Firmware가 해당 구현이나 Payload 계약에 의존하지 않도록 완전히 분리한다.

정책 기준은 Notion의 [Phase 5 정상 데이터 수집 정책 및 실행 기준](https://app.notion.com/p/3ab96c0fdc1c8164a97ae3d99ea6eee4)과 [P5-WM-01 원우민 — 실기기 Session 수집·E2E 차단 증적](https://app.notion.com/p/3aa96c0fdc1c8192bd38cf2be9e917d5)이다.

## 2. 범위

### 포함

- 신규 Arduino Sketch `firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino`
- `NORMAL_PROFILE=0..3` 인터페이스
- Canonical Payload와 실제 ESP32 측정값
- Device ID 기반 MQTT Topic·Client ID
- Firmware·Payload Schema Version과 Profile 부팅 로그
- 로컬 전용 Wi-Fi·Broker·Device·Profile 설정과 추적 가능한 예시 파일
- Firmware 정적 계약 테스트
- Arduino IDE 컴파일·업로드·Serial·MQTT Smoke Runbook
- 기존 MQTT Subscriber·Feature·Rule 경로와의 정합성 검증

### 제외

- 기존 MVP `normal_sender` 수정 또는 삭제
- 공격 Firmware 수정
- Run Manifest Schema 또는 PR #45 수정
- DB Schema·Migration·Backend·Frontend·탐지 Threshold 변경
- Raspberry Pi·ESP32 실기기 업로드와 Pilot 실행
- Profile 판정 및 정책 v1.1 확정

## 3. 디렉터리와 설정 경계

```text
firmware/esp32/phase5_normal_collector/
├── phase5_normal_collector.ino
└── phase5_firmware_config.example.h

docs/phase5-normal-firmware-runbook.md
tests/test_phase5_normal_collector_firmware.py
```

운영자는 `phase5_firmware_config.example.h`를 `phase5_firmware_config.h`로 복사하고 로컬 값만 수정한다. 실제 설정 파일은 `.gitignore`에 등록한다.

로컬 설정은 다음 항목만 소유한다.

- `PHASE5_CONFIGURED`: 예시 파일을 그대로 업로드하지 못하게 하는 Gate
- `PHASE5_DEVICE_SLOT`: `1` 또는 `2`; Firmware가 `esp32_01`·`esp32_02`를 파생
- `PHASE5_NORMAL_PROFILE`: `0..3`
- Wi-Fi SSID·Password
- MQTT Broker Host·Port

Sketch는 Device Slot과 Profile 범위를 전처리 단계에서 검증한다. 임의 Device ID 문자열을 직접 입력하지 않게 해 오타 위험을 줄인다. 물리 장비 오귀속을 완전히 막는 MAC 바인딩은 이번 범위에 포함하지 않고, 부팅 로그와 Runbook의 COM Port·물리 Device·Device Slot·실제 IP 대조 Gate로 관리한다.

## 4. 버전과 MQTT 식별자

- Firmware Version: `phase5-normal-pilot-v1`
- Payload Schema Version: `phase5-normal-payload-v1`
- Topic: `iot/{device_id}/sensor`
- MQTT Client ID: `p5-{device_id}-v1`

Topic과 Client ID는 Device Slot에서 파생한 동일 Device ID를 사용한다. 부팅 시 다음을 한 번에 출력한다.

- Firmware Version
- Payload Schema Version
- Device ID와 Device Slot
- `NORMAL_PROFILE`과 Profile 이름
- MQTT Topic과 Client ID
- Broker Host·Port

Wi-Fi Password는 절대 로그에 출력하지 않는다.

## 5. Canonical Payload

모든 정상 Profile은 다음 필드를 항상 포함한다.

```json
{"device_id":"esp32_01","sequence":1,"uptime_s":5}
```

- `device_id`: Topic·Client ID와 동일한 논리 Device ID
- `sequence`: 성공적으로 Publish된 메시지의 단조 증가 번호
- `uptime_s`: `millis()` 기반 부팅 후 경과 초

선택 필드는 ESP32가 실제 제공하는 값만 사용한다.

- `rssi`: `WiFi.RSSI()`의 실제 dBm 값
- `free_heap`: `ESP.getFreeHeap()`의 실제 Byte 값

실제 센서가 없는 `temp`·`hum`·`bat`와 임의 생성 센서값은 사용하지 않는다.

Profile 2·3의 선택 필드 구성은 `sequence % 3`으로 결정한다.

| 나머지 | Payload 구성 |
| --- | --- |
| `0` | 필수 필드만 |
| `1` | 필수 필드 + `rssi` |
| `2` | 필수 필드 + `rssi` + `free_heap` |

무작위 필드 선택 대신 결정적 순환을 사용해 Run 간 Payload 변화 패턴을 재현한다. 값 자체는 실제 측정값이므로 자연 변동을 유지한다.

Payload는 ASCII JSON으로 생성하고 Publish 전 `String.length()`가 100 bytes 이하인지 확인한다. 상한을 넘으면 불완전한 대체 Payload를 보내지 않고 해당 Publish를 거부하며 Serial에 오류를 기록한다.

## 6. Profile 계약

| Profile | 이름 | Publish 주기 | Payload |
| --- | --- | --- | --- |
| `0` | `normal_stable` | 5초 고정 | 필수 Canonical 필드 |
| `1` | `normal_interval_jitter` | 4~6초 | Profile 0과 동일 |
| `2` | `normal_payload_variation` | 5초 고정 | 결정적 선택 필드 변화 |
| `3` | `normal_combined_variation` | 4~6초 | Profile 2와 동일 |

Profile 0·2는 5,000ms를 사용한다. Profile 1·3은 ESP32 난수원을 Seed로 사용해 4,000~6,000ms 범위의 다음 간격을 선택한다.

Profile 3은 Firmware에서 지원하지만, Profile 1과 Profile 2의 Pilot 판정 전에는 공식 정상 수집에 사용하지 않는다. Runbook은 이 Gate를 명시한다.

## 7. 연결과 Publish 흐름

1. 설정 Gate와 Profile·Device Slot을 검증한다.
2. Serial에 Version·Device·Profile·MQTT 계약을 출력한다.
3. Wi-Fi 연결을 제한 시간 단위로 시도한다.
4. MQTT 연결을 한 번씩 시도하고 실패 시 다음 Retry 시각까지 `loop()`를 계속 실행한다.
5. MQTT 연결 상태에서만 Profile 주기에 따라 Payload를 만든다.
6. Payload 계약과 100 bytes 상한을 확인한 뒤 Publish한다.
7. Publish 성공 시에만 `sequence`를 확정하고 다음 간격을 계산한다.
8. 실패 시 Sequence를 증가시키지 않고 오류·MQTT State를 기록한다.

무한 Blocking 재연결 Loop와 `ESP.restart()`는 사용하지 않는다. `millis()` 차이를 이용한 스케줄링으로 Wrap-around에 안전하게 동작한다.

## 8. 기존 코드와의 정합성

### MQTT Subscriber

`edge/mqtt/subscriber.py`는 `iot/{device_id}/sensor` 형식과 Payload의 비어 있지 않은 `device_id`를 정상으로 판정한다. 새 Payload의 추가 필드는 무시되므로 Subscriber 계약 변경이 필요 없다. Topic과 Payload Device ID가 동일해 `device_id_mismatch`도 발생하지 않는다.

### MQTT Feature Builder와 Rule

Feature Builder는 메시지 수신 시각과 Payload Byte 크기로 `publish_count`, Payload 크기, 메시지 간격을 계산한다. 새 필드는 JSON 파싱 계약을 깨지 않고 Profile별 의도한 간격·크기 분포만 만든다.

4~6초 정상 주기는 기존 `ABNORMAL_PUBLISH_RATE` 기준인 10초 Window 15건 초과와 충분히 분리된다. Threshold는 이번 작업에서 변경하지 않고 Pilot 결과에서 정상 오탐만 측정한다.

### Packet 경로

Topic·Payload 변경은 Packet Capture·Packet Feature DB Schema를 변경하지 않는다. Profile별 실제 Packet·Byte 분포는 Pilot의 관찰 대상이며 사전에 정상 Threshold로 고정하지 않는다.

## 9. 오류 처리

- 설정 미완료 또는 Profile·Device Slot 범위 오류: 컴파일 실패
- Wi-Fi 연결 실패: Password를 제외한 상태와 재시도 시각 출력
- MQTT 연결 실패: MQTT State 출력 후 비차단 재시도
- Payload 100 bytes 초과: Publish 거부, Sequence 유지, 오류 출력
- MQTT Publish 실패: Sequence 유지, MQTT State 출력
- Profile 3: 부팅 로그에 Pilot 승인 Gate 경고 출력

## 10. 테스트 전략

Python 정적 계약 테스트를 먼저 추가하고 신규 Sketch 부재로 실패하는 RED를 확인한 뒤 구현한다.

테스트는 다음을 검증한다.

- 기존 MVP와 다른 신규 Sketch 경로
- 실제 로컬 설정 파일이 Git에서 제외되고 예시 파일만 추적됨
- Device Slot `1|2`와 Profile `0..3` 전처리 검증
- Topic·Client ID가 Device ID에서 파생됨
- 모든 Payload에 `device_id`, `sequence`, `uptime_s`가 포함됨
- Profile 0·1의 Payload가 동일함
- Profile 0·2는 5초, Profile 1·3은 4~6초
- Profile 2·3만 `rssi`, `free_heap` 선택 필드를 사용함
- 합성 센서 필드와 공격·Flood 코드가 없음
- 100 bytes 초과 시 Publish하지 않음
- 성공 Publish에서만 Sequence가 확정됨
- 부팅 로그에 Firmware·Payload Schema·Device·Profile·Topic·Client ID가 있음
- 무한 재연결 Loop와 `ESP.restart()`가 없음
- Runbook에 Arduino IDE 설정, 두 Device Compile·Upload·Serial·MQTT Smoke, 물리 매핑 Gate, Profile 3 Gate가 있음

검증 순서는 관련 Pytest, 기존 ESP32 공격 Firmware 회귀, 전체 비-Wrapper Pytest, `compileall`, `git diff --check` 순으로 한다. Arduino CLI가 설치되어 있으면 예시 설정을 임시 로컬 설정으로 준비해 ESP32 Compile도 수행하고, 설치되어 있지 않으면 미실행 사유와 Arduino IDE 검증 절차를 보고한다.

## 11. 완료 기준

- 신규 Firmware가 MVP 구현과 독립적으로 존재한다.
- 정책 v1.0의 `NORMAL_PROFILE=0..3`과 Canonical Payload를 만족한다.
- 두 Device용 설정을 동일 코드에서 안전하게 선택할 수 있다.
- 실제 측정값만 Payload 후보로 사용한다.
- MQTT Subscriber·Feature·Rule·Packet 계약 변경 없이 수집할 수 있다.
- 계약 테스트와 기존 Firmware 회귀가 통과한다.
- 실기기 작업 전 Runbook으로 Compile·Upload·식별자·Smoke 절차를 재현할 수 있다.

## 12. 남은 운영 Gate

코드 완료는 Pilot 실행 승인을 의미하지 않는다. 실제 Pilot 전에 다음이 별도로 필요하다.

- ESP32 #1·#2의 COM Port·물리 장비·Device Slot·실제 IP 매핑 확인
- 정책 v1.0과 Firmware Commit 기록
- PR #45의 Run·Session Manifest 계약 확정
- Raspberry Pi Cold Boot·NTP·Subscriber·Feature·Capture Smoke
- Profile별 독립 Session ID와 유효 Window 목표 설정
