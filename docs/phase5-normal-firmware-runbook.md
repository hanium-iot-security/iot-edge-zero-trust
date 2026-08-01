# Phase 5 정상 Firmware 실행 Runbook

## 1. 목적과 상태

이 문서는 `firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino`를 ESP32 #1·#2에 안전하게 컴파일·업로드하고, Notion 정책 v1.0 기준 Pilot 전 Serial·MQTT Smoke를 수행하는 절차다.

이 Firmware의 구현·Smoke 완료는 공식 정상 Dataset 수집 승인을 의미하지 않는다. Profile별 Pilot 판정과 정책 v1.1 동결 전에는 공식 Train·Validation·Test Session을 시작하지 않는다.

## 2. Firmware 계약

| 항목 | 계약 |
| --- | --- |
| Firmware Version | `phase5-normal-pilot-v1` |
| Payload Schema Version | `phase5-normal-payload-v1` |
| Device | `esp32_01`, `esp32_02` |
| Topic | `iot/{device_id}/sensor` |
| Client ID | `p5-{device_id}-v1` |
| 필수 Payload | `device_id`, `sequence`, `uptime_s` |
| 선택 Payload | 실제 `rssi`, `free_heap` |
| 최대 Payload | 100 bytes |

합성 `temp`·`hum`·`bat` 값은 사용하지 않는다. MQTT Topic과 Payload의 `device_id`는 항상 같아야 한다.

## 3. Profile 계약

| Profile | 이름 | Publish 주기 | Payload |
| --- | --- | --- | --- |
| `0` | `normal_stable` | 5초 고정 | 필수 필드 |
| `1` | `normal_interval_jitter` | 4~6초 | Profile 0과 동일 |
| `2` | `normal_payload_variation` | 5초 고정 | 필수 필드와 실제 선택 필드 순환 |
| `3` | `normal_combined_variation` | 4~6초 | Profile 2와 동일 |

Profile 3은 Profile 1·2의 Pilot 결과가 각각 승인되기 전에는 공식 정상 수집에 사용하지 않는다.

## 4. 사전 준비

### 4.1 Arduino IDE

```text
Board: ESP32 Dev Module
Serial Monitor: 115200 baud
ESP32 Core: 3.3.8 이상
Library: PubSubClient 2.8
```

Arduino IDE에서 다음 Sketch를 연다.

```text
firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino
```

### 4.2 로컬 설정 생성

저장소 루트의 PowerShell에서 실행한다.

```powershell
Copy-Item `
  firmware/esp32/phase5_normal_collector/phase5_firmware_config.example.h `
  firmware/esp32/phase5_normal_collector/phase5_firmware_config.h
```

`phase5_firmware_config.h`에서 다음 항목을 설정한다.

```cpp
#define PHASE5_CONFIGURED 1
#define PHASE5_DEVICE_SLOT 1
#define PHASE5_NORMAL_PROFILE 0
#define PHASE5_WIFI_SSID "LOCAL_WIFI_SSID"
#define PHASE5_WIFI_PASSWORD "LOCAL_WIFI_PASSWORD"
#define PHASE5_MQTT_BROKER "192.168.0.20"
#define PHASE5_MQTT_PORT 1883
```

- ESP32 #1은 `PHASE5_DEVICE_SLOT 1`을 사용하며 `esp32_01`로 파생된다.
- ESP32 #2는 `PHASE5_DEVICE_SLOT 2`를 사용하며 `esp32_02`로 파생된다.
- Wi-Fi Password는 문서·커밋·스크린샷·Serial Log에 남기지 않는다.

로컬 설정이 Git에서 제외되는지 확인한다.

```powershell
git check-ignore -v firmware/esp32/phase5_normal_collector/phase5_firmware_config.h
git status --short
```

첫 명령은 `.gitignore` 규칙을 출력해야 하고, 두 번째 명령에 실제 설정 파일이 나타나면 안 된다.

## 5. 물리 Device 매핑 Gate

업로드마다 아래 항목을 한 행으로 대조해 실행 기록에 남긴다.

| 물리 장비 | 물리 라벨 | COM Port | Device Slot | 예상 Device ID | Serial 실제 IP | DB 등록 IP | Topic |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ESP32 #1 | 장비 라벨 확인값 | 연결된 COM | `1` | `esp32_01` | 부팅 후 기록 | DB 조회값 | `iot/esp32_01/sensor` |
| ESP32 #2 | 장비 라벨 확인값 | 연결된 COM | `2` | `esp32_02` | 부팅 후 기록 | DB 조회값 | `iot/esp32_02/sensor` |

하나라도 일치하지 않으면 Upload와 Pilot을 중지한다. Device Slot을 바꾼 뒤 Arduino IDE가 이전 Build 결과를 재사용하지 않도록 다시 Verify한 후 Upload한다.

## 6. Compile·Upload 순서

각 ESP32에 대해 다음 순서를 독립적으로 수행한다.

1. USB 연결 장비의 물리 라벨과 COM Port를 확인한다.
2. 로컬 설정의 `PHASE5_DEVICE_SLOT`과 `PHASE5_NORMAL_PROFILE`을 확인한다.
3. Arduino IDE에서 **Verify**를 실행한다.
4. 컴파일 오류가 없고 Device Slot·Profile Gate가 통과했는지 확인한다.
5. **Upload**를 실행한다.
6. Serial Monitor를 115200 baud로 연다.
7. 부팅 계약과 실제 IP를 기록한다.

ESP32 #1과 #2를 같은 설정으로 연속 Upload하지 않는다. 두 장비 사이에 Device Slot·COM Port·예상 Topic을 다시 대조한다.

## 7. Serial Smoke

부팅 시 다음 항목이 모두 출력되어야 한다.

```text
phase5_normal_collector_boot
firmware_version=phase5-normal-pilot-v1
payload_schema_version=phase5-normal-payload-v1
device_id=esp32_01 또는 esp32_02
device_slot=1 또는 2
normal_profile=0..3
profile_name=<선택한 Profile 이름>
mqtt_topic=iot/<device_id>/sensor
mqtt_client_id=p5-<device_id>-v1
mqtt_broker=<설정한 Broker>:1883
```

다음도 확인한다.

- `wifi_connected ip=`의 실제 IP가 DB 등록 IP와 일치한다.
- `mqtt_connected`가 출력된다.
- `mqtt_publish_succeeded`의 Sequence가 단조 증가한다.
- `payload_size`가 100 이하이다.
- Password가 Serial에 출력되지 않는다.
- Profile 3은 `profile_3_requires_profile_1_and_2_pilot_approval` 경고를 출력한다.

다음 오류가 반복되면 Pilot을 시작하지 않는다.

- `wifi_connect_timeout`
- `mqtt_connect_failed`
- `payload_rejected reason=over_100_bytes`
- `mqtt_publish_failed`

## 8. MQTT·DB Smoke

Raspberry Pi에서 MQTT를 관찰한다.

```bash
mosquitto_sub -h localhost -p 1883 -t 'iot/+/sensor' -v
```

정상 예시는 다음과 같다.

```text
iot/esp32_01/sensor {"device_id":"esp32_01","sequence":1,"uptime_s":5}
iot/esp32_02/sensor {"device_id":"esp32_02","sequence":1,"uptime_s":5}
```

Profile 2·3에서는 `sequence`에 따라 `rssi`, `free_heap`이 선택적으로 포함될 수 있다. 모든 메시지에는 필수 세 필드가 있어야 한다.

운영 DB를 수정하지 않고 최근 수신만 조회한다.

```bash
sqlite3 "$DATABASE_PATH" "
SELECT id, device_id, topic, payload_size, received_at,
       is_json_valid, is_topic_valid, error_message
FROM mqtt_logs
WHERE device_id IN ('esp32_01', 'esp32_02')
ORDER BY id DESC
LIMIT 20;"
```

통과 조건:

- Topic·Payload Device ID가 물리 매핑과 일치한다.
- `is_json_valid=1`, `is_topic_valid=1`, `error_message IS NULL`이다.
- 신규 `received_at`은 UTC `Z` 형식이다.
- `devices.last_seen_at`이 같은 수신 시각으로 전진한다.
- MQTT Feature Builder Checkpoint와 `feature_logs` Window가 계속 전진한다.

## 9. Profile별 Pilot 전 확인

### Profile 0

- 간격이 약 5초로 고정된다.
- 필수 Payload 세 필드만 존재한다.

### Profile 1

- Payload 필드 집합이 Profile 0과 같다.
- 간격만 4~6초 범위에서 달라진다.

### Profile 2

- 간격이 약 5초로 고정된다.
- 필수-only, `+rssi`, `+rssi+free_heap` 순환이 재현된다.
- `rssi`·`free_heap` 값은 실제 장비 측정값이다.

### Profile 3

- Profile 2의 Payload 변화와 4~6초 간격을 결합한다.
- Profile 1·2의 Pilot 판정이 승인되기 전에는 Firmware Smoke까지만 수행한다.

각 Profile Pilot은 기기·Profile별 독립 Session ID를 사용하고 단순 경과 시간이 아니라 적격성 검사를 통과한 유효 Window 60개를 목표로 한다.

## 10. 실행 기록

각 Compile·Upload·Smoke 기록에 다음을 남긴다.

- Git Commit SHA
- Firmware Version
- Payload Schema Version
- Device Slot·Device ID·COM Port·실제 IP
- Profile 번호·이름
- Verify·Upload 결과
- Serial 부팅 계약
- MQTT Topic·대표 Payload
- MQTT·Feature Checkpoint 전진 여부
- 실행 시각과 실행자

PR #45의 Run·Session Manifest 계약이 확정되면 같은 항목을 공통 Manifest에 연결한다. 계약 확정 전 임의의 공식 Manifest Schema를 만들지 않는다.

## 11. 중단과 복구

- Device 매핑 오류: 즉시 전송을 중단하고 올바른 Device Slot으로 다시 Verify·Upload한다.
- MQTT·Feature 오류: 원본 로그를 보존하고 `HOLD`로 기록한다.
- Payload 계약 오류: 해당 Firmware Commit과 Profile의 Pilot을 무효 처리한다.
- 정상 Firmware 복구가 필요하면 마지막으로 검증된 Firmware Commit과 Device Slot을 사용해 다시 Upload한다.
- 운영 DB, Trust Score, Device Status, Firewall Rule을 임의 SQL로 수정하지 않는다.

## 12. 공식 수집 Gate

다음이 모두 완료된 뒤에만 공식 정상 Session 수집을 시작한다.

- 정책 v1.0 Pilot Profile 판정 완료
- 정책 v1.1의 승인 Profile·Split·Version 동결
- Firmware Commit과 Payload Schema Version 동결
- PR #45의 Run·Session Manifest 계약 확정
- ESP32 두 대의 물리 Device·Device ID·실제 IP 매핑 확인
- Raspberry Pi Cold Boot·NTP·Subscriber·Feature·Packet Capture Smoke 통과

