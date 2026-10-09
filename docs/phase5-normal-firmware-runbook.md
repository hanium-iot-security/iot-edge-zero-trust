# Phase 5 정상 Firmware 실행 Runbook

## 1. 목적과 상태

이 문서는 `firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino`를 ESP32 #1·#2에 안전하게 컴파일·업로드하고, Notion 정책 v1.0 기준 Pilot 전 Serial·MQTT Smoke를 수행하는 절차다.

이 Firmware의 구현·Smoke 완료는 공식 정상 Dataset 수집 승인을 의미하지 않는다. Profile별 Pilot 판정과 정책 v1.1 동결 전에는 공식 Train·Validation·Test Session을 시작하지 않는다.

현재 `phase9-normal-pilot-v2`의 P1·P2 단기 예비시험은 승인된 ESP32 한 대만
전환하고 다른 ESP32·Pico와 운영 Capture를 유지하는 별도 범위다.
[정상 후보 수집 절차](phase8-normal-collection.md)에 따라 안정화 이후의 UTC
10초 경계 구간을 사전 고정하며, Upload·재부팅·Profile 전환 시각은 수집 구간에
포함하지 않는다. 9절의 Capture 재시작·다른 Sender 중지와 10절의 유효 Window
60개 목표는 기존 Phase 5의 독립 Session Pilot·공식 수집 계약에 적용된다.
이 단기 예비시험에서는 서비스 중지나 Train·Validation·Test 배정을 하지 않으며,
동일 Capture Group의 후보는 학습 미승인 상태로 보존한다.

기존 후보 QC의 5초 기준 건수는 P1 Jitter와 맞지 않을 수 있으므로 원래 QC 결과를
보존하고 Profile별 간격·순번·필드·송수신 대조 결과를 함께 기록한다. 새 버전의
Profile 0을 다시 Upload한 경우는 P0 송신 동작 복귀로 기록하고, 기존 v1
바이너리 복원과 구분한다. 복귀 후 Boot Log의 실제 Version·Slot·Profile·Topic과
5초 간격·필수 필드 송신을 확인한다.

## 2. Firmware 계약

| 항목 | 계약 |
| --- | --- |
| Firmware Version | `phase9-normal-pilot-v2` (설정 가능한 한도·간격을 도입한 예비수집 버전) |
| Firmware Limits Version | `phase9-normal-limits-v1` |
| Payload Schema Version | `phase5-normal-payload-v1` |
| Device | `esp32_01`, `esp32_02` |
| Topic | `iot/{device_id}/sensor` |
| Client ID | `p5-{device_id}-v1` |
| 필수 Payload | `device_id`, `sequence`, `uptime_s` |
| 선택 Payload | 실제 `rssi`, `free_heap` |
| 최대 Payload | `PHASE5_PAYLOAD_MAX_BYTES`, 기본 128 bytes |
| MQTT Buffer | `PHASE5_MQTT_BUFFER_BYTES`, 기본 256 bytes |

합성 `temp`·`hum`·`bat` 값은 사용하지 않는다. MQTT Topic과 Payload의 `device_id`는 항상 같아야 한다.

ESP32 Core 3.3.8의 실제 필드 형식에서 필수 Payload의 최악 길이는 65 bytes,
`rssi` 추가 시 77 bytes, `rssi`·`free_heap` 추가 시 100 bytes다. Compile Gate는
Profile 0·1에 최소 65 bytes, Profile 2·3에 최소 100 bytes를 요구한다.
PubSubClient 2.8의 Buffer에는 최대 Header 5 bytes, Topic Length 2 bytes,
현재 Topic 19 bytes와 설정한 Payload 한도가 모두 들어가야 한다. 기본값에서는
154 bytes가 필요하므로 256 bytes Buffer가 충분하다. Buffer는 `uint16_t` 범위에
있어야 하며, 할당 실패 시 연결·송신을 중지한다. 송신 직전 실제 Topic·Payload와
실제 Buffer 크기도 대조한다. [PubSubClient 2.8 공식 코드](https://github.com/knolleary/pubsubclient/blob/v2.8/src/PubSubClient.cpp#L420-L440).

기존 `phase5-normal-pilot-v1`로 수집한 증적과 공식 Import 계약은 기존 버전을
유지한다. 새 버전의 예비수집을 기존 버전의 공식 수집으로 표시하지 않는다.

## 3. Profile 계약

| Profile | 이름 | Publish 주기 | Payload |
| --- | --- | --- | --- |
| `0` | `normal_stable` | 5초 고정 | 필수 필드 |
| `1` | `normal_interval_jitter` | 4~6초 | Profile 0과 동일 |
| `2` | `normal_payload_variation` | 5초 고정 | 필수 필드와 실제 선택 필드 순환 |
| `3` | `normal_combined_variation` | 4~6초 | Profile 2와 동일 |

Profile 3은 Profile 1·2의 Pilot 결과가 각각 승인되기 전에는 공식 정상 수집에 사용하지 않는다.

표의 간격은 기본값이다. `PHASE5_FIXED_PUBLISH_INTERVAL_MS`와
`PHASE5_JITTER_MIN_MS`·`PHASE5_JITTER_MAX_MS`로 설정하며 실제 값을 Boot Log에
기록한다. 고정 간격은 양의 `uint32_t`, Jitter는 양수·최솟값 ≤ 최댓값이며
최댓값은 `random(long)`의 배타적 상한을 위해 2,147,483,647보다 작아야 한다.

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
#define PHASE5_PAYLOAD_MAX_BYTES 128
#define PHASE5_MQTT_BUFFER_BYTES 256
#define PHASE5_FIXED_PUBLISH_INTERVAL_MS 5000UL
#define PHASE5_JITTER_MIN_MS 4000UL
#define PHASE5_JITTER_MAX_MS 6000UL
#define PHASE5_WIFI_SSID "LOCAL_WIFI_SSID"
#define PHASE5_WIFI_PASSWORD "LOCAL_WIFI_PASSWORD"
#define PHASE5_MQTT_BROKER "192.168.0.20"
#define PHASE5_MQTT_PORT 1883
```

- ESP32 #1은 `PHASE5_DEVICE_SLOT 1`을 사용하며 `esp32_01`로 파생된다.
- ESP32 #2는 `PHASE5_DEVICE_SLOT 2`를 사용하며 `esp32_02`로 파생된다.
- Wi-Fi Password는 문서·커밋·스크린샷·Serial Log에 남기지 않는다.
- 기존 로컬 Header에 새 한도·간격 설정이 없으면 위 기본값을 사용한다.

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
firmware_version=phase9-normal-pilot-v2
payload_schema_version=phase5-normal-payload-v1
firmware_limits_version=phase9-normal-limits-v1
payload_max_bytes=128
canonical_payload_max_bytes=65 또는 100
mqtt_buffer_bytes_configured=256
fixed_publish_interval_ms=5000
jitter_min_ms=4000
jitter_max_ms=6000
device_id=esp32_01 또는 esp32_02
device_slot=1 또는 2
normal_profile=0..3
profile_name=<선택한 Profile 이름>
mqtt_topic=iot/<device_id>/sensor
mqtt_client_id=p5-<device_id>-v1
mqtt_broker=<설정한 Broker>:1883
mqtt_buffer_bytes_actual=256
```

다음도 확인한다.

- `wifi_connected ip=`의 실제 IP가 DB 등록 IP와 일치한다.
- `mqtt_connected`가 출력된다.
- `mqtt_publish_succeeded`의 Sequence가 단조 증가한다.
- `payload_size`가 Boot Log의 `payload_max_bytes` 이하이다.
- `mqtt_buffer_bytes_actual`이 설정값과 같으며 `mqtt_buffer_allocation_failed`가 없다.
- Password가 Serial에 출력되지 않는다.
- Profile 3은 `profile_3_requires_profile_1_and_2_pilot_approval` 경고를 출력한다.

다음 오류가 반복되면 Pilot을 시작하지 않는다.

- `wifi_connect_timeout`
- `mqtt_connect_failed`
- `payload_rejected reason=over_configured_limit`
- `payload_rejected reason=mqtt_packet_budget`
- `mqtt_buffer_allocation_failed`
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

운영 DB를 수정하지 않고 최근 수신만 조회한다. 저장소의 운영 설정 키는
`DATABASE_URL`이며, `DATABASE_PATH`는 정의되어 있지 않다. 먼저 실제 Pi의
`.env`에 기록된 SQLite URL과 파일 경로를 대조하고, 그 파일을 `DB_PATH`로
명시한다. 아래 경로는 저장소 기본값을 `/home/pi/iot-edge-zero-trust`에서
해석한 예시이므로 `.env`의 값이 다르면 그대로 사용하지 않는다.

```bash
cd /home/pi/iot-edge-zero-trust
grep -E '^DATABASE_URL=' .env

DB_PATH=/home/pi/iot-edge-zero-trust/backend/data/iot_security.db
test -f "$DB_PATH" || {
  echo "운영 DB 파일을 찾지 못했습니다: $DB_PATH" >&2
  exit 1
}

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT id, device_id, topic, payload_size, received_at,
       is_json_valid, is_topic_valid, error_message
FROM mqtt_logs
WHERE device_id IN ('esp32_01', 'esp32_02')
ORDER BY id DESC
LIMIT 20;"
```

`test -f`와 `sqlite3 -readonly`를 생략하지 않는다. 잘못된 경로에 빈 SQLite
DB가 생성되는 것을 막고, Smoke 중 운영 DB를 실수로 변경하지 않기 위한 Gate다.

`devices.last_seen_at`, 기기별 최신 MQTT Feature Window, MQTT Feature Builder의
전역 Checkpoint를 각각 확인한다.

```bash
sqlite3 -readonly -header -column "$DB_PATH" "
SELECT d.device_id,
       d.last_seen_at,
       (
         SELECT m.received_at
         FROM mqtt_logs AS m
         WHERE m.device_id = d.device_id
         ORDER BY m.id DESC
         LIMIT 1
       ) AS latest_mqtt_received_at
FROM devices AS d
WHERE d.device_id IN ('esp32_01', 'esp32_02')
ORDER BY d.device_id;"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT id, device_id, window_start, window_end, publish_count,
       avg_payload_size, avg_message_interval
FROM feature_logs
WHERE id IN (
  SELECT MAX(id)
  FROM feature_logs
  WHERE device_id IN ('esp32_01', 'esp32_02')
  GROUP BY device_id
)
ORDER BY device_id;"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT detector_name, source_table, last_processed_id,
       last_completed_window_end, updated_at
FROM detector_checkpoints
WHERE detector_name = 'mqtt_feature_builder'
  AND source_table = 'mqtt_logs';"
```

Checkpoint는 기기별 Row가 아니라 `mqtt_logs` Source 전체에 대한 Producer
Watermark다. Smoke 전·후 값을 기록하고, 기기별 `feature_logs`의 최신 Window와
함께 전진했는지 확인한다.

통과 조건:

- Topic·Payload Device ID가 물리 매핑과 일치한다.
- `is_json_valid=1`, `is_topic_valid=1`, `error_message IS NULL`이다.
- 신규 `received_at`은 UTC `Z` 형식이다.
- `devices.last_seen_at`이 같은 수신 시각으로 전진한다.
- MQTT Feature Builder Checkpoint와 `feature_logs` Window가 계속 전진한다.

## 9. Capture Session·Profile 실행 경계

Packet Capture Runtime은 서비스 시작 시 UUIDv4 `session_id`를 하나 생성하고,
정상 중지 또는 실패 전까지 같은 Session을 사용한다. 따라서 Capture가 실행 중인
상태에서 Firmware, Profile 또는 수집 Device 구성을 바꾸지 않는다.

Pilot 또는 공식 수집은 다음 순서로 수행한다.

1. 수집 전에 Run ID, Train·Validation·Test Split, Profile, 포함 Device 목록을
   실행 기록에 사전 배정한다.
2. 기존 Capture Session이 실행 중이면 `packet-capture.service`를 정상 중지하고
   이전 Session이 `COMPLETED`로 마감됐는지 확인한다.
3. Firmware를 Upload하고 Serial·MQTT·DB Smoke가 안정적으로 통과할 때까지
   Packet Capture를 시작하지 않는다.
4. Profile과 Device 구성을 확정한 뒤 Capture Service를 시작하고 Runtime이 새로
   생성한 `session_id`를 확인한다.
5. 확인한 `session_id`를 사전 배정한 Run·Split 실행 기록에 연결한다. PR #45의
   공통 Manifest 계약이 확정된 뒤에는 같은 연결을 공식 Manifest에 기록한다.
6. 한 Capture Session 안에서는 Firmware Commit, Profile, Device Slot과 포함
   Device 목록을 변경하지 않는다.
7. 수집을 마치면 Service를 정상 중지하고 Session 상태와 Window 연속성을 확인한다.

```bash
sudo systemctl stop packet-capture.service
systemctl is-active packet-capture.service
sqlite3 -readonly -header -column "$DB_PATH" "
SELECT session_id, status, ended_at
FROM packet_capture_sessions
ORDER BY id DESC
LIMIT 1;"

# Firmware Upload와 Serial·MQTT·DB Smoke 완료 후 실행한다.
sudo systemctl start packet-capture.service
systemctl is-active packet-capture.service
journalctl --utc -u packet-capture.service -n 50 --no-pager

SESSION_ID="$(sqlite3 -readonly "$DB_PATH" \
  "SELECT session_id FROM packet_capture_sessions ORDER BY id DESC LIMIT 1;")"
test -n "$SESSION_ID"
printf 'capture_session_id=%s\n' "$SESSION_ID"
```

- 두 ESP32를 함께 수집하면 두 장비를 같은 Profile로 운영하고 두 Device ID를
  실행 기록에 명시한다.
- 기기별로 수집하면 다른 Sender를 중지한 상태에서 Device마다 별도 Capture
  Session을 시작한다.
- Profile을 전환하려면 현재 Capture Service를 정상 중지하고 기존 Session이
  `COMPLETED`인지 확인한 뒤, 새 Profile Smoke와 새 Session 시작 절차를 반복한다.

수집 종료 후 다음 조회로 Session과 Window 상태를 확인한다.
기존 운영 방식에 따라 Packet Feature Extractor가 남은 `READY` Segment를 모두
`PROCESSED` 또는 `EMPTY`로 마감한 뒤 최종 Gate를 판정한다. Extractor 실행 방식이
확정되지 않았거나 `READY`가 남아 있으면 완료로 기록하지 않고 `HOLD`로 둔다.

```bash
sudo systemctl stop packet-capture.service

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT session_id, status, started_at, first_window_start, ended_at,
       capture_gap_start, capture_gap_end
FROM packet_capture_sessions
WHERE session_id = '$SESSION_ID';"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT COUNT(*) AS total_windows,
       CAST((unixepoch(MAX(window_end)) - unixepoch(MIN(window_start))) / 10
            AS INTEGER) AS expected_contiguous_windows,
       SUM(CASE WHEN status IN ('PROCESSED', 'EMPTY') THEN 1 ELSE 0 END)
         AS processed_or_empty_windows,
       SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed_windows,
       MIN(window_start) AS first_segment_start,
       MAX(window_end) AS last_segment_end
FROM packet_capture_segments
WHERE capture_session_id = (
  SELECT id FROM packet_capture_sessions WHERE session_id = '$SESSION_ID'
);"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT device_id, COUNT(*) AS feature_windows,
       MIN(window_start) AS first_feature_window,
       MAX(window_end) AS last_feature_window
FROM feature_logs
WHERE device_id IN ('esp32_01', 'esp32_02')
  AND unixepoch(window_start) >= unixepoch((
    SELECT first_window_start
    FROM packet_capture_sessions
    WHERE session_id = '$SESSION_ID'
  ))
  AND unixepoch(window_end) <= unixepoch((
    SELECT ended_at
    FROM packet_capture_sessions
    WHERE session_id = '$SESSION_ID'
  ))
GROUP BY device_id
ORDER BY device_id;"
```

통과 조건은 Session `COMPLETED`, `total_windows=expected_contiguous_windows`,
모든 Segment가 `PROCESSED` 또는 `EMPTY`, `failed_windows=0`, 적격성 검사를
통과한 Profile·Device별 유효 Feature Window 60개 이상이다. 단순
`feature_windows` 개수만으로 적격을 확정하지 않는다.

정상 중지·Profile 전환처럼 Capture가 멈춘 구간은 새 Session의
`capture_gap_start`·`capture_gap_end`에 첫 Window 이전 감사 정보로 기록될 수
있다. 이 값을 임의로 NULL로 바꾸거나 삭제하지 않는다. 첫 Window 이후 수집 구간
내부에 누락·FAILED Window가 없어야 하며, 정책이 해당 사전 Gap까지 허용하지 않으면
그 Session은 `HOLD`로 기록하고 공식 Dataset에서 제외한다.

## 10. Profile별 Pilot 전 확인

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

각 Profile Pilot은 9절의 실행 경계에 따라 기기·Profile별 독립 Session ID를
사용하고, 단순 경과 시간이 아니라 적격성 검사를 통과한 유효 Window 60개를
목표로 한다.

## 11. 실행 기록

각 Compile·Upload·Smoke 기록에 다음을 남긴다.

- Git Commit SHA
- Firmware Version
- Firmware Limits Version·설정 Payload 한도·설정/실제 MQTT Buffer·실제 고정/Jitter 간격
- Payload Schema Version
- Device Slot·Device ID·COM Port·실제 IP
- Profile 번호·이름
- Run ID·Split·Capture Session ID·포함 Device 목록
- Verify·Upload 결과
- Serial 부팅 계약
- MQTT Topic·대표 Payload
- MQTT·Feature Checkpoint 전진 여부
- 실행 시각과 실행자

PR #45의 Run·Session Manifest 계약이 확정되면 같은 항목을 공통 Manifest에 연결한다. 계약 확정 전 임의의 공식 Manifest Schema를 만들지 않는다.

## 12. 중단과 복구

- Device 매핑 오류: 즉시 전송을 중단하고 올바른 Device Slot으로 다시 Verify·Upload한다.
- MQTT·Feature 오류: 원본 로그를 보존하고 `HOLD`로 기록한다.
- Payload 계약 오류: 해당 Firmware Commit과 Profile의 Pilot을 무효 처리한다.
- 정상 Firmware 복구가 필요하면 마지막으로 검증된 Firmware Commit과 Device Slot을 사용해 다시 Upload한다.
- 운영 DB, Trust Score, Device Status, Firewall Rule을 임의 SQL로 수정하지 않는다.

## 13. 공식 수집 Gate

다음이 모두 완료된 뒤에만 공식 정상 Session 수집을 시작한다.

- 정책 v1.0 Pilot Profile 판정 완료
- 정책 v1.1의 승인 Profile·Split·Version 동결
- Firmware Commit과 Payload Schema Version 동결
- PR #45의 Run·Session Manifest 계약 확정
- ESP32 두 대의 물리 Device·Device ID·실제 IP 매핑 확인
- Raspberry Pi Cold Boot·NTP·Subscriber·Feature·Packet Capture Smoke 통과
