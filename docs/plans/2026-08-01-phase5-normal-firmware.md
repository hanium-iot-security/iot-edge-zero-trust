# Phase 5 Normal Firmware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Notion 정책 v1.0의 `NORMAL_PROFILE=0..3`, Canonical Payload, 실제 ESP32 측정값과 안전한 장치 설정 계약을 만족하는 독립 Phase 5 정상 수집 Firmware를 구현한다.

**Architecture:** 기존 MVP Sketch는 수정하지 않고 `phase5_normal_collector`를 새로 추가한다. 추적되지 않는 로컬 Header가 Wi-Fi·Broker·Device Slot·Profile을 소유하고, Sketch는 Topic·Client ID·Payload·Publish 주기를 해당 설정에서 결정한다. Python 계약 테스트로 RED→GREEN을 진행한 뒤 Arduino CLI로 두 Device Slot과 대표 Profile Compile Matrix를 검증한다.

**Tech Stack:** Arduino ESP32 Core 3.3.8, PubSubClient 2.8, C++ Arduino Sketch, Python 3/Pytest, Arduino CLI

## Global Constraints

- 기존 `firmware/esp32/normal_sender/`와 `attack_sender/`는 수정하지 않는다.
- 필수 Payload 필드는 정확히 `device_id`, `sequence`, `uptime_s`이다.
- 선택 필드는 실제 `WiFi.RSSI()`와 `ESP.getFreeHeap()` 값만 사용한다.
- 합성 `temp`, `hum`, `bat` 값은 추가하지 않는다.
- Topic은 `iot/{device_id}/sensor`, MQTT Client ID는 Device별로 고유해야 한다.
- Profile 0·2는 5초 고정, Profile 1·3은 4~6초 범위다.
- Payload는 100 bytes를 초과하면 Publish하지 않는다.
- 실제 Wi-Fi Password와 운영 설정은 Git에 추가하지 않는다.
- DB·Backend·Frontend·탐지 Threshold·Raspberry Pi 설정은 변경하지 않는다.
- 실제 ESP32 Upload와 Pilot 수집은 이 로컬 구현 범위에서 수행하지 않는다.

---

### Task 1: 신규 Firmware 설정·식별 계약

**Files:**
- Create: `tests/test_phase5_normal_collector_firmware.py`
- Create: `firmware/esp32/phase5_normal_collector/phase5_firmware_config.example.h`
- Create: `firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: 운영자가 예시 Header를 복사해 만든 `phase5_firmware_config.h`
- Produces: `PHASE5_DEVICE_SLOT`, `PHASE5_NORMAL_PROFILE`, `DEVICE_ID`, `MQTT_TOPIC`, `MQTT_CLIENT_ID`, Firmware·Payload Schema Version

- [ ] **Step 1: 신규 Sketch와 설정 경계를 요구하는 실패 테스트 작성**

```python
from pathlib import Path

FIRMWARE_DIR = Path("firmware/esp32/phase5_normal_collector")
SKETCH = FIRMWARE_DIR / "phase5_normal_collector.ino"
EXAMPLE_CONFIG = FIRMWARE_DIR / "phase5_firmware_config.example.h"


def test_phase5_firmware_has_local_config_gate_and_supported_device_slots() -> None:
    source = SKETCH.read_text(encoding="utf-8")
    config = EXAMPLE_CONFIG.read_text(encoding="utf-8")

    assert '#include "phase5_firmware_config.h"' in source
    assert "#if PHASE5_CONFIGURED != 1" in source
    assert "#if PHASE5_DEVICE_SLOT == 1" in source
    assert "#elif PHASE5_DEVICE_SLOT == 2" in source
    assert 'const char* DEVICE_ID = "esp32_01";' in source
    assert 'const char* DEVICE_ID = "esp32_02";' in source
    assert "#define PHASE5_CONFIGURED 0" in config
```

- [ ] **Step 2: RED 확인**

Run:

```powershell
C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_phase5_normal_collector_firmware.py -q
```

Expected: `FileNotFoundError` because the new Sketch does not exist.

- [ ] **Step 3: 최소 설정 예시와 Sketch 설정 Gate 구현**

`phase5_firmware_config.example.h`:

```cpp
#pragma once

#define PHASE5_CONFIGURED 0
#define PHASE5_DEVICE_SLOT 1
#define PHASE5_NORMAL_PROFILE 0
#define PHASE5_WIFI_SSID "REPLACE_WITH_WIFI_SSID"
#define PHASE5_WIFI_PASSWORD "REPLACE_WITH_WIFI_PASSWORD"
#define PHASE5_MQTT_BROKER "192.168.0.20"
#define PHASE5_MQTT_PORT 1883
```

Sketch는 로컬 Header 존재 여부, `PHASE5_CONFIGURED`, Device Slot `1|2`, Profile `0..3`을 전처리기로 거부한다. Device Slot에서 `esp32_01` 또는 `esp32_02`를 파생하고 Topic·Client ID를 `String`으로 생성한다.

- [ ] **Step 4: 로컬 설정 파일 Ignore 추가**

`.gitignore`에 다음 정확한 경로를 추가한다.

```gitignore
firmware/esp32/phase5_normal_collector/phase5_firmware_config.h
```

- [ ] **Step 5: 관련 테스트 GREEN 확인**

Run:

```powershell
C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_phase5_normal_collector_firmware.py -q
```

Expected: setting/identity tests pass; later behavior tests are not added yet.

- [ ] **Step 6: 커밋**

```powershell
git add .gitignore firmware/esp32/phase5_normal_collector tests/test_phase5_normal_collector_firmware.py
git commit -m "feat: Phase 5 정상 Firmware 설정 계약 추가"
```

---

### Task 2: Canonical Payload와 Profile 동작

**Files:**
- Modify: `tests/test_phase5_normal_collector_firmware.py`
- Modify: `firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino`

**Interfaces:**
- Consumes: `PHASE5_NORMAL_PROFILE`, 성공 예정 Sequence, `millis()`, `WiFi.RSSI()`, `ESP.getFreeHeap()`
- Produces: `String buildCanonicalPayload(unsigned long sequence)`와 `unsigned long chooseNextPublishIntervalMs()`

- [ ] **Step 1: Profile·Payload 실패 테스트 추가**

테스트는 다음 Source 계약을 독립 Literal로 검증한다.

```python
def test_all_profiles_keep_required_canonical_fields_without_synthetic_sensors() -> None:
    source = SKETCH.read_text(encoding="utf-8")
    for field in ('device_id', 'sequence', 'uptime_s'):
        assert f'\\"{field}\\"' in source
    for forbidden in ('temp', 'hum', 'bat'):
        assert f'\\"{forbidden}\\"' not in source
    assert "WiFi.RSSI()" in source
    assert "ESP.getFreeHeap()" in source


def test_profiles_isolate_interval_and_payload_variation() -> None:
    source = SKETCH.read_text(encoding="utf-8")
    assert "PHASE5_NORMAL_PROFILE == 0 || PHASE5_NORMAL_PROFILE == 2" in source
    assert "random(4000, 6001)" in source
    assert "PHASE5_NORMAL_PROFILE == 2 || PHASE5_NORMAL_PROFILE == 3" in source
    assert "sequence % 3" in source
```

- [ ] **Step 2: RED 확인**

Run the two test names with `pytest -q`; expect missing Payload/Profile symbols.

- [ ] **Step 3: 최소 Profile·Payload 구현**

- Profile 0·1은 필수 필드만 생성한다.
- Profile 2·3은 `sequence % 3`에 따라 필수-only, `+rssi`, `+rssi+free_heap`을 순환한다.
- `uptime_s`는 `millis() / 1000UL`을 사용한다.
- Profile 0·2는 `5000UL`, Profile 1·3은 `random(4000, 6001)`을 사용한다.
- Payload 구성에서 실제 측정값 외 난수를 사용하지 않는다.

- [ ] **Step 4: Payload·Profile 테스트 GREEN 확인**

Run the full new firmware test file and expect all tests to pass.

- [ ] **Step 5: 커밋**

```powershell
git add firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino tests/test_phase5_normal_collector_firmware.py
git commit -m "feat: Phase 5 정상 Profile Payload 구현"
```

---

### Task 3: 비차단 연결·안전 Publish·부팅 로그

**Files:**
- Modify: `tests/test_phase5_normal_collector_firmware.py`
- Modify: `firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino`

**Interfaces:**
- Consumes: Profile Payload와 간격 함수, PubSubClient, WiFi 상태
- Produces: `connectWifiWithTimeout()`, `connectMqttOnce()`, `publishNormalTelemetry()`, `printBootContract()`

- [ ] **Step 1: 실패·안전 동작 테스트 추가**

```python
def test_publish_rejects_oversize_and_commits_sequence_only_after_success() -> None:
    source = SKETCH.read_text(encoding="utf-8")
    publish_body = source[source.index("bool publishNormalTelemetry()") : source.index("void setup()")]
    assert "MAX_PAYLOAD_BYTES = 100" in source
    assert "payload.length() > MAX_PAYLOAD_BYTES" in publish_body
    assert "return false;" in publish_body
    assert publish_body.index("mqttClient.publish") < publish_body.index("sequenceNumber = nextSequence")


def test_reconnect_path_is_bounded_and_boot_log_identifies_run_contract() -> None:
    source = SKETCH.read_text(encoding="utf-8")
    assert "WIFI_CONNECT_TIMEOUT_MS" in source
    assert "MQTT_RETRY_INTERVAL_MS" in source
    assert "while (true)" not in source
    assert "ESP.restart()" not in source
    for label in (
        "firmware_version=",
        "payload_schema_version=",
        "device_id=",
        "normal_profile=",
        "mqtt_topic=",
        "mqtt_client_id=",
    ):
        assert label in source
```

- [ ] **Step 2: RED 확인**

Run the two new tests; expect missing publish/reconnect/log contracts.

- [ ] **Step 3: 최소 연결·Publish 구현**

- Wi-Fi 연결 함수는 한 번의 15초 제한 시도 후 `false`를 반환한다.
- MQTT 연결 함수는 한 번 연결을 시도하고 실패 상태를 출력한다.
- `loop()`는 Retry 시각을 기준으로 재시도하며 무한 Blocking Loop를 사용하지 않는다.
- Payload 상한 초과와 Publish 실패에서는 Sequence를 유지한다.
- Publish 성공 후에만 `sequenceNumber = nextSequence`와 다음 간격을 확정한다.
- Profile 3 부팅 시 Pilot 승인 전 공식 수집 금지 경고를 출력한다.

- [ ] **Step 4: 전체 신규 Firmware 테스트 GREEN 확인**

Run the full new test file and expect all tests to pass.

- [ ] **Step 5: 커밋**

```powershell
git add firmware/esp32/phase5_normal_collector/phase5_normal_collector.ino tests/test_phase5_normal_collector_firmware.py
git commit -m "feat: Phase 5 정상 Firmware 안전 실행 흐름 추가"
```

---

### Task 4: Arduino IDE·실기기 검증 Runbook

**Files:**
- Create: `docs/phase5-normal-firmware-runbook.md`
- Modify: `firmware/esp32/README.md`

**Interfaces:**
- Consumes: 신규 Sketch와 로컬 Config 계약
- Produces: 두 ESP32의 Compile·Upload·Serial·MQTT Smoke 및 Profile별 Pilot 전 Gate

- [ ] **Step 1: Runbook 내용 작성**

다음 순서와 판정값을 명시한다.

1. 예시 Config를 실제 로컬 Config로 복사하고 `PHASE5_CONFIGURED=1` 설정
2. ESP32 #1은 Device Slot 1, ESP32 #2는 Device Slot 2 사용
3. COM Port·물리 라벨·Device Slot·예상 Device ID·DB 등록 IP 대조
4. Arduino IDE Board `ESP32 Dev Module`, Serial `115200`, PubSubClient 설치 확인
5. 각 Device Compile 후 Upload
6. Serial 부팅 계약과 실제 DHCP IP 확인
7. `mosquitto_sub -h localhost -p 1883 -t 'iot/+/sensor' -v`로 Topic·Payload 확인
8. Profile 0·1의 Payload 동일성과 간격 차이 확인
9. Profile 2의 실제 선택 필드 순환 확인
10. Profile 3은 Profile 1·2 승인 전 공식 정상 수집 금지
11. 실행한 Firmware Commit·Payload Schema Version·Profile을 Session Manifest에 기록

- [ ] **Step 2: Firmware README에 신규 경로와 Runbook 링크 추가**

기존 MVP 설명은 삭제하지 않고 Phase 5 공식 후보 Firmware가 별도 경로임을 명시한다.

- [ ] **Step 3: 문서 검사**

Run `git diff --check` and manually verify no credential or operational result is recorded.

- [ ] **Step 4: 커밋**

```powershell
git add docs/phase5-normal-firmware-runbook.md firmware/esp32/README.md
git commit -m "docs: Phase 5 정상 Firmware 실행 절차 추가"
```

---

### Task 5: Arduino Compile Matrix와 회귀 검증

**Files:**
- Modify only if a failing test proves a defect in files from Tasks 1–4.

**Interfaces:**
- Consumes: 완성된 Sketch와 Example Config
- Produces: Device Slot 1·2와 Profile 고정·변동 대표 Compile 증거

- [ ] **Step 1: 임시 Sketch 복사본 준비**

PowerShell의 임시 디렉터리에 Sketch와 Example Config를 복사한다. Example Config의 `PHASE5_CONFIGURED`를 `1`로 바꾸고 실제 비밀정보 대신 Compile 전용 Placeholder를 유지한다. 저장소의 Ignore된 실제 Config는 생성하거나 덮어쓰지 않는다.

- [ ] **Step 2: Compile Matrix 실행**

Arduino CLI:

```powershell
& 'C:\Users\woomin\AppData\Local\Programs\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe' compile --fqbn esp32:esp32:esp32 <temporary-sketch-directory>
```

다음 조합을 각각 컴파일한다.

- Device Slot 1, Profile 0
- Device Slot 1, Profile 3
- Device Slot 2, Profile 0
- Device Slot 2, Profile 3

Expected: four compiles exit 0.

- [ ] **Step 3: 관련·회귀 테스트 실행**

```powershell
C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_phase5_normal_collector_firmware.py tests/test_esp32_attack_sender_firmware.py -q
C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest -q --ignore=tests/test_firewall_rule_wrapper.py
C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m compileall -q backend edge tests
git diff --check origin/develop...HEAD
git status --short --branch
```

Expected: 신규·기존 Firmware 테스트 모두 통과, 비-Wrapper 전체 회귀 신규 실패 없음, Compileall과 Diff Check exit 0.

- [ ] **Step 4: 영향 검토**

`git diff --name-only origin/develop...HEAD`가 Firmware 신규 폴더, 신규 테스트, Runbook, README, `.gitignore`, 설계·계획 문서만 포함하는지 확인한다. MQTT Subscriber·Feature·Rule·DB·Backend·Frontend 파일이 변경되지 않았는지 확인한다.

- [ ] **Step 5: 최종 상태 보고**

커밋 목록, RED 증거, GREEN 결과, Arduino Compile Matrix, 전체 회귀, 변경하지 않은 영역, 실기기 Upload 전 Gate를 보고한다. Push·PR·실기기 Upload는 별도 사용자 지시 전 수행하지 않는다.
