# Phase 4 ESP32 #2 제한형 MQTT Flood Test Mode Implementation Plan

> **상태:** 코드·자동 계약 테스트·Runbook 구현 완료 / Arduino 컴파일·ESP32 #2 업로드·실기기 E2E는 미검증
>
> 아래 체크박스는 구현 전 TDD 실행 순서를 보존한 계획 기록이며, 실제 검증 결과는
> 테스트 출력과 `docs/phase4-esp32-attack-test-runbook.md`의 실기기 기록을 기준으로 한다.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 실제 `esp32_02` Source IP로 제한된 MQTT Flood를 재현하고 정상 펌웨어로 안전하게 복구할 수 있는 ESP32 Sketch와 실기기 Runbook을 제공한다.

**Architecture:** 정상 송신기와 별도의 `attack_sender` Sketch를 추가하고, 상수 기반 안전 계약을 Python 테스트에서 정적으로 검증한다. 공격 Sketch는 사설 Broker·명시적 활성화·부팅당 1회·4개 Burst·45초 공격 상한과 별도 45초 차단 관측 상한을 강제하며, Runbook은 DB IP 확인부터 공격·격리·정상 복구까지 기록 가능한 절차를 제공한다.

**Tech Stack:** Arduino ESP32, WiFi, PubSubClient, pytest, Markdown

## Global Constraints

- 실제 Source IP는 DB에 등록된 `esp32_02`의 `devices.ip_address`와 일치해야 한다.
- MQTT Broker는 `192.168.0.20:1883`, Topic은 `iot/esp32_02/sensor`이다.
- 40건 Burst를 10초 간격으로 최대 4회 수행하며 공격 전송은 45초를 넘기지 않는다.
- 공격 후 Canonical Payload Probe는 5초 간격·최대 9건·45초로 제한하고 신규 MQTT 연결은 1회만 시도한다.
- 공격 기능은 기본 비활성화하고 RFC1918 사설 IPv4 Broker에서만 실행한다.
- 공격은 부팅당 한 번만 실행하고 종료 후 자동 반복하지 않는다.
- 정상 데이터 공식 수집과 Trust·Firewall 정책 변경은 범위에 포함하지 않는다.

---

## File Structure

- Create `firmware/esp32/attack_sender/attack_sender.ino`: 제한형 공격 송신 상태 머신과 안전장치
- Create `tests/test_esp32_attack_sender_firmware.py`: Sketch·Runbook의 안전 계약 회귀 테스트
- Create `docs/phase4-esp32-attack-test-runbook.md`: 실기기 준비·실행·증적·복구 절차
- Modify `firmware/esp32/README.md`: 공격 Sender 사용 범위와 Runbook 연결

### Task 1: 공격 Sketch 안전 계약

**Files:**
- Create: `tests/test_esp32_attack_sender_firmware.py`
- Create: `firmware/esp32/attack_sender/attack_sender.ino`

**Interfaces:**
- Consumes: ESP32 `WiFi`, `PubSubClient`, `millis()`
- Produces: `setup()`, `loop()`, `isPrivateBrokerAddress()`, `connectWiFiWithTimeout()`, `connectMqttWithTimeout()`, `runBoundedFloodTest()`

- [ ] **Step 1: 기본 비활성화·고정 식별자·상한을 요구하는 실패 테스트 작성**

```python
from pathlib import Path


FIRMWARE = Path("firmware/esp32/attack_sender/attack_sender.ino")


def _source() -> str:
    return FIRMWARE.read_text(encoding="utf-8")


def test_attack_sender_is_disabled_by_default_and_targets_registered_test_device() -> None:
    source = _source()
    assert 'const bool ATTACK_TEST_ENABLED = false;' in source
    assert 'const char* DEVICE_ID = "esp32_02";' in source
    assert 'const char* MQTT_BROKER = "192.168.0.20";' in source
    assert 'const int MQTT_PORT = 1883;' in source
    assert 'const char* MQTT_TOPIC = "iot/esp32_02/sensor";' in source


def test_attack_sender_has_bounded_four_window_contract() -> None:
    source = _source()
    assert "const unsigned int MESSAGES_PER_BURST = 40;" in source
    assert "const unsigned int MAX_BURSTS = 4;" in source
    assert "const unsigned long PUBLISH_INTERVAL_MS = 50;" in source
    assert "const unsigned long BURST_START_INTERVAL_MS = 10000;" in source
    assert "const unsigned long MAX_TEST_DURATION_MS = 45000;" in source
```

- [ ] **Step 2: 테스트가 파일 부재로 실패하는지 확인**

Run: `python -m pytest tests/test_esp32_attack_sender_firmware.py -q`

Expected: FAIL because `firmware/esp32/attack_sender/attack_sender.ino` does not exist.

- [ ] **Step 3: 최소 상수와 안전 검사 테스트 추가**

```python
def test_attack_sender_rejects_public_broker_and_runs_once_per_boot() -> None:
    source = _source()
    assert "bool isPrivateBrokerAddress()" in source
    assert "isPrivateBrokerAddress()" in source
    assert "bool testExecuted = false;" in source
    assert "testExecuted = true;" in source
    assert "if (testExecuted)" in source


def test_attack_sender_has_bounded_connection_attempts_and_no_restart_loop() -> None:
    source = _source()
    assert "const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;" in source
    assert "const unsigned long MQTT_CONNECT_TIMEOUT_MS = 10000;" in source
    assert "while (true)" not in source
    assert "ESP.restart()" not in source
```

- [ ] **Step 4: Sketch 최소 구현**

`attack_sender.ino`에 다음 계약을 구현한다.

```cpp
const bool ATTACK_TEST_ENABLED = false;
const char* MQTT_BROKER = "192.168.0.20";
const int MQTT_PORT = 1883;
const char* DEVICE_ID = "esp32_02";
const char* MQTT_TOPIC = "iot/esp32_02/sensor";

const unsigned int MESSAGES_PER_BURST = 40;
const unsigned int MAX_BURSTS = 4;
const unsigned long PUBLISH_INTERVAL_MS = 50;
const unsigned long BURST_START_INTERVAL_MS = 10000;
const unsigned long MAX_TEST_DURATION_MS = 45000;
const unsigned long OBSERVATION_TIMEOUT_MS = 45000;
const unsigned long OBSERVATION_PROBE_INTERVAL_MS = 5000;
const unsigned int MAX_OBSERVATION_PROBES = 9;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
const unsigned long MQTT_CONNECT_TIMEOUT_MS = 10000;
const unsigned int MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS = 3;
const unsigned int MQTT_CONNECT_MAX_ATTEMPTS = 2;

bool testExecuted = false;
```

`isPrivateBrokerAddress()`는 IPv4 네 옥텟을 파싱해 `10/8`, `172.16/12`, `192.168/16`만 허용한다. Wi-Fi와 MQTT 연결 함수는 각각 지정된 제한 시간까지만 재시도하고 `bool` 성공 여부를 반환한다.

- [ ] **Step 5: RED 테스트를 다시 실행해 남은 구현 누락을 확인**

Run: `python -m pytest tests/test_esp32_attack_sender_firmware.py -q`

Expected: FAIL on missing bounded execution markers until `runBoundedFloodTest()` is complete.

- [ ] **Step 6: 제한형 Burst 상태 머신 구현**

`runBoundedFloodTest()`는 다음 순서를 따른다.

```cpp
unsigned long testStartedAt = millis();
for (unsigned int burstIndex = 0; burstIndex < MAX_BURSTS; burstIndex++) {
  if (millis() - testStartedAt >= MAX_TEST_DURATION_MS) {
    break;
  }
  // MESSAGES_PER_BURST만큼 JSON Publish
  // 각 메시지 뒤 PUBLISH_INTERVAL_MS만큼 대기
  // 다음 Burst는 첫 Burst 시작 기준 10초 배수까지 bounded wait
}
runBoundedIsolationObservation();
```

Payload는 정상 Firmware 기본 모드와 같은 `device_id` 전용 Canonical Schema를
사용한다. Publish 순번, Burst 번호와 실행 추적 정보는 Serial 로그와 Run
Manifest에만 남긴다. 공격 종료 후 `runBoundedIsolationObservation()`은 기존
연결의 정상 간격 Probe를 관측하고 신규 MQTT 연결을 정확히 1회 시도한다.
`setup()`은 비활성·공인 IP·연결 실패 시 즉시 안전 종료하고, 성공 시
`testExecuted=true` 설정 후 한 번만 실행한다. `loop()`은 재연결이나 재실행 없이
짧은 `delay()`만 수행한다.

- [ ] **Step 7: 공격 Sketch 테스트 통과 확인**

Run: `python -m pytest tests/test_esp32_attack_sender_firmware.py -q`

Expected: PASS.

- [ ] **Step 8: Task 1 커밋**

```bash
git add tests/test_esp32_attack_sender_firmware.py firmware/esp32/attack_sender/attack_sender.ino
git commit -m "기능: ESP32 제한형 MQTT Flood 테스트 모드 추가"
```

### Task 2: 실기기 Runbook과 복구 계약

**Files:**
- Modify: `tests/test_esp32_attack_sender_firmware.py`
- Create: `docs/phase4-esp32-attack-test-runbook.md`
- Modify: `firmware/esp32/README.md`

**Interfaces:**
- Consumes: `attack_sender.ino`, `normal_sender.ino`, SQLite `devices`, systemd Phase 4 서비스
- Produces: 공격 전 점검·실행·증적·복구 절차와 결과 기록 양식

- [ ] **Step 1: Runbook 계약 실패 테스트 작성**

```python
RUNBOOK = Path("docs/phase4-esp32-attack-test-runbook.md")
README = Path("firmware/esp32/README.md")


def test_runbook_covers_registered_ip_services_and_private_test_scope() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "devices.ip_address" in text
    assert "esp32_02" in text
    assert "192.168.0.20" in text
    assert "사설 테스트 LAN" in text
    assert "packet-capture.service" in text
    assert "mqtt-feature-builder.service" in text
    assert "detection-orchestrator.service" in text
    assert "firewall-worker.service" in text


def test_runbook_covers_window_evidence_and_normal_recovery() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "analysis_window_start" in text
    assert "analysis_window_end" in text
    assert "4회 Burst가 정확히 4개 Window를 보장하지 않습니다" in text
    assert "ABNORMAL_PUBLISH_RATE" in text
    assert "PENDING" in text and "APPLIED" in text
    assert "normal_sender.ino" in text
    assert "정상 Publish 재개" in text
    assert "미검증" in text


def test_firmware_readme_links_attack_sender_and_runbook() -> None:
    text = README.read_text(encoding="utf-8")
    assert "attack_sender/attack_sender.ino" in text
    assert "docs/phase4-esp32-attack-test-runbook.md" in text
```

- [ ] **Step 2: 문서 부재로 테스트 실패 확인**

Run: `python -m pytest tests/test_esp32_attack_sender_firmware.py -q`

Expected: FAIL because the Runbook does not exist and README lacks the attack section.

- [ ] **Step 3: Runbook 작성**

Runbook에 다음 순서를 명령과 판정 기준까지 포함한다.

1. 정상 Sketch와 ESP32 설정 백업
2. `devices.ip_address`, `status=normal`, `trust_score=100` Baseline 확인
3. MQTT Subscriber 실행과 정상 Publish Pipeline Preflight 확인
4. Broker·API·Capture·Feature Builder·Orchestrator·Firewall Worker 상태 확인
5. Firewall에 기존 `esp32_02` 차단 Rule이 없는지 확인
6. `ATTACK_TEST_ENABLED=true` 변경 후 업로드
7. 실제 `analysis_window_start/end`별 Event·Trust History 확인
8. `firewall_rules`의 `PENDING → APPLIED`와 별도 관측 단계의 ESP32 Publish·신규 연결 실패 확인
9. 정상 Sketch 재업로드와 Firewall 해제 후 정상 Publish 재개 확인
10. Baseline Reset이 불가능하면 `HOLD`, 복구 실패면 `RESET_FAILED`로 기록
11. Commit SHA, Firmware SHA256, DB Row, Serial 로그, 실행·복구 시각 기록

미실행 또는 일부 성공은 성공으로 꾸미지 않고 `미검증`으로 기록하도록 명시한다.

- [ ] **Step 4: 펌웨어 README 연결**

`firmware/esp32/README.md`에 공격 Sender는 정상 데이터 수집용이 아니며 사설 E2E 전용이라는 설명, 기본 비활성, Runbook 링크를 추가한다.

- [ ] **Step 5: 문서 계약 테스트 통과 확인**

Run: `python -m pytest tests/test_esp32_attack_sender_firmware.py -q`

Expected: PASS.

- [ ] **Step 6: Task 2 커밋**

```bash
git add tests/test_esp32_attack_sender_firmware.py docs/phase4-esp32-attack-test-runbook.md firmware/esp32/README.md
git commit -m "문서: ESP32 공격 검증과 정상 복구 절차 추가"
```

### Task 3: 전체 검증과 설계 일치 확인

**Files:**
- Verify: `docs/phase4-esp32-attack-test-mode-design.md`
- Verify: `firmware/esp32/attack_sender/attack_sender.ino`
- Verify: `docs/phase4-esp32-attack-test-runbook.md`
- Verify: `tests/test_esp32_attack_sender_firmware.py`

**Interfaces:**
- Consumes: Task 1·2 결과
- Produces: 병합 전 검증 증거

- [ ] **Step 1: 관련 테스트 실행**

Run: `python -m pytest tests/test_esp32_attack_sender_firmware.py tests/test_detection_orchestrator_runner.py -q`

Expected: PASS.

- [ ] **Step 2: 전체 회귀 테스트 실행**

Run: `python -m pytest -q`

Expected: PASS with only documented platform skips.

- [ ] **Step 3: 정적·포맷 검사**

Run:

```bash
python -m compileall tests
git diff --check
git status --short
```

Expected: all commands exit 0; only intended firmware, test, Runbook, README, design and plan changes appear.

- [ ] **Step 4: 설계 계약 수동 대조**

다음 항목을 파일별로 확인한다.

- 실제 `esp32_02` 식별자와 고정 Topic
- 기본 비활성·사설 IP·연결 제한 시간
- 40건 × 4회·10초 간격·45초 상한·부팅당 1회
- Canonical Payload와 45초·9 Probe 관측 및 신규 연결 1회 상한
- Subscriber·Preflight·Baseline·Reset Gate
- 정상 펌웨어 백업·복구
- 실기기 미실행 결과를 `미검증`으로 유지

- [ ] **Step 5: 최종 구현 커밋**

```bash
git add firmware/esp32 docs tests
git commit -m "검증: ESP32 제한형 공격 모드 계약 보완"
```
