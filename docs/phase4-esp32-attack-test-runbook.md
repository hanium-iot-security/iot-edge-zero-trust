# Phase 4 ESP32 #2 제한형 MQTT Flood 검증 Runbook

## 1. 목적과 안전 범위

이 문서는 등록 Device `esp32_02`의 **실제 Source IP**에서 제한된 MQTT Flood를
발생시켜 다음 흐름을 검증하기 위한 절차입니다.

```text
ESP32 #2 Publish
→ MQTT Feature·Detection Event
→ Trust Score 감점
→ firewall_rules PENDING
→ iptables 적용(APPLIED)
→ ESP32 #2 MQTT Publish 실패
→ Firewall 해제(REMOVED)
→ 정상 Firmware 복구
```

다음 안전 조건을 모두 충족할 때만 실행합니다.

- 팀이 소유·관리하는 사설 테스트 LAN에서만 실행합니다.
- Broker는 `192.168.0.20:1883`으로 고정합니다.
- 공격 대상은 팀의 Raspberry Pi Broker 한 대뿐입니다.
- `firmware/esp32/attack_sender/attack_sender.ino`의
  `ATTACK_TEST_ENABLED` 기본값은 `false`로 유지합니다.
- 공식 실행 직전에만 `true`로 변경하고, 실행이 끝나면
  `normal_sender.ino`를 다시 업로드합니다.
- 테스트 결과가 없는 항목은 성공으로 간주하지 않고 `미검증`으로 기록합니다.

노트북에서 Payload의 `device_id`만 `esp32_02`로 바꿔 보내는 방식은 공식 자동
격리 증거로 인정하지 않습니다. ESP32 #2의 실제 IP가 DB의
`devices.ip_address`와 일치해야 합니다.

## 2. 고정 테스트 계약

| 항목 | 값 |
| --- | --- |
| Device ID | `esp32_02` |
| Broker | `192.168.0.20` |
| Port | `1883/TCP` |
| Topic | `iot/esp32_02/sensor` |
| Burst당 메시지 | 40건 |
| Burst 수 | 4회 |
| Burst 시작 간격 | 10초 |
| 메시지 간격 | 50ms |
| 공격 최대 메시지 | 160건 |
| 공격 최대 실행 시간 | 45초 |
| 차단 관측 Probe | Canonical Payload, 5초 간격, 최대 9건 |
| 차단 관측 Timeout | 45초 |
| 관측 후 신규 MQTT 연결 | 1회, Socket Timeout 5초 |

Burst 시작 시각은 Firmware 실행 시각 기준이며 UTC 10초 경계와 정렬되지 않습니다.
따라서 4회 Burst가 정확히 4개 Window를 보장하지 않습니다. 실제
`analysis_window_start`·`analysis_window_end`를 기준으로 격리에 필요한 서로 다른
Window와 대표 `ABNORMAL_PUBLISH_RATE` Event가 생성됐는지 판정합니다. 현재 정책이
Event당 `-20`, 격리 기준이 Trust Score `< 30`이라면 서로 다른 4개 Window가
확인될 때 예상 흐름은 `100 → 80 → 60 → 40 → 20`입니다.

## 3. 실행 전 준비

### 3.1 코드·DB 백업

```bash
cd /home/pi/iot-edge-zero-trust
source venv/bin/activate

git rev-parse HEAD
git status --short

mkdir -p backend/data/backups data/exports
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
DB=backend/data/iot_security.db
BACKUP="backend/data/backups/iot_security_before_esp32_attack_${RUN_ID}.db"

sqlite3 "$DB" ".backup '$BACKUP'"
sqlite3 "$BACKUP" "PRAGMA integrity_check; PRAGMA foreign_key_check;"
sha256sum "$BACKUP" > "${BACKUP}.sha256"
```

정상 Firmware의 Wi-Fi·Device 설정을 별도 비공개 위치에 백업합니다. Wi-Fi
비밀번호를 Git이나 결과 문서에 기록하지 않습니다.

### 3.2 ESP32 #2 IP 매핑과 Baseline Gate

ESP32 #2에서 정상 Firmware를 실행하고 Serial Monitor의 실제 IP를 확인합니다.

```bash
sqlite3 -header -column "$DB" "
SELECT device_id, ip_address, status, trust_score, last_seen_at
FROM devices
WHERE device_id = 'esp32_02';
"
```

다음을 모두 확인합니다.

- 조회 Row가 정확히 1개입니다.
- `devices.ip_address`가 ESP32 #2 Serial 출력 IP와 같습니다.
- `status = 'normal'`입니다.
- `trust_score = 100`입니다.
- 공유기 DHCP 예약으로 실행 중 IP가 바뀌지 않습니다.
- Pi 관리 IP, 관리자 노트북 IP와 겹치지 않습니다.

아래 Baseline Gate를 모두 충족하지 않으면 공격 Firmware를 업로드하지 않습니다.

- `esp32_02`의 `status = 'normal'`
- `esp32_02`의 `trust_score = 100`
- `PENDING`·`APPLIED` Firewall Rule 없음
- 실제 `hanium-firewall` iptables Rule 없음
- 정상 Firmware의 MQTT 연결·Publish 가능
- Subscriber Gate와 Pipeline Preflight 통과

### 3.3 서비스·DB 상태 확인

```bash
for service in \
  packet-capture.service \
  mqtt-feature-builder.service \
  detection-orchestrator.service \
  firewall-worker.service \
  iot-edge-api.service
do
  printf "%s=" "$service"
  systemctl is-active "$service"
done

sqlite3 "$DB" "PRAGMA integrity_check; PRAGMA foreign_key_check;"
sudo -n /usr/local/sbin/hanium-firewall-rule list
```

필수 서비스가 없거나 비활성인 경우 공격을 시작하지 않고 `미검증`으로 남깁니다.

### 3.4 MQTT Subscriber Gate

`mqtt-feature-builder.service`는 기존 `mqtt_logs`를 읽지만 MQTT 메시지를 직접
저장하지 않습니다. 다음 명령으로 DB 저장 Subscriber가 실행 중인지 확인합니다.

```bash
pgrep -af "python -m edge.mqtt.subscriber"
```

현재 운영 방식에서는 전용 터미널에서 아래 Wrapper를 실행합니다.

```bash
./edge/scripts/run_subscriber.sh
# Wrapper와 같은 진입점: python -m edge.mqtt.subscriber
```

Subscriber 터미널에서 Broker 연결 완료 로그를 확인합니다. 단순
`mosquitto_sub` 수신 성공은 `mqtt_logs` 저장을 증명하지 않으므로 Subscriber
Gate를 대체하지 않습니다. 프로세스나 연결 로그를 확인할 수 없으면 공격을
시작하지 않습니다.

### 3.5 정상 Publish Pipeline Preflight

공격 전 정상 Firmware에서 Canonical Payload 1건을 Publish하고
`mqtt_logs → feature_logs → Producer·Detector Checkpoint` 전진을 확인합니다.
다른 Device의 트래픽으로 전역 ID와 Checkpoint가 전진한 것을 오인하지 않도록
Preflight 시작 시각을 먼저 기록합니다.

```bash
PREFLIGHT_STARTED_AT_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"
printf 'PREFLIGHT_STARTED_AT_UTC=%s\n' "$PREFLIGHT_STARTED_AT_UTC"
```

정상 Firmware에서 아래 Canonical Payload 1건이 Publish될 때까지 기다린 다음,
그 메시지의 정확한 Row ID를 고정합니다.

```json
{"device_id":"esp32_02"}
```

```bash
PREFLIGHT_MQTT_ID="$(sqlite3 "$DB" "
SELECT id
FROM mqtt_logs
WHERE device_id = 'esp32_02'
  AND topic = 'iot/esp32_02/sensor'
  AND payload = '{\"device_id\":\"esp32_02\"}'
  AND received_at >= '$PREFLIGHT_STARTED_AT_UTC'
ORDER BY id ASC
LIMIT 1;
")"

test -n "$PREFLIGHT_MQTT_ID"
printf 'PREFLIGHT_MQTT_ID=%s\n' "$PREFLIGHT_MQTT_ID"
```

해당 MQTT Row가 포함된 정확한 Feature Window가 생성될 때까지 기다린 뒤 Feature
ID와 Window 종료 시각을 고정합니다.

```bash
PREFLIGHT_FEATURE_ID="$(sqlite3 "$DB" "
SELECT fl.id
FROM feature_logs AS fl
JOIN mqtt_logs AS ml ON ml.id = $PREFLIGHT_MQTT_ID
WHERE fl.device_id = 'esp32_02'
  AND ml.received_at >= fl.window_start
  AND ml.received_at < fl.window_end
ORDER BY fl.id ASC
LIMIT 1;
")"

test -n "$PREFLIGHT_FEATURE_ID"

PREFLIGHT_WINDOW_END="$(sqlite3 "$DB" "
SELECT window_end FROM feature_logs WHERE id = $PREFLIGHT_FEATURE_ID;
")"

test -n "$PREFLIGHT_WINDOW_END"
printf 'PREFLIGHT_FEATURE_ID=%s\n' "$PREFLIGHT_FEATURE_ID"
printf 'PREFLIGHT_WINDOW_END=%s\n' "$PREFLIGHT_WINDOW_END"
```

마지막으로 Checkpoint가 이 두 Row와 Window를 실제로 통과했는지 확인합니다.

```bash
sqlite3 -header -column "$DB" "
SELECT detector_name || '+' || source_table AS checkpoint_key,
       last_processed_id,
       last_completed_window_end,
       CASE
         WHEN detector_name = 'mqtt_feature_builder'
          AND last_processed_id >= $PREFLIGHT_MQTT_ID
          AND last_completed_window_end >= '$PREFLIGHT_WINDOW_END' THEN 'PASS'
         WHEN detector_name = 'mqtt_message_rule'
          AND last_processed_id >= $PREFLIGHT_MQTT_ID THEN 'PASS'
         WHEN detector_name = 'mqtt_feature_rule'
          AND last_processed_id >= $PREFLIGHT_FEATURE_ID
          AND last_completed_window_end >= '$PREFLIGHT_WINDOW_END' THEN 'PASS'
         ELSE 'FAIL'
       END AS preflight_result
FROM detector_checkpoints
WHERE (detector_name = 'mqtt_feature_builder' AND source_table = 'mqtt_logs')
   OR (detector_name = 'mqtt_feature_rule' AND source_table = 'feature_logs')
   OR (detector_name = 'mqtt_message_rule' AND source_table = 'mqtt_logs')
ORDER BY checkpoint_key;
"
```

아래 세 Row가 모두 `PASS`여야 Preflight를 통과합니다.

- `mqtt_feature_builder+mqtt_logs`
- `mqtt_feature_rule+feature_logs`
- `mqtt_message_rule+mqtt_logs`

`esp32_02`의 정확한 MQTT Row와 Feature Window를 찾지 못하거나 Checkpoint가
해당 ID·Window를 통과하지 않으면 전체 탐지 흐름의 준비 실패이므로 공격을
시작하지 않습니다.

### 3.6 기존 격리 상태 확인

```bash
sqlite3 -header -column "$DB" "
SELECT id, device_id, source_ip, status, retry_count, last_error, updated_at
FROM firewall_rules
WHERE device_id = 'esp32_02'
ORDER BY id DESC
LIMIT 10;
"

sudo iptables -S INPUT | grep hanium-firewall || true
```

`PENDING` 또는 `APPLIED` Rule이나 실제 iptables Rule이 하나라도 있으면 Baseline
Gate 실패입니다. 원인을 확인하고 승인된 복구 절차를 완료하기 전에는 새 Run을
시작하지 않습니다.

## 4. Firmware 설정·업로드

Arduino IDE에서 다음을 준비합니다.

```text
Board: ESP32 Dev Module
Library: PubSubClient
Serial Monitor: 115200 baud
```

1. `firmware/esp32/attack_sender/attack_sender.ino`를 엽니다.
2. `WIFI_SSID`, `WIFI_PASSWORD`를 테스트 LAN 값으로 설정합니다.
3. Broker, Device ID, Topic이 고정 계약과 일치하는지 확인합니다.
4. 공식 실행 직전에만 아래 값을 변경합니다.

```cpp
const bool ATTACK_TEST_ENABLED = true;
```

5. ESP32 업로드 직전에 Pi에서 현재 Run의 기준 시각과 ID를 기록합니다.

```bash
RUN_STARTED_AT_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"
DETECTION_ID_BEFORE="$(sqlite3 "$DB" \
  "SELECT COALESCE(MAX(id), 0) FROM detection_events;")"
TRUST_HISTORY_ID_BEFORE="$(sqlite3 "$DB" \
  "SELECT COALESCE(MAX(id), 0) FROM trust_score_history;")"
FIREWALL_RULE_ID_BEFORE="$(sqlite3 "$DB" \
  "SELECT COALESCE(MAX(id), 0) FROM firewall_rules;")"

printf 'RUN_STARTED_AT_UTC=%s\n' "$RUN_STARTED_AT_UTC"
printf 'DETECTION_ID_BEFORE=%s\n' "$DETECTION_ID_BEFORE"
printf 'TRUST_HISTORY_ID_BEFORE=%s\n' "$TRUST_HISTORY_ID_BEFORE"
printf 'FIREWALL_RULE_ID_BEFORE=%s\n' "$FIREWALL_RULE_ID_BEFORE"
```

6. ESP32 #2에 업로드하고 Serial Monitor를 엽니다. Firmware의
   `run_started_at_device_ms` Serial 행이 출력된 호스트 UTC 시각도 함께
   기록합니다.

Firmware는 부팅당 한 번만 실행합니다. 공격 전송은 최대 45초·160건으로
종료되고, 이어서 별도 45초 관측 단계에서 정상 Canonical Payload를 5초 간격으로
최대 9건만 Probe합니다. 관측 종료 시 기존 연결을 닫고 신규 MQTT 연결을 정확히
1회 시도한 뒤 Wi-Fi를 종료합니다. 공격 Burst는 관측 단계에서 반복하지 않습니다.

## 5. 실행 중 증적 수집

Pi에서 동시에 다음 로그를 확인합니다.

```bash
journalctl --utc -f \
  -u packet-capture.service \
  -u mqtt-feature-builder.service \
  -u detection-orchestrator.service \
  -u firewall-worker.service
```

다른 터미널에서 DB 변화를 확인합니다.

```bash
watch -n 1 "sqlite3 -header -column '$DB' \"
SELECT id, device_id, event_type, incident_family, score_delta,
       applied_to_score, analysis_window_start, analysis_window_end,
       detected_at
FROM detection_events
WHERE device_id = 'esp32_02'
  AND id > $DETECTION_ID_BEFORE
  AND detected_at >= '$RUN_STARTED_AT_UTC'
ORDER BY id DESC
LIMIT 12;

SELECT id, previous_score, actual_delta, new_score,
       analysis_window_start, analysis_window_end, policy_version, created_at
FROM trust_score_history
WHERE device_id = 'esp32_02'
  AND id > $TRUST_HISTORY_ID_BEFORE
  AND created_at >= '$RUN_STARTED_AT_UTC'
ORDER BY id DESC
LIMIT 8;

SELECT id, source_ip, status, retry_count, created_at, applied_at,
       updated_at, last_error
FROM firewall_rules
WHERE device_id = 'esp32_02'
  AND id > $FIREWALL_RULE_ID_BEFORE
  AND created_at >= '$RUN_STARTED_AT_UTC'
ORDER BY id DESC
LIMIT 5;
\""
```

ID와 UTC 시각 조건을 둘 다 만족하는 Row만 현재 Run의 증적으로 사용합니다.
기준 ID 이전의 최신 Row나 다른 Device의 Row는 이번 Run에 귀속하지 않습니다.

기대 결과:

1. 실제 `analysis_window_start`·`analysis_window_end`가 서로 다른 Window에
   `ABNORMAL_PUBLISH_RATE` Event가 생성됩니다.
2. 격리까지 필요한 각 Window의 대표 Event가 중복 감점 없이 처리됩니다.
3. Trust Score가 격리 기준 미만으로 내려갑니다.
4. `firewall_rules`가 `PENDING → APPLIED`로 전이합니다.
5. `hanium-firewall:{rule_id}` iptables Rule이 존재합니다.
6. ESP32 관측 로그에 기존 연결의 Probe 실패 또는 연결 단절과 최초 실패
   `elapsed_ms`·MQTT 상태·Publish 결과가 기록됩니다.
7. 관측 종료 후 신규 MQTT 연결 1회 결과가 기록됩니다.

```bash
sudo iptables -S INPUT | grep hanium-firewall
```

Firewall 차단 증거로 인정하려면 DB의 `APPLIED` 시각과 Firmware
`run_started_at_device_ms` 행을 기록한 호스트 UTC 시각에
`first_failure_run_elapsed_ms` 또는 `reconnect_run_elapsed_ms`를 더한 시각의
순서를 대조합니다. `observation_elapsed_ms`는 관측 단계 내부 진단용이며 Run 시작
UTC에 직접 더하지 않습니다. `APPLIED` 전에 발생한 연결 실패, Firmware가
의도적으로 실행한 연결 종료, 관측 Timeout 뒤의 신규 연결 성공은 차단 증거가
아닙니다.

4회 Burst가 정확히 4개 Window를 보장하지 않습니다. 격리에 필요한 서로 다른
Window가 생성되지 않거나 신규 연결이 성공하면 즉시 재실행하지 않습니다. Serial
로그, 수집 시각, `analysis_window_start`·`analysis_window_end`, Feature와
Checkpoint를 먼저 분석하고 결과를 `미검증` 또는 실패로 기록합니다.

## 6. 격리 해제와 정상 복구

적용된 Rule ID를 확인합니다.

```bash
RULE_ID="$(sqlite3 "$DB" "
SELECT id
FROM firewall_rules
WHERE device_id = 'esp32_02' AND status = 'APPLIED'
ORDER BY id DESC
LIMIT 1;
")"

python -m edge.trust.run_firewall_worker --release "$RULE_ID"
sudo iptables -S INPUT | grep hanium-firewall || true
```

DB 상태가 `REMOVED`인지 확인합니다.

```bash
sqlite3 -header -column "$DB" "
SELECT id, device_id, source_ip, status, applied_at, released_at, last_error
FROM firewall_rules
WHERE id = $RULE_ID;
"
```

다음 순서로 정상 Firmware를 복구합니다.

1. `firmware/esp32/normal_sender/normal_sender.ino`의 Device ID·Topic을
   ESP32 #2 정상 계약에 맞춥니다.
2. ESP32 #2에 정상 Sketch를 업로드합니다.
3. Broker에서 정상 메시지 수신을 확인합니다.
4. `mqtt_logs`와 `last_seen_at` 갱신을 확인합니다.

```bash
mosquitto_sub -h 127.0.0.1 -p 1883 \
  -t "iot/esp32_02/sensor" -C 1 -W 15

sqlite3 -header -column "$DB" "
SELECT device_id, status, trust_score, last_seen_at
FROM devices
WHERE device_id = 'esp32_02';
"
```

정상 메시지가 다시 수신되고 DB가 갱신되어야 **정상 Publish 재개**로 판정합니다.
Firewall 해제 명령과 오류 복구는
[`firewall-runbook.md`](firewall-runbook.md)를 따릅니다. DB 전체 재해 복구 절차인
[`db-backup-restore.md`](db-backup-restore.md)는 반복 E2E Baseline Reset 용도가
아니므로 정상적인 다음 Run 준비에 사용하지 않습니다.

현재 저장소에는 승인된 Trust·Device Baseline Reset 절차는 아직 없습니다.
따라서 자동 SQL로 Trust Score를 100 또는 Device 상태를 `normal`로 되돌리지
않습니다.

- Firewall Rule이 `REMOVED`이고 정상 Publish가 복구됐지만 `status = 'normal'`,
  `trust_score = 100` Baseline을 충족하지 않으면 Run 상태를 `HOLD`로 기록합니다.
- Firewall 해제, iptables 제거 또는 정상 Firmware·Publish 복구 중 하나라도
  실패하면 `RESET_FAILED`로 기록합니다.
- `HOLD` 또는 `RESET_FAILED` 상태에서는 승인된 Reset 절차가 마련되고 Baseline
  Gate를 다시 통과할 때까지 다음 Run을 시작하지 않습니다.

## 7. 결과 기록

각 Run마다 다음을 남깁니다.

- 실행 Run ID와 UTC/KST 시작·종료 시각
- Git Commit SHA
- Firmware 파일 SHA256과 `ATTACK_TEST_ENABLED` 설정
- ESP32 #2 실제 IP와 실행 전 `devices.ip_address`
- 서비스 상태와 DB integrity/FK 결과
- 실제 `analysis_window_start`·`analysis_window_end`별 Detection Event·Trust History
- Firewall Rule ID와 `PENDING`, `APPLIED`, `REMOVED` 전이 시각
- iptables Comment와 전체 Match Specification
- ESP32 Serial 로그의 공격 Publish 수, 관측 Probe, 최초 실패와 신규 연결 1회 결과
- 정상 Firmware 복구 시각과 정상 Publish 재개 증거
- 최종 Run 상태(`완료`, `HOLD`, `RESET_FAILED`)
- 실행하지 않았거나 관찰하지 못한 항목의 `미검증` 사유

Firmware는 공격 메시지 최대 160건을 보냈다는 사실만으로 성공으로 판정하지 않습니다.
실제 Event·Trust·Firewall·격리 실패·정상 복구 증적이 모두 있어야 공식 E2E
성공으로 기록합니다.
