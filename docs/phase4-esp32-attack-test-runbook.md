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
| 최대 메시지 | 160건 |
| 최대 실행 시간 | 45초 |

4회 Burst는 서로 다른 4개 Window에 `ABNORMAL_PUBLISH_RATE` Event를 만들기 위한
계약입니다. 현재 정책이 Event당 `-20`, 격리 기준이 Trust Score `< 30`이라면
예상 흐름은 `100 → 80 → 60 → 40 → 20`입니다. 실제 결과가 다르면 정책 Version,
Checkpoint, Window 배치와 Event 중복 방지를 먼저 확인합니다.

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

### 3.2 ESP32 #2 IP와 DB 매핑 확인

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
- 공유기 DHCP 예약으로 실행 중 IP가 바뀌지 않습니다.
- Pi 관리 IP, 관리자 노트북 IP와 겹치지 않습니다.

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

### 3.4 기존 격리 상태 확인

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

기존 `APPLIED` Rule이 있으면 원인을 확인하고 정상 해제·복구한 뒤 새 Run을
시작합니다.

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

5. ESP32 #2에 업로드하고 Serial Monitor를 엽니다.

Firmware는 부팅당 한 번만 실행합니다. 연결 실패, 사설망 검증 실패, 45초 초과,
MQTT 연결 단절이 발생하면 자동 반복하지 않고 종료합니다.

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
       applied_to_score, analysis_window_start, analysis_window_end
FROM detection_events
WHERE device_id = 'esp32_02'
ORDER BY id DESC
LIMIT 12;

SELECT id, previous_score, actual_delta, new_score,
       analysis_window_start, analysis_window_end, policy_version
FROM trust_score_history
WHERE device_id = 'esp32_02'
ORDER BY id DESC
LIMIT 8;

SELECT id, source_ip, status, retry_count, applied_at, last_error
FROM firewall_rules
WHERE device_id = 'esp32_02'
ORDER BY id DESC
LIMIT 5;
\""
```

기대 결과:

1. 4개 Window에 `ABNORMAL_PUBLISH_RATE` Event가 생성됩니다.
2. 각 Window의 대표 Event가 중복 감점 없이 처리됩니다.
3. Trust Score가 격리 기준 미만으로 내려갑니다.
4. `firewall_rules`가 `PENDING → APPLIED`로 전이합니다.
5. `hanium-firewall:{rule_id}` iptables Rule이 존재합니다.
6. ESP32 Serial 로그에 MQTT 연결 단절 또는 Publish 실패가 나타납니다.

```bash
sudo iptables -S INPUT | grep hanium-firewall
```

Window가 경계에 걸려 기대한 Event 수가 나오지 않으면 즉시 재실행하지 않습니다.
Serial 로그, 수집 시각, Feature·Checkpoint를 먼저 분석하고 결과를 `미검증` 또는
실패로 기록합니다.

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
자동으로 Trust Score를 100으로 되돌리지 않습니다. 점수·Device 상태 복구는
승인된 E2E Reset 절차 또는 운영 정책을 따릅니다.

## 7. 결과 기록

각 Run마다 다음을 남깁니다.

- 실행 Run ID와 UTC/KST 시작·종료 시각
- Git Commit SHA
- Firmware 파일 SHA256과 `ATTACK_TEST_ENABLED` 설정
- ESP32 #2 실제 IP와 실행 전 `devices.ip_address`
- 서비스 상태와 DB integrity/FK 결과
- 4개 Window의 Detection Event·Trust History
- Firewall Rule ID와 `PENDING`, `APPLIED`, `REMOVED` 전이 시각
- iptables Comment와 전체 Match Specification
- ESP32 Serial 로그의 연결·Publish 성공/실패
- 정상 Firmware 복구 시각과 정상 Publish 재개 증거
- 실행하지 않았거나 관찰하지 못한 항목의 `미검증` 사유

Firmware는 최대 160건을 보냈다는 사실만으로 성공으로 판정하지 않습니다.
실제 Event·Trust·Firewall·격리 실패·정상 복구 증적이 모두 있어야 공식 E2E
성공으로 기록합니다.
