# MQTT Subscriber systemd 배포 Runbook

## 1. 목적과 적용 범위

이 문서는 Raspberry Pi에서 `edge.mqtt.subscriber`를
`mqtt-subscriber.service`로 설치하고, MQTT 수신 Row 저장과 재부팅 후 자동 시작을
검증하는 절차입니다. Unit 배포만 다루며 MQTT Topic, DB Schema, Trust, Firewall,
ESP32 Firmware와 다른 systemd Unit은 변경하지 않습니다.

기본 프로젝트 경로는 `/home/pi/iot-edge-zero-trust`입니다. 아래 명령은 Pi의 해당
저장소 루트에서 실행합니다.

## 2. 사전 조건

Mosquitto가 설치되어 있고 Broker가 active인지 확인합니다.

```bash
systemctl is-enabled mosquitto.service
systemctl is-active mosquitto.service
```

프로젝트 환경과 Subscriber 진입점을 확인합니다.

```bash
cd /home/pi/iot-edge-zero-trust
test -r /home/pi/iot-edge-zero-trust/.env
test -x /home/pi/iot-edge-zero-trust/venv/bin/python
sudo -u pi test -r /home/pi/iot-edge-zero-trust/.env
/home/pi/iot-edge-zero-trust/venv/bin/python -c "import edge.mqtt.subscriber"
```

하나라도 실패하면 Unit을 설치하지 않고 Mosquitto, `.env`, 프로젝트 venv 또는
파일 권한을 먼저 복구합니다.

## 3. 기존 Unit Backup

설치된 Unit이 있다면 UTC Timestamp가 포함된 Backup을 먼저 만듭니다.

```bash
cd /home/pi/iot-edge-zero-trust

if sudo test -f /etc/systemd/system/mqtt-subscriber.service; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  sudo cp -a /etc/systemd/system/mqtt-subscriber.service \
    "/etc/systemd/system/mqtt-subscriber.service.${stamp}.bak"
fi
```

생성된 Backup 경로는 배포 결과 기록에 남기며 검증이 끝날 때까지 삭제하지 않습니다.

## 4. 저장소 Unit 설치와 시작

```bash
cd /home/pi/iot-edge-zero-trust

sudo install -m 0644 \
  infra/systemd/mqtt-subscriber.service \
  /etc/systemd/system/mqtt-subscriber.service

sudo systemctl daemon-reload
sudo systemctl enable --now mqtt-subscriber.service
```

실제 운영 DB나 `.env`를 복사하거나 Git에 포함하지 않습니다. 저장소에는 Unit,
Runbook과 배포 계약 테스트만 포함하며, 실제 운영 DB와 `.env`는 포함하지 않습니다.

## 5. 설치 상태와 Unit 검증

```bash
systemctl is-enabled mqtt-subscriber.service
systemctl is-active mqtt-subscriber.service
sudo systemctl status mqtt-subscriber.service --no-pager
sudo systemd-analyze verify /etc/systemd/system/mqtt-subscriber.service
```

기대 결과는 각각 `enabled`, `active`이며 `systemd-analyze verify`에 오류가 없어야
합니다.

저장소본과 설치본이 동일한지 SHA256을 비교합니다.

```bash
cd /home/pi/iot-edge-zero-trust
sha256sum infra/systemd/mqtt-subscriber.service
sha256sum /etc/systemd/system/mqtt-subscriber.service
```

두 SHA256이 다르면 서비스를 운영 상태로 인정하지 말고 설치 경로와 파일 내용을
확인합니다.

## 6. 로그와 MQTT 저장 확인

```bash
journalctl --utc -u mqtt-subscriber.service -n 100 --no-pager
```

Broker 연결 완료 로그가 있고 반복되는 Import, `.env`, 인증 또는 DB 오류가 없어야
합니다. 정상 ESP32 메시지 한 건을 Publish한 뒤 운영 DB에서 해당 Device의 최신
`mqtt_logs` Row가 증가했는지 확인합니다. DB 경로는 실제 `.env`의
`DATABASE_URL`을 근거로 정하며 추측하지 않습니다.

## 7. 재시작 검증

재시작 전후 Row 수를 기록하고 정상 ESP32 Publish를 관측합니다.

```bash
cd /home/pi/iot-edge-zero-trust
DB=backend/data/iot_security.db
before_count="$(sqlite3 "$DB" "SELECT COUNT(*) FROM mqtt_logs;")"

sudo systemctl restart mqtt-subscriber.service
systemctl is-active mqtt-subscriber.service
journalctl --utc -u mqtt-subscriber.service -n 100 --no-pager

# 정상 ESP32 Publish가 도착한 뒤 실행합니다.
after_count="$(sqlite3 "$DB" "SELECT COUNT(*) FROM mqtt_logs;")"
test "$after_count" -gt "$before_count"
```

실제 DB 경로가 위 예시와 다르면 `.env`에 기록된 경로를 사용합니다. Row 증가가 다른
Publisher의 메시지 때문이 아닌지 Topic, Device ID와 `received_at`도 함께 확인합니다.

계획 종료 검증에서는 `SIGTERM`·`SIGINT`가 종료 요청만 기록하고, MQTT 연결을
닫은 뒤 실행 중인 메시지 저장 Callback과 DB Commit이 끝날 때까지 기다린다.
일시적인 연결 끊김의 재연결은 기존 Paho `loop_forever`가 담당한다. 저장 Callback·수신
Loop의 예외, 연결 거부와 Subscribe API 호출 실패는 비정상 종료로 남긴다. Subscribe
호출 성공만으로 Broker의 SUBACK 승인을 보장하지 않는다. 서비스가 `active`이거나
재시작됐다는 사실만으로 수집 정상으로 인정하지 않는다.
종료 제한 시간 15초를 넘긴 강제 종료도 정상 종료로 인정하지 않는다.

실제 종료 검증은 수집 공백을 기록하는 승인된 운영 절차 안에서 수행한다. 정지 직후
`systemctl show mqtt-subscriber.service -p Result -p ExecMainStatus`가 각각
`success`, `0`인지 확인하고, 재개 이후 기기별 메시지 순서와 저장 오류 로그를 확인한다.
계획 종료·재부팅은 [전용 Runbook](planned-maintenance-runbook.md)을 따른다.

## 8. 재부팅 후 자동 시작 검증

재부팅 명령 자체는 다른 Phase 4 서비스와 운영 영향이 검토되고 **운영자 승인**을
받은 뒤에만 실행합니다.

```bash
sudo reboot
```

Pi가 다시 연결된 뒤 다음을 확인합니다.

```bash
systemctl is-enabled mqtt-subscriber.service
systemctl is-active mqtt-subscriber.service
journalctl --utc -u mqtt-subscriber.service -b --no-pager
```

자동 시작, Broker 연결과 재부팅 이후 `mqtt_logs` Row 증가를 모두 확인해야 재부팅
검증을 완료한 것으로 기록합니다.

## 9. 장애 확인

```bash
sudo systemctl status mqtt-subscriber.service --no-pager
journalctl --utc -u mqtt-subscriber.service -n 100 --no-pager
systemctl is-active mosquitto.service
sudo -u pi test -r /home/pi/iot-edge-zero-trust/.env
/home/pi/iot-edge-zero-trust/venv/bin/python -c "import edge.mqtt.subscriber"
```

다음을 순서대로 확인합니다.

- Mosquitto 비활성 또는 Broker 연결 실패
- `.env` 누락·읽기 권한·MQTT 설정 오류
- 프로젝트 venv 또는 Python Module 누락
- SQLite 경로·디렉터리·쓰기 권한 오류
- 잘못된 Working Directory 또는 설치본과 저장소본의 SHA256 불일치
- Start Limit에 도달한 반복 재시작

## 10. 안전한 Rollback

검증 실패 시 신규 Unit을 중지하고, 3절에서 보존한 정확한 Backup 파일을 운영자가
확인한 뒤 복원합니다. 아래 `BACKUP`은 실제 생성된 파일 하나로 명시적으로
대체합니다.

```bash
sudo systemctl disable --now mqtt-subscriber.service

BACKUP=/etc/systemd/system/mqtt-subscriber.service.YYYYMMDDTHHMMSSZ.bak
sudo test -f "$BACKUP"
sudo cp -a "$BACKUP" /etc/systemd/system/mqtt-subscriber.service

sudo systemctl daemon-reload
sudo systemctl reset-failed mqtt-subscriber.service
sudo systemctl enable --now mqtt-subscriber.service

systemctl is-enabled mqtt-subscriber.service
systemctl is-active mqtt-subscriber.service
journalctl --utc -u mqtt-subscriber.service -n 100 --no-pager
```

기존 Unit이 없었던 최초 설치라면 승인 후 신규 Unit을 제거하고 daemon을 다시
읽습니다. 장애 분석 전 임의 수동 Subscriber와 systemd Subscriber를 동시에 실행하지
않습니다.

## 11. 결과 기록

- Git Commit SHA와 Unit SHA256
- 기존 Unit Backup 경로
- `systemd-analyze verify` 결과
- `enabled`·`active` 상태
- 재시작 전후 MQTT Row와 대표 Topic·Device ID
- 재부팅 실행 승인과 자동 시작 결과
- Journal 오류 유무
- Rollback 여부와 복원한 Backup 경로

실제 Pi에서 수행하지 않은 절차는 완료로 표시하지 않습니다.

## 12. 실제 배포 결과: 2026-08-01

### 12.1 적용 기준

- 적용 브랜치: `develop`
- 적용 Commit: `9bd9478f23f24e960b70bbfe61cf2d54af3a8a94`
- Pi 저장소: `/home/pi/iot-edge-zero-trust`
- 설치 Unit: `/etc/systemd/system/mqtt-subscriber.service`

Pi 저장소는 `d6772656f691cbd813c818519626632e695edde3`에서 병합된 `develop` Commit으로 Fast-forward 갱신했고, 갱신 후 `origin/develop`과 일치함을 확인했습니다.

### 12.2 Backup과 Unit 설치

기존 Unit Backup:

```text
/etc/systemd/system/mqtt-subscriber.service.20260731T162952Z.bak
```

저장소 Unit을 설치한 뒤 `systemctl daemon-reload`와 `systemd-analyze verify`를 수행했습니다. 검증 과정에서 Unit 문법 오류는 출력되지 않았습니다.

저장소본과 설치본 SHA256:

```text
697cc28b1f6cf0863b6a7e2e87def93c856a0a0689e6eeba196564fc88d03723
```

두 파일의 SHA256이 일치했고 설치 상태는 `enabled / active`였습니다.

### 12.3 서비스 재시작 검증

재시작 전후 MQTT Row 수:

```text
BEFORE=7037
AFTER=7043
MQTT_ROW_INCREASE=PASS
```

재시작 후 다음을 확인했습니다.

- Main PID 변경과 정상 재기동
- `NRestarts=0`
- MQTT Broker `localhost:1883`, Topic `#` 연결 완료
- `esp32_01`, `esp32_02` MQTT Row 저장 재개
- 반복되는 Traceback, DB 오류, Broker 연결 실패 없음

### 12.4 Pi 재부팅 검증

운영자 승인 후 Pi를 재부팅했습니다.

- 부팅 시각: `2026-08-01 01:37:20 KST`
- Failed Unit: 없음
- `mqtt-subscriber.service`: `enabled / active`
- 저장소본·설치본 SHA256: 일치
- NTP 동기화: `yes`
- Timezone: `Asia/Seoul`

재부팅 후 MQTT Row 수:

```text
BEFORE=7196
AFTER=7202
MQTT_ROW_INCREASE=PASS
```

최신 Row에서 `esp32_01`, `esp32_02`의 정상 Publish를 모두 확인했습니다.

함께 확인한 Runtime 서비스:

```text
mosquitto.service                 enabled / active
mqtt-subscriber.service           enabled / active
mqtt-feature-builder.service      enabled / active
detection-orchestrator.service    enabled / active
firewall-worker.service           enabled / active
packet-capture.service            enabled / active
gateway-metrics.service           enabled / active
iot-edge-api.service              enabled / active
```

API와 DB 확인:

```text
API Health: status=ok, database=ok, db_connected=true
SQLite integrity_check=ok
foreign_key_violations=0
```

### 12.5 최종 판정

- 저장소 Unit 정식 설치: 완료
- 기존 Unit Backup: 완료
- Unit SHA256 일치: 완료
- 서비스 재시작 후 MQTT 적재 복구: 완료
- Pi 재부팅 후 자동 시작: 완료
- Rollback: 수행하지 않음

이 결과는 `docs/phase4-completion-report.md`의 Phase 4 전체 완료 판정과 함께 관리합니다.
