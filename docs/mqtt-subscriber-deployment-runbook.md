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
