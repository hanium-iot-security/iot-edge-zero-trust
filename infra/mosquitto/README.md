# Mosquitto 설정 (MQTT 인증·Device별 Topic ACL)

이 디렉터리는 Raspberry Pi에서 사용할 Mosquitto 설정과 인증·ACL 도입 절차를 담는다.

```bash
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

## 파일 구성

| 파일 | 용도 |
| --- | --- |
| `mosquitto.conf` | 현재 운영 설정(전환 기간). `allow_anonymous true` 유지, `acl_file`/`password_file` 없음. |
| `mosquitto-strict.conf` | 인증·ACL이 강제된 목표 설정. Strict Test Listener로 먼저 검증한 뒤 운영에 적용한다. |
| `aclfile.conf` | Principal별 Topic 허용/거부 정책(비밀번호 없음, Git 포함). |
| `passwd.example` | Password File 생성 절차 안내(실제 비밀번호는 Git에 올리지 않음). |

## 두 개의 conf 파일로 나눈 이유

`allow_anonymous true`인 상태에서 `acl_file`만 먼저 추가하면, 그 acl_file에
Anonymous용 규칙이 없는 한 익명 Client는 **연결(CONNECT)은 성공하지만
Publish는 Broker 단계에서 조용히 거부된다**(`Denied PUBLISH`). 즉
`acl_file`을 섣불리 켜면 아직 Credential이 없는 ESP32가 갑자기 Publish를
못 하게 되어, 정상 MQTT 연결은 인증·ACL 적용 후에도 유지된다는 완료
기준을 스스로 깨뜨릴 수 있다. 그래서 `acl_file`/`password_file`은
`mosquitto-strict.conf`로 분리하고, 운영 `mosquitto.conf`와 겹치지 않는 별도
포트(Strict Test Listener)에서 먼저 검증한 뒤에만 운영에 반영한다.

## 전환 순서

1. **기존 설정 Backup**
   ```bash
   sudo cp -a /etc/mosquitto/mosquitto.conf \
       "/etc/mosquitto/mosquitto.conf.$(date -u +%Y%m%dT%H%M%SZ).bak"
   ```
2. **Password/ACL 파일 준비** — `passwd.example`의 절차대로 `mosquitto_passwd`로
   `/etc/mosquitto/passwd`를 만들고, 이 디렉터리의 `aclfile.conf`를
   `/etc/mosquitto/aclfile.conf`로 배치한다.
   ```bash
   sudo install -m 0644 infra/mosquitto/aclfile.conf /etc/mosquitto/aclfile.conf
   sudo chown mosquitto:mosquitto /etc/mosquitto/passwd /etc/mosquitto/aclfile.conf
   sudo chmod 0600 /etc/mosquitto/passwd /etc/mosquitto/aclfile.conf
   ```
3. **Subscriber/ESP32/Test Tool Credential 지원** — `edge/mqtt/subscriber.py`는
   `.env`의 `MQTT_SUBSCRIBER_USERNAME`/`MQTT_SUBSCRIBER_PASSWORD`를, `attacks/*`
   (공식 MQTT Scenario/Test Tool)는 `MQTT_TEST_TOOL_USERNAME`/
   `MQTT_TEST_TOOL_PASSWORD`를 읽는다. ESP32는
   `firmware/esp32/{normal_sender,attack_sender}/mqtt_credentials.example.h`를
   복사한 `mqtt_credentials.h`(Git 제외)에 Credential을 채운다.
4. **Broker 강제 전 Credential 기반 정상 Client 연결 Smoke** — 운영 Listener를
   건드리지 않고 별도 Port(예: 18831)로 Strict Listener를 띄운다.
   ```bash
   # mosquitto-strict.conf의 listener 포트를 임시로 18831 등으로 바꿔서 실행
   sudo mosquitto -c infra/mosquitto/mosquitto-strict.conf
   ```
   그 상태에서 Test Pack을 실행해 Own Topic PASS / Anonymous DENY /
   Cross Topic DENY / Wrong Password DENY를 확인한다.
   ```bash
   python -m edge.scripts.mqtt_acl_test_pack \
       --host <Pi IP> --port 18831 \
       --esp32-01-password '...' --esp32-02-password '...' \
       --edge-subscriber-password '...' --test-tool-password '...'
   ```
   모든 Check가 `[OK]`로 보고되고 Exit Code가 0이어야 다음 단계로 진행한다.
5. **Broker 인증·ACL 활성화** — 검증이 끝나면 운영 `mosquitto.conf`를
   `mosquitto-strict.conf` 내용(Port는 1883/9001 유지)으로 교체한다.
   ```bash
   sudo install -m 0644 infra/mosquitto/mosquitto-strict.conf /etc/mosquitto/mosquitto.conf
   sudo systemctl restart mosquitto
   ```
6. **정상 Subscribe/Publish 확인** — Test Pack을 운영 Port(1883)로 다시 실행해
   최종 확인한다.
   ```bash
   python -m edge.scripts.mqtt_acl_test_pack --host <Pi IP> --port 1883 ...
   ```
7. **이상 시 Rollback**
   ```bash
   sudo cp -a "<1번에서 만든 Backup 경로>" /etc/mosquitto/mosquitto.conf
   sudo systemctl restart mosquitto
   ```

## Broker ACL과 Application Identity Detection의 차이

- **Broker ACL DENY**: 예) `esp32_02` Credential이 `iot/esp32_01/sensor`에
  Publish → Broker 단계에서 거부된다. Subscriber까지 도달하지 않으므로
  `edge.mqtt.identity`/`DEVICE_ID_MISMATCH` 같은 Application Detection Event를
  기대하지 않는다.
- **Application Identity Detection**: 예) `esp32_02` Credential이 자기 허용
  Topic(`iot/esp32_02/sensor`)에 Publish하지만 Payload의 `device_id`만 다른
  등록 기기로 위조 → Broker는 통과시키고, Application(`edge.mqtt.identity`,
  `edge.detection.rule_detector.detect_mqtt_rules`)에서 `DEVICE_ID_MISMATCH`로
  탐지한다.

Application Detector 테스트를 위해 운영 ACL 자체를 느슨하게 만들지 않는다 —
공식 MQTT Scenario/Test Tool(`mqtt_test_tool` Principal)은 이 목적을 위해
운영 ESP32 Credential과 분리된 넓은 권한을 가지며, Production 상시 노출
경로에는 배치하지 않는다.

## 중요 — 표현 기준

MQTT 인증·ACL은 **접근제어 강화**다. TCP 1883을 계속 사용하는 동안 이를 MQTT 통신 암호화나 mTLS 기반 Device Identity라고 표현하지 않는다.
