# ESP32 펌웨어

ESP32 정상 telemetry 펌웨어와 공격 모드 펌웨어를 이 디렉터리에 둡니다.

권장 분리:

```txt
normal_sender/
attack_sender/
phase5_normal_collector/
```

## phase5_normal_collector

`phase5_normal_collector/phase5_normal_collector.ino`는 Notion 정책 v1.0의
정상 Pilot을 위한 Phase 5 전용 Firmware입니다. 기존 `normal_sender`의 MVP
Payload·Mode를 재사용하지 않고 다음 계약을 사용합니다.

- `NORMAL_PROFILE=0..3`
- 필수 Canonical Payload: `device_id`, `sequence`, `uptime_s`
- 실제 측정 선택 필드: `rssi`, `free_heap`
- Device ID 기반 Topic·MQTT Client ID
- Firmware·Payload Schema Version과 Profile 부팅 로그
- 100 bytes 초과 Payload 전송 거부

실제 Wi-Fi·Broker·Device Slot·Profile 설정은 Git에서 제외되는
`phase5_firmware_config.h`에만 저장합니다. Arduino IDE Compile·Upload,
ESP32 #1·#2 식별 대조, Serial·MQTT·DB Smoke와 Profile 3 승인 Gate는
[`docs/phase5-normal-firmware-runbook.md`](../../docs/phase5-normal-firmware-runbook.md)를
따릅니다.

## MQTT 설정

```txt
MQTT Broker: 192.168.0.20
MQTT Port: 1883
Topic: iot/esp32_01/sensor
Device ID: esp32_01
```

ESP32는 Raspberry Pi의 Mosquitto broker로 publish하므로 broker 주소는 Raspberry Pi 고정 IP인 `192.168.0.20`을 사용합니다.

## normal_sender

`normal_sender/normal_sender.ino`는 ESP32 #1이 정상 IoT 기기처럼 Raspberry Pi Mosquitto Broker로 MQTT 메시지를 주기적으로 publish하는 Arduino 펌웨어입니다.

이 펌웨어는 아래 파이프라인의 입력 데이터를 만듭니다.

```txt
ESP32 normal_sender
-> MQTT Publish
-> Raspberry Pi Mosquitto Broker
-> Python MQTT Subscriber
-> mqtt_logs 저장
-> feature_logs 생성
-> Isolation Forest 정상/추론 데이터 및 React Dashboard 표시
```

### Arduino IDE 설정

```txt
Board: ESP32 Dev Module
Library: PubSubClient
Serial Monitor: 115200 baud
```

업로드 전 `normal_sender.ino`에서 Wi-Fi 정보를 수정합니다.

```cpp
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
```

MQTT 기본값은 다음과 같습니다.

```txt
Broker: 192.168.0.20
Port: 1883
Topic: iot/esp32_01/sensor
Device ID: esp32_01
```

### NORMAL_MODE

기본 추천값은 `NORMAL_MODE = 1`입니다.

| NORMAL_MODE | 수집 유형 | interval | payload |
| --- | --- | --- | --- |
| `0` | normal_stable | 5초 고정 | 최소 payload |
| `1` | normal_jitter_interval | 4~6초 랜덤 | 최소 payload |
| `2` | normal_jitter_payload | 4~6초 랜덤 | 3단계 확장 정상 payload |

최소 payload:

```json
{"device_id":"esp32_01"}
```

`NORMAL_MODE = 2`는 센서값 이상 탐지가 아니라 정상 payload size 변동을 만들기 위한 모드입니다.

| payload 유형 | 목표 크기 | 예시 |
| --- | --- | --- |
| small | 약 35~50 bytes | `{"device_id":"esp32_01","seq":1,"rssi":-52}` |
| medium | 약 55~75 bytes | `{"device_id":"esp32_01","seq":2,"rssi":-51,"temp":24.3,"hum":45.3}` |
| large-normal | 약 80~90 bytes | `{"device_id":"esp32_01","seq":3,"rssi":-50,"temp":24.1,"hum":45.3,"bat":98,"st":"ok"}` |

payload size는 정상 기준인 100 bytes 이하로 유지합니다. 펌웨어는 publish 전 `payload.length()`를 확인하고, 100 bytes를 초과하면 최소 payload로 fallback합니다.

publish 주기는 `millis()` 기반으로 제어합니다. MQTT 연결 유지를 위해 `loop()`에서 `mqttClient.loop()`가 계속 호출됩니다.

### Raspberry Pi 수신 확인

Raspberry Pi에서 Mosquitto Broker가 실행 중일 때 아래 명령어로 수신을 확인합니다.

```bash
mosquitto_sub -h localhost -p 1883 -t "iot/+/sensor"
```

정상 수신 예시:

```json
{"device_id":"esp32_01"}
```

`NORMAL_MODE = 2` 정상 수신 예시:

```json
{"device_id":"esp32_01","seq":3,"rssi":-50,"temp":24.1,"hum":45.3,"bat":98,"st":"ok"}
```

## attack_sender

`attack_sender/attack_sender.ino`는 Phase 4 공식 E2E에서 등록 테스트 Device
`esp32_02`의 실제 Source IP로 제한된 MQTT Flood를 발생시키기 위한 별도
Firmware입니다.

- 기본값은 `ATTACK_TEST_ENABLED = false`입니다.
- 사설 IPv4 Broker만 허용합니다.
- 40개 메시지 Burst를 10초 간격으로 최대 4회만 실행합니다.
- 공격 Payload는 정상 기본 모드와 같은 `device_id` 전용 Canonical Schema를
  사용합니다.
- 공격 종료 후 정상 간격 Probe를 최대 45초·9건으로 제한하고, 기존 연결 종료 후
  신규 MQTT 연결을 1회만 시도합니다.
- 공격 전 MQTT 연결은 3초 Socket Timeout·최대 2회로 제한합니다.
- 부팅당 한 번만 실행하며 관측 종료 후 MQTT와 Wi-Fi 연결을 종료합니다.
- 정상 데이터 수집이나 일반 운영 Firmware로 사용하지 않습니다.

실행 전 DB IP 매핑·서비스 상태 확인, 실행 중 증적 수집, Firewall 해제와 정상
Firmware 복구는
[`docs/phase4-esp32-attack-test-runbook.md`](../../docs/phase4-esp32-attack-test-runbook.md)를
따릅니다.
