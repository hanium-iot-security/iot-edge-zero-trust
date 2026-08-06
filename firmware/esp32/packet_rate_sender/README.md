# ESP32 Packet Rate Sender

등록 기기 `esp32_02`가 Raspberry Pi로 제한된 UDP Packet Rate 트래픽을 보내는 Phase 5 실험용 Firmware입니다.

## 안전 계약

- 업로드·부팅·재연결만으로 트래픽을 보내지 않습니다.
- Serial Monitor의 `START` 명령으로만 실행됩니다.
- 예상 ESP32 IP가 `192.168.0.5`가 아니면 실행을 거부합니다.
- 대상은 사설망 `192.168.0.20:19999`로 고정합니다.
- 상한은 `100 PPS`, `15초`, `1400 bytes`입니다.
- 실행 시간이 끝나거나 Wi-Fi가 끊어지면 자동 종료합니다.
- 누락된 전송 시점을 한꺼번에 따라잡는 Burst 전송을 하지 않습니다.

## 로컬 설정 생성

```powershell
cd firmware\esp32\packet_rate_sender
copy packet_rate_firmware_config.example.h packet_rate_firmware_config.h
```

`packet_rate_firmware_config.h`에서 다음만 수정합니다.

```cpp
#define PACKET_RATE_CONFIGURED 1
#define PACKET_RATE_WIFI_SSID "실제_SSID"
#define PACKET_RATE_WIFI_PASSWORD "실제_비밀번호"
```

실제 설정 파일은 `.gitignore`에 의해 제외됩니다. 다음 값은 현재 Phase 5 실기기 계약이므로 임의 변경하지 않습니다.

```cpp
#define PACKET_RATE_DEVICE_SLOT 2
#define PACKET_RATE_EXPECTED_LOCAL_IP "192.168.0.5"
#define PACKET_RATE_TARGET_IP "192.168.0.20"
#define PACKET_RATE_TARGET_PORT 19999
```

## Arduino IDE 업로드

- 보드: 실제 사용 중인 ESP32 보드와 동일한 항목
- Serial baud: `115200`
- 추가 라이브러리: 없음
- 사용 라이브러리: ESP32 Arduino Core 기본 `WiFi`, `WiFiUDP`

업로드 후 Serial Monitor에서 다음 항목을 확인합니다.

```text
firmware_version=phase5-packet-rate-sender-v1
device_id=esp32_02
wifi_connected local_ip=192.168.0.5
expected_local_ip_match=true
target_ip=192.168.0.20
target_port=19999
auto_start=false
packet_rate_sender_ready
```

IP가 `192.168.0.5`가 아니면 공격 명령을 실행하지 않습니다.

## 지원 명령

```text
HELP
STATUS
START <pps> <duration_sec> <payload_bytes>
```

### Smoke Test

Packet Capture Session을 만들기 전에 다음만 실행합니다.

```text
START 10 3 64
```

예상 결과:

```text
reason=duration_completed
sent 약 30
failed=0
elapsed_ms 약 3000
average_pps 약 10
```

Smoke Test에서는 `packet-capture.service`를 시작하지 않습니다.

### 공식 Offline Test 후보

Smoke Test와 Pi Baseline 확인이 끝난 뒤 공식 Capture Session 안에서 실행합니다.

```text
START 80 12 64
```

예상 송신량은 약 960개이며, 실제 값은 ESP32 스케줄링과 무선 상태에 따라 약간 달라질 수 있습니다. 현재 Packet Rule 기본 임계값인 `packets_per_second > 50`을 넘기기 위한 후보 조건입니다.

## 종료 로그 보존

공식 수집 시 Serial 출력에서 다음을 함께 보존합니다.

```text
firmware_version
device_id
local_ip
target_ip
target_port
requested_pps
duration_sec
payload_bytes
started_at_ms
sent
failed
attempted
elapsed_ms
average_pps
reason
```

## 운영 복구

공격 Offline Test가 끝난 뒤에는 `esp32_02`에 정상 수집 Firmware를 다시 업로드합니다. 공격 Firmware 자체는 자동 시작하지 않지만, 정상 운영 Firmware로 복구한 사실을 Serial 로그로 남깁니다.

## 아직 필요한 실기기 검증

- 실제 ESP32 Arduino Core 컴파일
- `esp32_02` 업로드
- `STATUS`와 `START 10 3 64` Serial 확인
- Raspberry Pi에서 실제 UDP 송신 확인

실기기 검증 전에는 공식 Capture Session을 생성하지 않습니다.
