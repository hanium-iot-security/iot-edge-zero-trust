# ESP32 Packet Rate Sender

등록 기기 `esp32_02`가 Raspberry Pi로 제한된 UDP Packet Rate 트래픽을 보내는 실험용 Firmware입니다.

현재 Phase 6-A 진단 Branch에서는 Phase 5 Session 56의 두 번째 Burst에서 관측된 `failed=453`의 발생 단계를 분리하기 위해 **송신 동작은 유지한 채 진단 Counter만 추가**합니다.

## 안전 계약

- 업로드·부팅·재연결만으로 트래픽을 보내지 않습니다.
- Serial Monitor의 `START` 명령으로만 실행됩니다.
- 예상 ESP32 IP가 `192.168.0.5`가 아니면 실행을 거부합니다.
- 대상은 사설망 `192.168.0.20:19999`로 고정합니다.
- 상한은 `100 PPS`, `15초`, `1400 bytes`입니다.
- 실행 시간이 끝나거나 Wi-Fi가 끊어지면 자동 종료합니다.
- 누락된 전송 시점을 한꺼번에 따라잡는 Burst 전송을 하지 않습니다.
- Phase 6-A 진단 변경은 Burst 사이 UDP Socket stop/restart, 송신 재시도, PPS/duration/Payload 변경을 추가하지 않습니다.
- 송신 실패마다 Serial 로그를 출력하지 않고 Counter만 누적해 진단 자체가 송신 타이밍에 미치는 영향을 최소화합니다.

## 1. 저장소에 복사

이 폴더를 다음 위치에 복사합니다.

```text
firmware/esp32/packet_rate_sender/
```

실제 설정 파일은 폴더 내부 `.gitignore`에 의해 제외됩니다.

## 2. 로컬 설정 생성

Windows PowerShell 또는 명령 프롬프트에서:

```powershell
cd firmware\esp32\packet_rate_sender
copy packet_rate_firmware_config.example.h packet_rate_firmware_config.h
```

`packet_rate_firmware_config.h`를 열어 다음만 수정합니다.

```cpp
#define PACKET_RATE_CONFIGURED 1
#define PACKET_RATE_WIFI_SSID "실제_SSID"
#define PACKET_RATE_WIFI_PASSWORD "실제_비밀번호"
```

로컬 설정 파일에는 Wi-Fi SSID와 비밀번호만 둡니다. 실제 설정 파일은 폴더 내부 `.gitignore`에 의해 제외됩니다.

주소·포트·Device 식별 계약은 Firmware 내부에 고정되어 로컬 설정 파일로 변경할 수 없습니다.

```text
device_id=esp32_02
device_slot=2
expected_local_ip=192.168.0.5
target_ip=192.168.0.20
target_port=19999
local_udp_port=42100
```

## 3. Arduino IDE 업로드

진단 재현 시 기존 Session 환경과의 비교를 위해 아래 버전을 유지합니다.

```text
Arduino IDE = 2.3.10
esp32 by Espressif Systems = 3.3.8
Board = ESP32 Dev Module
```

Phase 6-A 진단 Build의 Firmware 식별자는 다음과 같습니다.

```text
firmware_version=phase6a-packet-rate-sender-diagnostics-v1
```

추가 라이브러리는 사용하지 않으며 ESP32 Arduino Core 기본 `WiFi`, `WiFiUDP`를 사용합니다.

업로드 후 Serial Monitor baud는 `115200`으로 설정하고 다음 항목을 확인합니다.

```text
firmware_version=phase6a-packet-rate-sender-diagnostics-v1
device_id=esp32_02
wifi_connected local_ip=192.168.0.5
expected_local_ip_match=true
target_ip=192.168.0.20
target_port=19999
auto_start=false
packet_rate_sender_ready
```

IP가 `192.168.0.5`가 아니면 공유기의 DHCP 고정 할당부터 확인하고 공격 명령을 실행하지 않습니다.

## 4. 지원 명령

```text
HELP
STATUS
START <pps> <duration_sec> <payload_bytes>
```

### Smoke Test

```text
START 10 3 64
```

정상적인 기준 예시는 다음과 같습니다.

```text
reason=duration_completed
sent 약 30
failed=0
elapsed_ms 약 3000
average_pps 약 10
```

이 진단 Smoke에서는 `packet-capture.service`를 시작하지 않습니다.

### Phase 6-A Sender 진단 Burst

Smoke Test가 정상일 때 동일 Firmware를 재부팅하지 않고 다음 순서로 실행합니다.

```text
START 80 15 64
```

첫 Burst 종료 Summary를 보존하고 잠시 대기한 뒤 같은 명령을 다시 실행합니다.

```text
START 80 15 64
```

이 절차는 **공식 Clean Holdout이 아니라 Sender 자체 진단**입니다. 이 진단만을 위해 Packet Capture Session을 만들거나 DB·Trust·Firewall 상태를 변경하지 않습니다.

## 5. 진단 Counter

기존 `sent`, `failed`, `attempted` 필드는 그대로 유지합니다. 아래 필드는 각 `START` 시 0으로 초기화되고 `STATUS`와 공격 종료 Summary에서 출력됩니다.

```text
begin_packet_fail
short_write_fail
end_packet_fail
last_end_packet_errno
schedule_skip_count
```

의미는 다음과 같습니다.

- `begin_packet_fail`: `udp.beginPacket()`이 성공값 `1`을 반환하지 않은 송신 시도 수
- `short_write_fail`: `udp.write()`가 요청한 Payload 전체 길이를 기록하지 못한 관측 횟수
- `end_packet_fail`: `udp.endPacket()`이 성공값 `1`을 반환하지 않은 관측 횟수
- `last_end_packet_errno`: 마지막 `endPacket()` 실패 직후 snapshot한 `errno`. Arduino Core 내부 호출 이후 값이므로 **best-effort 진단 힌트**이며 이 값 하나만으로 Root Cause를 확정하지 않습니다.
- `schedule_skip_count`: 기존 no-catch-up 정책으로 실제 건너뛴 예정 송신 Slot 수

`write()`와 `endPacket()`은 같은 송신 시도에서 동시에 이상일 수 있으므로 상세 Counter 합계가 항상 기존 `failed`와 같아야 하는 것은 아닙니다. 기존 `failed`는 실패한 송신 시도 수라는 의미를 유지합니다.

예를 들어 다음과 같이 관측되면 `endPacket()` 경로를 우선 조사할 근거가 됩니다.

```text
failed=453
begin_packet_fail=0
short_write_fail=0
end_packet_fail=453
last_end_packet_errno=<실측값>
schedule_skip_count=0
```

하지만 이 결과만으로 **Burst 사이 Socket 재사용이 Root Cause라고 확정하지 않습니다.** Socket lifecycle 변경은 실제 계측 결과를 확인한 뒤 별도 A/B 실험으로 판단합니다.

## 6. 종료 로그 보존

진단 시 Serial 출력에서 최소 다음 항목을 함께 보존합니다.

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
begin_packet_fail
short_write_fail
end_packet_fail
last_end_packet_errno
schedule_skip_count
elapsed_ms
average_pps
reason
```

## 7. 선택적 Raspberry Pi Raw 관측

Sender 자체 Counter만으로 원인이 충분히 좁혀지지 않으면 Raspberry Pi에서 별도의 수동 `tcpdump`를 사용할 수 있습니다.

이 경우 비교 대상은 다음처럼 분리합니다.

```text
ESP32 attempted
→ ESP32 local send success / failure
→ Pi raw tcpdump observation
```

수동 `tcpdump`는 공식 `packet-capture.service` Session 및 Packet Feature Pipeline과 별도 진단으로 취급합니다.

## 8. 운영 복구

진단이 끝난 뒤에는 `esp32_02`에 정상 수집 Firmware를 다시 업로드합니다. 진단 Firmware를 올린 상태에서도 자동 공격은 시작되지 않지만, 정상 운영 Firmware로 복구한 사실을 Serial 로그로 확인합니다.

## 검증 범위

Host-side 테스트는 Firmware 소스의 안전 계약과 진단 계측 구조만 검증합니다. 실제 ESP32 Arduino Core 3.3.8 컴파일, 업로드, UDP Runtime Counter 값, 연속 Burst 재현 여부는 실제 `esp32_02`에서 확인해야 하며 실기기 결과가 나오기 전에는 PASS로 기록하지 않습니다.
