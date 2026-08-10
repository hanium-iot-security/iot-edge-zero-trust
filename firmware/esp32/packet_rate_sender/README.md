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

진단 재현 시 기존 Session 환경과의 비교를 위해 아래 조건을 유지합니다.

```text
Arduino IDE = 2.3.10
esp32 by Espressif Systems = 3.3.8
Board = ESP32 Dev Module
Core Debug Level = None
```

`Core Debug Level`은 `None`으로 고정합니다. Error 이상으로 올리면 Arduino Core 내부 UDP 실패 로그가 packet 단위로 출력되어 80 PPS 진단 타이밍에 영향을 줄 수 있으므로, Debug Level을 바꾼 재시험은 별도 Run으로 취급합니다.

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
- `short_write_fail`: `udp.write()`가 요청한 Payload 전체 길이를 기록하지 못한 관측 횟수. 현재 기준인 Arduino-ESP32 3.3.8과 `payload_bytes <= 1400` 조건에서는 구현 특성상 구조적으로 `0`이 예상되며, 일반적인 단계 구분을 위한 보조 Counter로 유지합니다.
- `end_packet_fail`: `udp.endPacket()`이 성공값 `1`을 반환하지 않은 관측 횟수
- `last_end_packet_errno`: 마지막 `endPacket()` 실패 직후 snapshot한 `errno`. Arduino Core 내부 호출 이후 값이므로 **best-effort 진단 힌트**이며 이 값 하나만으로 Root Cause를 확정하지 않습니다.
- `schedule_skip_count`: 기존 no-catch-up 정책으로 실제 건너뛴 예정 송신 Slot 수

`write()`와 `endPacket()`은 같은 송신 시도에서 동시에 이상일 수 있으므로 상세 Counter 합계가 항상 기존 `failed`와 같아야 하는 것은 아닙니다. 기존 `failed`는 실패한 송신 시도 수라는 의미를 유지합니다.

## 6. 2026-08-11 실기기 검증 결과

### 빌드 및 기본 상태

- Host-side pytest: `14 passed in 0.10s`
- Arduino compile: PASS
  - Sketch: `923376 bytes (70%)`
  - Global variables: `48472 bytes (14%)`
- ESP32 #2 업로드 및 `STATUS`: PASS
- `wifi_connected=true`, `expected_local_ip_match=true`, `udp_ready=true` 확인

### 10 PPS Smoke

최초 Smoke 1회에서 다음 간헐 실패가 관측됐습니다.

```text
attempted=30
sent=3
failed=27
begin_packet_fail=0
short_write_fail=0
end_packet_fail=27
last_end_packet_errno=12
schedule_skip_count=0
```

이후 같은 Socket에서 Smoke 2회는 각각 `30/30` 정상 완료됐고, ESP32 재부팅 후 Fresh Boot 첫 Smoke도 `30/30` 정상 완료됐습니다.

따라서 최초 실패는 실제 관측된 미해결 현상이지만, 이번 검증만으로 부팅 직후 첫 Burst, Socket 재사용, Wi-Fi, 메모리 부족 중 어느 하나를 Root Cause로 확정하지 않습니다.

### 80 PPS × 15초

`START 80 15 64` 반복 Run에서는 4회 모두 다음과 같이 정상 완료됐습니다.

```text
attempted=1200
sent=1200
failed=0
begin_packet_fail=0
short_write_fail=0
end_packet_fail=0
last_end_packet_errno=0
schedule_skip_count=0
elapsed_ms=15000
average_pps=80.00
```

현재 통제 조건에서는 Phase 5 Session 56의 두 번째 Burst에서 관측된 `failed=453`이 재현되지 않았습니다.

### Raspberry Pi raw 관측

Raspberry Pi는 `eth0=192.168.0.20/24`, `wlan0=DOWN` 상태에서 수동 `tcpdump`로 확인했습니다.

```bash
sudo tcpdump -ni eth0 -q 'udp and src host 192.168.0.5 and dst host 192.168.0.20 and dst port 19999' > /dev/null
```

Raw 비교 결과:

```text
Run #1: ESP32 sent=1200 / Pi captured=1200 / received by filter=1202 / kernel drop=0
Run #2: ESP32 sent=1200 / Pi captured=1200 / received by filter=1200 / kernel drop=0
```

비교 기준인 ESP32 `sent`와 Pi `packets captured`는 두 Run 모두 `1200 ↔ 1200`으로 일치했습니다. 따라서 이번 통제 조건에서는 과거 Session 53/55/56에서 보였던 Sender↔Gateway observation gap이 재현되지 않았습니다.

현재 판정은 다음과 같습니다.

- 진단 Counter는 실패 단계를 구분하는 데 유효했습니다.
- 최초 10 PPS Smoke에서 간헐 `endPacket()` 실패 27건이 1회 관측됐습니다.
- 이후 동일 Socket/Fresh Boot/80 PPS 반복에서는 해당 실패가 재현되지 않았습니다.
- Sender→Pi raw path는 2회 연속 `1200 ↔ 1200`, kernel drop 0으로 정상 확인됐습니다.
- Wi-Fi, Socket reuse, 메모리 부족 중 어느 하나를 Root Cause로 확정하지 않습니다.
- retry 또는 Burst 사이 Socket restart는 이번 PR에 추가하지 않습니다.

## 7. 종료 로그 보존

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

실기기 증적에는 사용한 Arduino IDE 버전, ESP32 Core 버전, Board, `Core Debug Level=None`도 함께 기록합니다.

## 8. 선택적 Raspberry Pi Raw 관측

Sender 자체 Counter만으로 원인이 충분히 좁혀지지 않으면 Raspberry Pi에서 별도의 수동 `tcpdump`를 사용할 수 있습니다.

이 경우 비교 대상은 다음처럼 분리합니다.

```text
ESP32 attempted
→ ESP32 local send success / failure
→ Pi raw tcpdump observation
```

수동 `tcpdump`는 공식 `packet-capture.service` Session 및 Packet Feature Pipeline과 별도 진단으로 취급합니다.

## 9. 운영 복구

진단이 끝난 뒤에는 `esp32_02`에 정상 수집 Firmware를 다시 업로드합니다. 진단 Firmware를 올린 상태에서도 자동 공격은 시작되지 않지만, 정상 운영 Firmware로 복구한 사실을 Serial 로그로 확인합니다.

## 검증 범위

Host-side 테스트는 Firmware 소스의 안전 계약과 진단 계측 구조를 검증합니다. 이번 실기기 검증에서는 Arduino Core 3.3.8 compile, ESP32 업로드, STATUS, Smoke/Burst Runtime 및 Pi raw observation까지 확인했습니다. 다만 최초 간헐 `endPacket()` 실패의 Root Cause는 여전히 미확정이며, 이번 결과만으로 과거 Session 56 문제가 해결됐다고 표현하지 않습니다.
