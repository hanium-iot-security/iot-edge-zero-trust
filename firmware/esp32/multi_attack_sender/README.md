# ESP32 #2 다중 공격 시연 펌웨어

`multi_attack_sender.ino`는 승인된 내부 테스트베드에서 ESP32 #2가 아래 네 가지
이상 행위를 한 번의 `RUN_DEMO` 명령으로 순차 실행하도록 만든 시연 전용
펌웨어입니다.

```text
IDENTITY_MISMATCH -> MALFORMED_PAYLOAD -> PACKET_RATE -> MQTT_FLOOD
```

각 단계는 UTC 기준으로 서로 다른 10초 분석 윈도우가 시작된 직후 실행됩니다.
따라서 대시보드에서는 단계별 이벤트와 Trust 변화를 분리해 보여주기 쉽습니다.
정책 임계값이 모두 적용된 테스트베드의 예상 흐름은
`100 → 75 → 65 → 45 → 25`이지만, 실제 판정 결과는 Edge 로그·DB·대시보드를
기준으로 확인해야 합니다.

> 이 펌웨어는 소유하거나 명시적으로 허가받은 사설 테스트베드에서만
> 사용합니다. 외부 주소, 운영망 또는 제3자 장비를 대상으로 사용하지 않습니다.

## 고정 테스트베드 계약

| 항목 | 값 |
| --- | --- |
| 실행 장치 | ESP32 #2 (`esp32_02`) |
| ESP32 #2 고정 IP | `192.168.0.5` |
| Broker·Edge 대상 | Raspberry Pi 5, `192.168.0.20` |
| MQTT Topic | `iot/esp32_02/sensor` |
| MQTT Port | `1883` |
| Packet Rate UDP Port | `19999` |

사전 점검에서 실제 ESP32 IP가 `192.168.0.5`와 다르거나 대상이 사설 IPv4가
아니면 실행을 거부합니다. 공유기 DHCP 예약과 DB의 ESP32 #2 IP 매핑을 먼저
확인해야 Trust 감점과 자동 격리까지 관측할 수 있습니다.

## 준비 및 업로드

Arduino IDE 권장 설정은 다음과 같습니다.

```text
Board: ESP32 Dev Module
Library: PubSubClient
Serial Monitor: 115200 baud, Newline
```

예제 설정 파일을 같은 폴더의 로컬 설정 파일로 복사합니다.

```powershell
Copy-Item multi_attack_firmware_config.example.h multi_attack_firmware_config.h
Copy-Item mqtt_credentials.example.h mqtt_credentials.h
```

`multi_attack_firmware_config.h`에서 실제 테스트 Wi-Fi를 입력하고, 계약을 모두
확인한 뒤에만 아래 두 값을 `1`로 바꿉니다.

```cpp
#define MULTI_ATTACK_CONFIGURED 1
#define MULTI_ATTACK_TEST_ENABLED 1
```

Broker가 인증을 사용하면 `mqtt_credentials.h`에 계정을 입력합니다. 두 로컬
설정 파일은 `.gitignore` 대상이며 실제 SSID·비밀번호를 커밋하지 않습니다.
Broker ACL은 ESP32 #2가 자기 Topic만 publish할 수 있도록 유지합니다.
`IDENTITY_MISMATCH`는 Topic을 위조하지 않고 payload의 `device_id`만
`esp32_01`로 바꿉니다.

## 촬영용 실행 순서

1. Pi 5의 Broker·Edge·Backend·Frontend와 패킷 수집을 먼저 시작합니다.
2. DB에서 ESP32 #2가 `192.168.0.5`에 매핑됐고 Trust가 시연 시작값인지
   확인합니다.
3. ESP32 #2에 이 펌웨어를 업로드하고 Serial Monitor를 115200 baud와
   Newline으로 엽니다.
4. `STATUS`를 입력해 `auto_start=false`, IP·MQTT·시간 동기화 상태를
   확인합니다.
5. 대시보드에서 ESP32 #2 상세 또는 실시간 이벤트가 보이는 화면을 띄웁니다.
6. Serial Monitor에 `RUN_DEMO`를 한 번 입력합니다.
7. Serial의 `[DEMO 1/4]`부터 `[DEMO 4/4]`까지와 대시보드 변화를 함께
   촬영합니다. 단계 사이 10초 윈도우 대기는 편집에서 2~4배속할 수 있습니다.
8. 마지막 단계 뒤 최대 45초의 제한된 격리 관측에서 publish 실패,
   연결 끊김 또는 재연결 실패를 확인합니다.
9. 촬영 후 전원을 껐다 켜고 `normal_sender` 펌웨어로 반드시 복구합니다.

`RUN_DEMO`는 부팅당 한 번만 허용됩니다. 재촬영하려면 ESP32를 재부팅해야
합니다. 펌웨어는 Trust, DB 기록 또는 방화벽을 초기화하지 않으므로 재촬영 전
복구는 서버 운영 절차에 따라 별도로 수행합니다.

## Serial 명령

| 명령 | 동작 |
| --- | --- |
| `RUN_DEMO` | 네 공격을 정해진 순서와 별도 10초 윈도우로 한 번씩 실행 |
| `RUN IDENTITY_MISMATCH` | payload 기기 식별자 불일치 1건 전송 |
| `RUN MALFORMED_PAYLOAD` | 비정상 JSON payload 3건 전송 |
| `RUN PACKET_RATE` | Pi 5로 20 pps UDP를 6초간 전송 |
| `RUN MQTT_FLOOD` | 정상 스키마 메시지 40건을 50 ms 간격으로 전송 |
| `STATUS` | 현재 연결·동기화·시연 상태 출력 |
| `ABORT` | 진행 중인 시연을 다음 안전 중단 지점에서 종료 |
| `HELP` | 명령 목록 출력 |

개별 `RUN ...` 명령은 공격 하나의 배선·탐지 여부를 점검할 때만 사용합니다.
최종 시연에서는 `RUN_DEMO` 하나를 사용해야 순서와 화면 전환이 일정합니다.

## 실패 시 확인

- `test_not_enabled`: `MULTI_ATTACK_TEST_ENABLED`가 `1`인지 확인합니다.
- `local_ip_mismatch`: 공유기의 DHCP 예약과 ESP32 #2 실제 IP를 확인합니다.
- `mqtt_connect_timeout`: Pi 5의 Mosquitto, ACL, 계정과 방화벽을 확인합니다.
- `time_sync_unavailable`: 인터넷·NTP 연결을 복구합니다. 서로 다른 10초 분석
  윈도우를 보장할 수 없으므로 시간 동기화 실패 시 공격을 실행하지 않습니다.
- 이벤트만 남고 Trust 감점·격리가 없다면 DB의 IP-기기 매핑과 정책 활성화를
  확인합니다. 미등록 공격 노드라면 탐지 기록만 남는 것이 정상일 수 있습니다.

자동 격리의 실기기 종단간 결과는 Pi 5와 ESP32 #2가 켜진 현장에서 최종
확인해야 합니다. 이 폴더의 정적 테스트와 로컬 컴파일은 핀·전원·공유기·ACL을
대체하지 않습니다.
