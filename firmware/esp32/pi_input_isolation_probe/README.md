# Pi IPv4 INPUT 격리 실물 시험 앱

이 앱은 ESP32 #2 한 대의 MQTT·TCP·UDP·ICMP 통신을 독립적으로 확인한다.
정상 수집용 P0 펌웨어를 대체하는 **임시 시험 앱**이며 자동 발행·자동 probe·
자동 공격·시간 동기화·외부 주소 접속은 없다. 설치·실행과 MQTT 최초 격리는
[운영 활성화 절차](../../../docs/phase9-pi-input-isolation-activation.md)에 따라
실물 대상, 현재 원본 앱 백업, 중단·복귀 범위를 확인한 뒤 별도로 진행한다.

고정 계약은 ESP32 #2 `esp32_02` / `192.168.0.5`, Pi `192.168.0.20`이다.
MQTT는 자기 principal `esp32_02` / Topic `iot/esp32_02/sensor` / TCP 1883만 사용한다.
TCP는 기존 API 8000의 `/api/health`, UDP는 9002(기기 source port 42100), ICMP는
Pi IPv4 한 번의 echo다. 다른 주소·기기·Topic은 명령으로 선택할 수 없다.

## 빌드 준비

로컬에서 두 example 헤더를 `.example` 없는 이름으로 복사한다.
실제 Wi-Fi·MQTT 비밀번호는 gitignore된 로컬 헤더에만 넣는다. 일반 probe는
`ISOLATION_PROBE_CONFIGURED=1`, `ISOLATION_PROBE_TEST_ENABLED=1`이 필요하다.
최초 격리 burst까지 승인된 시험에만 `ISOLATION_PROBE_FLOOD_ENABLED=1`을 설정한다.
예제의 기본 값은 모두 0이다. 소스의 대상 주소나 Broker ACL을 넓히지 않는다.

Arduino `ESP32 Dev Module` / ESP32 Core 3.3.8 / PubSubClient 2.8을 사용한다.
ICMP는 Core에 포함된 ESP-IDF/lwIP raw IPv4 socket을 사용하며 별도 ping 라이브러리가
필요 없다. 비동기 ping-session 삭제를 자원 회수 완료로 간주하지 않도록, 직접 소유한
socket 하나를 모든 종료 경로에서 닫는다. 공개 example 설정만 사용한 빌드는 실물
업로드나 통신 완료 증명이 아니다.

## 수동 명령

Serial 115200 baud, Newline을 사용한다. 부팅 후에도 명령 전에는 Wi-Fi에 연결하지 않는다.

```text
CONNECT
STATUS
PROBE MQTT baseline_mqtt_01
PROBE TCP baseline_tcp_01
PROBE UDP baseline_udp_01
PROBE ICMP baseline_icmp_01
```

각 실행은 최소 10초 간격이다. nonce는 매번 새로운 8~32자리 ASCII 문자·숫자·`_`·`-`다.
이 간격은 분석 윈도우 정렬이나 정상 판정을 보장하지 않는다. 실제 메시지·대표 이벤트·
Rule·Trust의 시각과 정책 revision을 확인한다. 불명확한 응답은 같은 명령으로 재전송하지
않는다. `ABORT`는 실행 중 다음 확인 지점에 중단하고, 대기 중에는 준비된 burst를 취소한다.
TCP 연결 timeout과 PubSubClient의 개별 수신 대기는 각각 2초로 설정한다. PubSubClient
2.8은 packet의 각 byte 대기에 timeout을 다시 사용하므로 MQTT 명령 전체가 4초 안에
끝난다고 보장하지 않는다. 실제 시작·종료 시각도 기록한다. 이러한 연결 API 대기 중에는
중단 명령 처리가 다음 확인 지점까지 지연된다. 고정된 Pi Broker의 표준 CONNACK 경로를
사용하는 시험이며 범용 MQTT 서버의 전체 실행 시간 상한을 검증한 도구는 아니다.

| 확인 | 앱의 근거와 추가 확인 |
| --- | --- |
| MQTT | fresh 연결에서 Broker CONNACK 수락 여부를 기록한다. `publish_queued=true`는 로컬 송신 결과다. `probe_nonce`가 같은 **Pi mqtt_logs 실제 저장**을 별도로 조회해야 수신 완료다. 기기 ACL은 publish만 허용하므로 subscribe/echo 권한을 추가하지 않는다. |
| TCP | 실제 Pi peer와 HTTP 200, Content-Length와 일치하는 전체 body 및 유효한 health JSON을 확인한다. 잘린 JSON·unsupported Transfer-Encoding·잘못된 Content-Type은 성공으로 표시하지 않는다. nonce는 요청 header와 Serial 실행을 연결하며 API가 nonce를 echo하지는 않는다. `health_degraded`여도 TCP 응답은 성공이며 DB 정상이라고 표현하지 않는다. |
| UDP | 같은 nonce의 `P9UDP-ACK:`와 정확한 Pi IP·9002 source port를 확인한다. `endPacket()` 성공만으로 수신 성공이라고 표현하지 않는다. |
| ICMP | 요청 1개, 전체 응답 deadline 1초다. 실제 Pi source, IPv4 IHL/전체 길이, ICMP type/code·id/sequence·nonce·checksum이 모두 일치해야 echo로 기록한다. local socket/cleanup 오류와 timeout을 구분한다. |

MQTT 실패는 다른 세 probe를 막지 않는다. timeout/연결 실패만으로 격리를 확정하지 않는다.
Wi-Fi 단절·주소 이동·잘못된 자격 증명·로컬 socket 오류는 차단 증거가 아니다. 같은 시간의
정상 대조 ESP32 #1·Pico 수신, Pi 서비스/API, 정확한 Rule ID의 APPLIED·runtime match와
counter도 확인한다. 이 앱의 시험 구간과 nonce 메시지는 공식 Train/Validation에 자동 편입하지 않는다.

MQTT 시험 메시지는 기존 P0의 `device_id`, `sequence`, `uptime_s`와 구간 식별용
`probe_nonce`를 사용한다. 정상 5초 발행 loop는 수행하지 않는다. 따라서 시험 앱의
메시지 구성·중단 구간을 기존 정상 P0 수집의 연속 구간으로 기록하지 않는다.

## UDP 응답 도구

Pi에서 해당 주소가 실제 Pi이고 UDP 9002가 비어 있는지 먼저 확인한다. 승인된 실물
시험에서 일반 `pi` 사용자로 foreground 실행한다. sudo·systemd 설치가 필요 없다.

```sh
venv/bin/python infra/scripts/pi_input_udp_probe_responder.py
venv/bin/python infra/scripts/pi_input_udp_probe_responder.py --serve
```

첫 명령은 socket을 열지 않고 계획만 출력한다. 두 번째는 `.20:9002`에만 bind하며
`.5:42100`의 유효한 128B 이하 요청에만 응답한다. wildcard bind·주소 override·daemon·
root 실행은 거부한다. 전체 300초, idle 120초, 수신 30건 중 먼저 도달한 조건으로
종료한다. `Ctrl+C` 또는 SIGTERM도 socket을 닫는다. 포트 충돌은 실패로 종료하며
다른 프로세스를 정지하지 않는다. 이 도구의 `response_sent`도 기기 수신 완료 증명이
아니므로 Serial의 동일 nonce 응답과 대조한다. 다음 시험 구간에는 준비 상태를 다시 확인한다.

## 최초 MQTT 격리 시험

실물 최초 격리까지 승인된 경우에만 다음 두 명령을 사용한다.

```text
ARM MQTT_FLOOD isolation_run_01
RUN MQTT_FLOOD
```

준비는 15초 후 만료하고 `RUN`은 네트워크 동작 전에 준비를 소비한다.
자기 Topic에 정상 JSON 최대 40건을 50ms 간격으로 한 번만 보낸다. 다른 ID 위조,
비정상 JSON, UDP 공격이나 자동 재시도는 없다. 새 실행에는 새 nonce로 다시 준비해야 한다.
`attempted`·`publish_queued`·중단 여부를 기록할 뿐, 탐지·감점·격리 성공을 판정하지 않는다.
필요한 실행 횟수는 실제 효력 정책과 대표 이벤트·Trust 진행을 확인한 뒤 정한다.

## 복원

새 시험 직전에 현재 USB/serial mapping·MAC·chip·flash 크기·partition/app 범위를 확인하고
현재 원본의 새 백업과 SHA256을 보관한다. 과거 COM5·offset·길이를 자동 재사용하지 않는다.
시험 앱은 bootloader·NVS·partition을 바꾸지 않는 확인된 앱 구간만 사용할 것을 권장한다.
복귀는 실제 보존 앱 바이트의 write/verify와 부팅·기존 P0 메시지/주기·Pi 수신으로 확인한다.
재컴파일한 P0를 원본 복원이라고 부르지 않는다. 원본 flash·비밀 헤더는 저장소에 올리지 않는다.

wide Rule 정확 해제, MQTT Rule 정확 해제, 감사가 있는 기기 정상/100 복구, 앱 복원은
각각 별도 근거가 필요하다. 방화벽 해제나 펌웨어 복원만으로 Trust·기기 상태는 초기화되지 않는다.

## 검증 범위

2026/10/11 UDP helper의 nonce·source IP/port·큰 데이터그램 거부·idle/전체 수명·수신
상한·기본 실행 시 socket 미개방·root 거부를 Windows loopback에서 18개 검증했다.
Pi Python 3.10.11에서도 별도 `/tmp` 소스 사본과 loopback 임시 포트만 사용해 같은
18개가 0.36초에 통과했다(skip·warning 없음). 운영 LAN의 9002 listener, 실제 기기
패킷, host 방화벽·DB·API·서비스·root 변경이나 USB·업로드는 실행하지 않았다.

ICMP parser는 시험 앱이 사용하는 같은 순수 C++ 헤더를 native fixture에서 검사한다.
유효 echo·IPv4 options와 잘못된 source/type/code/id/sequence/nonce/checksum,
길이·fragment·IPv4 header를 구분한다. Windows에서는 native C++ compiler 부재로
이 항목을 skip했고, Pi에서 같은 헤더를 C++11·경고 오류 옵션으로 컴파일한 뒤 23개
사례를 실행해 통과했다. UDP를 포함한 최종 Pi pytest는 19개 모두 통과했다(skip·warning 없음).

최종 소스 `f4542733`와 protocol 헤더 `6191bab1`를 동결한 뒤 Arduino CLI 1.5.1 /
ESP32 Core 3.3.8(ESP-IDF 5.5.4) / PubSubClient 2.8에서 probe 전용과 수동 burst 활성화
구성 두 빌드가 통과했다. `CONFIGURED=0`은 의도한 compile 오류로 거부돼 3개 기대 결과가
모두 일치했다. 공개 example와 비밀이 아닌 compile 전용 값만 사용했고 비밀 헤더는 읽지
않았다. ICMP C++ fixture의 C++11 문법 검사와 Pi의 23개 frame case native 실행도
통과했다. 이 결과는 실물 flash·소켓·통신·차단·복원 검증을 대신하지 않는다.
