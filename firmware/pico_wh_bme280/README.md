# Pico WH / BME280 MQTT 센서

Pico W/WH에서 실제 BME280 온도·습도·기압을 읽어 `pico_01`의 센서 Topic으로
보내는 MicroPython 펌웨어다. 호스트 검증기는 실제로 수집한 기록을 검사한다.
비밀 설정과 실장비 증적은 이 디렉터리에 커밋하지 않는다.

## 배선과 센서 확인

| Pico | BME280 모듈 |
| --- | --- |
| 3V3(OUT) | VCC |
| GND | GND |
| GP4, physical pin 6 | SDA / MOSI |
| GP5, physical pin 7 | SCL / SCK |

I2C0, 100 kHz, 주소 `0x76`을 사용한다. 먼저 scan에서 `0x76`의 ACK를
확인하고, 레지스터 `0xD0`의 값이 BME280 ID `0x60`인지 읽는다. `[]`이거나
ID가 다르면 측정·MQTT 단계로 넘어가지 않는다. `0x77`만 보이면 실제 모듈의
주소 설정을 확인한다. 이 sender는 `0x76`으로 고정되어 있다.

CS/ADDR 배선은 실제 모듈의 문서를 따른다. [SEENGREAT 모듈](https://seengreat.com/wiki/87/bme280-environmental-sensor)은
I2C에서 CS와 MISO/ADDR를 NC로 두고 보드 switch로 주소를 선택한다.
원칩 기준으로는 CSB가 VDDIO에 연결되어야 하며 SDO의 low/high가
`0x76`/`0x77`을 결정한다. CSB가 한 번 low가 되면 다음 power-on-reset까지
I2C가 비활성화될 수 있다. 모듈의 저항·switch 연결을 확인하지 않고 외부
CS/ADDR 연결을 추가하지 않는다. [Bosch 데이터시트 §6.1–6.2](https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bme280-ds002.pdf)를
참고한다.

## 설정과 설치

MicroPython이 설치된 Pico에 `bme280.py`, `telemetry_sender.py`,
`lib/umqtt/__init__.py`, `lib/umqtt/simple.py`, `lib/umqtt/LICENSE.txt`를
복사한다. `verify_pico_telemetry.py`는 PC 호스트 전용이며 Pico에 설치하지
않는다. 부팅 파일을 바꾸기 전 기존 파일을 비공개 로컬 경로에 백업한다.

`config.example.py`를 참고해 Pico에 별도 `config.py`를 만든다. 실제 Wi-Fi
SSID/비밀번호, broker의 숫자 IPv4 주소, 전용 MQTT principal/비밀번호를
설정한다. 예제 주소와 `REPLACE_` 값을 그대로 쓰면 sender가 거부한다.
`DEVICE_ID`는 `pico_01`, `MQTT_TOPIC`은 `iot/pico_01/sensor`여야 한다.
이 폴더의 `.gitignore`는 실제 `config.py`, JSON/CSV/JSONL 증적과 로그를
제외한다. 설정 내용과 인증값을 증적 출력에 넣지 않는다.

아래 검증 gate를 통과할 때까지 자동 실행용 `main.py`를 Pico에 설치하지
않는다. 개발 중에는 REPL에서 직접 실행한다.

```python
import telemetry_sender
telemetry_sender.main()
```

최종 운영 설정을 확인한 뒤 이 폴더의 `main.py`를 복사하면 부팅 시 같은
sender를 시작한다. 개발·복구 시 USB REPL에서 Ctrl-C로 중단한다. 센서
측정과 연결 대기는 짧은 sleep 또는 제한된 I/O를 사용한다. 중단 시 MQTT
socket을 닫는다. 부팅 재시작을 원하지 않으면 먼저 `main.py`를 비공개
백업한 뒤 Pico에서 이름을 바꾸거나 제거한다. 이미 실행 중인 sender에
새로운 raw-REPL 연결을 열면 연결 도구의 Ctrl-C가 sender를 중단할 수 있다.

## 송신 계약

- 실제 측정 성공 뒤 `device_id`, `seq`, `uptime_ms`, `temperature_c`,
  `humidity_pct`, `pressure_hpa`를 JSON으로 보낸다. 기압은 hPa다.
- 다음 측정은 이전 처리 완료 후 5초 뒤다. 긴 작업이나 재연결 이후 누락된
  값을 재전송하거나 몰아서 보내지 않는다. `uptime_ms`는 sender 실행 이후
  누적 시간이며, 각 실행에서 sequence가 다시 시작한다.
- QoS 0, retain false, 최대 payload 5120 bytes다. `publish_sent`는 로컬
  송신 호출의 성공이며 broker 수신 ACK나 DB 적재 성공을 뜻하지 않는다.
- 센서 오류에는 기본값이나 이전 측정값을 보내지 않는다. 해당 `seq`를
  오류로 기록하고 다음 측정에서 센서를 다시 초기화한다. 따라서 오류가 난
  구간은 정상 연속 수신 검증을 통과하지 못한다.
- Wi-Fi 연결 대기는 15초, MQTT socket I/O는 5초 제한이다. 재시도 간격은
  1/2/4/8/16/30초이며 성공한 publish 이후 초기화한다. 설정과 인증값을
  로그에 출력하지 않는다.

## 실측·등록·수신 gate

1. 새 실행에서 scan `0x76`, ID `0x60`, driver 생성자 성공을 기록한다.
   같은 driver로 5초 간격 7회 측정하고 7개의 JSONL 행을 별도 로컬 output에
   저장한다. 각 행은 위 여섯 payload 필드와 `raw_t`, `raw_h`, `raw_p`,
   측정 직후 실제로 읽은 `ctrl_hum`(0xF2), `ctrl_meas`(0xF4), `status`(0xF3)를
   포함한다. x1 활성 설정은 `ctrl_hum & 7 == 1`, `ctrl_meas == 0x24`이며,
   `status & 0x09 == 0`이어야 한다. forced 변환이 끝나면 mode 비트는 sleep인
   `00`으로 돌아온다. 이전 proof 행에 상태 값을 추정해서 채워 넣지 않는다.
   실행 시각, 실제 scan/ID, 실행 소스 SHA256은 별도 metadata로
   보관한다. 센서 proof만으로 MQTT 수신이나 물리 출처의 인증을 주장하지
   않는다.
2. DHCP 예약과 실제 IP, `pico_01` 등록, 자기 Topic의 전용 publish ACL을
   확인한다. 초기 PENDING revision의 유효 경계와 자동 대응 제외 상태를
   확인한다. 기존 다른 기기의 정책·점수·격리를 대조한다.
3. sender를 시작하고 최소 12개의 연속 실제 gateway 행을 확인한다.
   `seq`는 정확히 1씩 증가하고 약 5초 주기를 유지해야 한다. 기존 ACL 시험
   payload를 포함하지 않도록 sender 시작 시각과 수신 행 범위를 고정한다.
4. 운영 절차를 통해 ACTIVE 승격을 예약하고, 경계 이후 API에서 실제 current
   ACTIVE revision을 확인한다. 경계 이후 약 2분 이상 정상 수신·MQTT/Packet
   feature·필수 checkpoint 전진·처리 gap 없음·신선한 Firewall snapshot과
   정상 기기의 점수/격리 상태를 확인한다. PENDING 수신 확인을 ACTIVE 전체
   처리 완료와 구분한다. 이전 window를 소급 정상 처리하지 않는다.

공통 Packet IF와 AI observe 설정을 유지한다. 이 센서 연결·검증은 모델
재학습이나 Pico 정상 분포의 적합성 확인을 뜻하지 않는다.

## PC에서 실제 기록 검증

프로젝트 root에서 다음처럼 실행한다. 입력 증적은 Git에서 제외된 `output/`
아래에 두고, report는 입력과 다른 경로로 지정한다.

```bash
python firmware/pico_wh_bme280/verify_pico_telemetry.py --mode sensor-proof --input output/sensor-proof-samples.jsonl --report output/sensor-proof-report.json
python firmware/pico_wh_bme280/verify_pico_telemetry.py --mode gateway --input output/gateway-pico-rows.jsonl --payload-max 5120 --report output/gateway-pico-report.json
```

gateway JSONL은 실제 `mqtt_logs`의 `device_id`, `topic`, `payload`,
`payload_size`, `received_at`, `is_json_valid`, `is_topic_valid`,
`error_message`를 모두 포함해야 한다. sensor-proof 모드는 세 raw 필드와 세
control/status 필드의 누락, 채널 비활성·설정 불일치·미완료 변환을 거부한다.
gateway 모드는 위 원본 수신 필드의 누락을 거부한다. 두 모드 모두
sequence 누락·중복, 비정상 수치와 주기 중단을 거부한다. gateway에서는
attribution/flag/byte size도 검사한다. 입력을 생성하지 않으며
하드웨어·등록·principal 인증·정책·Trust·
Firewall은 직접 검증하지 않는다. 운영 확인을 별도로 수행한다.

드라이버는 변환 완료와 x1 채널 활성 상태를 readback으로 확인한다.
`0x80000`(온도·기압)이나 `0x8000`(습도)라는 raw 숫자만으로 실패시키지
않는다. 이 값들은 skipped 채널의 출력이지만 활성 채널의 값으로는 금지되어
있지 않다. 유효 숫자를 오인할 가능성을 제거한 변경이며, 이전 단발
`RuntimeError`의 원인을 확정한 것은 아니다. 보정 후 유한 수치·동작 범위
검사와 센서 오류 시 무송신 계약은 유지한다.

보정 식의 근거와 `umqtt.simple` 원본 SHA256·라이선스는
[PROVENANCE.md](PROVENANCE.md)에 기록했다.
