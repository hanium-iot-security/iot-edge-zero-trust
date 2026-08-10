# Packet Rate Sender 진단 설계

기준일: 2026-08-11

## 1. 목적

Phase 5 Session 56의 두 번째 Packet Rate Burst에서 발생한 `attempted=1200`, `sent=747`, `failed=453`의 원인을 기존 송신 동작을 변경하지 않고 계측으로 좁힌다.

이번 변경은 Root Cause 진단용이며, Packet Rate Sender의 공격 패턴·속도·Socket lifecycle·재시도 정책을 수정하지 않는다.

## 2. 현재 확인된 사실

현재 `firmware/esp32/packet_rate_sender/packet_rate_sender.ino`는 한 Packet 송신에서 다음 순서를 사용한다.

```text
udp.beginPacket()
→ udp.write()
→ udp.endPacket()
```

그러나 세 단계의 실패를 모두 `failedPackets` 하나로 합산하므로 Session 56의 `failed=453`이 어느 단계에서 발생했는지 기존 로그만으로 구분할 수 없었다.

Session 56 두 번째 Burst는 `80 PPS × 15초 = 1200`과 동일한 `attempted=1200`을 기록했으므로, 해당 Run에서는 1200개의 송신 시도 자체가 수행됐다. 따라서 단순 Scheduler missed-slot만으로 453건의 실패를 설명할 수 없다.

진단 환경은 `Arduino IDE 2.3.10`, `esp32 by Espressif Systems 3.3.8`, `ESP32 Dev Module`, `Core Debug Level=None`으로 고정한다.

## 3. 범위

### 포함

- 진단 Build를 기존 Phase 5 Firmware와 구분할 수 있도록 Firmware version을 `phase6a-packet-rate-sender-diagnostics-v1`으로 변경
- `beginPacket()` 실패 횟수 계측
- `write()`가 요청 Payload 길이보다 적게 기록한 횟수 계측
- `endPacket()` 실패 횟수 계측
- `endPacket()` 직후 `errno` snapshot 보존
- 마지막 `endPacket()` 실패 errno 표시
- Scheduler가 기존 no-catch-up 정책으로 실제 건너뛴 송신 Slot 수 계측
- `STATUS`와 공격 종료 Summary에 진단 Counter 출력
- 기존 Host-side 정적 회귀 테스트에 진단 계약 추가
- README에 진단 필드와 실기기 진단 절차 문서화

### 제외

- `udp.stop()` / `udp.begin()`을 Burst 사이에 새로 호출하는 변경
- UDP Socket lifecycle 변경
- 송신 실패 재시도
- PPS 또는 duration 변경
- Payload 크기 변경
- `delay()`를 통한 송신 속도 조정
- 송신 실패마다 Serial을 출력하는 per-packet 로그 추가
- Packet Rule / Packet IF Threshold 변경
- Packet Capture / DB / Trust / Firewall 상태 변경
- Session 56 기존 DB·History 변경

## 4. 진단 Counter 계약

각 Burst 시작 시 기존 `sentPackets`, `failedPackets`와 함께 아래 값을 0으로 초기화한다.

```text
begin_packet_fail
short_write_fail
end_packet_fail
schedule_skip_count
last_end_packet_errno
```

`failedPackets`는 기존 호환성을 위해 유지한다. 한 송신 시도에서 `beginPacket()`이 실패하면 `begin_packet_fail`과 기존 `failed`를 각각 1 증가시킨다. `beginPacket()` 성공 후에는 `write()` 결과와 `endPacket()` 결과를 모두 관측하고, 둘 중 하나라도 정상 조건을 만족하지 않으면 기존 `failed`는 한 번만 증가시킨다.

`write()`와 `endPacket()`은 하나의 송신 시도에서 동시에 이상일 수 있으므로 다음 상세 Counter의 합을 기존 `failed`와 억지로 동일하게 만들지 않는다.

```text
begin_packet_fail
short_write_fail
end_packet_fail
```

상세 Counter는 실패 단계별 관측값이며, `failed`는 기존과 동일하게 실패한 송신 시도 수를 의미한다.

Arduino-ESP32 3.3.8의 현재 `NetworkUDP::write(buffer, size)` 구현과 이 Firmware의 `payload_bytes <= 1400` 상한에서는 `short_write_fail`은 구조적으로 `0`이 예상된다. 이 Counter는 다른 Core/구현으로 변경될 때도 단계 구분 계약을 유지하기 위한 보조 계측이며, 현재 실험에서 `short_write_fail=0` 자체를 정상 송신의 충분조건으로 해석하지 않는다.

## 5. errno 계측 계약

`errno`는 전역 상태이므로 Firmware에서는 `udp.endPacket()` 반환 직후 다른 Firmware 함수 호출 전에 즉시 snapshot한다.

```text
endResult = udp.endPacket()
endErrno = errno
```

다만 Arduino-ESP32 3.3.8의 `endPacket()` 내부에서는 `sendto()` 실패 후 Core의 `log_e()`를 거친 뒤 반환할 수 있으므로, Firmware가 읽는 값은 엄밀한 `sendto()` 직후 값이 아니라 **best-effort 진단 힌트**로 취급한다.

`endResult != 1`인 경우에만 `last_end_packet_errno`를 갱신한다.

성공한 `endPacket()` 뒤의 errno 값은 이전 오류가 남아 있을 수 있으므로 의미 있는 실패 근거로 사용하지 않는다.

이번 진단 PR은 errno histogram이나 특정 errno 원인 매핑을 구현하지 않는다. 실제 ESP32 실행 결과를 근거로 후속 진단 필요성을 판단한다.

## 6. Scheduler 계측 계약

현재 Scheduler는 늦어진 경우 누락된 Slot을 Catch-up Burst로 보내지 않고 다음 미래 Slot으로 이동한다. 이 정책은 그대로 유지한다.

`sendScheduledPacket()` 이후 기존 코드가 다음 예정 시각을 한 Interval 전진시킨 뒤에도 `afterSendUs`가 그 예정 시각 이상이면, 다음 식으로 실제 건너뛸 Slot 수를 계산해 `schedule_skip_count`에 누적한다.

```text
skipped_slots = floor((afterSendUs - nextPacketAtUs) / attackIntervalUs) + 1
```

그 뒤의 기존 동작은 그대로 `nextPacketAtUs = afterSendUs + attackIntervalUs`로 유지한다.

이 Counter는 UDP API 실패 횟수와 별도이며, `attempted`가 목표 송신량보다 줄어든 경우 Scheduler 지연이 실제로 얼마만큼 관여했는지 구분하기 위한 참고값이다.

Host-side 회귀 테스트에서는 대표 경계값과 32-bit `micros()` wrap-around 경계의 skipped-slot 계산을 별도로 검증한다.

## 7. Serial 출력

기존 필드는 삭제하거나 이름을 바꾸지 않는다.

추가 필드 예시는 다음과 같다.

```text
begin_packet_fail=0
short_write_fail=0
end_packet_fail=453
last_end_packet_errno=11
schedule_skip_count=0
```

`STATUS`와 `packet_rate_attack_finished` Summary에서 동일한 이름을 사용한다. Burst 진행 중에는 이 Counter 때문에 packet별 Serial 출력이나 추가 blocking I/O를 수행하지 않는다.

## 8. 테스트 전략

Host-side 테스트는 실제 UDP Runtime 성공 여부를 증명하지 않는다. 다음 정적·산술 계약을 검증한다.

- 진단 Firmware version이 기존 Phase 5 Build와 구분됨
- 기존 Serial-only 실행 계약 유지
- 기존 100 PPS / 15초 / 1400B 상한 유지
- 기존 no-catch-up 정책 유지
- 신규 단계별 Counter가 존재함
- Burst 시작 시 Counter가 초기화됨
- `endPacket()` 반환 직후 errno를 snapshot함
- 기존 `failedPackets` 필드와 Summary가 유지됨
- 한 송신 시도에서 `failedPackets`가 실패 경로별 최대 1회 증가함
- `schedule_skip_count`가 실제 skipped slot 수를 누적함
- 대표 경계값과 32-bit wrap-around 입력에서 skipped-slot 산술이 의도한 값을 반환함
- Socket stop/restart 또는 retry 로직이 Burst 정상 종료 경로에 새로 추가되지 않음
- Burst 내부 packet별 Serial 실패 로그가 추가되지 않음

최신 Host-side 실행 결과는 `14 passed in 0.10s`이다. 이 결과는 소스 계약 검증이며 ESP32 Runtime 성공을 단독으로 증명하지 않는다.

## 9. 실기기 진단 절차

공식 Clean Holdout과 분리된 Sender 진단으로 실행한다. `packet-capture.service`를 공식 Session 용도로 시작하지 않고, DB·Trust·Firewall을 변경하지 않는다.

재현 조건은 다음으로 고정하고 증적에 함께 남긴다.

```text
Arduino IDE = 2.3.10
esp32 by Espressif Systems = 3.3.8
Board = ESP32 Dev Module
Core Debug Level = None
```

`Core Debug Level`은 `None`으로 유지한다. Error 이상으로 변경하면 Arduino Core 내부 UDP 실패 로그가 packet 단위로 출력되어 80 PPS 타이밍에 영향을 줄 수 있으므로, Debug Level을 변경한 재시험은 별도 Run으로 분리한다.

기본 실행 순서는 다음과 같다.

```text
1. 위 Arduino/Core/Board/Debug 조건 확인
2. 진단 Firmware 컴파일/업로드
3. STATUS 확인
4. START 10 3 64
5. 종료 Summary 저장
6. START 80 15 64
7. 종료 Summary 저장
8. 잠시 대기
9. START 80 15 64
10. 종료 Summary 저장
```

필요하면 Raspberry Pi에서 별도 수동 `tcpdump`를 함께 사용하여 ESP32 local send success와 Pi raw observation을 비교한다. 이 비교는 Packet Capture Session/Feature Pipeline과 별도 진단으로 취급한다.

## 10. 판정 기준

예시 A:

```text
begin_packet_fail=0
short_write_fail=0
end_packet_fail≈failed
```

이면 `endPacket()` 내부 송신 경로 실패 가설이 강해진다.

예시 B:

```text
begin_packet_fail≈failed
```

이면 Socket 준비/상태 쪽을 우선 조사한다.

현재 Arduino-ESP32 3.3.8 + 1400B 이하 조건에서 `short_write_fail>0`이 실제 관측되면 예상 계약과 다른 결과이므로, 즉시 Buffer/Write 경로와 사용 Core/Build 조건을 재확인한다. 그러나 `short_write_fail=0`만으로 UDP 전송 성공을 확정하지 않는다.

예시 D:

```text
attempted < requested_pps × duration_sec
schedule_skip_count > 0
```

이면 Scheduler 지연이 송신 시도 수 감소에 관여한 것으로 판단한다. 단, UDP API 실패와 Scheduler 지연이 동시에 존재할 수 있으므로 두 Counter를 독립적으로 해석한다.

`end_packet_fail`이 확인되더라도 이번 PR만으로 Socket 재사용이 Root Cause라고 확정하지 않는다. 실제 반복 결과가 Socket lifecycle 변경 필요성을 뒷받침할 때에만 별도 A/B 변경을 검토한다.

## 11. 성공 조건

이번 진단 PR의 성공 조건은 "문제가 해결됨"이 아니라 다음과 같다.

- 기존 Sender 공격 동작과 안전 상한이 유지된다.
- 진단 Build를 기존 Phase 5 Firmware와 로그에서 구분할 수 있다.
- `failed`의 발생 단계를 실기기 로그에서 분리할 수 있다.
- Scheduler 지연과 UDP API 실패를 구분할 수 있다.
- 진단 계측 자체가 80 PPS 송신 타이밍을 불필요하게 교란하지 않는다.
- 실제 결과가 나오기 전 Root Cause를 과장하지 않는다.
- 이후 최소 수정 방향을 실측 근거로 결정할 수 있다.

## 12. 2026-08-11 실기기 진단 결과

### 12.1 빌드 및 시작 상태

- Host-side pytest: `14 passed in 0.10s`
- Arduino compile: PASS
  - Sketch: `923376 bytes (70%)`
  - Global variables: `48472 bytes (14%)`
- ESP32 #2 업로드: PASS
- `STATUS` 확인:
  - `firmware_version=phase6a-packet-rate-sender-diagnostics-v1`
  - `wifi_connected=true`
  - `local_ip=192.168.0.5`
  - `expected_local_ip_match=true`
  - `target_ip=192.168.0.20`
  - `target_port=19999`
  - `udp_ready=true`
  - 진단 Counter 초기값 전부 `0`

### 12.2 10 PPS Smoke

최초 Smoke에서 다음 간헐 실패가 1회 재현됐다.

```text
attempted=30
sent=3
failed=27
begin_packet_fail=0
short_write_fail=0
end_packet_fail=27
last_end_packet_errno=12
schedule_skip_count=0
elapsed_ms=3000
average_pps=1.00
```

이 결과는 실패가 Scheduler, `beginPacket()`, short write가 아니라 `endPacket()` 반환 실패와 함께 나타났음을 보여준다. 단, `errno=12`는 best-effort 값이므로 메모리 부족 등 특정 Root Cause를 확정하는 근거로 사용하지 않는다.

같은 Socket을 유지한 이후 Smoke 2회는 각각 `sent=30`, `failed=0`, `attempted=30`으로 정상 완료됐다. ESP32를 재부팅한 뒤 Fresh Boot 첫 Smoke도 `30/30`으로 정상 완료됐다.

따라서 이번 결과만으로 "부팅 직후 첫 Burst 실패" 또는 "Socket 재사용 실패"를 재현성 있는 원인으로 확정할 수 없다.

### 12.3 80 PPS × 15초 반복

`START 80 15 64`를 반복 실행한 결과 4개 Run 모두 다음 조건으로 정상 완료됐다.

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

따라서 현재 통제 조건에서는 Phase 5 Session 56 두 번째 Burst의 `failed=453`을 재현하지 못했다.

### 12.4 Raspberry Pi raw observation

Raspberry Pi `eth0`은 `192.168.0.20/24`로 확인됐고 `wlan0`은 DOWN 상태였다. 공식 `packet-capture.service` 대신 별도 수동 `tcpdump`로 Sender local success와 Pi raw observation을 비교했다.

필터:

```bash
sudo tcpdump -ni eth0 -q 'udp and src host 192.168.0.5 and dst host 192.168.0.20 and dst port 19999' > /dev/null
```

Raw 비교 Run #1:

```text
ESP32 sent=1200
Pi packets captured=1200
Pi packets received by filter=1202
Pi packets dropped by kernel=0
```

Raw 비교 Run #2:

```text
ESP32 sent=1200
Pi packets captured=1200
Pi packets received by filter=1200
Pi packets dropped by kernel=0
```

실제 비교 기준인 `ESP32 sent`와 `Pi packets captured`는 두 Run 모두 `1200 ↔ 1200`으로 일치했다. 따라서 이번 통제 조건에서는 과거 Session 53/55/56에서 보였던 Sender↔Gateway observation gap이 재현되지 않았다.

### 12.5 현재 판정

- 진단 Firmware는 의도한 단계별 Counter를 제공했고 기존 송신 상한/no-catch-up/Socket lifecycle/retry 정책을 변경하지 않았다.
- 최초 10 PPS Smoke에서 간헐 `endPacket()` 실패 27건을 1회 관측했다.
- 이후 동일 Socket, Fresh Boot, 80 PPS 반복에서는 해당 실패가 재현되지 않았다.
- 80 PPS raw 비교 2회에서 ESP32 `sent=1200`과 Pi `captured=1200`이 일치했고 kernel drop은 0이었다.
- 현재 증거만으로 Wi-Fi, Socket reuse, 메모리 부족 중 어느 하나를 Root Cause로 확정하지 않는다.
- 과거 Session의 Sender failure와 observation gap 기록은 유효하지만, 이번 통제 조건에서는 반복 재현되지 않았다.
- 따라서 이 PR에서는 retry 또는 Burst 사이 Socket restart 같은 동작 수정은 추가하지 않고, 진단 계측을 유지한 채 간헐 현상을 미해결 관찰사항으로 기록한다.
