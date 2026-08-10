# Packet Rate Sender 진단 설계

기준일: 2026-08-10

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

그러나 세 단계의 실패를 모두 `failedPackets` 하나로 합산하므로 Session 56의 `failed=453`이 어느 단계에서 발생했는지 현재 로그만으로 구분할 수 없다.

Session 56 두 번째 Burst는 `80 PPS × 15초 = 1200`과 동일한 `attempted=1200`을 기록했으므로, 해당 Run에서는 1200개의 송신 시도 자체가 수행됐다. 따라서 단순 Scheduler missed-slot만으로 453건의 실패를 설명할 수 없다.

사용자 Arduino 환경은 `esp32 by Espressif Systems 3.3.8`이다. 해당 환경과 현재 Firmware 동작을 기준으로 진단한다.

## 3. 범위

### 포함

- `beginPacket()` 실패 횟수 계측
- `write()`가 요청 Payload 길이보다 적게 기록한 횟수 계측
- `endPacket()` 실패 횟수 계측
- `endPacket()` 직후 `errno` snapshot 보존
- 마지막 `endPacket()` 실패 errno 표시
- errno별 최소 집계가 필요한 경우 제한된 고정 크기 집계 구조 사용
- Scheduler가 실제로 missed slot을 건너뛴 횟수 계측
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

`failedPackets`는 기존 호환성을 위해 유지하며 다음 관계를 만족해야 한다.

```text
failed = begin_packet_fail + short_write_fail_or_end_packet_failure_path
```

다만 `write()`와 `endPacket()`을 현재처럼 연속 호출하는 구조에서는 하나의 송신 시도에서 short write와 endPacket failure가 동시에 관측될 수 있다. 따라서 상세 Counter의 합을 `failedPackets`와 무조건 동일하게 만드는 대신, 각 단계별 관측값을 독립적으로 기록하고 `failedPackets`의 기존 의미는 변경하지 않는다.

## 5. errno 계측 계약

`errno`는 전역 상태이므로 `udp.endPacket()` 반환 직후 즉시 snapshot한다.

```text
endResult = udp.endPacket()
endErrno = errno
```

`endResult != 1`인 경우에만 `last_end_packet_errno`를 갱신한다.

성공한 `endPacket()` 뒤의 errno 값은 의미 있는 실패 근거로 사용하지 않는다.

이번 진단 PR은 특정 errno를 원인으로 단정하지 않는다. 실제 ESP32 실행 결과를 받은 뒤 해석한다.

## 6. Scheduler 계측 계약

현재 Scheduler는 늦어진 경우 누락된 Slot을 Catch-up Burst로 보내지 않고 다음 미래 Slot으로 이동한다. 이 정책은 그대로 유지한다.

진단용 `schedule_skip_count`는 실제로 다음 조건이 발생해 기존 코드가 `nextPacketAtUs = afterSendUs + attackIntervalUs`로 이동한 경우 증가시킨다.

이 Counter는 UDP API 실패 횟수와 별도이며, `attempted` 감소의 원인이 Scheduler 지연인지 구분하기 위한 참고값으로만 사용한다.

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

`STATUS`와 `packet_rate_attack_finished` Summary에서 동일한 이름을 사용한다.

## 8. 테스트 전략

Host-side 테스트는 실제 UDP Runtime 성공 여부를 증명하지 않는다. 다음 정적 계약만 검증한다.

- 기존 Serial-only 실행 계약 유지
- 기존 100 PPS / 15초 / 1400B 상한 유지
- 기존 no catch-up 정책 유지
- 신규 단계별 Counter가 존재함
- Burst 시작 시 Counter가 초기화됨
- `endPacket()` 직후 errno를 snapshot함
- 기존 `failedPackets` 필드와 Summary가 유지됨
- Socket stop/restart 또는 retry 로직이 이번 PR에서 새로 추가되지 않음

실제 Root Cause 판정은 ESP32 #2 실기기 결과가 있어야 한다.

## 9. 실기기 진단 절차

공식 Clean Holdout과 분리된 Sender 진단으로 실행한다. `packet-capture.service`를 공식 Session 용도로 시작하지 않고, DB·Trust·Firewall을 변경하지 않는다.

순서:

```text
1. Firmware 컴파일/업로드
2. STATUS 확인
3. START 10 3 64
4. 종료 Summary 저장
5. START 80 15 64
6. 종료 Summary 저장
7. 잠시 대기
8. START 80 15 64
9. 종료 Summary 저장
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

예시 C:

```text
short_write_fail>0
```

이면 Buffer/Memory 경로를 별도 조사한다.

`end_packet_fail`이 확인되더라도 이번 PR만으로 Socket 재사용이 Root Cause라고 확정하지 않는다. 다음 단계에서 Burst 사이 Socket 재생성 A/B 실험을 별도 변경으로 수행한다.

## 11. 성공 조건

이번 진단 PR의 성공 조건은 "문제가 해결됨"이 아니라 다음과 같다.

- 기존 Sender 동작이 유지된다.
- `failed`의 발생 단계를 실기기 로그에서 분리할 수 있다.
- Scheduler 지연과 UDP API 실패를 구분할 수 있다.
- 실제 결과가 나오기 전 Root Cause를 과장하지 않는다.
- 이후 최소 수정 방향을 실측 근거로 결정할 수 있다.
