# Packet Rate Sender 진단 구현 계획

**목표:** Session 56의 `failed=453`을 UDP API 단계와 Scheduler 지연으로 분리 진단할 수 있도록 계측만 추가한다.

**구현 원칙:** 기존 Packet Rate, duration, Payload, no-catch-up 정책, UDP Socket lifecycle, 재시도 정책은 변경하지 않는다. 진단 값은 Burst 중 per-packet Serial 출력 없이 메모리 Counter로만 누적하고 `STATUS` 및 종료 Summary에서 출력한다.

**대상 환경:** ESP32 Dev Module, `esp32 by Espressif Systems 3.3.8`, Arduino IDE 2.3.10, `Core Debug Level=None`.

## 변경 파일

- `tests/test_esp32_packet_rate_sender_firmware.py`
  - 진단 Firmware version, Counter, 초기화, errno snapshot, skipped-slot 계산, 기존 Socket lifecycle 보존 정적 계약을 고정한다.
- `firmware/esp32/packet_rate_sender/packet_rate_sender.ino`
  - 진단 Counter 및 출력만 추가한다.
- `firmware/esp32/packet_rate_sender/README.md`
  - Phase 6-A 진단 Build와 실기기 실행 절차 및 결과를 문서화한다.

## Task 1. 진단 계약 회귀 테스트

- [x] 진단 Firmware version `phase6a-packet-rate-sender-diagnostics-v1`을 요구하는 테스트를 추가한다.
- [x] `beginPacket`, short write, `endPacket`, `last errno`, skipped slot Counter 존재를 요구한다.
- [x] 각 Burst 시작 시 Counter 5개가 0으로 초기화되는지 요구한다.
- [x] `endPacket()` 직후 `errno`를 snapshot하는 코드 순서를 요구한다.
- [x] Scheduler가 `(afterSendUs - nextPacketAtUs) / attackIntervalUs + 1`로 실제 skipped slot 수를 누적하는지 요구한다.
- [x] `finishAttack()` 정상 종료 경로가 UDP socket을 stop/restart하지 않는 기존 계약을 요구한다.
- [x] 한 송신 시도에서 `failedPackets`가 실패 경로별 최대 1회 증가하는 계약을 보강한다.
- [x] 대표 경계값과 32-bit wrap-around 입력에서 skipped-slot 산술을 Host-side에서 검증한다.
- [x] 최신 Host-side 테스트가 통과하는지 확인한다. — `14 passed in 0.10s`

## Task 2. 최소 진단 Firmware 구현

- [x] `<errno.h>`를 추가한다.
- [x] Firmware version을 진단 Build 식별자로 변경한다.
- [x] 진단 Counter 5개를 전역 상태로 추가한다.
- [x] `startAttack()`에서 기존 `sentPackets`, `failedPackets`와 함께 모두 0으로 초기화한다.
- [x] `sendScheduledPacket()`에서 `beginPacket()` 실패, short write, `endPacket()` 실패를 독립 Counter로 기록한다.
- [x] `endPacket()` 직후 다른 Firmware 함수 호출 전에 `errno`를 지역 변수로 snapshot하고 실패 시에만 `lastEndPacketErrno`를 갱신한다.
- [x] 기존 `failedPackets`는 송신 시도 단위로 최대 1회만 증가시키는 의미를 보존한다.
- [x] `updateAttack()`에서 기존 no-catch-up 분기에서 실제 skipped slot 수를 계산해 누적하고 `nextPacketAtUs = afterSendUs + attackIntervalUs` 동작은 그대로 유지한다.
- [x] `STATUS` 및 종료 Summary에 동일한 5개 필드를 출력한다.
- [x] Burst 중 단계별 실패마다 Serial 출력하지 않는다.
- [x] 신규 테스트 및 기존 Sender 테스트가 통과하는지 확인한다.

## Task 3. README 정합성

- [x] 진단 Firmware version과 Core 3.3.8, `Core Debug Level=None` 고정 조건을 기록한다.
- [x] 새 Serial 진단 필드의 의미를 기록한다.
- [x] Arduino-ESP32 3.3.8 + 1400B 이하에서 `short_write_fail=0`이 구조적으로 예상되는 점을 기록한다.
- [x] `START 10 3 64` → `START 80 15 64` → 대기 → 동일 80 PPS Burst 순서를 기록한다.
- [x] 이 절차는 Clean Holdout이 아니라 Sender 진단이며 `packet-capture.service`, DB, Trust, Firewall을 변경하지 않는다고 명시한다.
- [x] `end_packet_fail`이 관측돼도 Socket 재사용을 Root Cause로 단정하지 않는다고 명시한다.
- [x] 실제 10 PPS/80 PPS/tcpdump 검증 결과와 현재 판정을 기록한다.

## Task 4. 최종 정적 검증

- [x] 작업 브랜치가 최신 `develop`보다 behind가 아닌지 확인한다.
- [x] 변경 파일이 설계 범위를 벗어나지 않는지 diff를 검토한다.
- [x] Firmware에 `udp.stop()` / `udp.begin()` Burst 경계 변경, retry, PPS/duration/Payload 변경이 없는지 확인한다.
- [x] Host-side 검증은 실제 ESP32 Runtime PASS를 의미하지 않는다고 기록한다.
- [x] Arduino IDE 2.3.10 / Core 3.3.8 / ESP32 Dev Module / Core Debug Level=None 환경에서 compile PASS를 확인한다.
- [x] ESP32 #2 업로드 및 STATUS 계약을 확인한다.
- [x] 10 PPS Smoke에서 간헐 `endPacket()` 실패 1회를 계측하고 이후 반복 정상 여부를 확인한다.
- [x] 80 PPS × 15초 반복 Run에서 `1200/1200`, `failed=0`, `schedule_skip_count=0`을 확인한다.
- [x] Raspberry Pi `eth0` 수동 tcpdump 2회에서 ESP32 `sent=1200`과 Pi `captured=1200`, kernel drop 0을 확인한다.

## 최종 상태

- 진단 계측 구현: 완료
- Host-side 회귀 테스트: PASS (`14 passed in 0.10s`)
- Arduino compile: PASS
- ESP32 #2 실기기 업로드/STATUS: PASS
- 80 PPS × 15초 반복: PASS
- Sender→Pi raw observation 2회: `1200 ↔ 1200`, kernel drop 0
- 최초 10 PPS Smoke의 간헐 `endPacket()` 실패 27건: 미해결 관찰사항
- Phase 5 Session 56의 `failed=453`: 이번 통제 조건에서는 재현되지 않음
- 과거 Sender↔Gateway observation gap: 이번 통제 조건에서는 재현되지 않음
- Root Cause: 미확정
- retry / Burst 사이 Socket restart: 이번 PR에서 추가하지 않음
