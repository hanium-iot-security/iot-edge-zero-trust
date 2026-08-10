# Packet Rate Sender 진단 구현 계획

**목표:** Session 56의 `failed=453`을 UDP API 단계와 Scheduler 지연으로 분리 진단할 수 있도록 계측만 추가한다.

**구현 원칙:** 기존 Packet Rate, duration, Payload, no-catch-up 정책, UDP Socket lifecycle, 재시도 정책은 변경하지 않는다. 진단 값은 Burst 중 per-packet Serial 출력 없이 메모리 Counter로만 누적하고 `STATUS` 및 종료 Summary에서 출력한다.

**대상 환경:** ESP32 Dev Module, `esp32 by Espressif Systems 3.3.8`, Arduino IDE 2.3.10.

## 변경 파일

- `tests/test_esp32_packet_rate_sender_firmware.py`
  - 진단 Firmware version, Counter, 초기화, errno snapshot, skipped-slot 계산, 기존 Socket lifecycle 보존 정적 계약을 먼저 고정한다.
- `firmware/esp32/packet_rate_sender/packet_rate_sender.ino`
  - 진단 Counter 및 출력만 추가한다.
- `firmware/esp32/packet_rate_sender/README.md`
  - Phase 6-A 진단 Build와 실기기 실행 절차를 문서화한다.

## Task 1. 진단 계약 회귀 테스트

- [ ] 진단 Firmware version `phase6a-packet-rate-sender-diagnostics-v1`을 요구하는 테스트를 추가한다.
- [ ] `beginPacket`, short write, `endPacket`, `last errno`, skipped slot Counter 존재를 요구한다.
- [ ] 각 Burst 시작 시 Counter 5개가 0으로 초기화되는지 요구한다.
- [ ] `endPacket()` 직후 `errno`를 snapshot하는 코드 순서를 요구한다.
- [ ] Scheduler가 `(afterSendUs - nextPacketAtUs) / attackIntervalUs + 1`로 실제 skipped slot 수를 누적하는지 요구한다.
- [ ] `finishAttack()` 정상 종료 경로가 UDP socket을 stop/restart하지 않는 기존 계약을 요구한다.
- [ ] 현재 Firmware에 대해 신규 테스트가 실패하는지 확인한다.

## Task 2. 최소 진단 Firmware 구현

- [ ] `<errno.h>`를 추가한다.
- [ ] Firmware version을 진단 Build 식별자로 변경한다.
- [ ] 진단 Counter 5개를 전역 상태로 추가한다.
- [ ] `startAttack()`에서 기존 `sentPackets`, `failedPackets`와 함께 모두 0으로 초기화한다.
- [ ] `sendScheduledPacket()`에서 `beginPacket()` 실패, short write, `endPacket()` 실패를 독립 Counter로 기록한다.
- [ ] `endPacket()` 직후 다른 함수 호출 전에 `errno`를 지역 변수로 snapshot하고 실패 시에만 `lastEndPacketErrno`를 갱신한다.
- [ ] 기존 `failedPackets`는 송신 시도 단위로 최대 1회만 증가시키는 의미를 보존한다.
- [ ] `updateAttack()`에서 기존 no-catch-up 분기에서 실제 skipped slot 수를 계산해 누적하고 `nextPacketAtUs = afterSendUs + attackIntervalUs` 동작은 그대로 유지한다.
- [ ] `STATUS` 및 종료 Summary에 동일한 5개 필드를 출력한다.
- [ ] Burst 중 단계별 실패마다 Serial 출력하지 않는다.
- [ ] 신규 테스트 및 기존 Sender 테스트가 통과하는지 확인한다.

## Task 3. README 정합성

- [ ] 진단 Firmware version과 Core 3.3.8 고정 조건을 기록한다.
- [ ] 새 Serial 진단 필드의 의미를 기록한다.
- [ ] `START 10 3 64` → `START 80 15 64` → 대기 → 동일 80 PPS Burst 순서를 기록한다.
- [ ] 이 절차는 Clean Holdout이 아니라 Sender 진단이며 `packet-capture.service`, DB, Trust, Firewall을 변경하지 않는다고 명시한다.
- [ ] `end_packet_fail`이 관측돼도 Socket 재사용을 Root Cause로 단정하지 않는다고 명시한다.

## Task 4. 최종 정적 검증

- [ ] 작업 브랜치가 최신 `develop`보다 behind가 아닌지 확인한다.
- [ ] 변경 파일이 설계 범위를 벗어나지 않는지 diff를 검토한다.
- [ ] Firmware에 `udp.stop()` / `udp.begin()` Burst 경계 변경, retry, PPS/duration/Payload 변경이 없는지 확인한다.
- [ ] Host-side 검증은 실제 ESP32 Runtime PASS를 의미하지 않는다고 기록한다.
- [ ] 실제 컴파일·업로드·연속 Burst 실행은 장비 보유자가 수행할 실기기 Gate로 남긴다.
