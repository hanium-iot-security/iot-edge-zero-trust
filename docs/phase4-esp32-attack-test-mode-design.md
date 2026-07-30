# Phase 4 ESP32 #2 제한형 MQTT Flood Test Mode 설계

## 1. 목적

등록 기기 자동 격리 E2E에서 PC가 `device_id`만 위조하는 방식이 아니라,
DB에 등록된 `esp32_02`의 실제 Source IP로 MQTT Flood를 재현한다.

이 기능은 사설 테스트 LAN에서 한 번의 제한된 공격 구간을 만드는 검증 도구다.
부하·성능 시험이나 장시간 공격 도구로 사용하지 않는다.

## 2. 구현 방식

정상 펌웨어와 공격 펌웨어를 별도 Sketch로 관리한다.

- 정상 동작: `firmware/esp32/normal_sender/normal_sender.ino`
- 공격 검증: `firmware/esp32/attack_sender/attack_sender.ino`
- 운영 절차: `docs/phase4-esp32-attack-test-runbook.md`

정상 펌웨어에 런타임 공격 토글을 섞지 않는다. 잘못된 설정이나 재부팅으로
공격 모드가 다시 실행되는 위험을 줄이고, 정상 복구 여부를 명확히 하기 위해서다.

## 3. 고정 계약

공격 Sketch는 다음 값을 기본 계약으로 사용한다.

| 항목 | 값 |
| --- | --- |
| Device ID | `esp32_02` |
| MQTT Broker | `192.168.0.20` |
| MQTT Port | `1883` |
| Topic | `iot/esp32_02/sensor` |
| Burst당 Publish 수 | 40건 |
| Burst 내부 Publish 간격 | 50ms |
| Burst 횟수 | 4회 |
| Burst 시작 간격 | 10초 |
| 공격 최대 Publish 수 | 160건 |
| 공격 최대 테스트 구간 | 45초 |
| 관측 Probe | 5초 간격, 최대 9건 |
| 관측 Timeout | 45초 |
| 관측 후 신규 MQTT 연결 | 1회, Socket Timeout 5초 |
| 공격 전 MQTT 연결 | 최대 2회, Socket Timeout 3초 |
| 실행 횟수 | 부팅당 1회 |

40건을 약 2초에 전송하면 MQTT Rule의 `10초 Window publish_count > 15`
조건을 각 Burst가 걸친 Window에서 넘기도록 구성한다. Burst 시작은 Firmware
실행 시각 기준이므로 UTC 10초 Window 경계와 정렬되지 않으며, 4회 Burst가
정확히 4개 Event Window를 보장하지는 않는다. 실제
`analysis_window_start`·`analysis_window_end`로 서로 다른 감점 Window를
확인한다.

공격과 관측 Probe의 Payload는 정상 Firmware 기본 모드와 같은 Canonical JSON
Schema를 유지하고 Publish 간격만 공격 변수로 둔다. Burst 번호, Publish 순번과
실행 추적 정보는 Payload가 아니라 Serial 로그와 Run Manifest에 기록한다.

```json
{
  "device_id": "esp32_02"
}
```

## 4. 안전장치

- 공격 기능은 소스에서 기본 비활성화한다.
- 실행 전에 명시적인 확인 상수를 변경해야 한다.
- Broker 주소가 RFC1918 사설 IPv4가 아니면 실행하지 않는다.
- 지정한 Burst·메시지 수 또는 최대 45초 중 하나에 도달하면 즉시 중지한다.
- 공격 종료 후에는 최대 45초·9건의 정상 간격 Probe만 허용한다.
- 관측 종료 후 기존 MQTT 연결을 끊고 신규 연결을 정확히 1회만 시도한다.
- 공격 전 MQTT 연결도 3초 Socket Timeout·최대 2회로 제한한다.
- 공격 구간은 부팅당 한 번만 실행하며 자동 반복하지 않는다.
- 관측과 신규 연결 1회가 끝나면 Wi-Fi를 끊고 재부팅 전까지 유휴 상태를 유지한다.
- Wi-Fi·MQTT 연결이 실패해도 무한 대기하지 않고 제한 시간 후 안전 종료한다.

## 5. 실행 흐름

```text
정상 펌웨어·설정 백업
→ DB devices.ip_address와 ESP32 #2 실제 IP 일치 확인
→ Packet Capture·Feature·Detection·Trust·Firewall 서비스 상태 확인
→ 공격 Sketch의 확인 상수 활성화
→ ESP32 #2에 업로드
→ 준비 지연 후 MQTT 40건 Burst를 10초 간격으로 최대 4회 전송
→ Burst별 성공·실패 건수와 시작·종료 시각 기록
→ 정상 간격 Probe로 기존 연결을 최대 45초 관측
→ 기존 연결 종료 후 신규 MQTT 연결 1회 결과 기록
→ Detection Event·Trust Score·Firewall PENDING/APPLIED 확인
→ ESP32 Publish 실패 또는 Broker 연결 차단 확인
→ 정상 펌웨어 재업로드
→ 정상 주기 Publish 복구 확인
```

## 6. 오류 처리

- Wi-Fi 연결 실패: 제한 시간 후 공격 미실행 상태로 종료한다.
- MQTT 연결 실패: 제한된 재시도 후 공격 미실행 상태로 종료한다.
- Publish 실패: Burst별 성공·실패 건수를 Serial에 기록하되 최대 시간까지 무한 재시도하지 않는다.
- 일부 Publish만 성공: 실제 성공 건수를 증거에 남기고 E2E 결과를 성공으로 간주하지 않는다.
- 관측 Timeout 내 실패 없음 또는 신규 연결 성공: Firewall 차단 성공으로 간주하지 않는다.
- Serial 실패·재연결 시각은 공통 Run 시작 기준 `run_elapsed_ms`로 기록한다.
- 정상 복구 실패: Firewall 해제 여부와 정상 펌웨어 업로드 상태를 확인하고 Phase 4 완료를 보류한다.

## 7. 검증

자동 테스트는 Sketch와 Runbook의 안전 계약을 확인한다.

- 공격 기능 기본 비활성
- `esp32_02`, Broker, Port, Topic 고정값
- Burst·메시지 수·간격·최대 시간 상한
- 별도 관측 Timeout·Probe 상한·신규 연결 1회
- 정상 Canonical Payload Schema
- 사설 IPv4 Broker 검사
- 부팅당 1회 실행
- 정상 펌웨어 복구 절차

실기기 검증은 PR 병합 전 로컬 자동 테스트와 분리해 기록한다.

- ESP32 #2 실제 IP와 DB 등록 IP 일치
- 실제 Window 경계 기준 격리에 필요한 서로 다른 MQTT Rule Event 또는 조기 격리 근거 기록
- Window별 Trust Score 하락
- Firewall Rule `PENDING → APPLIED`
- ESP32 #2의 MQTT 연결 또는 Publish 실패
- 정상 펌웨어 복구 후 정상 Publish 재개

## 8. 제외 범위

- 정상 데이터 공식 수집
- Packet IF 최종 모델 학습
- 장시간 부하·성능 시험
- 공인망 또는 제3자 Broker 대상 실행
- 공격 구간 자동 반복
- Firewall·Trust 정책 자체 변경
