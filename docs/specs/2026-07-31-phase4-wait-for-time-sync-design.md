# Phase 4 Time Sync Startup Ordering Design

## 목적

Raspberry Pi 부팅 직후 시스템 시간이 아직 NTP로 동기화되지 않은 상태에서 시간 기반 수집·탐지 서비스가 시작되는 문제를 방지한다.

이번 문제는 실제 Packet Capture 정지가 아니라, 부팅 당시 잘못 복원된 시각으로 `packet-capture.service`가 먼저 실행된 뒤 최초 NTP 동기화 시 시스템 시각이 약 8시간 앞으로 이동하면서 `LATE_CAPTURE`와 대규모 Capture Gap이 생성된 사례다.

## 확인된 원인

- Raspberry Pi RTC가 정상 현재 시각을 유지하지 못했다.
- systemd가 `/var/lib/systemd/timesync/clock`의 과거 시각을 임시 시스템 시각으로 복원했다.
- 기존 서비스는 `network-online.target`만 기다리고 실제 NTP 동기화 완료는 기다리지 않았다.
- `systemd-time-wait-sync.service`는 설치되어 있으나 비활성 상태였고, 어떤 프로젝트 Unit도 이를 `Wants=`로 당기지 않았다.
- 최초 NTP 동기화 시 시스템 시각이 크게 전진했고, Packet Capture Runtime은 이를 `LATE_CAPTURE`로 처리한 뒤 새 Session으로 복구했다.

## 적용 방식

시간 Window와 시각 순서에 직접 의존하는 서비스가 `systemd-time-wait-sync.service`를 직접 요구하도록 한다.

### 적용 대상

- `infra/systemd/packet-capture.service`
- `infra/systemd/gateway-metrics.service`
- `infra/systemd/mqtt-feature-builder.service`
- `infra/systemd/detection-orchestrator.service`

### 제외 대상

- `infra/systemd/iot-edge-api.service`
- `infra/systemd/firewall-worker.service`

FastAPI와 Firewall Worker는 이번에 확인된 10초 Window 시각 점프 문제의 직접 원인이 아니므로 범위를 확장하지 않는다.

## Unit 계약

`packet-capture.service`, `gateway-metrics.service`, `mqtt-feature-builder.service`는 다음 의존성을 사용한다.

```ini
After=network-online.target systemd-time-wait-sync.service
Wants=network-online.target systemd-time-wait-sync.service
```

`detection-orchestrator.service`는 기존 MQTT Feature Builder 의존성을 유지한다.

```ini
After=network-online.target systemd-time-wait-sync.service mqtt-feature-builder.service
Wants=network-online.target systemd-time-wait-sync.service mqtt-feature-builder.service
```

## 동작 흐름

```text
부팅
→ network-online.target 도달
→ systemd-time-wait-sync.service 실행
→ /run/systemd/timesync/synchronized 확인
→ 시간 기반 수집·탐지 서비스 시작
→ 실제 현재 UTC 기준 첫 Window 생성
```

## 실패 및 오프라인 정책

`systemd-time-wait-sync.service`는 동기화 완료까지 대기하므로 NTP 서버에 도달할 수 없는 환경에서는 대상 서비스가 시작되지 않을 수 있다.

이번 시스템에서는 잘못된 시각으로 Packet·Gateway·MQTT Feature·Detection 데이터를 생성하는 것보다 시작을 보류하는 것이 안전하다. 시연 및 운영 시에는 Raspberry Pi가 부팅 후 접근 가능한 NTP 서버와 통신할 수 있어야 한다.

## 테스트 전략

1. Unit 계약 테스트를 먼저 추가해 기존 Unit이 실패하는 것을 확인한다.
2. Unit 4개에 최소 의존성 변경만 적용한다.
3. 관련 Unit 정적 테스트와 전체 회귀 테스트를 실행한다.
4. Raspberry Pi에서 `systemd-analyze verify`를 실행한다.
5. 기존 설치 Unit을 백업한 뒤 Packet Capture와 Gateway Metrics Unit만 설치한다.
6. 재부팅 후 서비스 시작 순서를 검증한다.
7. NTP 동기화 완료 전에 대상 서비스가 시작되지 않았는지 확인한다.
8. 최초 Capture Window가 현재 UTC 10초 경계와 일치하고 대규모 `LATE_CAPTURE` 또는 가짜 Capture Gap이 생성되지 않았는지 확인한다.

## 성공 기준

- `systemd-time-wait-sync.service` 완료 후 시간 기반 서비스가 시작된다.
- 부팅 직후 잘못된 시스템 시각으로 Window가 생성되지 않는다.
- 최초 Packet Capture Window가 실제 현재 UTC 10초 경계와 일치한다.
- NTP 시각 점프로 인한 대규모 `LATE_CAPTURE`와 Capture Gap이 재발하지 않는다.
- 기존 Unit 기능, 전체 테스트, DB 무결성에 회귀가 없다.

## Rollback

- 설치 전 `/etc/systemd/system/*.service` 파일을 timestamp가 포함된 백업 경로에 저장한다.
- 검증 실패 시 백업 Unit을 복원하고 `systemctl daemon-reload`를 실행한다.
- 기존 서비스의 `enabled` 상태는 유지하되 실제 재시작 여부는 검증 결과에 따라 결정한다.
