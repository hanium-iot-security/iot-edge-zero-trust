# systemd 최초 시간 동기화 대기 Runbook

## 목적

Raspberry Pi 부팅 직후 과거 시각으로 복원된 시스템 시간이 최초 NTP 동기화에서 크게 이동하기 전에 시간 기반 Runtime이 시작되는 것을 방지한다.

적용 대상은 다음 Unit이다.

- `packet-capture.service`
- `gateway-metrics.service`
- `mqtt-feature-builder.service`
- `detection-orchestrator.service`

`iot-edge-api.service`와 `firewall-worker.service`는 10초 Window를 직접 생성하지 않으므로 이번 변경 범위에서 제외한다.

## 사전 점검

```bash
systemctl show systemd-time-wait-sync.service \
  --property=LoadState \
  --property=FragmentPath \
  --property=Type \
  --property=TimeoutStartUSec \
  --no-pager
```

정상 기준:

```text
LoadState=loaded
FragmentPath=/usr/lib/systemd/system/systemd-time-wait-sync.service
Type=oneshot
```

동기화 완료 Marker 확인:

```bash
ls -l /run/systemd/timesync/synchronized
```

Marker가 없으면 최초 동기화가 아직 완료되지 않은 상태일 수 있다.

## Unit 계약

시간 기반 Runtime은 다음 의존성을 사용한다.

```ini
After=network-online.target systemd-time-wait-sync.service
Wants=network-online.target systemd-time-wait-sync.service
```

Detection Orchestrator는 MQTT Feature Builder 순서도 유지한다.

```ini
After=network-online.target systemd-time-wait-sync.service mqtt-feature-builder.service
Wants=network-online.target systemd-time-wait-sync.service mqtt-feature-builder.service
```

`systemd-time-wait-sync.service`는 UnitFileState가 `disabled`여도 프로젝트 Unit의 `Wants=`에 의해 실행된다.

## 오프라인 정책

NTP 서버에 도달할 수 없는 환경에서는 대상 Runtime이 대기 상태로 남을 수 있다. 잘못된 시각으로 Window, Capture Gap, Gateway Metrics, MQTT Feature 또는 Detector Checkpoint를 생성하는 것보다 시작을 보류하는 것을 안전 정책으로 사용한다.

시연 전에는 Raspberry Pi가 접근 가능한 NTP 서버와 통신할 수 있는지 확인한다.

```bash
timedatectl status
timedatectl timesync-status
```

정상 기준:

```text
System clock synchronized: yes
NTP service: active
```

## 정적 검증

```bash
sudo systemd-analyze verify \
  infra/systemd/packet-capture.service \
  infra/systemd/gateway-metrics.service \
  infra/systemd/mqtt-feature-builder.service \
  infra/systemd/detection-orchestrator.service
```

오류 출력 없이 종료되어야 한다.

## 설치 전 백업

```bash
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

sudo install -m 0644 \
  /etc/systemd/system/packet-capture.service \
  "/etc/systemd/system/packet-capture.service.${STAMP}.bak"

sudo install -m 0644 \
  /etc/systemd/system/gateway-metrics.service \
  "/etc/systemd/system/gateway-metrics.service.${STAMP}.bak"
```

백업 일치 확인:

```bash
sudo cmp -s \
  /etc/systemd/system/packet-capture.service \
  "/etc/systemd/system/packet-capture.service.${STAMP}.bak"

sudo cmp -s \
  /etc/systemd/system/gateway-metrics.service \
  "/etc/systemd/system/gateway-metrics.service.${STAMP}.bak"
```

## 설치

실제 Pi에 이미 설치되어 있는 두 Runtime만 먼저 갱신한다.

```bash
sudo install -m 0644 \
  infra/systemd/packet-capture.service \
  /etc/systemd/system/packet-capture.service

sudo install -m 0644 \
  infra/systemd/gateway-metrics.service \
  /etc/systemd/system/gateway-metrics.service

sudo systemctl daemon-reload
```

이 단계에서는 서비스를 시작하지 않는다.

## 재부팅 검증

재부팅은 코드·테스트·정적 검증과 백업이 모두 통과한 뒤 수행한다.

검증할 순서:

1. 부팅 시작
2. `systemd-timesyncd.service` 시작
3. 최초 NTP 동기화 및 `/run/systemd/timesync/synchronized` 생성
4. `systemd-time-wait-sync.service` 완료
5. Packet Capture와 Gateway Metrics 시작

```bash
sudo journalctl -b \
  -u systemd-timesyncd.service \
  -u systemd-time-wait-sync.service \
  -u packet-capture.service \
  -u gateway-metrics.service \
  --no-pager \
  -o short-precise
```

성공 기준:

- 최초 NTP 동기화 로그가 대상 Runtime 시작 로그보다 먼저 나타난다.
- 첫 Packet Capture Window가 현재 UTC 10초 경계와 일치한다.
- 부팅 직후 대규모 `LATE_CAPTURE`가 발생하지 않는다.
- 과거 시각에서 현재 시각까지의 가짜 Capture Gap이 생성되지 않는다.

## Rollback

검증 실패 시 서비스를 중지하고 백업 Unit을 복원한다.

```bash
sudo systemctl stop packet-capture.service gateway-metrics.service

sudo install -m 0644 \
  "/etc/systemd/system/packet-capture.service.${STAMP}.bak" \
  /etc/systemd/system/packet-capture.service

sudo install -m 0644 \
  "/etc/systemd/system/gateway-metrics.service.${STAMP}.bak" \
  /etc/systemd/system/gateway-metrics.service

sudo systemctl daemon-reload
```

복원 후 서비스 시작 여부는 별도로 판단한다.
