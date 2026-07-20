# Gateway Metrics Runtime Runbook

## 목적

`GatewayMetricsCollector`를 수동 또는 systemd로 실행하고, DB Row 증가와
재시작 동작을 Raspberry Pi에서 검증한다. 동일 DB에 두 Runtime이 동시에
Sample을 저장하지 않도록 수동 실행 전에는 systemd Service를 반드시 중지한다.

## 사전 조건

- 프로젝트 경로: `/home/pi/iot-edge-zero-trust`
- 가상환경: `/home/pi/iot-edge-zero-trust/venv`
- 운영 설정: `/home/pi/iot-edge-zero-trust/.env`
- Migration이 적용된 `DATABASE_URL`의 SQLite DB

`.env`에는 최소한 다음 Gateway 설정과 실제 운영 DB 경로를 기록한다.

```dotenv
DATABASE_URL=sqlite:///./backend/data/iot_security.db
GATEWAY_METRICS_INTERVAL_SECONDS=10
INTERNAL_LAN_INTERFACE=eth0
USB_LAN_INTERFACE=eth1
```

`gateway-metrics.service`는 `.env`를 필수 파일로 사용한다. 파일이 없거나
읽을 수 없으면 기본값으로 조용히 실행하지 않고 Service 시작이 실패해야 한다.

아래 SQLite 조회 명령은 기본 운영 DB 경로인
`sqlite:///./backend/data/iot_security.db`를 기준으로 한다. `DATABASE_URL`을
변경했다면 `DB_PATH`를 동일한 실제 SQLite 파일 경로로 변경해 실행한다.

## 수동 2-Sample Smoke Test

먼저 운영 Service를 중지해 수동 Runner와 동시에 실행되지 않게 한다.

```bash
cd /home/pi/iot-edge-zero-trust
sudo systemctl stop gateway-metrics.service
source venv/bin/activate
python -m edge.gateway.run_gateway_metrics_collector --samples 2
```

수동 실행은 공통 `backend.app.config.settings`를 사용하므로 프로젝트 `.env`의
수집 주기와 Interface 이름을 읽는다. 로그 Timestamp는 UTC ISO 형식으로 출력된다.

실행 후 Row와 최신 Sample을 확인한다.

```bash
DB_PATH=backend/data/iot_security.db

sqlite3 "$DB_PATH" \
  "SELECT id, collected_at, sample_interval_seconds, cpu_percent FROM gateway_metrics ORDER BY id DESC LIMIT 2;"
```

예상 결과:

- 새 Row가 정확히 2건 증가한다.
- 재시작 후 첫 Sample의 `sample_interval_seconds`, `cpu_percent`, RX/TX Rate는
  `NULL`일 수 있다.
- 두 번째 Sample부터 실제 경과 시간과 유효 Counter를 기준으로 Rate가 계산된다.
- `disk_total_mb`는 현재 DB/API 계약에 따라 저장되지 않는다.

검증 후 운영 Service를 다시 시작한다.

```bash
deactivate
sudo systemctl start gateway-metrics.service
sudo systemctl status gateway-metrics.service --no-pager
```

## systemd 설치·갱신

```bash
cd /home/pi/iot-edge-zero-trust
sudo cp infra/systemd/gateway-metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gateway-metrics.service
```

실시간 로그:

```bash
journalctl -u gateway-metrics.service -f
```

서비스 오류 시 현재 Transaction은 Rollback되고 프로세스는 non-zero로 종료된다.
systemd는 5초 후 재시작하며, 반복 실패는 Start Limit으로 제한한다.

## 재시작 검증

```bash
DB_PATH=backend/data/iot_security.db

before=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM gateway_metrics;")
sudo systemctl restart gateway-metrics.service
sleep 12
after=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM gateway_metrics;")
printf 'before=%s after=%s\n' "$before" "$after"
```

`after > before`인지 확인하고, API의 최신 Gateway Metrics 응답과 Dashboard가
동일한 최신 Sample을 표시하는지 확인한다. 실행하지 않은 검증은 완료로 기록하지 않는다.
