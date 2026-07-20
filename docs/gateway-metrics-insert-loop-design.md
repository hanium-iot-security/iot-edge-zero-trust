# Gateway Metrics DB Insert Loop 설계

## 목표

Raspberry Pi에서 `GatewayMetricsSample`을 지속적으로 수집하고, 기존 Gateway Metrics Repository를 통해 각 Sample을 DB에 저장한다. Commit된 최신 Row는 기존 조회 API와 Dashboard에서 확인할 수 있어야 한다.

이 설계는 Notion의 `P4-0-02 — Gateway Metrics DB Insert Loop` 작업을 구현한다.

## 범위

### 포함 범위

- 공통 `backend.app.config.settings`를 통해 `.env`를 읽고, 해당 설정으로 프로세스 수명 동안 유지되는 `GatewayMetricsCollector` 하나를 생성한다.
- `interval_seconds` 주기로 Sample을 수집하고 저장한다.
- Runner가 DB의 `commit()`과 `rollback()` 경계를 관리한다.
- `SIGTERM` 또는 `SIGINT` 수신 시 안전하게 종료한다.
- 프로젝트 가상환경과 `.env`를 사용하는 systemd Service로 실행한다.
- 정상 저장, 설정 전달, 오류, Rollback, 종료 및 최초 Sample의 Nullable 필드를 검증하는 단위 테스트를 추가한다.

### 제외 범위

- Collector의 Rate, Interface DOWN·Missing, Counter Reset, 장시간 수집 간격 처리 규칙 변경
- Gateway Metrics 테이블, Repository 조회 계약, API 또는 Dashboard 변경
- `GatewayMetricsSample.disk_total_mb`의 DB 저장
- Windows 작업 환경에서 최종 Raspberry Pi 재시작 검증 수행

## 구성 요소

### `edge/gateway/run_gateway_metrics_collector.py`

이 모듈은 다음 세 가지 책임 경계를 제공한다.

1. `build_collector(config)`는 `LinuxSystemMetricsReader`와 `GatewayMetricsCollector` 하나를 생성한다. 누적 Counter와 이전 Sample을 Rate 계산의 기준값으로 유지할 수 있도록 동일한 Collector 인스턴스를 프로세스 수명 동안 재사용한다.
2. `collect_and_store_sample(db, collector)`는 한 번의 `collect → repository insert → commit` Transaction을 수행한다. 예외가 발생하면 `rollback`한 뒤 예외를 다시 전파한다.
3. `run_gateway_metrics_loop(...)`는 반복 실행과 중단 가능한 대기를 담당한다. 첫 Sample은 즉시 수집하고 이후에는 설정된 간격만큼 대기한다.

`main()`은 공통 `.env` 기반 설정을 불러오고 Signal Handler를 설치한 뒤, Collector를 한 번만 생성하여 `SessionLocal`과 함께 Loop를 시작한다. 양수인 `--samples N` 옵션을 사용하면 수동 Smoke Test를 N개 Sample로 제한할 수 있다. 이 옵션을 생략하면 systemd 프로세스가 종료 Signal을 받을 때까지 계속 실행된다.

## Transaction 및 오류 처리 정책

- 각 Sample은 새로운 SQLAlchemy Session을 사용한다.
- Repository Insert가 성공하면 정확히 한 번 Commit한다.
- Collector, Validation, Repository 또는 Commit 과정에서 실패하면 현재 Session을 Rollback하고 예외를 프로세스 밖으로 전파한다.
- 운영 오류가 발생하면 프로세스는 non-zero 상태로 종료한다. systemd는 `RestartSec=5` 이후 프로세스를 재시작한다.
- 프로세스가 재생성되면 Collector도 새로 생성된다. 따라서 재시작 후 최초 Sample의 수집 간격, CPU 및 RX/TX Rate가 Nullable 값으로 저장되는 것은 정상 동작이다.
- `SIGTERM`과 `SIGINT`는 종료 Flag만 설정한다. 저장 전에 Signal을 받으면 Commit되지 않은 현재 Sample을 Rollback한다. 대기 중 Signal을 받으면 즉시 대기를 종료하며, 종료 요청 이후에는 새로운 Sample 수집을 시작하지 않는다.

## 데이터 계약

- 공통 Settings 필드를 `GatewayMetricsConfig`로 변환한다. `interval_seconds`는 Collector에 직접 전달하며 Loop 대기 간격에도 동일하게 적용한다.
- 최초 Sample, 수집 주기 3배 초과, Interface DOWN·Missing 및 Counter Reset 값은 기존 Collector 동작을 기준 계약으로 유지한다.
- 저장에는 `insert_gateway_metrics_sample`을 사용한다. 따라서 `disk_total_mb`는 Collector 내부 값으로만 유지하고 현재 DB·API 계약에는 저장하지 않는다.

## systemd 계약

`infra/systemd/gateway-metrics.service`는 다음 설정을 사용한다.

- `WorkingDirectory=/home/pi/iot-edge-zero-trust`
- `EnvironmentFile=/home/pi/iot-edge-zero-trust/.env`: 운영 설정 파일이 없을 때 기본값으로 조용히 실행하지 않고 Service 시작을 실패 처리한다.
- `/home/pi/iot-edge-zero-trust/venv/bin/python -m edge.gateway.run_gateway_metrics_collector`
- `Restart=on-failure`, `RestartSec=5` 및 제한된 Start Limit
- journal 로그 출력과 유한한 `TimeoutStopSec`

이 Service에는 Packet Capture Capability가 필요하지 않다.

## 테스트 설계

`tests/test_gateway_metrics_runner.py`는 다음 항목을 검증한다.

- 환경변수의 수집 간격과 Interface 이름이 장기 실행되는 Collector에 전달된다.
- 수동 실행도 공통 Settings를 통해 프로젝트 `.env`의 값을 읽는다.
- 동일한 Collector를 재사용하면서 두 Cycle이 두 Row를 Insert하고 Commit한다.
- 최초 저장 Sample의 수집 간격, CPU, 온도 및 Network Rate가 Nullable 계약을 유지한다.
- Collector와 Repository·Commit 오류가 Rollback되고 호출자에게 전파된다.
- 종료 요청이 새로운 Cycle을 막고 대기 상태를 즉시 해제한다.
- UTC 로그 형식과 `--samples 2`를 사용한 제한된 Smoke Test가 일관되게 동작한다.
- systemd Unit에 필수 가상환경, 작업 경로, 환경 파일, 재시작 및 Start Limit 설정이 포함된다.

`docs/gateway-metrics-runbook.md`에는 수동 Smoke Test 전에 Service를 중지하고 검증 후 다시 시작하는 절차를 명시한다. 이를 통해 두 Collector가 동시에 실행되어 중복 Sample을 저장하는 상황을 방지한다.

기존 Collector 및 Repository 테스트는 Rate와 저장 계약에 대한 회귀 검증으로 유지한다. 최종 완료를 위해서는 Raspberry Pi에서 다음 항목을 추가로 검증하고 실제 결과를 기록해야 한다.

- Service 실행 및 재시작 전후로 Gateway Metrics Row가 계속 증가한다.
- 최신 Row를 기존 API와 Dashboard에서 조회할 수 있다.
