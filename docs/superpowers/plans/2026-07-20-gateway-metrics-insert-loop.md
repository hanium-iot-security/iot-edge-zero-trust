# Gateway Metrics DB Insert Loop 구현 계획

> **Agent 작업 지침:** 이 계획은 `superpowers:subagent-driven-development` 또는 `superpowers:executing-plans` 절차로 Task별 실행한다. 진행 상태는 체크박스(`- [ ]`)로 추적한다.

**목표:** Raspberry Pi의 Gateway Metrics를 설정된 주기로 수집해 기존 Repository를 통해 DB에 저장하고, Commit된 최신 Row를 기존 API에서 조회할 수 있게 한다.

**구조:** 장기 실행되는 Collector 한 개가 누적 Counter 기준값을 유지하고, Runner는 Sample마다 새 SQLAlchemy Session을 생성한다. 각 Cycle은 `Collect → Insert → Commit`을 하나의 Transaction 경계로 처리한다. 오류가 발생하면 Rollback 후 예외를 전파하여 systemd가 깨끗한 프로세스로 재시작하게 한다. Signal Handler는 종료 Event를 설정해 새로운 작업을 막고 대기 상태를 즉시 해제한다.

**기술 구성:** Python 3.10, SQLAlchemy, SQLite, pytest, systemd

## 공통 구현 계약

- `GatewayMetricsConfig.from_env()`로 설정을 읽고 동일한 Config를 Collector와 Loop에 전달한다.
- 프로세스 수명 동안 하나의 `GatewayMetricsCollector`를 재사용한다.
- 오류 정책은 현재 Transaction Rollback, non-zero 프로세스 종료, 5초 후 systemd 재시작으로 고정한다.
- 기존 최초 Sample, 긴 수집 간격, Interface DOWN·Missing, Counter Reset 계약을 유지한다.
- `GatewayMetricsSample.disk_total_mb`는 현재 DB 저장 대상에서 제외한다.
- 기존 DB Schema, Repository 조회 계약, API, Dashboard는 변경하지 않는다.
- 모든 자동 테스트는 Windows에서도 실행 가능해야 하며, 최종 Service·재시작 검증은 Raspberry Pi에서 수행한다.

---

### Task 1: 단일 Sample Transaction 저장

**대상 파일:**
- 신규: `tests/test_gateway_metrics_runner.py`
- 신규: `edge/gateway/run_gateway_metrics_collector.py`

**Interface:**
- 사용: `GatewayMetricsCollector.collect()`, `insert_gateway_metrics_sample(db, sample=...)`
- 제공: `collect_and_store_sample(db, collector, *, shutdown_requested) -> GatewayMetricsSample | None`

- [ ] **Step 1: 실패하는 Transaction 테스트 작성**

Migration을 적용한 실제 임시 SQLite DB를 사용한다. 최초 Sample Commit, Insert 후 Repository 실패, Collector 실패, Insert 후 종료 요청을 검증한다. `apply_migrations`, 임시 Engine, Nullable 최초 Sample을 반환하는 Fake Collector를 사용한다.

```python
def test_collect_and_store_commits_first_nullable_sample(db_session):
    sample = first_sample()
    result = collect_and_store_sample(
        db_session,
        FakeCollector([sample]),
        shutdown_requested=lambda: False,
    )

    assert result == sample
    assert count_gateway_metrics(db_session) == 1
    row = list_gateway_metrics(db_session)[0]
    assert row["sample_interval_seconds"] is None
    assert row["cpu_percent"] is None
    assert row["temperature_c"] is None


def test_collect_and_store_rolls_back_repository_failure(db_session, monkeypatch):
    real_insert = runner.insert_gateway_metrics_sample

    def insert_then_fail(db, *, sample):
        real_insert(db, sample=sample)
        raise RuntimeError("repository failed")

    monkeypatch.setattr(runner, "insert_gateway_metrics_sample", insert_then_fail)
    with pytest.raises(RuntimeError, match="repository failed"):
        collect_and_store_sample(
            db_session,
            FakeCollector([first_sample()]),
            shutdown_requested=lambda: False,
        )

    assert count_gateway_metrics(db_session) == 0


def test_collect_and_store_rolls_back_when_shutdown_arrives_before_commit(
    db_session, monkeypatch
):
    shutdown = False
    real_insert = runner.insert_gateway_metrics_sample

    def insert_and_request_shutdown(db, *, sample):
        nonlocal shutdown
        real_insert(db, sample=sample)
        shutdown = True
        return 1

    monkeypatch.setattr(runner, "insert_gateway_metrics_sample", insert_and_request_shutdown)
    result = collect_and_store_sample(
        db_session,
        FakeCollector([first_sample()]),
        shutdown_requested=lambda: shutdown,
    )

    assert result is None
    assert count_gateway_metrics(db_session) == 0
```

- [ ] **Step 2: 테스트를 실행해 RED 확인**

실행:

```powershell
python -m pytest tests/test_gateway_metrics_runner.py -q
```

예상 결과: `edge.gateway.run_gateway_metrics_collector`가 아직 없으므로 Test Collection이 실패한다.

- [ ] **Step 3: 최소 Transaction 함수 구현**

모듈을 생성하고 다음 Transaction 경계를 구현한다.

```python
def collect_and_store_sample(
    db: Session,
    collector: GatewayMetricsCollector,
    *,
    shutdown_requested: Callable[[], bool] = lambda: False,
) -> GatewayMetricsSample | None:
    try:
        sample = collector.collect()
        if shutdown_requested():
            db.rollback()
            return None

        insert_gateway_metrics_sample(db, sample=sample)
        if shutdown_requested():
            db.rollback()
            return None

        db.commit()
        return sample
    except BaseException:
        db.rollback()
        raise
```

- [ ] **Step 4: 관련 테스트를 실행해 GREEN 확인**

`python -m pytest tests/test_gateway_metrics_runner.py -q`를 실행한다.

예상 결과: Transaction 테스트가 통과하고, 실패 또는 종료 요청 이후에는 Commit된 Row가 없어야 한다.

- [ ] **Step 5: Transaction 경계 Commit**

```powershell
git add tests/test_gateway_metrics_runner.py edge/gateway/run_gateway_metrics_collector.py
git commit -m "feat: persist gateway metrics transactions"
```

---

### Task 2: 장기 실행 Collector·Loop·Graceful Shutdown

**대상 파일:**
- 수정: `tests/test_gateway_metrics_runner.py`
- 수정: `edge/gateway/run_gateway_metrics_collector.py`

**Interface:**
- 사용: Task 1의 `collect_and_store_sample`
- 제공: `GracefulShutdown`, `build_collector(config)`, `run_gateway_metrics_loop(config, collector, shutdown, session_factory) -> int`, `main()`

- [ ] **Step 1: 실패하는 Loop·Config 테스트 작성**

실제 Sleep이나 Linux `/proc`를 읽지 않고 Dependency Injection으로 다음 동작을 검증한다.

```python
def test_build_collector_passes_gateway_config(monkeypatch):
    config = GatewayMetricsConfig(
        interval_seconds=5.0,
        internal_lan_interface="lan0",
        usb_lan_interface="usb0",
    )
    captured = {}

    class CollectorSpy:
        def __init__(self, *, reader, clock, config):
            captured.update(reader=reader, clock=clock, config=config)

    monkeypatch.setattr(runner, "GatewayMetricsCollector", CollectorSpy)
    collector = build_collector(config)

    assert isinstance(collector, CollectorSpy)
    assert captured["config"] is config
    assert captured["clock"]().tzinfo is not None


def test_loop_reuses_one_collector_and_stores_two_samples(session_factory):
    collector = FakeCollector([first_sample(), second_sample()])
    shutdown = FakeShutdown(stop_after_waits=2)

    stored = run_gateway_metrics_loop(
        GatewayMetricsConfig(interval_seconds=5.0),
        collector,
        shutdown,
        session_factory=session_factory,
    )

    assert stored == 2
    assert collector.collect_count == 2
    assert shutdown.wait_timeouts == [5.0, 5.0]


def test_loop_propagates_cycle_failure_for_systemd_restart(session_factory):
    with pytest.raises(RuntimeError, match="collector failed"):
        run_gateway_metrics_loop(
            GatewayMetricsConfig(),
            FailingCollector(),
            FakeShutdown(),
            session_factory=session_factory,
        )
```

미리 종료가 요청된 상태에서는 Session을 열지 않는지, `request()` 이후 `GracefulShutdown.wait()`가 즉시 반환되는지도 검증한다.

- [ ] **Step 2: 관련 테스트를 실행해 RED 확인**

`python -m pytest tests/test_gateway_metrics_runner.py -q`를 실행한다.

예상 결과: `GracefulShutdown`, `build_collector`, `run_gateway_metrics_loop`가 없다는 이유로 실패한다.

- [ ] **Step 3: Loop와 Entry Point 구현**

Collector 인스턴스 하나를 계속 유지하면서 다음 Public 동작을 구현한다.

```python
class GracefulShutdown:
    def __init__(self) -> None:
        self._event = Event()

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    def request(self, signum: int, _frame: object | None) -> None:
        logger.info("Shutdown signal received (signum=%s)", signum)
        self._event.set()

    def install(self) -> None:
        signal.signal(signal.SIGTERM, self.request)
        signal.signal(signal.SIGINT, self.request)

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def build_collector(config: GatewayMetricsConfig) -> GatewayMetricsCollector:
    return GatewayMetricsCollector(
        reader=LinuxSystemMetricsReader(),
        clock=lambda: datetime.now(timezone.utc),
        config=config,
    )


def run_gateway_metrics_loop(
    config: GatewayMetricsConfig,
    collector: GatewayMetricsCollector,
    shutdown: GracefulShutdown,
    *,
    session_factory: Callable[[], Session] = SessionLocal,
) -> int:
    stored_count = 0
    while not shutdown.requested:
        with session_factory() as db:
            sample = collect_and_store_sample(
                db,
                collector,
                shutdown_requested=lambda: shutdown.requested,
            )
        if sample is None:
            break
        stored_count += 1
        if shutdown.wait(config.interval_seconds):
            break
    return stored_count
```

`main()`은 Logging을 설정하고 `GatewayMetricsConfig.from_env()`를 읽은 뒤 Signal Handler를 설치한다. Collector를 한 번만 생성해 Loop를 실행하며, 오류는 잡아서 정상 처리하지 않고 전파해 non-zero로 종료되게 한다.

- [ ] **Step 4: Runner·Collector·Repository 테스트 실행**

```powershell
python -m pytest tests/test_gateway_metrics_runner.py tests/test_gateway_metrics_collector.py tests/test_gateway_metrics_repository.py -q
```

예상 결과: 모든 테스트가 통과하고 기존 Collector 계약 테스트는 변경 없이 유지된다.

- [ ] **Step 5: Runtime Commit**

```powershell
git add tests/test_gateway_metrics_runner.py edge/gateway/run_gateway_metrics_collector.py
git commit -m "feat: run gateway metrics collection loop"
```

---

### Task 3: systemd Service와 최종 검증

**대상 파일:**
- 신규: `infra/systemd/gateway-metrics.service`
- 수정: `tests/test_gateway_metrics_runner.py`

**Interface:**
- 사용: Task 2의 Module Entry Point
- 제공: Raspberry Pi에 설치할 systemd Unit

- [ ] **Step 1: 실패하는 systemd Unit 계약 테스트 작성**

```python
def test_gateway_metrics_systemd_unit_contract():
    unit = Path("infra/systemd/gateway-metrics.service").read_text(encoding="utf-8")

    assert "WorkingDirectory=/home/pi/iot-edge-zero-trust" in unit
    assert "EnvironmentFile=-/home/pi/iot-edge-zero-trust/.env" in unit
    assert (
        "ExecStart=/home/pi/iot-edge-zero-trust/venv/bin/python "
        "-m edge.gateway.run_gateway_metrics_collector"
    ) in unit
    assert "Restart=on-failure" in unit
    assert "RestartSec=5" in unit
    assert "StartLimitIntervalSec=" in unit
    assert "StartLimitBurst=" in unit
    assert "TimeoutStopSec=" in unit
```

- [ ] **Step 2: 테스트를 실행해 RED 확인**

`python -m pytest tests/test_gateway_metrics_runner.py::test_gateway_metrics_systemd_unit_contract -q`를 실행한다.

예상 결과: `infra/systemd/gateway-metrics.service`가 없어 `FileNotFoundError`가 발생한다.

- [ ] **Step 3: systemd Unit 추가**

```ini
[Unit]
Description=IoT Edge Zero Trust - Gateway Metrics Collector
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=pi
Group=pi
WorkingDirectory=/home/pi/iot-edge-zero-trust
EnvironmentFile=-/home/pi/iot-edge-zero-trust/.env
ExecStart=/home/pi/iot-edge-zero-trust/venv/bin/python -m edge.gateway.run_gateway_metrics_collector
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gateway-metrics

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: 전체 검증을 새로 실행**

```powershell
python -m pytest tests/test_gateway_metrics_runner.py -q
python -m pytest tests/test_gateway_metrics_collector.py tests/test_gateway_metrics_repository.py backend/tests/test_packet_gateway_api.py -q
python -m pytest -q
python -m compileall -q edge backend tests
git diff --check
```

예상 결과: 모든 명령이 Exit Code 0으로 끝난다. Windows에서는 기존에 문서화된 POSIX 전용 테스트 Skip만 허용한다.

- [ ] **Step 5: 요구사항 Checklist 재검토**

Diff와 테스트 결과에서 다음 항목을 확인한다.

- 하나의 Collector 인스턴스가 여러 Cycle에서 유지된다.
- Interval 설정이 Collector의 Rate 유효 간격과 Loop 대기 시간에 함께 적용된다.
- 성공 시 Commit하고, 실패 또는 Commit 전 종료 요청 시 Rollback한다.
- 오류는 내부에서 무한 반복하지 않고 systemd가 처리하도록 전파한다.
- `disk_total_mb`는 저장 대상에서 계속 제외된다.
- 기존 Nullable·Network Rate 계약 테스트가 통과한다.
- Pi 재시작과 API·Dashboard 최신값 검증은 실제 장비에서 실행하기 전까지 명시적으로 미검증 상태를 유지한다.

- [ ] **Step 6: Service와 테스트 Commit**

```powershell
git add infra/systemd/gateway-metrics.service tests/test_gateway_metrics_runner.py
git commit -m "ops: add gateway metrics systemd service"
```
