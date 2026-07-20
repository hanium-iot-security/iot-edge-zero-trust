# Gateway Metrics DB Insert Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist Raspberry Pi Gateway Metrics at the configured interval through the existing Repository and expose fresh committed rows to the existing API.

**Architecture:** A long-lived Collector retains cumulative counter state while a small runner creates one SQLAlchemy Session per sample. Each cycle performs collect, insert, and commit atomically; any failure rolls back and escapes so systemd can restart a clean process. Signal handlers set an event that prevents new work and interrupts the idle wait.

**Tech Stack:** Python 3.10, SQLAlchemy, SQLite, pytest, systemd

## Global Constraints

- Use `GatewayMetricsConfig.from_env()` and pass the same config to the Collector and loop.
- Reuse one `GatewayMetricsCollector` for the process lifetime.
- Error policy is rollback, non-zero process exit, and systemd restart after 5 seconds.
- Preserve existing first-sample, long-interval, DOWN, Missing, and Counter Reset contracts.
- Do not persist `GatewayMetricsSample.disk_total_mb`.
- Do not change the existing DB schema, Repository query contract, API, or Dashboard.
- All tests must run on Windows; final service and restart acceptance is performed on Raspberry Pi.

---

### Task 1: Transactional single-sample persistence

**Files:**
- Create: `tests/test_gateway_metrics_runner.py`
- Create: `edge/gateway/run_gateway_metrics_collector.py`

**Interfaces:**
- Consumes: `GatewayMetricsCollector.collect()`, `insert_gateway_metrics_sample(db, sample=...)`
- Produces: `collect_and_store_sample(db, collector, *, shutdown_requested) -> GatewayMetricsSample | None`

- [ ] **Step 1: Write the failing transaction tests**

Add real migrated SQLite tests that cover a committed first sample, repository failure after an insert, Collector failure, and shutdown requested after insert. Use `apply_migrations`, a temporary engine, and a fake Collector that returns a complete `GatewayMetricsSample` with nullable first-sample fields.

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

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_gateway_metrics_runner.py -q
```

Expected: collection fails because `edge.gateway.run_gateway_metrics_collector` does not exist.

- [ ] **Step 3: Implement the minimal transaction function**

Create the module and implement:

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

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run `python -m pytest tests/test_gateway_metrics_runner.py -q`.

Expected: transaction tests pass with no committed row after failure or shutdown.

- [ ] **Step 5: Commit the transaction boundary**

```powershell
git add tests/test_gateway_metrics_runner.py edge/gateway/run_gateway_metrics_collector.py
git commit -m "feat: persist gateway metrics transactions"
```

---

### Task 2: Long-lived Collector, loop, and graceful shutdown

**Files:**
- Modify: `tests/test_gateway_metrics_runner.py`
- Modify: `edge/gateway/run_gateway_metrics_collector.py`

**Interfaces:**
- Consumes: Task 1 `collect_and_store_sample`
- Produces: `GracefulShutdown`, `build_collector(config)`, `run_gateway_metrics_loop(config, collector, shutdown, session_factory) -> int`, `main()`

- [ ] **Step 1: Write failing loop and configuration tests**

Cover these behaviors with dependency injection rather than real sleep or Linux `/proc` reads:

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

Also test that a pre-requested shutdown opens no Session and that
`GracefulShutdown.wait()` returns immediately after `request()`.

- [ ] **Step 2: Run the focused tests and verify RED**

Run `python -m pytest tests/test_gateway_metrics_runner.py -q`.

Expected: failures report missing `GracefulShutdown`, `build_collector`, or `run_gateway_metrics_loop`.

- [ ] **Step 3: Implement the loop and entry point**

Implement the public behavior below, preserving one Collector instance:

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

`main()` configures logging, loads `GatewayMetricsConfig.from_env()`, installs handlers, builds the Collector once, runs the loop, and lets exceptions escape for a non-zero exit.

- [ ] **Step 4: Run runner, Collector, and Repository tests**

```powershell
python -m pytest tests/test_gateway_metrics_runner.py tests/test_gateway_metrics_collector.py tests/test_gateway_metrics_repository.py -q
```

Expected: all tests pass; existing Collector contract tests remain unchanged.

- [ ] **Step 5: Commit the runtime**

```powershell
git add tests/test_gateway_metrics_runner.py edge/gateway/run_gateway_metrics_collector.py
git commit -m "feat: run gateway metrics collection loop"
```

---

### Task 3: systemd service and final verification

**Files:**
- Create: `infra/systemd/gateway-metrics.service`
- Modify: `tests/test_gateway_metrics_runner.py`

**Interfaces:**
- Consumes: Task 2 module entry point
- Produces: Pi service installation artifact

- [ ] **Step 1: Write the failing unit-file contract test**

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

- [ ] **Step 2: Run the test and verify RED**

Run `python -m pytest tests/test_gateway_metrics_runner.py::test_gateway_metrics_systemd_unit_contract -q`.

Expected: `FileNotFoundError` for `infra/systemd/gateway-metrics.service`.

- [ ] **Step 3: Add the systemd unit**

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

- [ ] **Step 4: Run fresh verification**

```powershell
python -m pytest tests/test_gateway_metrics_runner.py -q
python -m pytest tests/test_gateway_metrics_collector.py tests/test_gateway_metrics_repository.py backend/tests/test_packet_gateway_api.py -q
python -m pytest -q
python -m compileall -q edge backend tests
git diff --check
```

Expected: every command exits zero. On Windows, only already-documented POSIX-only skips are acceptable.

- [ ] **Step 5: Review the requirement checklist**

Confirm in the diff and test output:

- One Collector instance survives across cycles.
- Interval configuration controls Collector validity and loop waiting.
- Success commits; failure and pre-commit shutdown roll back.
- Failures propagate to systemd rather than looping internally.
- `disk_total_mb` remains absent from persistence.
- Existing nullable and network rate contracts still pass.
- Pi restart and API/dashboard freshness remain explicitly unverified until run on hardware.

- [ ] **Step 6: Commit the service and tests**

```powershell
git add infra/systemd/gateway-metrics.service tests/test_gateway_metrics_runner.py
git commit -m "ops: add gateway metrics systemd service"
```
