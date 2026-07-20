# Gateway Metrics DB Insert Loop Design

## Goal

Continuously collect `GatewayMetricsSample` values on Raspberry Pi, persist each
sample through the existing Gateway Metrics repository, and expose fresh rows to
the existing read API and dashboard.

This design implements Notion task `P4-0-02 — Gateway Metrics DB Insert Loop`.

## Scope

In scope:

- Build one long-lived `GatewayMetricsCollector` from
  `GatewayMetricsConfig.from_env()`.
- Collect and store samples at `interval_seconds`.
- Own database `commit()` and `rollback()` in the runner.
- Stop safely on `SIGTERM` or `SIGINT`.
- Run under systemd with the project virtual environment and `.env` file.
- Add unit tests for normal storage, configuration, failures, rollback, shutdown,
  and first-sample nullable fields.

Out of scope:

- Changing Collector rate, DOWN, Missing, Counter Reset, or long-interval rules.
- Changing the Gateway Metrics table, repository query contract, API, or dashboard.
- Persisting `GatewayMetricsSample.disk_total_mb`.
- Running the final Raspberry Pi restart verification in the Windows workspace.

## Components

### `edge/gateway/run_gateway_metrics_collector.py`

The module provides three boundaries:

1. `build_collector(config)` creates `LinuxSystemMetricsReader` and one
   `GatewayMetricsCollector`. The same Collector instance is reused for the
   lifetime of the process so cumulative counters and the previous sample remain
   available for rate calculations.
2. `collect_and_store_sample(db, collector)` performs one
   `collect → repository insert → commit` transaction. Any exception triggers
   `rollback` and is re-raised.
3. `run_gateway_metrics_loop(...)` owns the repeating loop and interruptible wait.
   It executes the first sample immediately, then waits the configured interval.

`main()` loads the environment configuration, installs signal handlers, creates
the Collector once, and starts the loop with `SessionLocal`.

## Transaction and failure policy

- Each sample uses a fresh SQLAlchemy Session.
- A successful repository insert is committed exactly once.
- Collector, validation, repository, or commit failure rolls back the current
  Session and propagates out of the process.
- The process exits non-zero on operational failure. systemd restarts it after
  `RestartSec=5`.
- Recreating the process also recreates the Collector, so the first sample after a
  restart legitimately stores nullable interval, CPU, and RX/TX rates.
- `SIGTERM`/`SIGINT` only set a shutdown flag. If received before persistence,
  the current uncommitted sample is rolled back; if received during the idle wait,
  the wait ends immediately. No new sample starts after shutdown is requested.

## Data contract

- `GatewayMetricsConfig.interval_seconds` is passed directly to the Collector and
  is also the loop interval.
- Existing Collector behavior remains the source of truth for first sample,
  interval greater than three collection periods, interface DOWN/Missing, and
  Counter Reset values.
- Persistence uses `insert_gateway_metrics_sample`; therefore
  `disk_total_mb` remains Collector-only and is not written to the current DB/API
  contract.

## systemd contract

`infra/systemd/gateway-metrics.service` uses:

- `WorkingDirectory=/home/pi/iot-edge-zero-trust`
- `EnvironmentFile=-/home/pi/iot-edge-zero-trust/.env`
- `/home/pi/iot-edge-zero-trust/venv/bin/python -m
  edge.gateway.run_gateway_metrics_collector`
- `Restart=on-failure`, `RestartSec=5`, and a bounded Start Limit
- journal output and a finite `TimeoutStopSec`

The service needs no packet-capture capabilities.

## Test design

`tests/test_gateway_metrics_runner.py` verifies:

- The environment interval and interface names reach the long-lived Collector.
- Two cycles insert and commit two rows while reusing one Collector.
- The first stored sample preserves nullable interval, CPU, temperature, and
  network rates.
- Collector and repository/commit failures roll back and propagate.
- A shutdown request prevents a new cycle and interrupts the idle wait.
- The systemd unit contains the required venv, working directory, environment,
  restart, and Start Limit settings.

Existing Collector and Repository tests remain the regression coverage for rate
and storage contracts. Final acceptance additionally requires Raspberry Pi proof
that rows increase across service operation and restart, and that the latest row
is visible through the API/dashboard.
