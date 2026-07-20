from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.gateway.gateway_metrics_repository import (
    count_gateway_metrics,
    list_gateway_metrics,
)
from edge.gateway import run_gateway_metrics_collector as runner
from edge.gateway.metrics_collector import GatewayMetricsSample, InterfaceMetrics
from edge.gateway.run_gateway_metrics_collector import collect_and_store_sample


@pytest.fixture
def db_session(tmp_path: Path):
    db_path = tmp_path / "gateway-metrics-runner.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with session_factory() as session:
        session.execute(text("PRAGMA foreign_keys = ON"))
        yield session
    engine.dispose()


@pytest.fixture
def session_factory(tmp_path: Path):
    db_path = tmp_path / "gateway-metrics-loop.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _first_sample() -> GatewayMetricsSample:
    return GatewayMetricsSample(
        collected_at=datetime(2026, 7, 20, 10, 0, 0, tzinfo=timezone.utc),
        sample_interval_seconds=None,
        cpu_percent=None,
        memory_percent=25.0,
        disk_percent=30.0,
        disk_total_mb=1024.0,
        disk_used_mb=307.2,
        temperature_c=None,
        interface_metrics={
            "internal_lan": InterfaceMetrics(
                interface_name="eth0",
                exists=True,
                is_up=True,
                ip_address="192.168.0.20",
                rx_bytes=100,
                tx_bytes=200,
                rx_bytes_per_sec=None,
                tx_bytes_per_sec=None,
            ),
            "usb_lan": InterfaceMetrics(
                interface_name="eth1",
                exists=False,
                is_up=False,
                ip_address=None,
                rx_bytes=None,
                tx_bytes=None,
                rx_bytes_per_sec=None,
                tx_bytes_per_sec=None,
            ),
        },
    )


def _second_sample() -> GatewayMetricsSample:
    first = _first_sample()
    return replace(
        first,
        collected_at=first.collected_at + timedelta(seconds=10),
        sample_interval_seconds=10.0,
        cpu_percent=12.5,
        temperature_c=45.0,
    )


class FakeCollector:
    def __init__(self, samples: list[GatewayMetricsSample]) -> None:
        self._samples = iter(samples)
        self.collect_count = 0

    def collect(self) -> GatewayMetricsSample:
        self.collect_count += 1
        return next(self._samples)


class FailingCollector:
    def collect(self) -> GatewayMetricsSample:
        raise RuntimeError("collector failed")


class FakeShutdown:
    def __init__(self, *, stop_after_waits: int = 1_000, requested: bool = False) -> None:
        self.requested = requested
        self._stop_after_waits = stop_after_waits
        self.wait_timeouts: list[float] = []

    def wait(self, timeout: float) -> bool:
        self.wait_timeouts.append(timeout)
        if len(self.wait_timeouts) >= self._stop_after_waits:
            self.requested = True
        return self.requested


def test_collect_and_store_commits_first_nullable_sample(db_session: Session) -> None:
    sample = _first_sample()

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


def test_collect_and_store_rolls_back_repository_failure(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_insert = runner.insert_gateway_metrics_sample

    def insert_then_fail(db: Session, *, sample: GatewayMetricsSample) -> None:
        real_insert(db, sample=sample)
        raise RuntimeError("repository failed")

    monkeypatch.setattr(runner, "insert_gateway_metrics_sample", insert_then_fail)

    with pytest.raises(RuntimeError, match="repository failed"):
        collect_and_store_sample(
            db_session,
            FakeCollector([_first_sample()]),
            shutdown_requested=lambda: False,
        )

    assert count_gateway_metrics(db_session) == 0


def test_collect_and_store_rolls_back_collector_failure(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rollback_spy = Mock(wraps=db_session.rollback)
    monkeypatch.setattr(db_session, "rollback", rollback_spy)

    with pytest.raises(RuntimeError, match="collector failed"):
        collect_and_store_sample(
            db_session,
            FailingCollector(),
            shutdown_requested=lambda: False,
        )

    rollback_spy.assert_called_once_with()


def test_collect_and_store_rolls_back_when_shutdown_arrives_before_commit(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shutdown = False
    real_insert = runner.insert_gateway_metrics_sample

    def insert_and_request_shutdown(db: Session, *, sample: GatewayMetricsSample) -> int:
        nonlocal shutdown
        row_id = real_insert(db, sample=sample)
        shutdown = True
        return row_id

    monkeypatch.setattr(
        runner,
        "insert_gateway_metrics_sample",
        insert_and_request_shutdown,
    )

    result = collect_and_store_sample(
        db_session,
        FakeCollector([_first_sample()]),
        shutdown_requested=lambda: shutdown,
    )

    assert result is None
    assert count_gateway_metrics(db_session) == 0


def test_build_collector_passes_gateway_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = runner.GatewayMetricsConfig(
        interval_seconds=5.0,
        internal_lan_interface="lan0",
        usb_lan_interface="usb0",
    )
    captured: dict[str, object] = {}

    class CollectorSpy:
        def __init__(self, *, reader, clock, config) -> None:
            captured.update(reader=reader, clock=clock, config=config)

    monkeypatch.setattr(runner, "GatewayMetricsCollector", CollectorSpy)

    collector = runner.build_collector(config)

    assert isinstance(collector, CollectorSpy)
    assert captured["config"] is config
    clock = captured["clock"]
    assert callable(clock)
    assert clock().tzinfo is not None


def test_loop_reuses_one_collector_and_stores_two_samples(session_factory) -> None:
    collector = FakeCollector([_first_sample(), _second_sample()])
    shutdown = FakeShutdown(stop_after_waits=2)

    stored_count = runner.run_gateway_metrics_loop(
        runner.GatewayMetricsConfig(interval_seconds=5.0),
        collector,
        shutdown,
        session_factory=session_factory,
    )

    assert stored_count == 2
    assert collector.collect_count == 2
    assert shutdown.wait_timeouts == [5.0, 5.0]
    with session_factory() as db:
        assert count_gateway_metrics(db) == 2


def test_loop_propagates_cycle_failure_for_systemd_restart(session_factory) -> None:
    with pytest.raises(RuntimeError, match="collector failed"):
        runner.run_gateway_metrics_loop(
            runner.GatewayMetricsConfig(),
            FailingCollector(),
            FakeShutdown(),
            session_factory=session_factory,
        )


def test_loop_does_not_open_session_after_shutdown_request() -> None:
    session_calls = 0

    def session_factory():
        nonlocal session_calls
        session_calls += 1
        raise AssertionError("session must not be opened")

    stored_count = runner.run_gateway_metrics_loop(
        runner.GatewayMetricsConfig(),
        FakeCollector([_first_sample()]),
        FakeShutdown(requested=True),
        session_factory=session_factory,
    )

    assert stored_count == 0
    assert session_calls == 0


def test_graceful_shutdown_interrupts_wait() -> None:
    shutdown = runner.GracefulShutdown()

    assert shutdown.wait(0) is False
    shutdown.request(15, None)

    assert shutdown.requested is True
    assert shutdown.wait(1) is True


def test_gateway_metrics_systemd_unit_contract() -> None:
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
