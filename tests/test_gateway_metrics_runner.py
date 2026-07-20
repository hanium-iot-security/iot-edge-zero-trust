from __future__ import annotations

from datetime import datetime, timezone
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
