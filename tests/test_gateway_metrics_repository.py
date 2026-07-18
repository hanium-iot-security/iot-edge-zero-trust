from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import json

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.gateway.gateway_metrics_repository import (
    count_gateway_metrics,
    insert_gateway_metrics_sample,
    list_gateway_metrics,
)
from edge.gateway.metrics_collector import GatewayMetricsSample, InterfaceMetrics


@pytest.fixture
def db_session(tmp_path: Path):
    db_path = tmp_path / "gateway-metrics-repository.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with SessionLocal() as session:
        session.execute(text("PRAGMA foreign_keys = ON"))
        yield session
    engine.dispose()


def _sample(
    *,
    collected_at: datetime = datetime(2026, 7, 16, 10, 0, 0, tzinfo=timezone.utc),
    sample_interval_seconds: float | None = None,
    cpu_percent: float | None = None,
    memory_percent: float = 40.0,
    disk_percent: float = 30.0,
    disk_used_mb: float = 512.0,
    temperature_c: float | None = None,
    internal_rate: float | None = None,
    usb_exists: bool = False,
) -> GatewayMetricsSample:
    return GatewayMetricsSample(
        collected_at=collected_at,
        sample_interval_seconds=sample_interval_seconds,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_percent=disk_percent,
        disk_total_mb=1024.0,
        disk_used_mb=disk_used_mb,
        temperature_c=temperature_c,
        interface_metrics={
            "internal_lan": InterfaceMetrics(
                interface_name="eth0",
                exists=True,
                is_up=True,
                ip_address="192.168.0.20",
                rx_bytes=124000000,
                tx_bytes=36000000,
                rx_bytes_per_sec=internal_rate,
                tx_bytes_per_sec=internal_rate,
            ),
            "usb_lan": InterfaceMetrics(
                interface_name="eth1",
                exists=usb_exists,
                is_up=False,
                ip_address=None,
                rx_bytes=None,
                tx_bytes=None,
                rx_bytes_per_sec=None,
                tx_bytes_per_sec=None,
            ),
        },
    )


def test_insert_gateway_metrics_sample_preserves_contract_and_json(
    db_session: Session,
) -> None:
    first_sample = _sample()
    normal_sample = _sample(
        collected_at=datetime(2026, 7, 16, 10, 0, 10, tzinfo=timezone.utc),
        sample_interval_seconds=10.5,
        cpu_percent=75.0,
        memory_percent=41.0,
        disk_percent=31.0,
        disk_used_mb=640.0,
        temperature_c=48.5,
        internal_rate=100.0,
        usb_exists=True,
    )
    zero_sample = _sample(
        collected_at=datetime(2026, 7, 16, 10, 0, 20, tzinfo=timezone.utc),
        sample_interval_seconds=0,
    )
    long_interval_sample = _sample(
        collected_at=datetime(2026, 7, 16, 10, 0, 51, tzinfo=timezone.utc),
        sample_interval_seconds=31.0,
    )

    for sample in (first_sample, normal_sample, zero_sample, long_interval_sample):
        insert_gateway_metrics_sample(db_session, sample=sample)
    db_session.commit()

    rows = list_gateway_metrics(db_session)
    assert count_gateway_metrics(db_session) == 4
    assert [row["collected_at"] for row in rows] == [
        "2026-07-16T10:00:51Z",
        "2026-07-16T10:00:20Z",
        "2026-07-16T10:00:10Z",
        "2026-07-16T10:00:00Z",
    ]

    latest = rows[0]
    assert latest["network_rx_bytes"] is None
    assert latest["network_tx_bytes"] is None

    normal = rows[2]
    payload = json.loads(normal["interface_metrics_json"])
    assert payload["internal_lan"]["interface_name"] == "eth0"
    assert payload["internal_lan"]["exists"] is True
    assert payload["internal_lan"]["ip_address"] == "192.168.0.20"
    assert payload["internal_lan"]["rx_bytes"] == 124000000
    assert payload["internal_lan"]["rx_bytes_per_sec"] == 100.0
    assert payload["usb_lan"]["interface_name"] == "eth1"
    assert payload["usb_lan"]["exists"] is True
    assert payload["usb_lan"]["is_up"] is False
    assert payload["usb_lan"]["rx_bytes_per_sec"] is None

    columns = {
        row["name"]
        for row in db_session.execute(text("PRAGMA table_info(gateway_metrics)")).mappings()
    }
    assert "disk_total_mb" not in columns


def test_gateway_metrics_query_filters_limit_offset_and_count(
    db_session: Session,
) -> None:
    for index in range(4):
        insert_gateway_metrics_sample(
            db_session,
            sample=_sample(
                collected_at=datetime(2026, 7, 16, 10, 0, index * 10, tzinfo=timezone.utc),
                sample_interval_seconds=10.0 if index else None,
            ),
        )
    db_session.commit()

    from_at = datetime(2026, 7, 16, 10, 0, 10, tzinfo=timezone.utc)
    to_at = datetime(2026, 7, 16, 10, 0, 30, tzinfo=timezone.utc)
    assert count_gateway_metrics(db_session, from_at=from_at, to_at=to_at) == 3

    rows = list_gateway_metrics(
        db_session,
        from_at=from_at,
        to_at=to_at,
        limit=1,
        offset=1,
    )
    assert len(rows) == 1
    assert rows[0]["collected_at"] == "2026-07-16T10:00:20Z"


def test_gateway_metrics_repository_rejects_invalid_input(db_session: Session) -> None:
    invalid_samples = [
        replace(_sample(), sample_interval_seconds=-1),
        replace(_sample(), sample_interval_seconds=float("nan")),
        replace(_sample(), sample_interval_seconds=float("inf")),
        replace(_sample(), collected_at=datetime(2026, 7, 16, 10, 0, 0)),
        replace(_sample(), cpu_percent=101.0),
        replace(_sample(), memory_percent=-0.1),
        replace(_sample(), disk_percent=100.1),
        replace(_sample(), disk_used_mb=-1.0),
        replace(_sample(), interface_metrics={
            "internal_lan": InterfaceMetrics(
                interface_name="eth0",
                exists=True,
                is_up=True,
                ip_address="192.168.0.20",
                rx_bytes=-1,
                tx_bytes=1,
                rx_bytes_per_sec=None,
                tx_bytes_per_sec=None,
            )
        }),
        replace(_sample(), interface_metrics={
            "internal_lan": InterfaceMetrics(
                interface_name="eth0",
                exists=True,
                is_up=True,
                ip_address="192.168.0.20",
                rx_bytes=1,
                tx_bytes=1,
                rx_bytes_per_sec=float("nan"),
                tx_bytes_per_sec=None,
            )
        }),
    ]

    for sample in invalid_samples:
        with pytest.raises(ValueError):
            insert_gateway_metrics_sample(db_session, sample=sample)

    db_session.rollback()
    assert count_gateway_metrics(db_session) == 0


def test_gateway_metrics_repository_does_not_commit(db_session: Session) -> None:
    insert_gateway_metrics_sample(db_session, sample=_sample())
    db_session.rollback()

    assert count_gateway_metrics(db_session) == 0
