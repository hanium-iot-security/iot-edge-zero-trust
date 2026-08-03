"""edge/scenarios/compare_events.py 단위 테스트.

기존 Phase 4 마이그레이션(db/migrations/001~003)으로 실제와 동일한
``detection_events`` 스키마를 임시 SQLite에 만든 뒤, Scenario Runner가
남긴 run-manifest.json(PR #45 실제 contracts.py 스키마)과 대조한다.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from edge.scenarios.compare_events import build_comparison_report
from edge.scenarios.run_scenario import ScenarioRunner

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "db" / "migrations"


def _build_test_db(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        for name in ("001_init.sql", "002_packet_gateway.sql", "003_phase4_detection.sql"):
            sql = (MIGRATIONS_DIR / name).read_text(encoding="utf-8")
            conn.executescript(sql)
        conn.commit()


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _insert_event(
    db_path: Path,
    *,
    device_id: str | None,
    subject_ip: str | None,
    event_type: str,
    window_start,
    window_end,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO detection_events
                (device_id, detector_type, event_type, severity, score_delta,
                 applied_to_score, analysis_window_start, analysis_window_end, subject_ip)
            VALUES (?, 'RULE', ?, 'high', -20, 1, ?, ?, ?)
            """,
            (device_id, event_type, _fmt(window_start), _fmt(window_end), subject_ip),
        )
        conn.commit()


@pytest.fixture
def db_session(tmp_path: Path):
    db_path = tmp_path / "test.db"
    _build_test_db(db_path)
    engine = create_engine(f"sqlite:///{db_path}")
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session, db_path
    finally:
        session.close()


def test_matched_event_is_detected(tmp_path: Path, db_session):
    session, db_path = db_session
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )

    _insert_event(
        db_path,
        device_id="esp32_02",
        subject_ip=None,
        event_type="ABNORMAL_PUBLISH_RATE",
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["matched"] == ["ABNORMAL_PUBLISH_RATE"]
    assert report.comparison["missing"] == []


def test_missing_when_no_event_recorded(tmp_path: Path, db_session):
    session, _db_path = db_session
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["missing"] == ["ABNORMAL_PUBLISH_RATE"]
    assert report.actual_event_types == []


def test_unexpected_event_is_flagged(tmp_path: Path, db_session):
    session, db_path = db_session
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )

    _insert_event(
        db_path,
        device_id="esp32_02",
        subject_ip=None,
        event_type="AI_ANOMALY",
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["unexpected"] == ["AI_ANOMALY"]
    assert report.comparison["missing"] == ["ABNORMAL_PUBLISH_RATE"]


def test_packet_scenario_falls_back_to_subject_ip(tmp_path: Path, db_session):
    """target_device_id가 없는(미매핑 IP) Packet 시나리오는 subject_ip로 조회한다."""
    session, db_path = db_session
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )

    _insert_event(
        db_path,
        device_id=None,
        subject_ip="192.168.0.10",
        event_type="PACKET_RATE_ANOMALY",
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["matched"] == ["PACKET_RATE_ANOMALY"]