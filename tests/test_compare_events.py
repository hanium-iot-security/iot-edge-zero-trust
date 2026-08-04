"""edge/scenarios/compare_events.py 단위 테스트.

기존 Phase 4 마이그레이션(db/migrations/001~003)으로 실제와 동일한
``detection_events`` 스키마를 임시 SQLite에 만든 뒤, Scenario Runner가
남긴 run-manifest.json(PR #45 실제 contracts.py 스키마)과 대조한다.
"""

from __future__ import annotations

import subprocess
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
    detected_at,
    window_start,
    window_end,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO detection_events
                (device_id, detector_type, event_type, severity, score_delta,
                 applied_to_score, detected_at, analysis_window_start, analysis_window_end, subject_ip)
            VALUES (?, 'RULE', ?, 'high', -20, 1, ?, ?, ?, ?)
            """,
            (
                device_id,
                event_type,
                _fmt(detected_at),
                _fmt(window_start),
                _fmt(window_end),
                subject_ip,
            ),
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


def _run_real(runner: ScenarioRunner, scenario_id: str, **kwargs):
    """compare_events는 attack_started_at이 채워진(실제 실행된) Run을 전제로
    하므로, 여기서는 dry_run이 아닌 mocked subprocess 실행으로 Manifest를 만든다."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        return runner.run(scenario_id, dry_run=False, **kwargs)


def test_matched_event_is_detected(tmp_path: Path, db_session):
    session, db_path = db_session
    runner = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path, allow_execute=True
    )
    result, manifest = _run_real(
        runner, "mqtt_abnormal_publish_rate", target_device_id="esp32_02"
    )

    _insert_event(
        db_path,
        device_id="esp32_02",
        subject_ip=None,
        event_type="ABNORMAL_PUBLISH_RATE",
        detected_at=manifest.attack_started_at,
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["matched"] == ["ABNORMAL_PUBLISH_RATE"]
    assert report.comparison["missing"] == []


def test_missing_when_no_event_recorded(tmp_path: Path, db_session):
    session, _db_path = db_session
    runner = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path, allow_execute=True
    )
    result, _manifest = _run_real(
        runner, "mqtt_abnormal_publish_rate", target_device_id="esp32_02"
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["missing"] == ["ABNORMAL_PUBLISH_RATE"]
    assert report.actual_event_types == []


def test_unexpected_event_is_flagged(tmp_path: Path, db_session):
    session, db_path = db_session
    runner = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path, allow_execute=True
    )
    result, manifest = _run_real(
        runner, "mqtt_abnormal_publish_rate", target_device_id="esp32_02"
    )

    _insert_event(
        db_path,
        device_id="esp32_02",
        subject_ip=None,
        event_type="AI_ANOMALY",
        detected_at=manifest.attack_started_at,
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
        runner = ScenarioRunner(
            execution_node="unit-test-node", runs_root=tmp_path, allow_execute=True
        )
        result, manifest = _run_real(
            runner, "packet_rate_flood", source_ip="192.168.0.10"
        )

    _insert_event(
        db_path,
        device_id=None,
        subject_ip="192.168.0.10",
        event_type="PACKET_RATE_ANOMALY",
        detected_at=manifest.attack_started_at,
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["matched"] == ["PACKET_RATE_ANOMALY"]


def test_event_detected_mid_window_is_still_matched(tmp_path: Path, db_session):
    """analysis_window_start가 공격 시작보다 앞서더라도(집계 Window 중간에 공격이
    시작된 경우) detected_at이 관찰 구간 안에 있으면 matched로 잡혀야 한다."""
    session, db_path = db_session
    runner = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path, allow_execute=True
    )
    result, manifest = _run_real(
        runner, "mqtt_abnormal_publish_rate", target_device_id="esp32_02"
    )

    # analysis_window_start는 공격 시작보다 훨씬 이전(예: 집계 Window가 공격
    # 시작 전부터 열려 있었던 경우)이지만, detected_at(실제 탐지 시각)은 관찰 구간 안에 있다.
    from datetime import timedelta

    window_start_before_attack = manifest.started_at - timedelta(seconds=8)

    _insert_event(
        db_path,
        device_id="esp32_02",
        subject_ip=None,
        event_type="ABNORMAL_PUBLISH_RATE",
        detected_at=manifest.attack_started_at,
        window_start=window_start_before_attack,
        window_end=manifest.observation_deadline_at,
    )

    report = build_comparison_report(tmp_path / result.run_id, session)
    assert report.comparison["matched"] == ["ABNORMAL_PUBLISH_RATE"]
    assert report.comparison["missing"] == []