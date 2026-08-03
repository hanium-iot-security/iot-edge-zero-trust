"""Scenario Runner가 만든 run-manifest.json + scenario-result.jsonl이
``edge/evaluation/export_phase5_results.py``를 통과해 올바른 TP/FP/FN을 낼 수 있는지 end-to-end로 검증한다.

이 테스트는 실제로 재현했던 버그(마이크로초 포함 attack_started_at 때문에 같은 초에 기록된 Detection Event가 "공격 시작 이전"으로 잘못 배제되는 문제)의 회귀를 막기 위한 것이다.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3

from edge.evaluation.export_phase5_results import (
    PHASE5_EVALUATION_SCHEMA_VERSION,
    export_phase5_results,
)
from edge.scenarios.run_scenario import ScenarioRunner

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "db" / "migrations"
FAKE_SOURCE_COMMIT = "a" * 40


def _build_test_db(db_path: Path, *, device_id: str, ip_address: str) -> None:
    with sqlite3.connect(db_path) as conn:
        for name in ("001_init.sql", "002_packet_gateway.sql", "003_phase4_detection.sql"):
            conn.executescript((MIGRATIONS_DIR / name).read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO devices (device_id, ip_address, status, trust_score) "
            "VALUES (?, ?, 'active', 100)",
            (device_id, ip_address),
        )
        conn.commit()


def _insert_detection_event(
    db_path: Path,
    *,
    device_id: str,
    event_type: str,
    detected_at,
    window_start,
    window_end,
) -> None:
    fmt = "%Y-%m-%d %H:%M:%S"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO detection_events
                (device_id, detector_type, event_type, severity, score_delta,
                 applied_to_score, detected_at, analysis_window_start, analysis_window_end)
            VALUES (?, 'RULE', ?, 'high', -20, 1, ?, ?, ?)
            """,
            (
                device_id,
                event_type,
                detected_at.strftime(fmt),
                window_start.strftime(fmt),
                window_end.strftime(fmt),
            ),
        )
        conn.commit()


def test_matched_detection_produces_true_positive(tmp_path: Path):
    db_path = tmp_path / "test.db"
    _build_test_db(db_path, device_id="esp32_02", ip_address="192.168.0.20")

    runner = ScenarioRunner(
        execution_node="pi2", execution_node_registered=True, runs_root=tmp_path / "runs"
    )
    result, manifest = runner.run(
        "mqtt_abnormal_publish_rate",
        target_device_id="esp32_02",
        source_ip="192.168.0.20",
        session_id="sess-integration-1",
        run_id="integration-tp",
        dry_run=True,
    )

    # 같은 초(마이크로초 0)에 기록된 실제 Detection Event를 흉내낸다.
    _insert_detection_event(
        db_path,
        device_id="esp32_02",
        event_type="ABNORMAL_PUBLISH_RATE",
        detected_at=manifest.attack_started_at,
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )

    run_dir = tmp_path / "runs" / result.run_id
    output = export_phase5_results(
        manifest_path=run_dir / "run-manifest.json",
        scenario_results_path=run_dir / "scenario-result.jsonl",
        db_path=db_path,
        output_dir=tmp_path / "export",
        evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
        source_commit=FAKE_SOURCE_COMMIT,
    )

    classification = output["summary"]["classification"]
    assert classification["tp"] == 1
    assert classification["fn"] == 0
    assert classification["recall"] == 1.0


def test_missing_detection_produces_false_negative(tmp_path: Path):
    db_path = tmp_path / "test.db"
    _build_test_db(db_path, device_id="esp32_02", ip_address="192.168.0.20")

    runner = ScenarioRunner(
        execution_node="pi2", execution_node_registered=True, runs_root=tmp_path / "runs"
    )
    result, _manifest = runner.run(
        "mqtt_abnormal_publish_rate",
        target_device_id="esp32_02",
        source_ip="192.168.0.20",
        session_id="sess-integration-2",
        run_id="integration-fn",
        dry_run=True,
    )
    # Detection Event를 아예 넣지 않는다 (탐지 실패 상황 재현).

    run_dir = tmp_path / "runs" / result.run_id
    output = export_phase5_results(
        manifest_path=run_dir / "run-manifest.json",
        scenario_results_path=run_dir / "scenario-result.jsonl",
        db_path=db_path,
        output_dir=tmp_path / "export",
        evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
        source_commit=FAKE_SOURCE_COMMIT,
    )

    classification = output["summary"]["classification"]
    assert classification["tp"] == 0
    assert classification["fn"] == 1