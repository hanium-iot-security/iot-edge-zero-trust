from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.evaluation.export_phase5_results import (
    CSV_FILENAME,
    JSONL_FILENAME,
    SUMMARY_FILENAME,
    Phase5ExportError,
    export_phase5_results,
    main,
    parse_args,
)
from edge.evaluation.phase5_evaluator import PHASE5_EVALUATION_SCHEMA_VERSION
from edge.phase5.contracts import RunManifest


SOURCE_COMMIT = "b" * 40


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "phase5-export.db"
    apply_migrations(path, MIGRATIONS_DIR)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '192.168.0.50', 'isolated', 80)
            """
        )
        conn.execute(
            """
            INSERT INTO detection_events (
                id,
                device_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                detected_at,
                analysis_window_start,
                analysis_window_end,
                incident_family,
                subject_ip
            )
            VALUES (
                1,
                'esp32_01',
                'RULE',
                'PACKET_RATE_ANOMALY',
                'high',
                -20,
                1,
                '2026-08-01T01:00:21Z',
                '2026-08-01T01:00:10Z',
                '2026-08-01T01:00:20Z',
                'FLOODING',
                '192.168.0.50'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO trust_score_history (
                id,
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version,
                created_at
            )
            VALUES (
                1,
                'esp32_01',
                '2026-08-01T01:00:10Z',
                '2026-08-01T01:00:20Z',
                100,
                -20,
                -20,
                -20,
                80,
                '[1]',
                'phase4-trust-v2',
                '2026-08-01T01:00:22Z'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO firewall_rules (
                id,
                device_id,
                source_ip,
                status,
                trigger_event_id,
                created_at,
                applied_at
            )
            VALUES (
                1,
                'esp32_01',
                '192.168.0.50',
                'APPLIED',
                1,
                '2026-08-01T01:00:23Z',
                '2026-08-01T01:00:24Z'
            )
            """
        )
        conn.commit()
    return path


@pytest.fixture
def manifest_path(tmp_path: Path) -> Path:
    path = tmp_path / "run-manifest.json"
    path.write_text(_manifest().to_json(), encoding="utf-8")
    return path


@pytest.fixture
def scenario_results_path(tmp_path: Path) -> Path:
    path = tmp_path / "scenario-results.jsonl"
    path.write_text(
        json.dumps(
            {
                "run_id": "run-001",
                "session_id": "11111111-1111-4111-8111-111111111111",
                "scenario_id": "packet-flood",
                "traffic_label": "attack",
                "block_confirmed": True,
                "block_confirmed_at": "2026-08-01T01:00:30Z",
                "detection_observed_at": "2026-08-01T01:00:25Z",
                "trust_observed_at": "2026-08-01T01:00:26Z",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _manifest(**overrides: object) -> RunManifest:
    payload: dict[str, object] = {
        "run_manifest_schema_version": "phase5-run-manifest-v1",
        "run_id": "run-001",
        "session_id": "11111111-1111-4111-8111-111111111111",
        "scenario": {"scenario_id": "packet-flood"},
        "target_device_id": "esp32_01",
        "source_ip": "192.168.0.50",
        "execution_node": {"node_id": "pi-lab-01", "registered": True},
        "evaluation_scope": "FULL_RUN",
        "is_active": False,
        "started_at": "2026-08-01T01:00:00Z",
        "attack_started_at": "2026-08-01T01:00:05Z",
        "observation_deadline_at": "2026-08-01T01:01:00Z",
        "expected_outcome": {
            "expected_event_types": ["PACKET_RATE_ANOMALY"],
            "detection_expected": True,
            "trust_score_change_expected": True,
            "firewall_expected": True,
            "block_expected": True,
            "evaluation_scope": "FULL_RUN",
        },
        "statuses": {
            "scenario_status": "NOT_EVALUATED",
            "detection_status": "NOT_EVALUATED",
            "trust_status": "NOT_EVALUATED",
            "firewall_status": "NOT_EVALUATED",
            "block_status": "NOT_EVALUATED",
            "data_status": "NOT_EVALUATED",
            "final_status": "NOT_EVALUATED",
        },
        "matched_ids": {
            "detection_event_ids": None,
            "trust_score_history_ids": [],
            "firewall_rule_ids": [],
            "trigger_event_ids": None,
        },
    }
    payload.update(overrides)
    return RunManifest.from_dict(payload)


def _export(
    *,
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    output_dir: Path,
) -> dict[str, object]:
    return export_phase5_results(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
        evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
        source_commit=SOURCE_COMMIT,
    )


def test_export_creates_jsonl_csv_and_summary(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"

    result = _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    assert result["row_count"] == 1
    assert (output_dir / JSONL_FILENAME).exists()
    assert (output_dir / CSV_FILENAME).exists()
    assert (output_dir / SUMMARY_FILENAME).exists()


def test_jsonl_is_source_for_csv_and_summary(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    jsonl_row = json.loads((output_dir / JSONL_FILENAME).read_text(encoding="utf-8"))
    summary = json.loads((output_dir / SUMMARY_FILENAME).read_text(encoding="utf-8"))
    with (output_dir / CSV_FILENAME).open(newline="", encoding="utf-8") as csv_file:
        csv_row = next(csv.DictReader(csv_file))

    assert csv_row["evaluation_identity"] == jsonl_row["evaluation_identity"]
    assert summary["total_attempts"] == 1
    assert summary["classification"]["tp"] == 1


def test_csv_preserves_json_null_empty_array_and_na(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    with (output_dir / CSV_FILENAME).open(newline="", encoding="utf-8") as csv_file:
        csv_row = next(csv.DictReader(csv_file))

    assert csv_row["matched_detection_event_ids"] == "[1]"
    assert csv_row["latencies"].startswith("[{")
    assert csv_row["block_status"] != ""


def test_same_input_rerun_does_not_duplicate_rows(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    first = _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )
    first_jsonl = (output_dir / JSONL_FILENAME).read_text(encoding="utf-8")
    second = _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    assert first["row_count"] == second["row_count"] == 1
    assert (output_dir / JSONL_FILENAME).read_text(encoding="utf-8") == first_jsonl


def test_rows_are_written_in_deterministic_order(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )
    second_manifest = tmp_path / "run-manifest-2.json"
    second_manifest.write_text(
        _manifest(run_id="run-000").to_json(),
        encoding="utf-8",
    )
    second_results = tmp_path / "scenario-results-2.jsonl"
    second_results.write_text(
        json.dumps({"run_id": "run-000", "traffic_label": "attack"}) + "\n",
        encoding="utf-8",
    )

    _export(
        manifest_path=second_manifest,
        scenario_results_path=second_results,
        db_path=db_path,
        output_dir=output_dir,
    )

    rows = [
        json.loads(line)
        for line in (output_dir / JSONL_FILENAME).read_text(encoding="utf-8").splitlines()
    ]
    assert [row["run_id"] for row in rows] == ["run-000", "run-001"]


def test_input_validation_failure_creates_no_result_files(
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"

    with pytest.raises(Phase5ExportError):
        _export(
            manifest_path=tmp_path / "missing-manifest.json",
            scenario_results_path=scenario_results_path,
            db_path=db_path,
            output_dir=output_dir,
        )

    assert not (output_dir / JSONL_FILENAME).exists()
    assert not (output_dir / CSV_FILENAME).exists()
    assert not (output_dir / SUMMARY_FILENAME).exists()


def test_existing_corrupt_jsonl_is_not_silently_overwritten(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    jsonl_path = output_dir / JSONL_FILENAME
    jsonl_path.write_text("{not-json\n", encoding="utf-8")

    with pytest.raises(Phase5ExportError):
        _export(
            manifest_path=manifest_path,
            scenario_results_path=scenario_results_path,
            db_path=db_path,
            output_dir=output_dir,
        )

    assert jsonl_path.read_text(encoding="utf-8") == "{not-json\n"


def test_cli_success_exit_code(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    exit_code = main(
        [
            "--manifest",
            str(manifest_path),
            "--scenario-results",
            str(scenario_results_path),
            "--db",
            str(db_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--evaluation-schema-version",
            PHASE5_EVALUATION_SCHEMA_VERSION,
            "--source-commit",
            SOURCE_COMMIT,
        ]
    )

    assert exit_code == 0


def test_cli_error_exit_code(
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    exit_code = main(
        [
            "--manifest",
            str(tmp_path / "missing.json"),
            "--scenario-results",
            str(scenario_results_path),
            "--db",
            str(db_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--evaluation-schema-version",
            PHASE5_EVALUATION_SCHEMA_VERSION,
            "--source-commit",
            SOURCE_COMMIT,
        ]
    )

    assert exit_code != 0


def test_cli_help() -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_args(["--help"])

    assert exc_info.value.code == 0


def test_schema_version_and_commit_are_recorded(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    row = json.loads((output_dir / JSONL_FILENAME).read_text(encoding="utf-8"))

    assert row["evaluation_schema_version"] == PHASE5_EVALUATION_SCHEMA_VERSION
    assert row["source_commit"] == SOURCE_COMMIT


def test_summary_latency_statistics(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "out"
    _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    summary = json.loads((output_dir / SUMMARY_FILENAME).read_text(encoding="utf-8"))

    stats = summary["latency_statistics"]["detection_processing_latency"]
    assert stats["count"] == 1
    assert stats["min"] == 16000.0
    assert stats["p95"] == 16000.0


def test_summary_records_null_when_metric_denominator_is_zero(
    manifest_path: Path,
    scenario_results_path: Path,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "empty.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    output_dir = tmp_path / "out"

    _export(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        output_dir=output_dir,
    )

    summary = json.loads((output_dir / SUMMARY_FILENAME).read_text(encoding="utf-8"))

    assert summary["classification"]["precision"] is None
    assert summary["classification"]["normal_window_fpr"] is None


def test_scenario_results_identity_must_not_be_ambiguous(
    manifest_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    scenario_results = tmp_path / "scenario-results.jsonl"
    scenario_results.write_text(
        '{"run_id":"run-001"}\n{"run_id":"run-001"}\n',
        encoding="utf-8",
    )

    with pytest.raises(Phase5ExportError):
        _export(
            manifest_path=manifest_path,
            scenario_results_path=scenario_results,
            db_path=db_path,
            output_dir=tmp_path / "out",
        )


def test_invalid_source_commit_is_rejected_before_outputs(
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(Phase5ExportError):
        export_phase5_results(
            manifest_path=manifest_path,
            scenario_results_path=scenario_results_path,
            db_path=db_path,
            output_dir=tmp_path / "out",
            evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
            source_commit="not-a-sha",
        )

    assert not (tmp_path / "out" / JSONL_FILENAME).exists()


def test_missing_database_returns_environment_error_exit_code(
    manifest_path: Path,
    scenario_results_path: Path,
    tmp_path: Path,
) -> None:
    exit_code = main(
        [
            "--manifest",
            str(manifest_path),
            "--scenario-results",
            str(scenario_results_path),
            "--db",
            str(tmp_path / "missing.db"),
            "--output-dir",
            str(tmp_path / "out"),
            "--evaluation-schema-version",
            PHASE5_EVALUATION_SCHEMA_VERSION,
            "--source-commit",
            SOURCE_COMMIT,
        ]
    )

    assert exit_code == 74
