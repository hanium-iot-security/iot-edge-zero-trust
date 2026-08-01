from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sqlite3

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.evaluation.phase5_evaluator import (
    PHASE5_EVALUATION_SCHEMA_VERSION,
    evaluate_phase5_run,
    summarize_evaluation_rows,
)
from edge.phase5.contracts import RunManifest


SOURCE_COMMIT = "a" * 40


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "phase5-evaluator.db"
    apply_migrations(path, MIGRATIONS_DIR)
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
        "statuses": _statuses(),
    }
    payload.update(overrides)
    return RunManifest.from_dict(payload)


def _statuses(value: str = "NOT_EVALUATED") -> dict[str, str]:
    return {
        "scenario_status": value,
        "detection_status": value,
        "trust_status": value,
        "firewall_status": value,
        "block_status": value,
        "data_status": value,
        "final_status": value,
    }


def _normal_manifest(**overrides: object) -> RunManifest:
    expected = {
        "expected_event_types": [],
        "detection_expected": False,
        "trust_score_change_expected": False,
        "firewall_expected": False,
        "block_expected": False,
        "evaluation_scope": "FULL_RUN",
    }
    return _manifest(
        scenario={"scenario_id": "normal-baseline"},
        expected_outcome=expected,
        **overrides,
    )


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _seed_device(conn: sqlite3.Connection, *, device_id: str = "esp32_01", ip: str = "192.168.0.50") -> None:
    conn.execute(
        """
        INSERT INTO devices (device_id, ip_address, status, trust_score)
        VALUES (?, ?, 'isolated', 75)
        """,
        (device_id, ip),
    )


def _seed_packet_session(conn: sqlite3.Connection, *, session_id: str = "11111111-1111-4111-8111-111111111111") -> None:
    conn.execute(
        """
        INSERT INTO packet_capture_sessions (
            id,
            session_id,
            capture_interface,
            started_at,
            first_window_start,
            ended_at,
            status
        )
        VALUES (
            1,
            ?,
            'eth0',
            '2026-08-01T01:00:00Z',
            '2026-08-01T01:00:00Z',
            '2026-08-01T01:01:00Z',
            'COMPLETED'
        )
        """,
        (session_id,),
    )
    conn.execute(
        """
        INSERT INTO packet_capture_segments (
            id,
            capture_session_id,
            file_name,
            capture_interface,
            window_start,
            window_end,
            status,
            packet_count,
            processed_at,
            actual_capture_started_at,
            capture_stop_requested_at,
            capture_process_exited_at,
            start_delay_seconds,
            captured_duration_seconds
        )
        VALUES (
            1,
            1,
            'capture_11111111-1111-4111-8111-111111111111_eth0_1785546000_1785546010.pcap',
            'eth0',
            '2026-08-01T01:00:10Z',
            '2026-08-01T01:00:20Z',
            'PROCESSED',
            100,
            '2026-08-01T01:00:21Z',
            '2026-08-01T01:00:10Z',
            '2026-08-01T01:00:20Z',
            '2026-08-01T01:00:21Z',
            0.2,
            9.8
        )
        """
    )
    conn.execute(
        """
        INSERT INTO packet_feature_logs (
            id,
            capture_segment_id,
            device_id,
            peer_ip,
            direction,
            window_start,
            window_end,
            packet_count,
            total_bytes,
            avg_packet_size,
            max_packet_size,
            mean_inter_arrival_time,
            distinct_dest_port_count,
            tcp_syn_count,
            mqtt_related_packet_count,
            non_mqtt_tcp_udp_packet_count,
            capture_scope
        )
        VALUES (
            1,
            1,
            'esp32_01',
            '192.168.0.50',
            'INBOUND',
            '2026-08-01T01:00:10Z',
            '2026-08-01T01:00:20Z',
            100,
            10000,
            100.0,
            120,
            0.1,
            3,
            1,
            100,
            0,
            'gateway'
        )
        """
    )


def _insert_detection(
    conn: sqlite3.Connection,
    *,
    event_id: int = 1,
    event_type: str = "PACKET_RATE_ANOMALY",
    detector_type: str = "RULE",
    device_id: str = "esp32_01",
    subject_ip: str = "192.168.0.50",
    packet_feature_log_id: int | None = 1,
    detected_at: str | None = "2026-08-01T01:00:21Z",
) -> None:
    conn.execute(
        """
        INSERT INTO detection_events (
            id,
            device_id,
            packet_feature_log_id,
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
        VALUES (?, ?, ?, ?, ?, 'high', -20, 1, ?, '2026-08-01T01:00:10Z', '2026-08-01T01:00:20Z', 'FLOODING', ?)
        """,
        (
            event_id,
            device_id,
            packet_feature_log_id,
            detector_type,
            event_type,
            detected_at,
            subject_ip,
        ),
    )


def _insert_trust(conn: sqlite3.Connection, *, history_id: int = 1, event_ids: list[int] | None = None, created_at: str = "2026-08-01T01:00:22Z") -> None:
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
        VALUES (?, 'esp32_01', '2026-08-01T01:00:10Z', '2026-08-01T01:00:20Z', 100, -20, -20, -20, 80, ?, 'phase4-trust-v2', ?)
        """,
        (history_id, json.dumps(event_ids or [1]), created_at),
    )


def _insert_firewall(conn: sqlite3.Connection, *, rule_id: int = 1, trigger_event_id: int = 1, source_ip: str = "192.168.0.50", status: str = "APPLIED", applied_at: str | None = "2026-08-01T01:00:24Z") -> None:
    conn.execute(
        """
        INSERT INTO firewall_rules (
            id,
            device_id,
            source_ip,
            status,
            reason,
            trigger_event_id,
            created_at,
            applied_at
        )
        VALUES (?, 'esp32_01', ?, ?, 'PACKET_RATE_ANOMALY', ?, '2026-08-01T01:00:23Z', ?)
        """,
        (rule_id, source_ip, status, trigger_event_id, applied_at),
    )


def _seed_success(conn: sqlite3.Connection) -> None:
    _seed_device(conn)
    _seed_packet_session(conn)
    _insert_detection(conn)
    _insert_trust(conn)
    _insert_firewall(conn)
    conn.commit()


def _evaluate(path: Path, manifest: RunManifest | None = None, scenario_result: dict[str, object] | None = None) -> dict[str, object]:
    return evaluate_phase5_run(
        manifest or _manifest(),
        db_path=path,
        evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
        source_commit=SOURCE_COMMIT,
        scenario_result=scenario_result or {
            "run_id": "run-001",
            "session_id": "11111111-1111-4111-8111-111111111111",
            "scenario_id": "packet-flood",
            "traffic_label": "attack",
            "block_confirmed": True,
            "block_confirmed_at": "2026-08-01T01:00:30Z",
            "detection_observed_at": "2026-08-01T01:00:25Z",
            "trust_observed_at": "2026-08-01T01:00:26Z",
        },
    )


def test_evaluator_imports_common_run_schema() -> None:
    from edge.evaluation import phase5_evaluator

    assert phase5_evaluator.RunManifest is RunManifest
    assert "class RunManifest" not in Path(phase5_evaluator.__file__).read_text(
        encoding="utf-8"
    )


def test_attack_e2e_success_matches_session_source_and_expected_event(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_success(conn)

    row = _evaluate(db_path)

    assert row["final_status"] == "SUCCESS"
    assert row["classification"] == {"tp": True, "fp": False, "tn": False, "fn": False, "basis": "expected_event_types"}
    assert row["matched_ids"]["detection_event_ids"] == [1]
    assert row["matched_ids"]["trust_score_history_ids"] == [1]
    assert row["matched_ids"]["firewall_rule_ids"] == [1]
    assert row["matching"]["strategy"] == ["session_id+device_id+source_ip"]


def test_device_and_source_ip_match_without_session_fk(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _insert_detection(conn, packet_feature_log_id=None)
        conn.commit()

    row = _evaluate(db_path)

    assert row["matched_ids"]["detection_event_ids"] == [1]
    assert row["matching"]["strategy"] == ["device_id+source_ip+time_range"]


def test_time_only_candidate_is_not_linked(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn, device_id="esp32_02", ip="192.168.0.60")
        _insert_detection(
            conn,
            device_id="esp32_02",
            subject_ip="192.168.0.60",
            packet_feature_log_id=None,
        )
        conn.commit()

    row = _evaluate(db_path)

    assert row["matched_ids"]["detection_event_ids"] == []
    assert row["detection"]["matched_expected_event"] is False
    assert row["final_status"] == "FAILED"


def test_expected_event_type_only_narrows_after_identity_match(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _insert_detection(
            conn,
            event_id=1,
            event_type="PORT_SCAN",
            packet_feature_log_id=None,
        )
        conn.commit()

    row = _evaluate(db_path)

    assert row["detection"]["actual_event_types"] == ["PORT_SCAN"]
    assert row["detection"]["unexpected_event_types"] == ["PORT_SCAN"]
    assert row["detection"]["matched_expected_event"] is False
    assert row["classification"]["fn"] is True


def test_other_session_and_source_rows_are_not_mixed(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _seed_packet_session(conn, session_id="22222222-2222-4222-8222-222222222222")
        _insert_detection(conn, subject_ip="192.168.0.99", packet_feature_log_id=None)
        conn.commit()

    row = _evaluate(db_path)

    assert row["matched_ids"]["detection_event_ids"] == []
    assert "source_ip_mismatch" in row["matching"]["excluded_candidate_reasons"]


def test_normal_session_false_positive_and_attack_false_negative(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _insert_detection(conn, event_type="PORT_SCAN", packet_feature_log_id=None)
        conn.commit()

    normal = _evaluate(
        db_path,
        manifest=_normal_manifest(),
        scenario_result={"traffic_label": "normal"},
    )
    missing_attack = _evaluate(db_path, scenario_result={"traffic_label": "attack"})

    assert normal["classification"]["fp"] is True
    assert normal["final_status"] == "FAILED"
    assert missing_attack["classification"]["fn"] is True


def test_trust_score_delta_and_firewall_state_are_recorded(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_success(conn)

    row = _evaluate(db_path)

    assert row["trust"]["score_before"] == 100
    assert row["trust"]["score_after"] == 80
    assert row["trust"]["total_score_delta"] == -20
    assert row["firewall"]["rule_created"] is True
    assert row["firewall"]["rule_applied"] is True
    assert row["block"]["block_confirmed"] is True


def test_db_latency_and_external_observation_delay_are_separate(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_success(conn)

    row = _evaluate(db_path)
    latencies = {latency["name"]: latency for latency in row["latencies"]}

    assert latencies["detection_processing_latency"]["milliseconds"] == 16000.0
    assert latencies["trust_processing_latency"]["milliseconds"] == 1000.0
    assert latencies["firewall_apply_latency"]["milliseconds"] == 1000.0
    assert latencies["detection_observation_delay"]["milliseconds"] == 4000.0


def test_missing_timestamp_is_null_with_reason(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _insert_detection(conn, detected_at=None, packet_feature_log_id=None)
        conn.commit()

    row = _evaluate(db_path)
    detection_latency = {
        latency["name"]: latency for latency in row["latencies"]
    }["detection_processing_latency"]

    assert row["matched_ids"]["detection_event_ids"] == []
    assert detection_latency["milliseconds"] is None
    assert detection_latency["reason"] == "END_TIMESTAMP_MISSING"


def test_timestamp_order_error_is_not_reported_as_negative_latency(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _insert_detection(
            conn,
            packet_feature_log_id=None,
            detected_at="2026-08-01T01:00:04Z",
        )
        conn.commit()

    manifest = _manifest(attack_started_at="2026-08-01T01:00:03Z")
    row = _evaluate(
        db_path,
        manifest=manifest,
        scenario_result={
            "traffic_label": "attack",
            "block_confirmed": True,
            "block_confirmed_at": "2026-08-01T01:00:02Z",
        },
    )
    block_latency = {
        latency["name"]: latency for latency in row["latencies"]
    }["block_e2e_latency"]

    assert block_latency["milliseconds"] is None
    assert block_latency["reason"] == "TIMESTAMP_ORDER_ERROR"


def test_ambiguous_time_only_candidates_are_not_selected(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn, device_id="esp32_02", ip="192.168.0.60")
        _insert_detection(
            conn,
            event_id=1,
            device_id="esp32_02",
            subject_ip="192.168.0.60",
            packet_feature_log_id=None,
        )
        _insert_detection(
            conn,
            event_id=2,
            device_id="esp32_02",
            subject_ip="192.168.0.61",
            packet_feature_log_id=None,
        )
        conn.commit()

    row = _evaluate(db_path)

    assert row["matching"]["ambiguous_candidate_exists"] is True
    assert row["matched_ids"]["detection_event_ids"] == []


def test_source_ip_mismatch_is_recorded(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_device(conn)
        _insert_detection(
            conn,
            subject_ip="192.168.0.99",
            packet_feature_log_id=None,
        )
        conn.commit()

    row = _evaluate(db_path)

    assert row["matched_ids"]["detection_event_ids"] == []
    assert row["matching"]["excluded_candidate_reasons"]["source_ip_mismatch"] == 1


def test_capture_ineligible_is_excluded_from_valid_success_denominator(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_success(conn)

    row = _evaluate(
        db_path,
        scenario_result={
            "traffic_label": "attack",
            "capture_eligible": False,
            "capture_exclusion_reason": "missing_timing_metadata",
        },
    )

    assert row["data_status"] == "CAPTURE_INELIGIBLE"
    assert row["valid_run"] is False
    assert row["success_denominator_included"] is False


def test_environment_error_for_missing_table(tmp_path: Path) -> None:
    path = tmp_path / "empty.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE devices (device_id TEXT)")

    row = _evaluate(path)

    assert row["final_status"] == "ENVIRONMENT_ERROR"
    assert row["matched_ids"]["detection_event_ids"] is None
    assert row["failure_reasons"][0]["code"] == "SCHEMA_MISSING"


def test_evaluator_does_not_modify_sqlite_database(db_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_success(conn)
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()

    _evaluate(db_path)

    after = hashlib.sha256(db_path.read_bytes()).hexdigest()
    assert after == before


def test_summary_separates_valid_and_overall_metrics(db_path: Path, tmp_path: Path) -> None:
    with _connect(db_path) as conn:
        _seed_success(conn)
    success = _evaluate(db_path)
    env = _evaluate(tmp_path / "missing.db")
    summary = summarize_evaluation_rows(
        [success, env],
        evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
        source_commit=SOURCE_COMMIT,
    )

    assert summary["total_attempts"] == 2
    assert summary["valid_runs"] == 1
    assert summary["valid_run_success_rate"] == 1.0
    assert summary["overall_attempt_success_rate"] == 0.5
    assert summary["environment_error_ratio"] == 0.5


def test_zero_denominator_metrics_are_null() -> None:
    summary = summarize_evaluation_rows(
        [],
        evaluation_schema_version=PHASE5_EVALUATION_SCHEMA_VERSION,
        source_commit=SOURCE_COMMIT,
    )

    assert summary["overall_attempt_success_rate"] is None
    assert summary["classification"]["precision"] is None
    assert summary["classification"]["normal_window_fpr"] is None
