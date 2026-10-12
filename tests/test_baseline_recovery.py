"""Phase 5 Baseline Recovery의 SQLite 안전 계약 테스트."""

from __future__ import annotations

import importlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from backend.app.config import settings
from edge.trust.firewall_runtime_snapshot import SNAPSHOT_SCHEMA_VERSION


def _load_core():
    try:
        return importlib.import_module("edge.trust.baseline_recovery")
    except ModuleNotFoundError as exc:
        pytest.fail(f"Baseline Recovery core is not implemented: {exc}")


def _load_cli():
    try:
        return importlib.import_module("edge.trust.run_baseline_recovery")
    except ModuleNotFoundError as exc:
        pytest.fail(f"Baseline Recovery CLI is not implemented: {exc}")


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch) -> Path:
    snapshot = tmp_path / "runtime.json"
    snapshot.write_text(json.dumps({
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "available": True, "managed_rules": [], "error": None,
    }), encoding="utf-8")
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_path", str(snapshot))
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "firewall.lock"))
    path = tmp_path / "baseline-recovery.db"
    apply_migrations(path, MIGRATIONS_DIR)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executemany(
            """
            INSERT INTO devices (
                device_id, ip_address, status, trust_score, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("esp32_01", "192.168.0.4", "isolated", 20, "2026-08-03T00:00:00Z"),
                ("esp32_02", "192.168.0.5", "isolated", 40, "2026-08-03T00:00:01Z"),
                ("camera_01", "192.168.0.30", "warning", 60, "2026-08-03T00:00:02Z"),
            ],
        )
        connection.commit()
    return path


def _rows(database: Path, query: str, parameters: tuple[object, ...] = ()) -> list[tuple]:
    with sqlite3.connect(database) as connection:
        return connection.execute(query, parameters).fetchall()


def _device_rows(database: Path) -> list[tuple]:
    return _rows(
        database,
        """
        SELECT device_id, ip_address, status, trust_score, last_seen_at, created_at
        FROM devices
        ORDER BY device_id
        """,
    )


def _table_rows(database: Path, table: str) -> list[tuple]:
    return _rows(database, f'SELECT * FROM "{table}" ORDER BY rowid')


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _insert_detection_event(
    database: Path,
    *,
    device_id: str = "esp32_01",
    processed_at: str | None = None,
    processing_reason: str | None = None,
) -> int:
    with sqlite3.connect(database) as connection:
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, description,
                analysis_window_start, analysis_window_end, detected_at,
                processed_at, processing_reason
            )
            VALUES (
                ?, 'MQTT_RULE', 'ABNORMAL_PUBLISH_RATE', 'HIGH',
                -20, 0, 'pending trust event',
                '2026-08-03T00:00:00Z', '2026-08-03T00:00:10Z',
                '2026-08-03T00:00:11Z', ?, ?
            )
            """,
            (device_id, processed_at, processing_reason),
        ).lastrowid
        connection.commit()
    assert event_id is not None
    return int(event_id)


def _insert_release_request(
    database: Path,
    *,
    status: str,
    device_id: str | None = "esp32_01",
    source_ip: str = "192.168.0.4",
) -> int:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        rule_id = connection.execute(
            """
            INSERT INTO firewall_rules (
                device_id, source_ip, status, applied_at, released_at
            )
            VALUES (
                ?, ?, 'REMOVED',
                '2026-08-03T00:00:00Z', '2026-08-03T00:00:10Z'
            )
            """,
            (device_id, source_ip),
        ).lastrowid
        request_id = connection.execute(
            """
            INSERT INTO firewall_release_requests (
                firewall_rule_id, status, requested_by, reason,
                requested_at, processed_at, last_error
            )
            VALUES (
                ?, ?, 'operator@example', 'official release',
                '2026-08-03T00:00:01Z',
                CASE WHEN ? = 'PENDING' THEN NULL ELSE '2026-08-03T00:00:02Z' END,
                CASE WHEN ? = 'FAILED' THEN 'runtime check failed' ELSE NULL END
            )
            """,
            (rule_id, status, status, status),
        ).lastrowid
        connection.commit()
    assert request_id is not None
    return int(request_id)


def _seed_preserved_history(database: Path) -> tuple[str, ...]:
    preserved_tables = (
        "mqtt_logs",
        "feature_logs",
        "detection_events",
        "trust_score_history",
        "isolation_history",
        "firewall_rules",
        "gateway_metrics",
        "detector_checkpoints",
        "packet_capture_sessions",
        "packet_capture_segments",
        "packet_feature_logs",
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, description, detected_at,
                processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'MQTT_RULE', 'ABNORMAL_PUBLISH_RATE', 'HIGH',
                -20, 1, 'preserve me', '2026-08-03T00:00:10Z',
                '2026-08-03T00:00:11Z', 'APPLIED'
            )
            """
        ).lastrowid
        connection.execute(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size, received_at,
                is_json_valid, is_topic_valid
            )
            VALUES (
                'esp32_01', 'devices/esp32_01/data', '{"temperature":25}',
                18, '2026-08-03T00:00:09Z', 1, 1
            )
            """
        )
        connection.execute(
            """
            INSERT INTO feature_logs (
                device_id, window_start, window_end, publish_count, topic_count
            )
            VALUES (
                'esp32_01', '2026-08-03T00:00:00Z',
                '2026-08-03T00:00:10Z', 1, 1
            )
            """
        )
        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-03T00:00:00Z', '2026-08-03T00:00:10Z',
                40, -20, -20, -20, 20, ?, 'trust-v2'
            )
            """,
            (json.dumps([event_id]),),
        )
        connection.execute(
            """
            INSERT INTO isolation_history (
                device_id, action, reason, trust_score, trigger_event_id
            )
            VALUES ('esp32_01', 'ISOLATED', 'preserve me', 20, ?)
            """,
            (event_id,),
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (
                device_id, source_ip, status, trigger_event_id,
                applied_at, released_at
            )
            VALUES (
                'esp32_01', '192.168.0.4', 'REMOVED', ?,
                '2026-08-03T00:00:11Z', '2026-08-03T00:00:12Z'
            )
            """,
            (event_id,),
        )
        connection.execute(
            """
            INSERT INTO gateway_metrics (
                collected_at, memory_percent, disk_percent,
                interface_metrics_json
            )
            VALUES ('2026-08-03T00:00:10Z', 30.0, 40.0, '{}')
            """
        )
        connection.execute(
            """
            INSERT INTO detector_checkpoints (
                detector_name, source_table, last_processed_id,
                last_completed_window_end
            )
            VALUES (
                'mqtt_message_rule', 'mqtt_logs', 123,
                '2026-08-03T00:00:10Z'
            )
            """
        )
        session_pk = connection.execute(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at, first_window_start,
                ended_at, status
            )
            VALUES (
                '11111111-1111-4111-8111-111111111111', 'eth0',
                '2026-08-03T00:00:00Z', '2026-08-03T00:00:00Z',
                '2026-08-03T00:00:10Z', 'COMPLETED'
            )
            """
        ).lastrowid
        segment_pk = connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, packet_count, processed_at
            )
            VALUES (
                ?, 'preserved.pcap', 'eth0',
                '2026-08-03T00:00:00Z', '2026-08-03T00:00:10Z',
                'PROCESSED', 1, '2026-08-03T00:00:11Z'
            )
            """,
            (session_pk,),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id, device_id, peer_ip, direction,
                window_start, window_end, packet_count, total_bytes,
                avg_packet_size, max_packet_size
            )
            VALUES (
                ?, 'esp32_01', '192.168.0.4', 'INBOUND',
                '2026-08-03T00:00:00Z', '2026-08-03T00:00:10Z',
                1, 100, 100.0, 100
            )
            """,
            (segment_pk,),
        )
        connection.commit()
    return preserved_tables


@pytest.mark.parametrize(
    ("device_ids", "expectation_entries", "message"),
    [
        (["esp32_01", "esp32_02"], ["esp32_01=20"], "모든 --device"),
        (["esp32_01"], ["esp32_01=20", "esp32_01=20"], "중복"),
        (["esp32_01"], ["esp32_01=20", "esp32_02=20"], "대상에 없는"),
        (["esp32_01"], ["esp32_01=-1"], "0~100"),
        (["esp32_01"], ["esp32_01=101"], "0~100"),
        (["esp32_01", "esp32_01"], ["esp32_01=20"], "--device 중복"),
    ],
)
def test_parse_device_expectations_rejects_ambiguous_or_incomplete_input(
    device_ids: list[str],
    expectation_entries: list[str],
    message: str,
) -> None:
    core = _load_core()

    with pytest.raises(core.BaselineRecoveryError, match=message):
        core.parse_device_expectations(device_ids, expectation_entries)


def test_parse_device_expectations_returns_each_device_expected_score() -> None:
    core = _load_core()

    result = core.parse_device_expectations(
        ["esp32_01", "esp32_02"],
        ["esp32_02=40", "esp32_01=20"],
    )

    assert result == {"esp32_01": 20, "esp32_02": 40}


def test_dry_run_reports_two_isolated_devices_without_changing_database(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01", "esp32_02"],
        expected_trust_scores={"esp32_01": 20, "esp32_02": 40},
        artifact_dir=tmp_path / "artifacts",
    )

    assert result["mode"] == "dry-run"
    assert result["can_execute"] is True
    assert result["database_changed"] is False
    assert result["active_firewall_rule_check"] == {
        "passed": True,
        "count": 0,
        "statuses": ["PENDING", "APPLIED"],
    }
    assert result["pending_trust_event_check"] == {
        "passed": True,
        "count": 0,
        "event_ids": [],
        "events": [],
    }
    assert result["devices"] == [
        {
            "device_id": "esp32_01",
            "ip_address": "192.168.0.4",
            "last_firewall_activity_at": None,
            "current": {"status": "isolated", "trust_score": 20},
            "expected": {"status": "isolated", "trust_score": 20},
            "proposed": {"status": "normal", "trust_score": 100},
        },
        {
            "device_id": "esp32_02",
            "ip_address": "192.168.0.5",
            "last_firewall_activity_at": None,
            "current": {"status": "isolated", "trust_score": 40},
            "expected": {"status": "isolated", "trust_score": 40},
            "proposed": {"status": "normal", "trust_score": 100},
        },
    ]
    command = result["execute_command"]
    assert "--device esp32_01" in command
    assert "--device esp32_02" in command
    assert "--expected-trust-score esp32_01=20" in command
    assert "--expected-trust-score esp32_02=40" in command
    assert "--confirm RESET-TO-NORMAL-100" in command
    assert _device_rows(db_path) == before
    assert not (tmp_path / "artifacts").exists()


def test_dry_run_pending_trust_event_blocks_and_reports_event_details(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    event_id = _insert_detection_event(db_path)
    artifacts = tmp_path / "artifacts"
    before = {
        "devices": _device_rows(db_path),
        "events": _table_rows(db_path, "detection_events"),
    }

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=artifacts,
    )

    assert result["can_execute"] is False
    assert result["pending_trust_event_check"] == {
        "passed": False,
        "count": 1,
        "event_ids": [event_id],
        "events": [
            {
                "id": event_id,
                "device_id": "esp32_01",
                "detector_type": "MQTT_RULE",
                "event_type": "ABNORMAL_PUBLISH_RATE",
                "analysis_window_start": "2026-08-03T00:00:00Z",
                "analysis_window_end": "2026-08-03T00:00:10Z",
                "detected_at": "2026-08-03T00:00:11Z",
                "processing_reason": None,
            }
        ],
    }
    assert "미처리 Detection Event" in result["preflight_errors"][-1]
    assert _device_rows(db_path) == before["devices"]
    assert _table_rows(db_path, "detection_events") == before["events"]
    assert not artifacts.exists()


def test_dry_run_rejects_missing_device_without_changing_database(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)

    with pytest.raises(core.BaselineRecoveryError, match="존재하지"):
        core.inspect_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01", "missing_device"],
            expected_trust_scores={"esp32_01": 20, "missing_device": 20},
            artifact_dir=tmp_path / "artifacts",
        )

    assert _device_rows(db_path) == before
    assert not (tmp_path / "artifacts").exists()


def test_dry_run_rejects_device_that_is_not_isolated(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["camera_01"],
        expected_trust_scores={"camera_01": 60},
        artifact_dir=tmp_path / "artifacts",
    )

    assert result["can_execute"] is False
    assert "isolated" in result["preflight_errors"][0]
    assert result["devices"][0]["current"] == {
        "status": "warning",
        "trust_score": 60,
    }
    assert _device_rows(db_path) == before


def test_dry_run_rejects_changed_trust_score(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 40},
        artifact_dir=tmp_path / "artifacts",
    )

    assert result["can_execute"] is False
    assert "예상 Trust Score" in result["preflight_errors"][0]
    assert result["devices"][0]["expected"]["trust_score"] == 40
    assert _device_rows(db_path) == before


@pytest.mark.parametrize(
    ("status", "rule_device_id", "source_ip"),
    [
        ("PENDING", "esp32_01", "192.168.0.99"),
        ("APPLIED", None, "192.168.0.4"),
    ],
)
def test_dry_run_rejects_active_firewall_rule_for_device_or_ip(
    db_path: Path,
    tmp_path: Path,
    status: str,
    rule_device_id: str | None,
    source_ip: str,
) -> None:
    core = _load_core()
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO firewall_rules (device_id, source_ip, status)
            VALUES (?, ?, ?)
            """,
            (rule_device_id, source_ip, status),
        )
        connection.commit()
    before = _device_rows(db_path)

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
    )

    assert result["can_execute"] is False
    assert result["active_firewall_rule_check"]["passed"] is False
    assert result["active_firewall_rule_check"]["count"] == 1
    assert result["active_firewall_rule_check"]["rules"][0]["status"] == status
    assert "Firewall" in result["preflight_errors"][0]
    assert _device_rows(db_path) == before


def test_dry_run_rejects_pending_firewall_release_request(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    request_id = _insert_release_request(db_path, status="PENDING")
    before = _device_rows(db_path)

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
    )

    assert result["can_execute"] is False
    assert result["pending_firewall_release_request_check"] == {
        "passed": False,
        "count": 1,
        "statuses": ["PENDING"],
        "request_ids": [request_id],
        "requests": [
            {
                "id": request_id,
                "firewall_rule_id": 1,
                "status": "PENDING",
                "firewall_rule_status": "REMOVED",
                "requested_at": "2026-08-03T00:00:01Z",
            }
        ],
    }
    assert "Firewall Release Request" in result["preflight_errors"][0]
    assert _device_rows(db_path) == before


def test_dry_run_allows_failed_firewall_release_request_history(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    _insert_release_request(db_path, status="FAILED")

    result = core.inspect_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
    )

    assert result["can_execute"] is True
    assert result["pending_firewall_release_request_check"] == {
        "passed": True,
        "count": 0,
        "statuses": ["PENDING"],
        "request_ids": [],
        "requests": [],
    }


def test_execute_rejects_pending_firewall_release_request_without_state_change(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    request_id = _insert_release_request(db_path, status="PENDING")
    before = _device_rows(db_path)

    with pytest.raises(core.BaselineRecoveryError, match="Firewall Release Request"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=tmp_path / "artifacts",
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before
    assert _table_rows(db_path, "firewall_release_requests")[0][0] == request_id


def test_execute_recovers_two_isolated_devices_and_creates_verified_artifacts(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    artifacts = tmp_path / "artifacts"

    result = core.execute_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01", "esp32_02"],
        expected_trust_scores={"esp32_01": 20, "esp32_02": 40},
        artifact_dir=artifacts,
        confirm="RESET-TO-NORMAL-100",
    )

    assert result["mode"] == "execute"
    assert result["result"] == "SUCCESS"
    assert result["integrity_check"] == "ok"
    assert result["foreign_key_violations"] == []
    assert result["devices"] == [
        {
            "device_id": "esp32_01",
            "previous": {"status": "isolated", "trust_score": 20},
            "current": {"status": "normal", "trust_score": 100},
        },
        {
            "device_id": "esp32_02",
            "previous": {"status": "isolated", "trust_score": 40},
            "current": {"status": "normal", "trust_score": 100},
        },
    ]
    backup_path = Path(result["backup_path"])
    log_path = Path(result["log_path"])
    assert backup_path.is_file()
    assert log_path.is_file()
    assert result["backup_sha256"] == _sha256(backup_path)
    assert json.loads(log_path.read_text(encoding="utf-8"))["result"] == "SUCCESS"
    assert _rows(backup_path, "PRAGMA integrity_check") == [("ok",)]
    assert _rows(backup_path, "PRAGMA foreign_key_check") == []
    assert _rows(
        db_path,
        "SELECT device_id, status, trust_score FROM devices ORDER BY device_id",
    ) == [
        ("camera_01", "warning", 60),
        ("esp32_01", "normal", 100),
        ("esp32_02", "normal", 100),
    ]
    assert _rows(
        backup_path,
        "SELECT device_id, status, trust_score FROM devices ORDER BY device_id",
    ) == [
        ("camera_01", "warning", 60),
        ("esp32_01", "isolated", 20),
        ("esp32_02", "isolated", 40),
    ]


def test_execute_recovers_only_selected_device(db_path: Path, tmp_path: Path) -> None:
    core = _load_core()

    core.execute_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
        confirm="RESET-TO-NORMAL-100",
    )

    assert _rows(
        db_path,
        "SELECT device_id, status, trust_score FROM devices ORDER BY device_id",
    ) == [
        ("camera_01", "warning", 60),
        ("esp32_01", "normal", 100),
        ("esp32_02", "isolated", 40),
    ]


def test_execute_reports_json_log_failure_after_commit_and_preserves_backup(
    db_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core = _load_core()
    artifacts = tmp_path / "artifacts"

    def fail_json_log(*_args, **_kwargs) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(core, "_write_json_log", fail_json_log)

    with pytest.raises(core.BaselineRecoveryError, match="JSON Log 저장 실패"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=artifacts,
            confirm="RESET-TO-NORMAL-100",
        )

    assert _rows(
        db_path,
        "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'",
    ) == [("normal", 100)]
    backups = list(artifacts.glob("baseline-recovery-*.db"))
    assert len(backups) == 1
    assert _rows(
        backups[0],
        "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'",
    ) == [("isolated", 20)]


@pytest.mark.parametrize(
    ("device_ids", "expected_scores", "message"),
    [
        (["missing_device"], {"missing_device": 20}, "존재하지"),
        (["camera_01"], {"camera_01": 60}, "isolated"),
        (["esp32_01"], {"esp32_01": 40}, "예상 Trust Score"),
    ],
)
def test_execute_rejects_ineligible_device_before_backup(
    db_path: Path,
    tmp_path: Path,
    device_ids: list[str],
    expected_scores: dict[str, int],
    message: str,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)
    artifacts = tmp_path / "artifacts"

    with pytest.raises(core.BaselineRecoveryError, match=message):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=device_ids,
            expected_trust_scores=expected_scores,
            artifact_dir=artifacts,
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before
    assert not artifacts.exists() or not list(artifacts.glob("*.db"))


def test_execute_rejects_active_firewall_rule_before_backup(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO firewall_rules (device_id, source_ip, status)
            VALUES ('esp32_01', '192.168.0.4', 'APPLIED')
            """
        )
        connection.commit()
    before = _device_rows(db_path)
    artifacts = tmp_path / "artifacts"

    with pytest.raises(core.BaselineRecoveryError, match="Firewall"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=artifacts,
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before
    assert not artifacts.exists() or not list(artifacts.glob("*.db"))


def test_execute_pending_trust_event_rejects_before_any_artifact_or_change(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    _insert_detection_event(db_path)
    artifacts = tmp_path / "artifacts"
    before = {
        "devices": _device_rows(db_path),
        "events": _table_rows(db_path, "detection_events"),
    }

    with pytest.raises(core.BaselineRecoveryError, match="미처리 Detection Event"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=artifacts,
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before["devices"]
    assert _table_rows(db_path, "detection_events") == before["events"]
    assert not artifacts.exists()


def test_execute_pending_trust_event_writes_only_failure_json_when_dir_exists(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    event_id = _insert_detection_event(db_path)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    with pytest.raises(core.BaselineRecoveryError, match=str(event_id)):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=artifacts,
            confirm="RESET-TO-NORMAL-100",
        )

    assert list(artifacts.glob("*.db")) == []
    logs = list(artifacts.glob("*.json"))
    assert len(logs) == 1
    failure = json.loads(logs[0].read_text(encoding="utf-8"))
    assert failure["result"] == "FAILED"
    assert failure["backup_path"] is None
    assert str(event_id) in failure["error"]


def test_processed_trust_event_does_not_block_recovery(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    _insert_detection_event(
        db_path,
        processed_at="2026-08-03T00:00:12Z",
        processing_reason="NOT_REPRESENTATIVE",
    )

    result = core.execute_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
        confirm="RESET-TO-NORMAL-100",
    )

    assert result["result"] == "SUCCESS"
    assert _rows(
        db_path,
        "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'",
    ) == [("normal", 100)]


def test_other_device_pending_trust_event_does_not_block_selected_device(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    event_id = _insert_detection_event(db_path, device_id="esp32_02")

    result = core.execute_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
        confirm="RESET-TO-NORMAL-100",
    )

    assert result["result"] == "SUCCESS"
    assert _rows(
        db_path,
        "SELECT processed_at FROM detection_events WHERE id = ?",
        (event_id,),
    ) == [(None,)]


def test_execute_rejects_wrong_confirmation_before_backup(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)

    with pytest.raises(core.BaselineRecoveryError, match="confirm"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=tmp_path / "artifacts",
            confirm="yes",
        )

    assert _device_rows(db_path) == before
    assert not (tmp_path / "artifacts").exists()


def test_backup_failure_keeps_database_unchanged(
    db_path: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)

    def fail_backup(*_args, **_kwargs):
        raise OSError("forced backup failure")

    monkeypatch.setattr(core, "_create_backup", fail_backup, raising=False)

    with pytest.raises(core.BaselineRecoveryError, match="Backup"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=tmp_path / "artifacts",
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before


@pytest.mark.parametrize("slow_stage", ["backup", "sha256", "backup_integrity"])
def test_capture_and_mqtt_writers_commit_during_backup_validation(
    db_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    slow_stage: str,
) -> None:
    """A slow recovery stage must not hold the single SQLite writer slot."""
    core = _load_core()
    with sqlite3.connect(db_path) as connection:
        session_id = connection.execute(
            "INSERT INTO packet_capture_sessions "
            "(session_id,capture_interface,started_at,first_window_start,status) "
            "VALUES ('22222222-2222-4222-8222-222222222222','eth0',"
            "'2026-08-03T00:00:00Z','2026-08-03T00:00:00Z','RUNNING')"
        ).lastrowid

    stage_entered = threading.Event()
    writer_finished = threading.Event()

    def commit_capture_and_message():
        assert stage_entered.wait(2)
        with sqlite3.connect(db_path, timeout=0) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                "INSERT INTO packet_capture_segments "
                "(capture_session_id,file_name,capture_interface,window_start,window_end,"
                "status,actual_capture_started_at,captured_duration_seconds) "
                "VALUES (?,'during-recovery.pcap','eth0','2026-08-03T00:00:00Z',"
                "'2026-08-03T00:00:10Z','READY','2026-08-03T00:00:00Z',10)",
                (session_id,),
            )
            connection.execute(
                "INSERT INTO mqtt_logs "
                "(device_id,topic,payload,payload_size,is_json_valid,is_topic_valid) "
                "VALUES ('esp32_01','devices/esp32_01/data','{\"seq\":1}',9,1,1)"
            )
            connection.commit()
        writer_finished.set()

    hook_name = {
        "backup": "_create_backup",
        "sha256": "_file_sha256",
        "backup_integrity": "_verify_database_path",
    }[slow_stage]
    original = getattr(core, hook_name)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(commit_capture_and_message)

        def slow_stage_with_concurrent_writer(*args):
            # The operation deliberately cannot finish until the independent
            # Capture/Subscriber writer commits. No timing/sleep race is needed.
            if not stage_entered.is_set():
                stage_entered.set()
                future.result(timeout=2)
                assert writer_finished.is_set()
            return original(*args)

        monkeypatch.setattr(core, hook_name, slow_stage_with_concurrent_writer)
        result = core.execute_baseline_recovery(
            db_path=db_path, device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=tmp_path / "artifacts", confirm=core.CONFIRMATION,
        )

    assert result["result"] == "SUCCESS"
    assert _rows(db_path, "SELECT status FROM packet_capture_segments") == [("READY",)]
    assert _rows(db_path, "SELECT payload FROM mqtt_logs") == [('{"seq":1}',)]
    assert _rows(Path(result["backup_path"]),
                 "SELECT status,trust_score FROM devices WHERE device_id='esp32_01'") == [
        ("isolated", 20),
    ]


@pytest.mark.parametrize("change", ["ip", "score", "status", "event", "rule", "release"])
def test_changes_during_backup_are_revalidated_before_reset(
    db_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    core = _load_core()
    original = core._create_backup

    def change_after_backup(database, backup):
        original(database, backup)
        if change == "event":
            _insert_detection_event(database)
        elif change == "release":
            _insert_release_request(database, status="PENDING")
        else:
            with sqlite3.connect(database) as connection:
                if change == "rule":
                    connection.execute(
                        "INSERT INTO firewall_rules(device_id,source_ip,status) "
                        "VALUES ('esp32_01','192.168.0.4','PENDING')"
                    )
                elif change == "ip":
                    connection.execute("UPDATE devices SET ip_address='192.168.0.9' "
                                       "WHERE device_id='esp32_01'")
                elif change == "score":
                    connection.execute("UPDATE devices SET trust_score=19 WHERE device_id='esp32_01'")
                else:
                    connection.execute("UPDATE devices SET status='warning' WHERE device_id='esp32_01'")

    monkeypatch.setattr(core, "_create_backup", change_after_backup)
    with pytest.raises(core.BaselineRecoveryError):
        core.execute_baseline_recovery(
            db_path=db_path, device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=tmp_path / "artifacts", confirm=core.CONFIRMATION,
        )
    assert _rows(db_path, "SELECT trust_score FROM devices WHERE device_id='esp32_01'")[0][0] < 100
    backup = next((tmp_path / "artifacts").glob("*.db"))
    assert _rows(backup, "SELECT status,trust_score FROM devices WHERE device_id='esp32_01'") == [
        ("isolated", 20),
    ]
    report = json.loads(next((tmp_path / "artifacts").glob("*.json")).read_text(encoding="utf-8"))
    assert report["result"] == "FAILED"
    assert report["backup_sha256"] == _sha256(backup)


def test_backup_with_pending_event_cannot_be_used_even_if_live_event_is_processed(
    db_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core = _load_core()
    original = core._create_backup

    def backup_with_intervening_event(database, backup):
        event_id = _insert_detection_event(database)
        original(database, backup)
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE detection_events SET processed_at='2026-08-03T00:00:12Z' "
                               "WHERE id=?", (event_id,))

    monkeypatch.setattr(core, "_create_backup", backup_with_intervening_event)
    with pytest.raises(core.BaselineRecoveryError, match="미처리 Detection Event"):
        core.execute_baseline_recovery(
            db_path=db_path, device_ids=["esp32_01"],
            expected_trust_scores={"esp32_01": 20},
            artifact_dir=tmp_path / "artifacts", confirm=core.CONFIRMATION,
        )
    assert _rows(db_path, "SELECT status,trust_score FROM devices WHERE device_id='esp32_01'") == [
        ("isolated", 20),
    ]


def test_one_device_update_failure_rolls_back_all_devices(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_esp32_02_recovery
            BEFORE UPDATE OF status, trust_score ON devices
            WHEN OLD.device_id = 'esp32_02'
            BEGIN
                SELECT RAISE(ABORT, 'forced update failure');
            END
            """
        )
        connection.commit()

    with pytest.raises(core.BaselineRecoveryError, match="Update"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01", "esp32_02"],
            expected_trust_scores={"esp32_01": 20, "esp32_02": 40},
            artifact_dir=tmp_path / "artifacts",
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before


def test_conditional_update_mismatch_rolls_back_all_devices(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    before = _device_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER change_second_expected_score
            AFTER UPDATE OF status, trust_score ON devices
            WHEN OLD.device_id = 'esp32_01'
            BEGIN
                UPDATE devices SET trust_score = 41 WHERE device_id = 'esp32_02';
            END
            """
        )
        connection.commit()

    with pytest.raises(core.BaselineRecoveryError, match="조건부 Update"):
        core.execute_baseline_recovery(
            db_path=db_path,
            device_ids=["esp32_01", "esp32_02"],
            expected_trust_scores={"esp32_01": 20, "esp32_02": 40},
            artifact_dir=tmp_path / "artifacts",
            confirm="RESET-TO-NORMAL-100",
        )

    assert _device_rows(db_path) == before


def test_execute_preserves_history_mqtt_feature_gateway_and_packet_tables(
    db_path: Path,
    tmp_path: Path,
) -> None:
    core = _load_core()
    preserved_tables = _seed_preserved_history(db_path)
    before = {table: _table_rows(db_path, table) for table in preserved_tables}

    core.execute_baseline_recovery(
        db_path=db_path,
        device_ids=["esp32_01"],
        expected_trust_scores={"esp32_01": 20},
        artifact_dir=tmp_path / "artifacts",
        confirm="RESET-TO-NORMAL-100",
    )

    after = {table: _table_rows(db_path, table) for table in preserved_tables}
    assert after == before


def test_cli_dry_run_prints_json_without_creating_artifacts(
    db_path: Path,
    tmp_path: Path,
    capsys,
) -> None:
    cli = _load_cli()
    artifacts = tmp_path / "artifacts"

    exit_code = cli.main(
        [
            "dry-run",
            "--db-path",
            str(db_path),
            "--device",
            "esp32_01",
            "--expected-trust-score",
            "esp32_01=20",
            "--artifact-dir",
            str(artifacts),
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dry-run"
    assert output["devices"][0]["device_id"] == "esp32_01"
    assert not artifacts.exists()


def test_cli_rejects_missing_expected_score_before_backup(
    db_path: Path,
    tmp_path: Path,
    capsys,
) -> None:
    cli = _load_cli()
    artifacts = tmp_path / "artifacts"
    before = _device_rows(db_path)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "execute",
                "--db-path",
                str(db_path),
                "--device",
                "esp32_01",
                "--artifact-dir",
                str(artifacts),
                "--confirm",
                "RESET-TO-NORMAL-100",
            ]
        )

    assert exc_info.value.code == 2
    assert "--expected-trust-score" in capsys.readouterr().err
    assert _device_rows(db_path) == before
    assert not artifacts.exists()


def test_cli_dry_run_requires_explicit_artifact_dir(
    db_path: Path,
    capsys,
) -> None:
    cli = _load_cli()

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "dry-run",
                "--db-path",
                str(db_path),
                "--device",
                "esp32_01",
                "--expected-trust-score",
                "esp32_01=20",
            ]
        )

    assert exc_info.value.code == 2
    assert "--artifact-dir" in capsys.readouterr().err


def test_cli_dry_run_returns_nonzero_with_json_when_device_is_ineligible(
    db_path: Path,
    tmp_path: Path,
    capsys,
) -> None:
    cli = _load_cli()

    exit_code = cli.main(
        [
            "dry-run",
            "--db-path",
            str(db_path),
            "--device",
            "camera_01",
            "--expected-trust-score",
            "camera_01=60",
            "--artifact-dir",
            str(tmp_path / "artifacts"),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dry-run"
    assert output["can_execute"] is False
    assert output["devices"][0]["current"]["status"] == "warning"


def test_cli_execute_prints_result_and_log_path(
    db_path: Path,
    tmp_path: Path,
    capsys,
) -> None:
    cli = _load_cli()

    exit_code = cli.main(
        [
            "execute",
            "--db-path",
            str(db_path),
            "--device",
            "esp32_01",
            "--expected-trust-score",
            "esp32_01=20",
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            "--confirm",
            "RESET-TO-NORMAL-100",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["result"] == "SUCCESS"
    assert Path(output["backup_path"]).is_file()
    assert Path(output["log_path"]).is_file()
