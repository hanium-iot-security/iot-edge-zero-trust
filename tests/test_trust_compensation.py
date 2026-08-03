"""운영자 승인형 Trust Score 보상 복구의 SQLite 안전 계약 테스트."""

from __future__ import annotations

import importlib
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations


def _load_core():
    try:
        return importlib.import_module("edge.trust.trust_compensation")
    except ModuleNotFoundError as exc:
        pytest.fail(f"Trust Compensation core is not implemented: {exc}")


def _load_cli():
    try:
        return importlib.import_module("edge.trust.run_trust_compensation")
    except ModuleNotFoundError as exc:
        pytest.fail(f"Trust Compensation CLI is not implemented: {exc}")


@pytest.fixture
def compensation_db(tmp_path: Path) -> dict[str, object]:
    db_path = tmp_path / "trust-compensation.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO devices (
                device_id, ip_address, status, trust_score, last_seen_at
            )
            VALUES (
                'esp32_01', '192.168.0.4', 'normal', 80,
                '2026-08-03T06:40:00Z'
            )
            """
        )
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, description,
                analysis_window_start, analysis_window_end, detected_at,
                processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'MQTT_RULE', 'ABNORMAL_PUBLISH_RATE', 'high',
                -20, 1, 'subscriber backlog false positive',
                '2026-08-03T06:39:30Z', '2026-08-03T06:39:40Z',
                '2026-08-03T06:39:40Z', '2026-08-03T06:40:00Z',
                'APPLIED_TO_TRUST'
            )
            """
        ).lastrowid
        assert event_id is not None
        history_id = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version,
                created_at
            )
            VALUES (
                'esp32_01', '2026-08-03T06:39:30Z',
                '2026-08-03T06:39:40Z', 100, -20, -20, -20, 80,
                ?, 'trust-score-v2', '2026-08-03T06:40:00Z'
            )
            """,
            (json.dumps([event_id]),),
        ).lastrowid
        assert history_id is not None
        connection.commit()
    return {
        "db_path": db_path,
        "event_id": int(event_id),
        "history_id": int(history_id),
    }


def _inspect(
    scenario: dict[str, object],
    artifact_dir: Path,
    *,
    expected_status: str = "normal",
    expected_trust_score: int = 80,
):
    core = _load_core()
    return core.inspect_trust_compensation(
        db_path=scenario["db_path"],
        device_id="esp32_01",
        source_event_id=scenario["event_id"],
        expected_status=expected_status,
        expected_trust_score=expected_trust_score,
        reason="subscriber backlog false positive",
        approved_by="operator@example",
        artifact_dir=artifact_dir,
    )


def _rows(
    database: Path,
    query: str,
    parameters: tuple[object, ...] = (),
) -> list[tuple]:
    with sqlite3.connect(database) as connection:
        return connection.execute(query, parameters).fetchall()


def _device_row(database: Path) -> tuple:
    return _rows(
        database,
        """
        SELECT device_id, ip_address, status, trust_score, last_seen_at, created_at
        FROM devices
        WHERE device_id = 'esp32_01'
        """,
    )[0]


def _execute(
    scenario: dict[str, object],
    artifact_dir: Path,
    *,
    confirm: str = "APPLY-TRUST-COMPENSATION",
):
    core = _load_core()
    return core.execute_trust_compensation(
        db_path=scenario["db_path"],
        device_id="esp32_01",
        source_event_id=scenario["event_id"],
        expected_status="normal",
        expected_trust_score=80,
        reason="subscriber backlog false positive",
        approved_by="operator@example",
        artifact_dir=artifact_dir,
        confirm=confirm,
    )


def test_dry_run_calculates_exact_compensation_without_changing_db_or_artifacts(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before_device = _device_row(database)
    before_event = _rows(
        database,
        "SELECT * FROM detection_events WHERE id = ?",
        (compensation_db["event_id"],),
    )
    before_history = _rows(
        database,
        "SELECT * FROM trust_score_history WHERE id = ?",
        (compensation_db["history_id"],),
    )
    artifacts = tmp_path / "artifacts"

    result = _inspect(compensation_db, artifacts)

    assert result["mode"] == "dry-run"
    assert result["can_execute"] is True
    assert result["preflight_errors"] == []
    assert result["device"] == {
        "device_id": "esp32_01",
        "ip_address": "192.168.0.4",
        "current_status": "normal",
        "current_trust_score": 80,
        "expected_status": "normal",
        "expected_trust_score": 80,
    }
    assert result["source_event"]["id"] == compensation_db["event_id"]
    assert result["source_trust_history"]["id"] == compensation_db["history_id"]
    assert result["compensation"] == {
        "compensation_delta": 20,
        "proposed_score": 100,
        "proposed_status": "normal",
    }
    assert "APPLY-TRUST-COMPENSATION" in result["execute_command"]
    assert _device_row(database) == before_device
    assert _rows(
        database,
        "SELECT * FROM detection_events WHERE id = ?",
        (compensation_db["event_id"],),
    ) == before_event
    assert _rows(
        database,
        "SELECT * FROM trust_score_history WHERE id = ?",
        (compensation_db["history_id"],),
    ) == before_history
    assert not artifacts.exists()


@pytest.mark.parametrize(
    ("sql", "parameters", "expected_error"),
    [
        (
            "UPDATE devices SET status = 'warning' WHERE device_id = 'esp32_01'",
            (),
            "예상 status",
        ),
        (
            "UPDATE devices SET trust_score = 79 WHERE device_id = 'esp32_01'",
            (),
            "예상 Trust Score",
        ),
        (
            "UPDATE detection_events SET applied_to_score = 0 WHERE id = ?",
            ("event_id",),
            "applied_to_score",
        ),
        (
            "UPDATE detection_events SET processed_at = NULL WHERE id = ?",
            ("event_id",),
            "처리되지 않았습니다",
        ),
        (
            "UPDATE detection_events SET processing_reason = 'NOT_REPRESENTATIVE' WHERE id = ?",
            ("event_id",),
            "processing_reason",
        ),
        (
            "UPDATE detection_events SET score_delta = 0 WHERE id = ?",
            ("event_id",),
            "score_delta",
        ),
        (
            "UPDATE trust_score_history SET policy_version = 'v1' WHERE id = ?",
            ("history_id",),
            "policy_version",
        ),
        (
            "UPDATE trust_score_history SET actual_delta = 0, new_score = 100 WHERE id = ?",
            ("history_id",),
            "actual_delta",
        ),
        (
            "UPDATE trust_score_history SET new_score = 79 WHERE id = ?",
            ("history_id",),
            "산술",
        ),
        (
            "UPDATE trust_score_history SET calculated_delta = -15 WHERE id = ?",
            ("history_id",),
            "calculated_delta",
        ),
    ],
)
def test_dry_run_rejects_ineligible_source_contracts_without_artifacts(
    compensation_db: dict[str, object],
    tmp_path: Path,
    sql: str,
    parameters: tuple[object, ...],
    expected_error: str,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    resolved_parameters = tuple(
        compensation_db[value] if isinstance(value, str) and value in compensation_db else value
        for value in parameters
    )
    with sqlite3.connect(database) as connection:
        connection.execute(sql, resolved_parameters)
        connection.commit()
    before = _device_row(database)
    artifacts = tmp_path / "artifacts"

    result = _inspect(compensation_db, artifacts)

    assert result["can_execute"] is False
    assert any(expected_error in error for error in result["preflight_errors"])
    assert _device_row(database) == before
    assert not artifacts.exists()


def test_dry_run_rejects_missing_device_and_event_without_artifacts(
    compensation_db: dict[str, object], tmp_path: Path
) -> None:
    core = _load_core()
    artifacts = tmp_path / "artifacts"
    common = {
        "db_path": compensation_db["db_path"],
        "expected_status": "normal",
        "expected_trust_score": 80,
        "reason": "false positive",
        "approved_by": "operator@example",
        "artifact_dir": artifacts,
    }

    missing_device = core.inspect_trust_compensation(
        **common,
        device_id="missing-device",
        source_event_id=int(compensation_db["event_id"]),
    )
    missing_event = core.inspect_trust_compensation(
        **common,
        device_id="esp32_01",
        source_event_id=999999,
    )

    assert missing_device["can_execute"] is False
    assert any("Device가 존재하지" in error for error in missing_device["preflight_errors"])
    assert missing_event["can_execute"] is False
    assert any("Source Event가 존재하지" in error for error in missing_event["preflight_errors"])
    assert not artifacts.exists()


def test_dry_run_rejects_event_from_another_device(
    compensation_db: dict[str, object], tmp_path: Path
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO devices (device_id, status, trust_score) VALUES ('esp32_02', 'normal', 100)"
        )
        connection.execute(
            "UPDATE detection_events SET device_id = 'esp32_02' WHERE id = ?",
            (compensation_db["event_id"],),
        )
        connection.commit()

    result = _inspect(compensation_db, tmp_path / "artifacts")

    assert result["can_execute"] is False
    assert any("Event의 Device" in error for error in result["preflight_errors"])


def test_dry_run_rejects_missing_source_history(
    compensation_db: dict[str, object], tmp_path: Path
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM trust_score_history WHERE id = ?",
            (compensation_db["history_id"],),
        )
        connection.commit()

    result = _inspect(compensation_db, tmp_path / "artifacts")

    assert result["can_execute"] is False
    assert any("연결된 Trust History가 없습니다" in error for error in result["preflight_errors"])


@pytest.mark.parametrize(
    ("representative_ids_json", "expected_error"),
    [
        ("not-json", "JSON"),
        (json.dumps(["1"]), "정수 ID"),
        (json.dumps([1, 2]), "정확히 하나"),
        (json.dumps([]), "연결된 Trust History"),
    ],
)
def test_dry_run_rejects_invalid_representative_event_json(
    compensation_db: dict[str, object],
    tmp_path: Path,
    representative_ids_json: str,
    expected_error: str,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    if representative_ids_json == json.dumps(["1"]):
        representative_ids_json = json.dumps([str(compensation_db["event_id"])])
    if representative_ids_json == json.dumps([1, 2]):
        representative_ids_json = json.dumps([compensation_db["event_id"], 999])
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE trust_score_history
            SET representative_event_ids_json = ?
            WHERE id = ?
            """,
            (representative_ids_json, compensation_db["history_id"]),
        )
        connection.commit()

    result = _inspect(compensation_db, tmp_path / "artifacts")

    assert result["can_execute"] is False
    assert any(expected_error in error for error in result["preflight_errors"])


def test_dry_run_rejects_multiple_histories_for_source_event(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-03T06:39:40Z',
                '2026-08-03T06:39:50Z', 100, -20, -20, -20, 80,
                ?, 'trust-score-v2'
            )
            """,
            (json.dumps([compensation_db["event_id"]]),),
        )
        connection.commit()

    result = _inspect(compensation_db, tmp_path / "artifacts")

    assert result["can_execute"] is False
    assert any("여러 Trust History" in error for error in result["preflight_errors"])


def test_dry_run_rejects_pending_event_active_firewall_and_existing_compensation(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, score_delta,
                applied_to_score, processed_at
            )
            VALUES (
                'esp32_01', 'MQTT_RULE', 'LARGE_PAYLOAD', -15, 0, NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (device_id, source_ip, status)
            VALUES ('esp32_01', '192.168.0.4', 'PENDING')
            """
        )
        connection.execute(
            """
            INSERT INTO trust_score_compensations (
                operation_id, device_id, source_event_id,
                source_trust_history_id, previous_score,
                compensation_delta, new_score, reason, approved_by,
                backup_path, backup_sha256
            )
            VALUES (
                'existing-operation', 'esp32_01', ?, ?, 80, 20, 100,
                'already compensated', 'operator@example',
                '/evidence/existing.db', ?
            )
            """,
            (
                compensation_db["event_id"],
                compensation_db["history_id"],
                "a" * 64,
            ),
        )
        connection.commit()

    result = _inspect(compensation_db, tmp_path / "artifacts")

    assert result["can_execute"] is False
    errors = "\n".join(result["preflight_errors"])
    assert "미처리 Detection Event" in errors
    assert "활성 Firewall Rule" in errors
    assert "이미 보상" in errors


def test_dry_run_rejects_current_policy_status_mismatch(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE devices SET trust_score = 60, status = 'normal' WHERE device_id = 'esp32_01'"
        )
        connection.commit()

    result = _inspect(
        compensation_db,
        tmp_path / "artifacts",
        expected_status="normal",
        expected_trust_score=60,
    )

    assert result["can_execute"] is False
    assert any("현재 상태가 Trust Score 정책" in error for error in result["preflight_errors"])


def test_dry_run_rejects_compensation_that_requires_status_change(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE devices SET trust_score = 60, status = 'warning' WHERE device_id = 'esp32_01'"
        )
        connection.commit()

    result = _inspect(
        compensation_db,
        tmp_path / "artifacts",
        expected_status="warning",
        expected_trust_score=60,
    )

    assert result["can_execute"] is False
    assert any("상태 변경" in error for error in result["preflight_errors"])


def test_dry_run_rejects_score_above_100_without_capping(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE devices SET trust_score = 90 WHERE device_id = 'esp32_01'"
        )
        connection.commit()

    result = _inspect(
        compensation_db,
        tmp_path / "artifacts",
        expected_trust_score=90,
    )

    assert result["can_execute"] is False
    assert result["compensation"]["proposed_score"] == 110
    assert any("100을 초과" in error for error in result["preflight_errors"])


def test_dry_run_rejects_missing_migration_before_artifact_creation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "migration-missing.db"
    migrations_003 = tmp_path / "migrations-003"
    migrations_003.mkdir()
    for name in (
        "001_init.sql",
        "002_packet_gateway.sql",
        "003_phase4_detection.sql",
    ):
        (migrations_003 / name).write_text(
            (MIGRATIONS_DIR / name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    apply_migrations(database, migrations_003)
    artifacts = tmp_path / "artifacts"
    core = _load_core()

    result = core.inspect_trust_compensation(
        db_path=database,
        device_id="esp32_01",
        source_event_id=21,
        expected_status="normal",
        expected_trust_score=80,
        reason="subscriber backlog false positive",
        approved_by="operator@example",
        artifact_dir=artifacts,
    )

    assert result["can_execute"] is False
    assert any("Migration" in error for error in result["preflight_errors"])
    assert not artifacts.exists()


def test_execute_compensates_exact_actual_delta_and_records_audit(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before_event = _rows(
        database,
        "SELECT * FROM detection_events WHERE id = ?",
        (compensation_db["event_id"],),
    )
    before_history = _rows(
        database,
        "SELECT * FROM trust_score_history WHERE id = ?",
        (compensation_db["history_id"],),
    )
    artifacts = tmp_path / "artifacts"

    result = _execute(compensation_db, artifacts)

    assert result["result"] == "SUCCESS"
    assert _rows(
        database,
        "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'",
    ) == [("normal", 100)]
    audit = _rows(
        database,
        """
        SELECT operation_id, device_id, source_event_id,
               source_trust_history_id, previous_score,
               compensation_delta, new_score, reason, approved_by,
               backup_path, backup_sha256
        FROM trust_score_compensations
        """,
    )
    assert audit == [
        (
            result["operation_id"],
            "esp32_01",
            compensation_db["event_id"],
            compensation_db["history_id"],
            80,
            20,
            100,
            "subscriber backlog false positive",
            "operator@example",
            result["backup_path"],
            result["backup_sha256"],
        )
    ]
    assert _rows(
        database,
        "SELECT * FROM detection_events WHERE id = ?",
        (compensation_db["event_id"],),
    ) == before_event
    assert _rows(
        database,
        "SELECT * FROM trust_score_history WHERE id = ?",
        (compensation_db["history_id"],),
    ) == before_history

    backup_path = Path(result["backup_path"])
    log_path = Path(result["log_path"])
    assert backup_path.is_file()
    assert log_path.is_file()
    assert hashlib.sha256(backup_path.read_bytes()).hexdigest() == result["backup_sha256"]
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute(
            "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone() == ("normal", 80)
        assert backup.execute(
            "SELECT COUNT(*) FROM trust_score_compensations"
        ).fetchone()[0] == 0
        assert backup.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert backup.execute("PRAGMA foreign_key_check").fetchall() == []
    saved = json.loads(log_path.read_text(encoding="utf-8"))
    assert saved["result"] == "SUCCESS"
    assert saved["operation_id"] == result["operation_id"]
    assert saved["backup_sha256"] == result["backup_sha256"]


def test_execute_preserves_every_existing_table_except_device_and_new_audit(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    with sqlite3.connect(database) as connection:
        table_names = [
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
        ]
        preserved_tables = [
            name
            for name in table_names
            if name not in {"devices", "trust_score_compensations"}
        ]
        before = {
            name: connection.execute(f'SELECT * FROM "{name}"').fetchall()
            for name in preserved_tables
        }

    _execute(compensation_db, tmp_path / "artifacts")

    with sqlite3.connect(database) as connection:
        after = {
            name: connection.execute(f'SELECT * FROM "{name}"').fetchall()
            for name in preserved_tables
        }
    assert after == before


def test_execute_rejects_wrong_confirmation_before_artifacts_or_change(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before = _device_row(database)
    artifacts = tmp_path / "artifacts"
    core = _load_core()

    with pytest.raises(core.TrustCompensationError, match="confirm"):
        _execute(compensation_db, artifacts, confirm="yes")

    assert _device_row(database) == before
    assert not artifacts.exists()


def test_execute_backup_failure_rolls_back_without_audit(
    compensation_db: dict[str, object],
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before = _device_row(database)
    artifacts = tmp_path / "artifacts"
    core = _load_core()

    def fail_backup(*_args, **_kwargs):
        raise OSError("forced backup failure")

    monkeypatch.setattr(core, "_create_backup", fail_backup, raising=False)

    with pytest.raises(core.TrustCompensationError, match="Backup 생성 실패"):
        _execute(compensation_db, artifacts)

    assert _device_row(database) == before
    assert _rows(database, "SELECT * FROM trust_score_compensations") == []


def test_execute_invalid_backup_rolls_back_without_audit(
    compensation_db: dict[str, object],
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before = _device_row(database)
    core = _load_core()
    real_verify = None

    def reject_backup(path: Path):
        if path.name.endswith(".db") and "trust-compensation-" in path.name:
            return "corrupt", [("broken",)]
        assert real_verify is not None
        return real_verify(path)

    real_verify = core._verify_database_path
    monkeypatch.setattr(core, "_verify_database_path", reject_backup)

    with pytest.raises(core.TrustCompensationError, match="Backup 검증 실패"):
        _execute(compensation_db, tmp_path / "artifacts")

    assert _device_row(database) == before
    assert _rows(database, "SELECT * FROM trust_score_compensations") == []


def test_execute_conditional_update_mismatch_rolls_back_audit(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before = _device_row(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER skip_trust_compensation_update
            BEFORE UPDATE OF trust_score ON devices
            WHEN OLD.device_id = 'esp32_01'
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
        connection.commit()
    core = _load_core()

    with pytest.raises(core.TrustCompensationError, match="조건부 Update"):
        _execute(compensation_db, tmp_path / "artifacts")

    assert _device_row(database) == before
    assert _rows(database, "SELECT * FROM trust_score_compensations") == []


def test_execute_audit_insert_failure_rolls_back_device_update(
    compensation_db: dict[str, object],
    tmp_path: Path,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    before = _device_row(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_trust_compensation_audit
            BEFORE INSERT ON trust_score_compensations
            BEGIN
                SELECT RAISE(ABORT, 'forced audit failure');
            END
            """
        )
        connection.commit()
    core = _load_core()

    with pytest.raises(core.TrustCompensationError, match="Transaction"):
        _execute(compensation_db, tmp_path / "artifacts")

    assert _device_row(database) == before
    assert _rows(database, "SELECT * FROM trust_score_compensations") == []


def test_execute_json_failure_keeps_committed_score_audit_and_backup(
    compensation_db: dict[str, object],
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    artifacts = tmp_path / "artifacts"
    core = _load_core()

    def fail_json(*_args, **_kwargs):
        raise OSError("forced JSON failure")

    monkeypatch.setattr(core, "_write_json_log", fail_json, raising=False)

    with pytest.raises(core.TrustCompensationCommittedArtifactError) as exc_info:
        _execute(compensation_db, artifacts)

    assert exc_info.value.database_committed is True
    assert exc_info.value.backup_path.is_file()
    assert _rows(
        database,
        "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'",
    ) == [("normal", 100)]
    assert _rows(
        database,
        """
        SELECT source_event_id, source_trust_history_id,
               previous_score, compensation_delta, new_score
        FROM trust_score_compensations
        """,
    ) == [
        (
            compensation_db["event_id"],
            compensation_db["history_id"],
            80,
            20,
            100,
        )
    ]


def test_execute_rejects_missing_migration_before_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "migration-missing.db"
    migrations_003 = tmp_path / "migrations-003"
    migrations_003.mkdir()
    for name in ("001_init.sql", "002_packet_gateway.sql", "003_phase4_detection.sql"):
        (migrations_003 / name).write_text(
            (MIGRATIONS_DIR / name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    apply_migrations(database, migrations_003)
    artifacts = tmp_path / "artifacts"
    core = _load_core()

    with pytest.raises(core.TrustCompensationError, match="Migration"):
        core.execute_trust_compensation(
            db_path=database,
            device_id="esp32_01",
            source_event_id=21,
            expected_status="normal",
            expected_trust_score=80,
            reason="false positive",
            approved_by="operator@example",
            artifact_dir=artifacts,
            confirm=core.CONFIRMATION,
        )

    assert not artifacts.exists()


def _cli_common_args(scenario: dict[str, object], artifact_dir: Path) -> list[str]:
    return [
        "--db-path", str(scenario["db_path"]),
        "--device", "esp32_01",
        "--source-event-id", str(scenario["event_id"]),
        "--expected-status", "normal",
        "--expected-trust-score", "80",
        "--reason", "subscriber backlog false positive",
        "--approved-by", "operator@example",
        "--artifact-dir", str(artifact_dir),
    ]


def test_cli_dry_run_prints_json_without_artifacts(
    compensation_db: dict[str, object], tmp_path: Path, capsys
) -> None:
    cli = _load_cli()
    artifacts = tmp_path / "artifacts"

    exit_code = cli.main(["dry-run", *_cli_common_args(compensation_db, artifacts)])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["can_execute"] is True
    assert not artifacts.exists()


def test_cli_dry_run_ineligible_returns_two(
    compensation_db: dict[str, object], tmp_path: Path, capsys
) -> None:
    cli = _load_cli()
    args = _cli_common_args(compensation_db, tmp_path / "artifacts")
    args[args.index("80")] = "60"

    exit_code = cli.main(["dry-run", *args])

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out)["can_execute"] is False


def test_cli_execute_applies_compensation(
    compensation_db: dict[str, object], tmp_path: Path, capsys
) -> None:
    database = compensation_db["db_path"]
    assert isinstance(database, Path)
    cli = _load_cli()

    exit_code = cli.main(
        [
            "execute",
            *_cli_common_args(compensation_db, tmp_path / "artifacts"),
            "--confirm", "APPLY-TRUST-COMPENSATION",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["result"] == "SUCCESS"
    assert _device_row(database)[3] == 100


def test_cli_precommit_error_returns_two(
    compensation_db: dict[str, object], tmp_path: Path, capsys
) -> None:
    cli = _load_cli()

    exit_code = cli.main(
        [
            "execute",
            *_cli_common_args(compensation_db, tmp_path / "artifacts"),
            "--confirm", "wrong",
        ]
    )

    assert exit_code == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["database_committed"] is False


def test_cli_postcommit_artifact_error_returns_three_with_hold_evidence(
    compensation_db: dict[str, object], tmp_path: Path, capsys, monkeypatch
) -> None:
    cli = _load_cli()
    core = _load_core()
    backup = tmp_path / "backup.db"
    backup.write_bytes(b"backup")

    def fail_after_commit(**_kwargs):
        raise core.TrustCompensationCommittedArtifactError(
            "artifact failed; HOLD",
            operation_id="operation-1",
            backup_path=backup,
        )

    monkeypatch.setattr(cli, "execute_trust_compensation", fail_after_commit)

    exit_code = cli.main(
        [
            "execute",
            *_cli_common_args(compensation_db, tmp_path / "artifacts"),
            "--confirm", "APPLY-TRUST-COMPENSATION",
        ]
    )

    assert exit_code == 3
    payload = json.loads(capsys.readouterr().err)
    assert payload["database_committed"] is True
    assert payload["operation_id"] == "operation-1"
    assert payload["backup_path"] == str(backup)
    assert payload["operation_status"] == "HOLD"
