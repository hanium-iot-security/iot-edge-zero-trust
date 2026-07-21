from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

import pytest

from edge.scripts import rollback_phase4_cutover as rollback_cli
from edge.scripts import run_phase4_cutover as cutover_cli
from edge.scripts.phase4_cutover import (
    CutoverConfig,
    CutoverDependencies,
    CutoverExecutionError,
    CutoverSafetyError,
    RollbackConfig,
    RollbackDependencies,
    SmokeTestConfig,
    create_sqlite_backup,
    execute_cutover,
    execute_rollback,
    restore_sqlite_backup,
    run_cutover_smoke_test,
)


CHECKPOINT_KEYS = (
    "mqtt_feature_builder+mqtt_logs",
    "mqtt_feature_rule+feature_logs",
    "mqtt_message_rule+mqtt_logs",
    "mqtt_if+feature_logs",
    "packet_rule+packet_feature_logs",
    "packet_if+packet_feature_logs",
    "trust_score_v2+detection_events",
)


def _complete_checkpoint_summary() -> dict[str, object]:
    return {
        "legacy_migration_event_count": 0,
        "checkpoints": {
            key: {
                "last_processed_id": None,
                "last_completed_window_end": "2026-07-21T04:30:00Z",
            }
            for key in CHECKPOINT_KEYS
        },
    }


def _create_source_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE parent (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parent(id)
            )
            """
        )
        connection.execute("INSERT INTO parent (id, name) VALUES (1, 'before-cutover')")
        connection.execute("INSERT INTO child (id, parent_id) VALUES (1, 1)")


def test_create_sqlite_backup_writes_consistent_snapshot_and_sha256(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    backup = tmp_path / "backups" / "operational_before_phase4.db"
    _create_source_database(source)

    result = create_sqlite_backup(source, backup)

    assert result.database_path == backup.resolve()
    assert result.sha256_path == backup.with_suffix(backup.suffix + ".sha256").resolve()
    assert result.sha256 == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert result.integrity_check == "ok"
    assert result.foreign_key_violations == ()
    assert result.sha256_path.read_text(encoding="utf-8") == (
        f"{result.sha256}  {backup.name}\n"
    )

    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )


def test_create_sqlite_backup_rejects_source_as_destination(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    _create_source_database(source)

    with pytest.raises(CutoverSafetyError, match="different paths"):
        create_sqlite_backup(source, source)


def test_create_sqlite_backup_rejects_missing_source_and_existing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"

    with pytest.raises(CutoverSafetyError, match="does not exist"):
        create_sqlite_backup(source, backup)
    assert not source.exists()

    _create_source_database(source)
    backup.write_bytes(b"existing evidence")
    with pytest.raises(CutoverSafetyError, match="already exists"):
        create_sqlite_backup(source, backup)
    assert backup.read_bytes() == b"existing evidence"

    backup.unlink()
    checksum_manifest = backup.with_suffix(backup.suffix + ".sha256")
    checksum_manifest.write_text("existing manifest\n", encoding="utf-8")
    with pytest.raises(CutoverSafetyError, match="SHA256 destination already exists"):
        create_sqlite_backup(source, backup)
    assert not backup.exists()
    assert checksum_manifest.read_text(encoding="utf-8") == "existing manifest\n"


def test_restore_sqlite_backup_rejects_checksum_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"
    _create_source_database(source)
    artifact = create_sqlite_backup(source, backup)
    backup.write_bytes(backup.read_bytes() + b"tampered")

    with pytest.raises(CutoverSafetyError, match="SHA256 mismatch"):
        restore_sqlite_backup(
            target_path=source,
            backup_path=backup,
            sha256_path=artifact.sha256_path,
        )


def test_restore_sqlite_backup_replaces_database_after_verification(tmp_path: Path) -> None:
    target = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"
    _create_source_database(target)
    artifact = create_sqlite_backup(target, backup)

    with sqlite3.connect(target) as connection:
        connection.execute("UPDATE parent SET name = 'after-cutover' WHERE id = 1")

    restored = restore_sqlite_backup(
        target_path=target,
        backup_path=backup,
        sha256_path=artifact.sha256_path,
    )

    assert restored.integrity_check == "ok"
    assert restored.foreign_key_violations == ()
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )


def test_execute_cutover_uses_safe_order_and_records_result(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    result_path = tmp_path / "results" / "cutover.json"
    _create_source_database(database)
    events: list[str] = []
    cutover_at = datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc)

    def stop_service(service: str) -> None:
        events.append(f"stop:{service}")

    def start_service(service: str) -> None:
        events.append(f"start:{service}")

    def migrate(db_path: Path, migrations_dir: Path) -> dict[str, object]:
        assert db_path == database.resolve()
        assert migrations_dir.name == "migrations"
        events.append("migrate")
        return {"applied_versions": [3], "skipped_versions": [1, 2]}

    def initialize_checkpoints(db_path: Path, timestamp: datetime) -> dict[str, object]:
        assert db_path == database.resolve()
        assert timestamp == cutover_at
        events.append("initialize")
        return _complete_checkpoint_summary()

    def now() -> datetime:
        events.append("cutover-timestamp")
        return cutover_at

    report = execute_cutover(
        CutoverConfig(
            database_path=database,
            backup_directory=tmp_path / "backups",
            migrations_directory=Path("db/migrations"),
            result_path=result_path,
            git_sha="3e30d0d",
            legacy_services=("rule-detector.service", "trust-score.service"),
            new_services=("detection-orchestrator.service", "firewall-worker.service"),
        ),
        CutoverDependencies(
            stop_service=stop_service,
            start_service=start_service,
            apply_migrations=migrate,
            initialize_checkpoints=initialize_checkpoints,
            now=now,
        ),
    )

    assert report.status == "succeeded"
    assert events == [
        "stop:rule-detector.service",
        "stop:trust-score.service",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
        "cutover-timestamp",
        "migrate",
        "initialize",
        "start:detection-orchestrator.service",
        "start:firewall-worker.service",
    ]
    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["status"] == "succeeded"
    assert saved["git_sha"] == "3e30d0d"
    assert saved["phase4_cutover_at"] == "2026-07-21T04:30:00Z"
    assert set(saved["checkpoint_summary"]["checkpoints"]) == set(CHECKPOINT_KEYS)
    assert Path(saved["backup_database"]).exists()
    assert Path(saved["backup_sha256_path"]).exists()


def test_execute_cutover_restores_backup_and_legacy_services_on_failure(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    result_path = tmp_path / "results" / "cutover.json"
    _create_source_database(database)
    events: list[str] = []
    cutover_at = datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc)

    def migrate(db_path: Path, _: Path) -> dict[str, object]:
        events.append("migrate")
        with sqlite3.connect(db_path) as connection:
            connection.execute("UPDATE parent SET name = 'partially-migrated' WHERE id = 1")
        return {"applied_versions": [3]}

    def fail_checkpoint_initialization(_: Path, __: datetime) -> dict[str, object]:
        events.append("initialize")
        raise RuntimeError("checkpoint validation failed")

    with pytest.raises(CutoverExecutionError, match="checkpoint validation failed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=Path("db/migrations"),
                result_path=result_path,
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service",),
                new_services=("detection-orchestrator.service", "firewall-worker.service"),
            ),
            CutoverDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                apply_migrations=migrate,
                initialize_checkpoints=fail_checkpoint_initialization,
                now=lambda: cutover_at,
            ),
        )

    assert events == [
        "stop:rule-detector.service",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
        "migrate",
        "initialize",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
        "start:rule-detector.service",
    ]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )
    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["status"] == "rolled_back"
    assert saved["error"] == "checkpoint validation failed"
    assert saved["rollback_verification"]["integrity_check"] == "ok"


@pytest.mark.parametrize("existing_result", [False, True])
def test_execute_cutover_rejects_unsafe_result_path_before_stopping_services(
    tmp_path: Path,
    existing_result: bool,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    result_path = tmp_path / "previous-result.json" if existing_result else database
    if existing_result:
        result_path.write_text("previous evidence\n", encoding="utf-8")
    events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="result"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=Path("db/migrations"),
                result_path=result_path,
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service",),
                new_services=("detection-orchestrator.service",),
            ),
            CutoverDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                apply_migrations=lambda *_: {},
                initialize_checkpoints=lambda *_: {},
            ),
        )

    assert events == []


def test_cutover_smoke_test_uses_copy_and_preserves_source(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    smoke_database = tmp_path / "smoke" / "phase4-smoke.db"
    result_path = tmp_path / "results" / "smoke.json"
    _create_source_database(database)
    cutover_at = datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc)

    def migrate(db_path: Path, _: Path) -> dict[str, object]:
        assert db_path == smoke_database.resolve()
        with sqlite3.connect(db_path) as connection:
            connection.execute("UPDATE parent SET name = 'smoke-migrated' WHERE id = 1")
        return {"applied_versions": [3]}

    def initialize(db_path: Path, _: datetime) -> dict[str, object]:
        with sqlite3.connect(db_path) as connection:
            connection.execute("CREATE TABLE checkpoint_smoke (id INTEGER PRIMARY KEY)")
        return _complete_checkpoint_summary()

    report = run_cutover_smoke_test(
        SmokeTestConfig(
            source_database_path=database,
            smoke_database_path=smoke_database,
            migrations_directory=Path("db/migrations"),
            result_path=result_path,
            git_sha="3e30d0d",
        ),
        apply_migrations=migrate,
        initialize_checkpoints=initialize,
        now=lambda: cutover_at,
    )

    assert report.status == "succeeded"
    assert report.mode == "smoke-test"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )
    with sqlite3.connect(smoke_database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "smoke-migrated"
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM checkpoint_smoke"
        ).fetchone()[0] == 0

    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["source_database"] == str(database.resolve())
    assert saved["smoke_database"] == str(smoke_database.resolve())
    assert set(saved["checkpoint_summary"]["checkpoints"]) == set(CHECKPOINT_KEYS)
    smoke_manifest = smoke_database.with_suffix(smoke_database.suffix + ".sha256")
    assert smoke_manifest.read_text(encoding="utf-8") == (
        f"{hashlib.sha256(smoke_database.read_bytes()).hexdigest()}  {smoke_database.name}\n"
    )


@pytest.mark.parametrize(
    ("migration_summary", "checkpoint_summary", "expected_error"),
    [
        ({"applied_versions": [], "skipped_versions": [1, 2]}, None, "Migration 003"),
        (
            {"applied_versions": [3]},
            {"checkpoints": {"mqtt_if+feature_logs": {}}},
            "checkpoint keys",
        ),
    ],
)
def test_execute_cutover_rolls_back_when_phase4_contract_is_incomplete(
    tmp_path: Path,
    migration_summary: dict[str, object],
    checkpoint_summary: dict[str, object] | None,
    expected_error: str,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    events: list[str] = []

    with pytest.raises(CutoverExecutionError, match=expected_error):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=Path("db/migrations"),
                result_path=tmp_path / "cutover.json",
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service",),
                new_services=("detection-orchestrator.service",),
            ),
            CutoverDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                apply_migrations=lambda *_: migration_summary,
                initialize_checkpoints=lambda *_: checkpoint_summary or {},
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    assert "start:detection-orchestrator.service" not in events
    assert events[-1] == "start:rule-detector.service"


def test_execute_rollback_verifies_backup_then_restores_and_starts_legacy_services(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    backup = tmp_path / "backups" / "operational.before.db"
    result_path = tmp_path / "results" / "rollback.json"
    _create_source_database(database)
    artifact = create_sqlite_backup(database, backup)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE parent SET name = 'broken-cutover' WHERE id = 1")
    events: list[str] = []

    report = execute_rollback(
        RollbackConfig(
            database_path=database,
            backup_path=backup,
            sha256_path=artifact.sha256_path,
            result_path=result_path,
            git_sha="3e30d0d",
            legacy_services=("rule-detector.service", "trust-score.service"),
            new_services=("detection-orchestrator.service", "firewall-worker.service"),
        ),
        RollbackDependencies(
            stop_service=lambda service: events.append(f"stop:{service}"),
            start_service=lambda service: events.append(f"start:{service}"),
            now=lambda: datetime(2026, 7, 21, 5, 0, tzinfo=timezone.utc),
        ),
    )

    assert report.status == "succeeded"
    assert events == [
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
        "start:rule-detector.service",
        "start:trust-score.service",
    ]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )
    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["restored_backup_sha256"] == artifact.sha256
    assert saved["integrity_check"] == "ok"


def test_cutover_cli_dry_run_has_no_database_or_service_side_effects(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "operational.db"
    backup_directory = tmp_path / "backups"
    result_path = tmp_path / "results" / "cutover.json"
    _create_source_database(database)

    exit_code = cutover_cli.main(
        [
            "--database",
            str(database),
            "--backup-dir",
            str(backup_directory),
            "--result",
            str(result_path),
            "--git-sha",
            "3e30d0d",
            "--legacy-service",
            "rule-detector.service",
            "--new-service",
            "detection-orchestrator.service",
            "--dry-run",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["mode"] == "dry-run"
    assert output["will_modify_database"] is False
    assert output["database"] == str(database.resolve())
    assert not backup_directory.exists()
    assert not result_path.exists()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )


def test_cutover_cli_execute_requires_explicit_confirmation(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)

    with pytest.raises(CutoverSafetyError, match="PHASE4-CUTOVER"):
        cutover_cli.main(
            [
                "--database",
                str(database),
                "--backup-dir",
                str(tmp_path / "backups"),
                "--result",
                str(tmp_path / "cutover.json"),
                "--git-sha",
                "3e30d0d",
                "--execute",
            ]
        )


def test_rollback_cli_dry_run_does_not_restore_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"
    _create_source_database(database)
    artifact = create_sqlite_backup(database, backup)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE parent SET name = 'current-state' WHERE id = 1")

    exit_code = rollback_cli.main(
        [
            "--database",
            str(database),
            "--backup",
            str(backup),
            "--sha256",
            str(artifact.sha256_path),
            "--result",
            str(tmp_path / "rollback.json"),
            "--git-sha",
            "3e30d0d",
            "--dry-run",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["mode"] == "dry-run"
    assert output["will_restore_database"] is False
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "current-state"
        )
