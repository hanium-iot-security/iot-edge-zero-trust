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
    _operation_lock,
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
        connection.execute(
            """
            CREATE TABLE detector_checkpoints (
                detector_name TEXT NOT NULL,
                source_table TEXT NOT NULL,
                last_processed_id INTEGER,
                last_completed_window_end DATETIME,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (detector_name, source_table)
            )
            """
        )


def _persist_checkpoint_summary(
    database: Path,
    summary: dict[str, object] | None = None,
) -> dict[str, object]:
    result = summary or _complete_checkpoint_summary()
    checkpoints = result["checkpoints"]
    assert isinstance(checkpoints, dict)
    with sqlite3.connect(database) as connection:
        for key, value in checkpoints.items():
            assert isinstance(value, dict)
            detector_name, source_table = key.split("+", 1)
            connection.execute(
                """
                INSERT OR REPLACE INTO detector_checkpoints (
                    detector_name,
                    source_table,
                    last_processed_id,
                    last_completed_window_end
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    detector_name,
                    source_table,
                    value["last_processed_id"],
                    value["last_completed_window_end"],
                ),
            )
    return result


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
        return _persist_checkpoint_summary(db_path)

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
            is_service_active=lambda service: service in {
                "rule-detector.service",
                "trust-score.service",
            },
            apply_migrations=migrate,
            initialize_checkpoints=initialize_checkpoints,
            now=now,
        ),
    )

    assert report.status == "succeeded"
    assert events == [
        "cutover-timestamp",
        "stop:rule-detector.service",
        "stop:trust-score.service",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
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
                is_service_active=lambda service: service == "rule-detector.service",
                apply_migrations=migrate,
                initialize_checkpoints=fail_checkpoint_initialization,
                now=lambda: cutover_at,
            ),
        )

    assert events[:7] == [
        "stop:rule-detector.service",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
        "migrate",
        "initialize",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
    ]
    assert "start:rule-detector.service" in events[7:]
    assert "start:detection-orchestrator.service" not in events
    assert "start:firewall-worker.service" not in events
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
                is_service_active=lambda _: False,
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
        return _persist_checkpoint_summary(db_path)

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
    assert saved["source_unchanged"] is True
    assert saved["source_sha256_before"] == saved["source_sha256_after"]
    assert saved["source_table_row_counts_before"] == saved[
        "source_table_row_counts_after"
    ]
    assert set(saved["checkpoint_summary"]["checkpoints"]) == set(CHECKPOINT_KEYS)
    smoke_manifest = smoke_database.with_suffix(smoke_database.suffix + ".sha256")
    post_manifest = smoke_database.with_suffix(
        smoke_database.suffix + ".post-migration.sha256"
    )
    assert smoke_manifest.read_text(encoding="utf-8").split()[0] == (
        report.smoke_sha256_before_migration
    )
    assert post_manifest.read_text(encoding="utf-8") == (
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
                is_service_active=lambda service: service == "rule-detector.service",
                apply_migrations=lambda *_: migration_summary,
                initialize_checkpoints=lambda *_: checkpoint_summary or {},
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    assert "start:detection-orchestrator.service" not in events
    assert "start:rule-detector.service" in events


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
            is_service_active=lambda service: service in {
                "detection-orchestrator.service",
                "firewall-worker.service",
            },
            now=lambda: datetime(2026, 7, 21, 5, 0, tzinfo=timezone.utc),
        ),
    )

    assert report.status == "succeeded"
    assert events == [
        "stop:rule-detector.service",
        "stop:trust-score.service",
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


def test_execute_rollback_rejects_missing_operational_database_before_services_change(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    _create_source_database(source)
    artifact = create_sqlite_backup(source, backup)
    events: list[str] = []
    result_path = tmp_path / "rollback.json"

    with pytest.raises(CutoverSafetyError, match="Operational database does not exist"):
        execute_rollback(
            RollbackConfig(
                database_path=tmp_path / "typo-operational.db",
                backup_path=backup,
                sha256_path=artifact.sha256_path,
                backup_directory=tmp_path / "pre-rollback",
                result_path=result_path,
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service",),
                new_services=("detection-orchestrator.service",),
                paused_writer_services=("gateway-metrics.service",),
            ),
            RollbackDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                is_service_active=lambda _: True,
            ),
        )

    assert events == []
    assert not (tmp_path / "typo-operational.db").exists()
    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["status"] == "failed"
    assert saved["failure_stage"] == "preflight"


def test_cutover_failure_restores_only_originally_active_services_and_writers(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    events: list[str] = []
    active = {
        "rule-detector.service": True,
        "trust-score.service": False,
        "gateway-metrics.service": True,
        "packet-capture.service": False,
        "detection-orchestrator.service": False,
    }

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

    with pytest.raises(CutoverExecutionError, match="checkpoint failed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service", "trust-score.service"),
                new_services=("detection-orchestrator.service",),
                paused_writer_services=(
                    "gateway-metrics.service",
                    "packet-capture.service",
                ),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda *_: (_ for _ in ()).throw(
                    RuntimeError("checkpoint failed")
                ),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    assert active["rule-detector.service"] is True
    assert active["trust-score.service"] is False
    assert active["gateway-metrics.service"] is True
    assert active["packet-capture.service"] is False
    assert active["detection-orchestrator.service"] is False
    assert "start:trust-score.service" not in events
    assert "start:packet-capture.service" not in events


def test_manual_rollback_stops_all_writers_and_preserves_current_database_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    selected_backup = tmp_path / "selected.db"
    _create_source_database(database)
    artifact = create_sqlite_backup(database, selected_backup)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE parent SET name = 'pre-manual-rollback' WHERE id = 1")
    active = {
        "rule-detector.service": False,
        "detection-orchestrator.service": True,
        "gateway-metrics.service": True,
    }
    events: list[str] = []

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

    report = execute_rollback(
        RollbackConfig(
            database_path=database,
            backup_path=selected_backup,
            sha256_path=artifact.sha256_path,
            backup_directory=tmp_path / "pre-rollback",
            result_path=tmp_path / "rollback.json",
            git_sha="3e30d0d",
            legacy_services=("rule-detector.service",),
            new_services=("detection-orchestrator.service",),
            paused_writer_services=("gateway-metrics.service",),
        ),
        RollbackDependencies(
            stop_service=stop,
            start_service=start,
            is_service_active=lambda service: active[service],
            now=lambda: datetime(2026, 7, 21, 5, 0, tzinfo=timezone.utc),
        ),
    )

    assert events[:3] == [
        "stop:rule-detector.service",
        "stop:detection-orchestrator.service",
        "stop:gateway-metrics.service",
    ]
    assert report.pre_rollback_backup is not None
    pre_rollback = Path(report.pre_rollback_backup)
    assert pre_rollback.is_file()
    with sqlite3.connect(pre_rollback) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "pre-manual-rollback"
        )
    assert active["rule-detector.service"] is True
    assert active["detection-orchestrator.service"] is False
    assert active["gateway-metrics.service"] is True


def test_smoke_test_records_source_evidence_and_rejects_source_mutation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "operational.db"
    smoke = tmp_path / "smoke.db"
    result = tmp_path / "smoke.json"
    _create_source_database(source)

    def mutate_source_while_migrating(_: Path, __: Path) -> dict[str, object]:
        with sqlite3.connect(source) as connection:
            connection.execute("UPDATE parent SET name = 'unexpected-mutation' WHERE id = 1")
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match="source database changed"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=result,
                git_sha="3e30d0d",
            ),
            apply_migrations=mutate_source_while_migrating,
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )

    saved = json.loads(result.read_text(encoding="utf-8"))
    assert saved["status"] == "failed"
    assert saved["source_unchanged"] is False
    assert saved["source_sha256_before"] != saved["source_sha256_after"]
    assert saved["failure_stage"] == "source-preservation-check"


def test_cutover_rejects_checkpoint_summary_not_persisted_to_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    events: list[str] = []

    with pytest.raises(CutoverExecutionError, match="database rows"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="3e30d0d",
                new_services=("detection-orchestrator.service",),
            ),
            CutoverDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                is_service_active=lambda _: False,
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda *_: _complete_checkpoint_summary(),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    assert "start:detection-orchestrator.service" not in events


def test_datetime_checkpoint_summary_is_json_serializable_after_database_match(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    completed_at = datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc)
    summary = _complete_checkpoint_summary()
    checkpoints = summary["checkpoints"]
    assert isinstance(checkpoints, dict)
    for value in checkpoints.values():
        assert isinstance(value, dict)
        value["last_completed_window_end"] = completed_at

    report = execute_cutover(
        CutoverConfig(
            database_path=database,
            backup_directory=tmp_path / "backups",
            migrations_directory=tmp_path / "migrations",
            result_path=tmp_path / "cutover.json",
            git_sha="3e30d0d",
            new_services=("detection-orchestrator.service",),
        ),
        CutoverDependencies(
            stop_service=lambda _: None,
            start_service=lambda _: None,
            is_service_active=lambda _: False,
            apply_migrations=lambda *_: {"applied_versions": [3]},
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db, summary),
            now=lambda: completed_at,
        ),
    )

    assert report.status == "succeeded"
    saved = json.loads((tmp_path / "cutover.json").read_text(encoding="utf-8"))
    assert saved["checkpoint_summary"]["checkpoints"][CHECKPOINT_KEYS[0]][
        "last_completed_window_end"
    ] == "2026-07-21T04:30:00Z"


def test_cutover_service_stop_failure_still_restores_other_service_states(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    active = {
        "rule-detector.service": True,
        "missing-new.service": False,
        "gateway-metrics.service": True,
    }
    events: list[str] = []

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        if service == "missing-new.service":
            raise RuntimeError("unit not found")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

    with pytest.raises(CutoverExecutionError, match="unit not found"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service",),
                new_services=("missing-new.service",),
                paused_writer_services=("gateway-metrics.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            ),
        )

    assert "stop:gateway-metrics.service" in events
    assert active["rule-detector.service"] is True
    assert active["gateway-metrics.service"] is True
    saved = json.loads((tmp_path / "cutover.json").read_text(encoding="utf-8"))
    assert saved["status"] == "rollback_failed"
    assert saved["failure_stage"] == "service-stop"


def test_cutover_rejects_concurrent_operation_lock_before_services_change(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    events: list[str] = []

    with _operation_lock(database):
        with pytest.raises(CutoverSafetyError, match="holds the lock"):
            execute_cutover(
                CutoverConfig(
                    database_path=database,
                    backup_directory=tmp_path / "backups",
                    migrations_directory=tmp_path / "migrations",
                    result_path=tmp_path / "cutover.json",
                    git_sha="3e30d0d",
                    legacy_services=("rule-detector.service",),
                ),
                CutoverDependencies(
                    stop_service=lambda service: events.append(f"stop:{service}"),
                    start_service=lambda service: events.append(f"start:{service}"),
                    is_service_active=lambda _: True,
                    apply_migrations=lambda *_: {"applied_versions": [3]},
                    initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
                ),
            )

    assert events == []


def test_sqlite_backup_preserves_wal_mode_committed_rows(tmp_path: Path) -> None:
    source = tmp_path / "wal-operational.db"
    backup = tmp_path / "wal-backup.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("CREATE TABLE samples (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO samples (value) VALUES ('committed-in-wal')")
        connection.commit()
        artifact = create_sqlite_backup(source, backup)

    assert artifact.integrity_check == "ok"
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT value FROM samples").fetchone()[0] == (
            "committed-in-wal"
        )


def test_cutover_backup_collision_is_rejected_before_services_stop(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    backup_directory = tmp_path / "backups"
    _create_source_database(database)
    backup_directory.mkdir()
    collision = backup_directory / "operational_before_phase4_20260721T043000Z.db"
    collision.write_bytes(b"existing evidence")
    events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="already exists"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=backup_directory,
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="3e30d0d",
                legacy_services=("rule-detector.service",),
            ),
            CutoverDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                is_service_active=lambda _: True,
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    assert events == []
    assert collision.read_bytes() == b"existing evidence"
