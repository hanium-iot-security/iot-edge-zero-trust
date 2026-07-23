from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

import pytest

from edge.scripts import phase4_cutover as cutover_runtime
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
    run_cutover_smoke_test,
    termination_signal_guard,
)
from tests.phase4_cutover_test_support import (
    CHECKPOINT_KEYS,
    complete_checkpoint_summary as _complete_checkpoint_summary,
    create_phase3b_evidence_tables as _create_phase3b_evidence_tables,
    create_source_database as _create_source_database,
    persist_checkpoint_summary as _persist_checkpoint_summary,
)


def test_termination_signal_guard_converts_sigterm_and_restores_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous_handlers = {
        cutover_runtime.signal.SIGINT: object(),
        cutover_runtime.signal.SIGTERM: object(),
    }
    installed_handlers: dict[int, object] = {}

    monkeypatch.setattr(
        cutover_runtime.signal,
        "getsignal",
        lambda signal_number: previous_handlers[signal_number],
    )

    def record_handler(signal_number: int, handler: object) -> None:
        installed_handlers[signal_number] = handler

    monkeypatch.setattr(cutover_runtime.signal, "signal", record_handler)

    with pytest.raises(KeyboardInterrupt, match="SIGTERM"):
        with termination_signal_guard():
            handler = installed_handlers[cutover_runtime.signal.SIGTERM]
            assert callable(handler)
            handler(cutover_runtime.signal.SIGTERM, None)

    assert installed_handlers == previous_handlers


def test_execute_cutover_uses_safe_order_and_records_result(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    result_path = tmp_path / "results" / "cutover.json"
    _create_source_database(database)
    events: list[str] = []
    wall_clock = datetime(
        2026, 7, 21, 4, 30, 0, 123_456, tzinfo=timezone.utc
    )
    cutover_at = wall_clock.replace(microsecond=0)
    active = {
        "rule-detector.service": True,
        "trust-score.service": True,
        "detection-orchestrator.service": False,
        "firewall-worker.service": False,
    }

    def stop_service(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start_service(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

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
        return wall_clock

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
            is_service_active=lambda service: active[service],
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
    active = {
        "rule-detector.service": True,
        "detection-orchestrator.service": False,
        "firewall-worker.service": False,
    }
    cutover_at = datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc)

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

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
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=migrate,
                initialize_checkpoints=fail_checkpoint_initialization,
                now=lambda: cutover_at,
            ),
        )

    assert events[:8] == [
        "stop:rule-detector.service",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
        "migrate",
        "initialize",
        "stop:rule-detector.service",
        "stop:detection-orchestrator.service",
        "stop:firewall-worker.service",
    ]
    assert "start:rule-detector.service" in events[8:]
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
    wall_clock = datetime(
        2026, 7, 21, 4, 30, 0, 123_456, tzinfo=timezone.utc
    )
    cutover_at = wall_clock.replace(microsecond=0)

    def migrate(db_path: Path, _: Path) -> dict[str, object]:
        assert db_path == smoke_database.resolve()
        with sqlite3.connect(db_path) as connection:
            connection.execute("UPDATE parent SET name = 'smoke-migrated' WHERE id = 1")
        return {"applied_versions": [3]}

    def initialize(db_path: Path, timestamp: datetime) -> dict[str, object]:
        assert timestamp == cutover_at
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
        now=lambda: wall_clock,
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
    active = {
        "rule-detector.service": True,
        "detection-orchestrator.service": False,
    }

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

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
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
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
    active = {
        "rule-detector.service": False,
        "trust-score.service": False,
        "detection-orchestrator.service": True,
        "firewall-worker.service": True,
    }

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

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
            stop_service=stop,
            start_service=start,
            is_service_active=lambda service: active[service],
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
    assert saved["primary_error"]
    assert saved["rollback_attempted"] is False
    assert saved["rollback_succeeded"] is None
    assert saved["rollback_error"] is None


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
    saved = json.loads((tmp_path / "cutover.json").read_text(encoding="utf-8"))
    assert saved["primary_error"] == "checkpoint failed"
    assert saved["rollback_attempted"] is True
    assert saved["rollback_succeeded"] is True
    assert saved["rollback_error"] is None


def test_cutover_report_separates_primary_and_database_restore_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    result_path = tmp_path / "cutover.json"
    _create_source_database(database)
    active = {"legacy.service": True, "new.service": False}

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        active[service] = True

    monkeypatch.setattr(
        cutover_runtime,
        "restore_sqlite_backup",
        lambda **_: (_ for _ in ()).throw(RuntimeError("restore IO failed")),
    )

    with pytest.raises(CutoverExecutionError, match="checkpoint failed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=result_path,
                git_sha="2e833fa",
                legacy_services=("legacy.service",),
                new_services=("new.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda *_: (_ for _ in ()).throw(
                    RuntimeError("checkpoint failed")
                ),
            ),
        )

    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["primary_error"] == "checkpoint failed"
    assert saved["rollback_attempted"] is True
    assert saved["rollback_succeeded"] is False
    assert "restore IO failed" in saved["rollback_error"]
    assert "service restart skipped" in saved["rollback_error"]


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


def test_manual_rollback_rejects_prebackup_collision_before_services_stop(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    selected_backup = tmp_path / "selected.db"
    pre_rollback_directory = tmp_path / "pre-rollback"
    result_path = tmp_path / "rollback.json"
    _create_source_database(database)
    artifact = create_sqlite_backup(database, selected_backup)
    pre_rollback_directory.mkdir()
    collision = (
        pre_rollback_directory
        / "operational_pre_manual_rollback_20260721T050000Z.db"
    )
    collision.write_bytes(b"existing evidence")
    events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="already exists"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=selected_backup,
                sha256_path=artifact.sha256_path,
                backup_directory=pre_rollback_directory,
                result_path=result_path,
                git_sha="2e833fa",
                legacy_services=("legacy.service",),
            ),
            RollbackDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                is_service_active=lambda _: True,
                now=lambda: datetime(2026, 7, 21, 5, 0, tzinfo=timezone.utc),
            ),
        )

    assert events == []
    assert collision.read_bytes() == b"existing evidence"
    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "preflight"
    assert saved["rollback_attempted"] is False


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
    active = {"detection-orchestrator.service": False}

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
            stop_service=lambda service: active.__setitem__(service, False),
            start_service=lambda service: active.__setitem__(service, True),
            is_service_active=lambda service: active[service],
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
    assert saved["primary_error"]
    assert saved["rollback_attempted"] is True
    assert saved["rollback_succeeded"] is False
    assert saved["rollback_error"]


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
    saved = json.loads((tmp_path / "cutover.json").read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "preflight"
    assert saved["rollback_attempted"] is False
    assert saved["primary_error"]


def test_cutover_rolls_back_when_new_service_exits_after_successful_start(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    result_path = tmp_path / "cutover.json"
    _create_source_database(database)
    active = {
        "legacy.service": True,
        "orchestrator.service": False,
        "writer.service": True,
    }

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        if service != "orchestrator.service":
            active[service] = True

    def migrate(path: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE parent SET name = 'migrated' WHERE id = 1")
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match="service state verification"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=result_path,
                git_sha="2e833fa",
                legacy_services=("legacy.service",),
                new_services=("orchestrator.service",),
                paused_writer_services=("writer.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=migrate,
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )
    assert active == {
        "legacy.service": True,
        "orchestrator.service": False,
        "writer.service": True,
    }
    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["status"] == "rolled_back"
    assert saved["failure_stage"] == "post-service-verification"
    assert "orchestrator.service" in saved["error"]


def test_smoke_snapshot_detects_wal_row_value_change_with_equal_row_count(
    tmp_path: Path,
) -> None:
    source = tmp_path / "wal-source.db"
    smoke = tmp_path / "smoke.db"
    result = tmp_path / "smoke.json"
    _create_source_database(source)
    keeper = sqlite3.connect(source)
    keeper.execute("PRAGMA journal_mode = WAL")
    keeper.commit()

    def mutate_source(_: Path, __: Path) -> dict[str, object]:
        with sqlite3.connect(source) as connection:
            connection.execute("UPDATE parent SET name = 'wal-only-change' WHERE id = 1")
        return {"applied_versions": [3]}

    try:
        with pytest.raises(CutoverExecutionError, match="source database changed"):
            run_cutover_smoke_test(
                SmokeTestConfig(
                    source_database_path=source,
                    smoke_database_path=smoke,
                    migrations_directory=tmp_path / "migrations",
                    result_path=result,
                    git_sha="2e833fa",
                ),
                apply_migrations=mutate_source,
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            )
    finally:
        keeper.close()

    saved = json.loads(result.read_text(encoding="utf-8"))
    assert saved["source_unchanged"] is False
    assert saved["source_snapshot_sha256_before"] != saved[
        "source_snapshot_sha256_after"
    ]
    assert Path(saved["source_snapshot_before"]).is_file()
    assert Path(saved["source_snapshot_after"]).is_file()


@pytest.mark.parametrize(
    ("mutation_sql", "expected_error"),
    [
        (
            "UPDATE packet_capture_segments SET id = 11 WHERE id = 10",
            "segment IDs changed",
        ),
        (
            "UPDATE packet_capture_segments SET status = 'FAILED' WHERE id = 10",
            "segment values changed",
        ),
        (
            "DELETE FROM packet_feature_logs WHERE id = 20",
            "packet feature rows decreased",
        ),
        (
            "INSERT INTO packet_feature_logs (id, capture_segment_id) VALUES (21, 10)",
            "packet feature rows changed",
        ),
        (
            "UPDATE packet_feature_logs SET capture_segment_id = 999 WHERE id = 20",
            "orphan packet feature foreign keys",
        ),
        (
            "UPDATE packet_feature_logs SET packet_count = 0, total_bytes = 0 "
            "WHERE id = 20",
            "packet feature values changed",
        ),
        (
            "DELETE FROM detection_events WHERE id = 30",
            "detection event rows decreased",
        ),
    ],
)
def test_smoke_rejects_phase3b_data_preservation_violation(
    tmp_path: Path,
    mutation_sql: str,
    expected_error: str,
) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    result = tmp_path / "smoke.json"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def migrate(path: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(mutation_sql)
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match=expected_error):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=result,
                git_sha="2e833fa",
            ),
            apply_migrations=migrate,
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )

    saved = json.loads(result.read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "data-preservation-check"
    assert saved["database_evidence"]["smoke_before"]
    assert saved["database_evidence"]["smoke_after"]


def test_smoke_allows_legacy_detection_event_addition(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def migrate(path: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(path) as connection:
            connection.execute(
                "INSERT INTO detection_events (id, event_type) VALUES (31, 'LEGACY_MIGRATION')"
            )
        return {"applied_versions": [3]}

    report = run_cutover_smoke_test(
        SmokeTestConfig(
            source_database_path=source,
            smoke_database_path=smoke,
            migrations_directory=tmp_path / "migrations",
            result_path=tmp_path / "smoke.json",
            git_sha="2e833fa",
        ),
        apply_migrations=migrate,
        initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
        now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
    )

    assert report.status == "succeeded"
    assert report.database_evidence["smoke_after"]["detection_event_count"] == 2
    assert report.database_evidence["smoke_final"]["detection_event_count"] == 2
    assert report.database_evidence["smoke_after"]["detection_event_rows"][31][
        "event_type"
    ] == "LEGACY_MIGRATION"
    assert report.database_evidence["smoke_final"]["detection_event_rows"][30][
        "score_delta"
    ] == -20


def test_smoke_rejects_non_legacy_detection_event_addition(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def migrate(database: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO detection_events (id, event_type) VALUES (31, 'AI_ANOMALY')"
            )
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match="non-LEGACY_MIGRATION"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "smoke.json",
                git_sha="43663ed",
            ),
            apply_migrations=migrate,
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )

    saved = json.loads((tmp_path / "smoke.json").read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "data-preservation-check"


def test_smoke_rejects_existing_detection_event_value_changes(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def migrate(database: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE detection_events SET score_delta = -99 WHERE id = 30"
            )
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match="existing detection event values changed"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "smoke.json",
                git_sha="43663ed",
            ),
            apply_migrations=migrate,
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )


def test_smoke_allows_new_nullable_detection_event_columns(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def migrate(database: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute("ALTER TABLE detection_events ADD COLUMN dedupe_key TEXT")
            connection.execute("ALTER TABLE detection_events ADD COLUMN policy_version TEXT")
        return {"applied_versions": [3]}

    report = run_cutover_smoke_test(
        SmokeTestConfig(
            source_database_path=source,
            smoke_database_path=smoke,
            migrations_directory=tmp_path / "migrations",
            result_path=tmp_path / "smoke.json",
            git_sha="43663ed",
        ),
        apply_migrations=migrate,
        initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
        now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
    )

    assert report.status == "succeeded"


def test_smoke_rejects_non_legacy_event_added_by_checkpoint_initializer(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def initialize(database: Path, _: datetime) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO detection_events (id, event_type) VALUES (31, 'UNKNOWN_DEVICE')"
            )
        return _persist_checkpoint_summary(database)

    with pytest.raises(CutoverExecutionError, match="non-LEGACY_MIGRATION"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "smoke.json",
                git_sha="43663ed",
            ),
            apply_migrations=lambda *_: {"applied_versions": [3]},
            initialize_checkpoints=initialize,
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )

    saved = json.loads((tmp_path / "smoke.json").read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "final-data-preservation-check"


def test_automatic_rollback_rejects_service_state_mismatch(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    result_path = tmp_path / "cutover.json"
    _create_source_database(database)
    active = {
        "legacy.service": True,
        "orchestrator.service": False,
    }

    def stop(service: str) -> None:
        active[service] = False

    def start_without_becoming_active(_: str) -> None:
        return None

    with pytest.raises(CutoverExecutionError, match="service state verification"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=result_path,
                git_sha="ef4a64a",
                legacy_services=("legacy.service",),
                new_services=("orchestrator.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start_without_becoming_active,
                is_service_active=lambda service: active[service],
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda *_: (_ for _ in ()).throw(
                    RuntimeError("checkpoint failed")
                ),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["status"] == "rollback_failed"
    assert saved["rollback_succeeded"] is False
    assert "service state verification" in saved["rollback_error"]


def test_manual_rollback_rejects_post_restore_service_state_mismatch(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    backup = tmp_path / "selected.db"
    result_path = tmp_path / "rollback.json"
    _create_source_database(database)
    artifact = create_sqlite_backup(database, backup)
    active = {
        "legacy.service": False,
        "orchestrator.service": True,
    }

    def stop(service: str) -> None:
        active[service] = False

    with pytest.raises(CutoverExecutionError, match="service state verification"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=backup,
                sha256_path=artifact.sha256_path,
                result_path=result_path,
                git_sha="ef4a64a",
                legacy_services=("legacy.service",),
                new_services=("orchestrator.service",),
            ),
            RollbackDependencies(
                stop_service=stop,
                start_service=lambda _: None,
                is_service_active=lambda service: active[service],
                now=lambda: datetime(2026, 7, 21, 5, 0, tzinfo=timezone.utc),
            ),
        )

    saved = json.loads(result_path.read_text(encoding="utf-8"))
    assert saved["status"] == "recovery_failed"
    assert saved["failure_stage"] == "post-service-verification"


def test_cutover_rejects_result_path_matching_planned_backup(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    backup_directory = tmp_path / "backups"
    _create_source_database(database)
    result_path = backup_directory / "operational_before_phase4_20260721T043000Z.db"
    service_events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="artifact paths conflict"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=backup_directory,
                migrations_directory=tmp_path / "migrations",
                result_path=result_path,
                git_sha="ef4a64a",
            ),
            CutoverDependencies(
                stop_service=lambda service: service_events.append(f"stop:{service}"),
                start_service=lambda service: service_events.append(f"start:{service}"),
                is_service_active=lambda _: False,
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
                now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
            ),
        )

    assert service_events == []
    assert not result_path.exists()


def test_smoke_rejects_result_path_matching_source_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    result_path = tmp_path / "smoke.source-before.db"
    _create_source_database(source)

    with pytest.raises(CutoverSafetyError, match="artifact paths conflict"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=result_path,
                git_sha="ef4a64a",
            ),
            apply_migrations=lambda *_: {"applied_versions": [3]},
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )

    assert not result_path.exists()
    assert not smoke.exists()


def test_manual_rollback_rejects_result_path_matching_prebackup(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    selected_backup = tmp_path / "selected.db"
    prebackup_directory = tmp_path / "pre-rollback"
    result_path = (
        prebackup_directory
        / "operational_pre_manual_rollback_20260721T050000Z.db"
    )
    _create_source_database(database)
    artifact = create_sqlite_backup(database, selected_backup)
    service_events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="artifact paths conflict"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=selected_backup,
                sha256_path=artifact.sha256_path,
                backup_directory=prebackup_directory,
                result_path=result_path,
                git_sha="ef4a64a",
            ),
            RollbackDependencies(
                stop_service=lambda service: service_events.append(f"stop:{service}"),
                start_service=lambda service: service_events.append(f"start:{service}"),
                is_service_active=lambda _: False,
                now=lambda: datetime(2026, 7, 21, 5, 0, tzinfo=timezone.utc),
            ),
        )

    assert service_events == []
    assert not result_path.exists()


def test_smoke_revalidates_data_after_checkpoint_initialization(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def destructive_initializer(database: Path, _: datetime) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute("DELETE FROM packet_feature_logs")
        return _persist_checkpoint_summary(database)

    with pytest.raises(CutoverExecutionError, match="packet feature rows decreased"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "smoke.json",
                git_sha="ef4a64a",
            ),
            apply_migrations=lambda *_: {"applied_versions": [3]},
            initialize_checkpoints=destructive_initializer,
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )


def test_smoke_rejects_packet_value_change_after_checkpoint_initialization(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    result = tmp_path / "smoke.json"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def mutate_existing_packet_values(
        database: Path,
        _: datetime,
    ) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'FAILED' WHERE id = 10"
            )
            connection.execute(
                "UPDATE packet_feature_logs SET packet_count = 0 WHERE id = 20"
            )
        return _persist_checkpoint_summary(database)

    with pytest.raises(CutoverExecutionError, match="values changed"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=result,
                git_sha="a2754c3",
            ),
            apply_migrations=lambda *_: {"applied_versions": [3]},
            initialize_checkpoints=mutate_existing_packet_values,
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )

    saved = json.loads(result.read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "final-data-preservation-check"


def test_smoke_allows_new_nullable_packet_columns_without_changing_existing_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def add_nullable_columns(database: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute(
                "ALTER TABLE packet_capture_segments "
                "ADD COLUMN actual_capture_started_at DATETIME"
            )
            connection.execute(
                "ALTER TABLE packet_feature_logs ADD COLUMN policy_version TEXT"
            )
        return {"applied_versions": [3]}

    report = run_cutover_smoke_test(
        SmokeTestConfig(
            source_database_path=source,
            smoke_database_path=smoke,
            migrations_directory=tmp_path / "migrations",
            result_path=tmp_path / "smoke.json",
            git_sha="a2754c3",
        ),
        apply_migrations=add_nullable_columns,
        initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
        now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
    )

    assert report.status == "succeeded"


def test_smoke_rejects_replacing_existing_detection_event_ids(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    smoke = tmp_path / "smoke.db"
    _create_source_database(source)
    _create_phase3b_evidence_tables(source)

    def replace_existing_event(database: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(database) as connection:
            connection.execute("DELETE FROM detection_events WHERE id = 30")
            connection.executemany(
                "INSERT INTO detection_events (id, event_type) VALUES (?, ?)",
                ((31, "LEGACY_MIGRATION"), (32, "LEGACY_MIGRATION")),
            )
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match="detection event IDs were removed"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=smoke,
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "smoke.json",
                git_sha="ef4a64a",
            ),
            apply_migrations=replace_existing_event,
            initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            now=lambda: datetime(2026, 7, 21, 4, 30, tzinfo=timezone.utc),
        )


def test_cutover_does_not_restart_services_when_database_restore_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    active = {"legacy.service": True, "new.service": False}
    started: list[str] = []

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        started.append(service)
        active[service] = True

    def migrate(path: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE parent SET name = 'unsafe' WHERE id = 1")
        return {"applied_versions": [3]}

    monkeypatch.setattr(
        cutover_runtime,
        "restore_sqlite_backup",
        lambda **_: (_ for _ in ()).throw(RuntimeError("restore failed")),
    )

    with pytest.raises(CutoverExecutionError, match="restore failed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="2b7a517",
                legacy_services=("legacy.service",),
                new_services=("new.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=migrate,
                initialize_checkpoints=lambda *_: (_ for _ in ()).throw(
                    RuntimeError("checkpoint failed")
                ),
            ),
        )

    assert started == []
    assert active == {"legacy.service": False, "new.service": False}


@pytest.mark.parametrize("interrupt_stage", ["migration", "checkpoint", "service-start"])
def test_cutover_rolls_back_keyboard_interrupt_at_each_mutating_stage(
    tmp_path: Path,
    interrupt_stage: str,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    active = {"legacy.service": True, "new.service": False}

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        if interrupt_stage == "service-start" and service == "new.service":
            raise KeyboardInterrupt("SIGTERM")
        active[service] = True

    def migrate(path: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE parent SET name = 'migrated' WHERE id = 1")
        if interrupt_stage == "migration":
            raise KeyboardInterrupt("SIGTERM")
        return {"applied_versions": [3]}

    def initialize(path: Path, _: datetime) -> dict[str, object]:
        if interrupt_stage == "checkpoint":
            raise KeyboardInterrupt("SIGTERM")
        return _persist_checkpoint_summary(path)

    with pytest.raises(CutoverExecutionError, match="SIGTERM"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="2b7a517",
                legacy_services=("legacy.service",),
                new_services=("new.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=migrate,
                initialize_checkpoints=initialize,
            ),
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )
    assert active == {"legacy.service": True, "new.service": False}


def test_operational_cutover_rejects_phase3b_data_preservation_violation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    _create_phase3b_evidence_tables(database)
    active = {"new.service": False}

    def migrate(path: Path, _: Path) -> dict[str, object]:
        with sqlite3.connect(path) as connection:
            connection.execute("DELETE FROM packet_capture_segments WHERE id = 10")
        return {"applied_versions": [3]}

    with pytest.raises(CutoverExecutionError, match="segment rows changed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="2b7a517",
                new_services=("new.service",),
            ),
            CutoverDependencies(
                stop_service=lambda service: active.__setitem__(service, False),
                start_service=lambda service: active.__setitem__(service, True),
                is_service_active=lambda service: active[service],
                apply_migrations=migrate,
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            ),
        )

    saved = json.loads((tmp_path / "cutover.json").read_text(encoding="utf-8"))
    assert saved["failure_stage"] == "data-preservation-check"
    assert saved["database_evidence"]["before"]
    assert saved["database_evidence"]["after_migration"]


def test_cutover_rejects_unrelated_sqlite_database_before_services_change(
    tmp_path: Path,
) -> None:
    database = tmp_path / "unrelated.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="Phase 3-B database"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="2b7a517",
            ),
            CutoverDependencies(
                stop_service=lambda service: events.append(service),
                start_service=lambda service: events.append(service),
                is_service_active=lambda _: False,
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda *_: _complete_checkpoint_summary(),
            ),
        )

    assert events == []


def test_smoke_pauses_and_restores_configured_writer_services(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    _create_source_database(source)
    active = {"mqtt-writer.service": True, "gateway-metrics.service": True}
    events: list[str] = []

    def stop(service: str) -> None:
        events.append(f"stop:{service}")
        active[service] = False

    def start(service: str) -> None:
        events.append(f"start:{service}")
        active[service] = True

    report = run_cutover_smoke_test(
        SmokeTestConfig(
            source_database_path=source,
            smoke_database_path=tmp_path / "smoke.db",
            migrations_directory=tmp_path / "migrations",
            result_path=tmp_path / "smoke.json",
            git_sha="2b7a517",
            paused_writer_services=("mqtt-writer.service", "gateway-metrics.service"),
        ),
        apply_migrations=lambda *_: {"applied_versions": [3]},
        initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
        stop_service=stop,
        start_service=start,
        is_service_active=lambda service: active[service],
    )

    assert report.status == "succeeded"
    assert events[:2] == ["stop:mqtt-writer.service", "stop:gateway-metrics.service"]
    assert active == {"mqtt-writer.service": True, "gateway-metrics.service": True}
    assert report.writer_services_before == active
    assert report.writer_services_after == active


def test_manual_rollback_rejects_invalid_pre_rollback_backup_before_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    selected_backup = tmp_path / "selected.db"
    _create_source_database(database)
    selected_artifact = create_sqlite_backup(database, selected_backup)
    real_create_backup = cutover_runtime.create_sqlite_backup
    real_restore_backup = cutover_runtime.restore_sqlite_backup
    restore_called = False

    def create_invalid_prebackup(source: Path, destination: Path):
        artifact = real_create_backup(source, destination)
        return type(artifact)(
            database_path=artifact.database_path,
            sha256_path=artifact.sha256_path,
            sha256=artifact.sha256,
            integrity_check="corrupt",
            foreign_key_violations=(),
        )

    def track_restore(**kwargs):
        nonlocal restore_called
        restore_called = True
        return real_restore_backup(**kwargs)

    monkeypatch.setattr(cutover_runtime, "create_sqlite_backup", create_invalid_prebackup)
    monkeypatch.setattr(cutover_runtime, "restore_sqlite_backup", track_restore)

    with pytest.raises(CutoverExecutionError, match="Pre-rollback backup failed"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=selected_backup,
                sha256_path=selected_artifact.sha256_path,
                backup_directory=tmp_path / "pre-rollback",
                result_path=tmp_path / "rollback.json",
                git_sha="2b7a517",
            ),
            RollbackDependencies(
                stop_service=lambda _: None,
                start_service=lambda _: None,
                is_service_active=lambda _: False,
            ),
        )

    assert restore_called is False


def test_manual_rollback_rejects_unrelated_backup_before_services_change(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operational.db"
    unrelated = tmp_path / "unrelated.db"
    _create_source_database(database)
    with sqlite3.connect(unrelated) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    manifest = unrelated.with_suffix(".db.sha256")
    digest = hashlib.sha256(unrelated.read_bytes()).hexdigest()
    manifest.write_text(f"{digest}  {unrelated.name}\n", encoding="utf-8")
    events: list[str] = []

    with pytest.raises(CutoverSafetyError, match="Phase 3-B database"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=unrelated,
                sha256_path=manifest,
                backup_directory=tmp_path / "pre-rollback",
                result_path=tmp_path / "rollback.json",
                git_sha="2b7a517",
            ),
            RollbackDependencies(
                stop_service=lambda service: events.append(f"stop:{service}"),
                start_service=lambda service: events.append(f"start:{service}"),
                is_service_active=lambda _: False,
            ),
        )

    assert events == []


def test_manual_rollback_does_not_restart_services_when_database_recovery_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    selected = tmp_path / "selected.db"
    _create_source_database(database)
    artifact = create_sqlite_backup(database, selected)
    active = {"legacy.service": False, "new.service": True}
    started: list[str] = []
    restore_attempts = 0

    def fail_restore(**_: object):
        nonlocal restore_attempts
        restore_attempts += 1
        raise RuntimeError(f"restore failed {restore_attempts}")

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        started.append(service)
        active[service] = True

    monkeypatch.setattr(cutover_runtime, "restore_sqlite_backup", fail_restore)

    with pytest.raises(CutoverExecutionError, match="rollback recovery failed"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=selected,
                sha256_path=artifact.sha256_path,
                backup_directory=tmp_path / "pre-rollback",
                result_path=tmp_path / "rollback.json",
                git_sha="2b7a517",
                legacy_services=("legacy.service",),
                new_services=("new.service",),
            ),
            RollbackDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
            ),
        )

    assert restore_attempts == 2
    assert started == []
    assert active == {"legacy.service": False, "new.service": False}


def test_cutover_automatic_rollback_stops_all_database_services_before_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    active = {
        "legacy.service": True,
        "orchestrator.service": False,
        "writer.service": True,
    }
    restore_states: list[dict[str, bool]] = []
    real_restore = cutover_runtime.restore_sqlite_backup

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        active[service] = True
        if service == "writer.service":
            raise RuntimeError("writer start failed after activation")

    def record_restore(**kwargs):
        restore_states.append(dict(active))
        return real_restore(**kwargs)

    monkeypatch.setattr(cutover_runtime, "restore_sqlite_backup", record_restore)

    with pytest.raises(CutoverExecutionError, match="writer start failed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="review-fix",
                legacy_services=("legacy.service",),
                new_services=("orchestrator.service",),
                paused_writer_services=("writer.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            ),
        )

    assert restore_states == [
        {
            "legacy.service": False,
            "orchestrator.service": False,
            "writer.service": False,
        }
    ]


def test_cutover_automatic_rollback_refuses_restore_when_writer_remains_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    _create_source_database(database)
    active = {
        "legacy.service": True,
        "writer.service": True,
    }
    restore_called = False
    writer_stop_blocked = False

    def stop(service: str) -> None:
        if service == "writer.service" and writer_stop_blocked:
            return
        active[service] = False

    def start(service: str) -> None:
        nonlocal writer_stop_blocked
        active[service] = True
        if service == "writer.service":
            writer_stop_blocked = True
            raise RuntimeError("writer start failed after activation")

    def record_restore(**_):
        nonlocal restore_called
        restore_called = True
        raise AssertionError("database restore must not run")

    monkeypatch.setattr(cutover_runtime, "restore_sqlite_backup", record_restore)

    with pytest.raises(CutoverExecutionError, match="writer start failed"):
        execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=tmp_path / "backups",
                migrations_directory=tmp_path / "migrations",
                result_path=tmp_path / "cutover.json",
                git_sha="review-fix",
                legacy_services=("legacy.service",),
                paused_writer_services=("writer.service",),
            ),
            CutoverDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
                apply_migrations=lambda *_: {"applied_versions": [3]},
                initialize_checkpoints=lambda db, _: _persist_checkpoint_summary(db),
            ),
        )

    assert restore_called is False


def test_manual_rollback_recovery_stops_all_database_services_before_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    selected = tmp_path / "selected.db"
    _create_source_database(database)
    selected_artifact = create_sqlite_backup(database, selected)
    active = {
        "legacy.service": False,
        "orchestrator.service": True,
        "writer.service": True,
    }
    restore_states: list[dict[str, bool]] = []
    real_restore = cutover_runtime.restore_sqlite_backup

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        active[service] = True
        if service == "writer.service":
            raise RuntimeError("writer start failed after activation")

    def record_restore(**kwargs):
        restore_states.append(dict(active))
        return real_restore(**kwargs)

    monkeypatch.setattr(cutover_runtime, "restore_sqlite_backup", record_restore)

    with pytest.raises(CutoverExecutionError, match="writer start failed"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=selected,
                sha256_path=selected_artifact.sha256_path,
                backup_directory=tmp_path / "pre-rollback",
                result_path=tmp_path / "rollback.json",
                git_sha="review-fix",
                legacy_services=("legacy.service",),
                new_services=("orchestrator.service",),
                paused_writer_services=("writer.service",),
            ),
            RollbackDependencies(
                stop_service=stop,
                start_service=start,
                is_service_active=lambda service: active[service],
            ),
        )

    assert restore_states == [
        {
            "legacy.service": False,
            "orchestrator.service": False,
            "writer.service": False,
        },
        {
            "legacy.service": False,
            "orchestrator.service": False,
            "writer.service": False,
        },
    ]


def test_manual_rollback_refuses_database_restore_when_services_remain_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    selected = tmp_path / "selected.db"
    _create_source_database(database)
    selected_artifact = create_sqlite_backup(database, selected)
    restore_called = False

    def record_restore(**_):
        nonlocal restore_called
        restore_called = True
        raise AssertionError("database restore must not run")

    monkeypatch.setattr(cutover_runtime, "restore_sqlite_backup", record_restore)

    with pytest.raises(CutoverExecutionError, match="inactive"):
        execute_rollback(
            RollbackConfig(
                database_path=database,
                backup_path=selected,
                sha256_path=selected_artifact.sha256_path,
                backup_directory=tmp_path / "pre-rollback",
                result_path=tmp_path / "rollback.json",
                git_sha="review-fix",
                paused_writer_services=("writer.service",),
            ),
            RollbackDependencies(
                stop_service=lambda _: None,
                start_service=lambda _: None,
                is_service_active=lambda _: True,
            ),
        )

    assert restore_called is False


def test_smoke_failure_snapshots_source_before_writer_recovery(
    tmp_path: Path,
) -> None:
    source = tmp_path / "operational.db"
    result = tmp_path / "smoke.json"
    _create_source_database(source)
    active = {"writer.service": True}

    def stop(service: str) -> None:
        active[service] = False

    def start(service: str) -> None:
        active[service] = True
        with sqlite3.connect(source) as connection:
            connection.execute(
                "UPDATE parent SET name = 'writer-resumed' WHERE id = 1"
            )

    with pytest.raises(CutoverExecutionError, match="checkpoint failed"):
        run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=source,
                smoke_database_path=tmp_path / "smoke.db",
                migrations_directory=tmp_path / "migrations",
                result_path=result,
                git_sha="review-fix",
                paused_writer_services=("writer.service",),
            ),
            apply_migrations=lambda *_: {"applied_versions": [3]},
            initialize_checkpoints=lambda *_: (_ for _ in ()).throw(
                RuntimeError("checkpoint failed")
            ),
            stop_service=stop,
            start_service=start,
            is_service_active=lambda service: active[service],
        )

    saved = json.loads(result.read_text(encoding="utf-8"))
    assert saved["source_unchanged"] is True
    assert (
        saved["source_snapshot_sha256_before"]
        == saved["source_snapshot_sha256_after"]
    )
    assert active["writer.service"] is True
