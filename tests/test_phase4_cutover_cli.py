from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from edge.scripts import rollback_phase4_cutover as rollback_cli
from edge.scripts import run_phase4_cutover as cutover_cli
from edge.scripts.phase4_cutover import CutoverSafetyError, create_sqlite_backup
from tests.phase4_cutover_test_support import (
    create_migration_set,
    create_source_database,
)


def test_cutover_cli_dry_run_has_no_database_or_service_side_effects(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "operational.db"
    backup_directory = tmp_path / "backups"
    result_path = tmp_path / "results" / "cutover.json"
    create_source_database(database)

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
    create_source_database(database)

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
    create_source_database(database)
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


def test_rollback_preflight_probes_actual_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    backup = tmp_path / "selected.db"
    create_source_database(database)
    artifact = create_sqlite_backup(database, backup)
    pre_rollback_directory = tmp_path / "nvme" / "pre-rollback"
    result_path = tmp_path / "exports" / "rollback.json"
    probed: list[Path] = []
    monkeypatch.setattr(
        rollback_cli,
        "_probe_writable_directory",
        lambda path: probed.append(path),
    )

    rollback_cli._validate_rollback_preflight(
        database=database,
        backup=backup,
        sha256_path=artifact.sha256_path,
        pre_rollback_backup_directory=pre_rollback_directory,
        result_path=result_path,
        services=(),
    )

    assert set(probed) == {
        database.parent.resolve(),
        pre_rollback_directory.resolve(),
        result_path.parent.resolve(),
    }


def test_rollback_preflight_rejects_missing_systemd_unit_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    backup = tmp_path / "selected.db"
    create_source_database(database)
    artifact = create_sqlite_backup(database, backup)
    calls: list[list[str]] = []

    def missing_unit(command: list[str], **_: object) -> object:
        calls.append(command)
        return type(
            "Completed",
            (),
            {"returncode": 0, "stdout": "not-found\n"},
        )()

    monkeypatch.setattr(rollback_cli.subprocess, "run", missing_unit)

    with pytest.raises(CutoverSafetyError, match="unit is unavailable"):
        rollback_cli._validate_rollback_preflight(
            database=database,
            backup=backup,
            sha256_path=artifact.sha256_path,
            pre_rollback_backup_directory=tmp_path / "pre-rollback",
            result_path=tmp_path / "rollback.json",
            services=("missing.service",),
        )

    assert calls == [
        [
            "systemctl",
            "show",
            "missing.service",
            "--property=LoadState",
            "--value",
        ]
    ]


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (
            lambda directory: (directory / "003_phase4_detection.sql").write_text(
                "CREATE TABLE incomplete (id INTEGER", encoding="utf-8"
            ),
            "Incomplete SQL statement",
        ),
        (
            lambda directory: (directory / "003_duplicate.sql").write_text(
                "CREATE TABLE duplicate_3 (id INTEGER);\n", encoding="utf-8"
            ),
            "Duplicate migration version: 3",
        ),
        (
            lambda directory: (directory / "002_packet_gateway.sql").unlink(),
            "Missing migration version: 2",
        ),
        (
            lambda directory: (directory / "bad-name.sql").write_text(
                "SELECT 1;\n", encoding="utf-8"
            ),
            "Invalid migration file name: bad-name.sql",
        ),
        (
            lambda directory: (directory / "003_phase4_detection.sql").unlink(),
            "Migration set must contain exactly one version 3",
        ),
    ],
)
def test_operational_preflight_uses_full_migration_discovery(
    tmp_path: Path,
    mutate: object,
    expected_error: str,
) -> None:
    database = tmp_path / "operational.db"
    migrations = tmp_path / "migrations"
    create_source_database(database)
    create_migration_set(migrations)
    assert callable(mutate)
    mutate(migrations)

    with pytest.raises(CutoverSafetyError, match=expected_error):
        cutover_cli._validate_operational_preflight(
            database,
            migrations,
            (),
            backup_directory=tmp_path / "backups",
            result_path=tmp_path / "results" / "cutover.json",
        )


def test_operational_preflight_probes_actual_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    migrations = tmp_path / "migrations"
    backup_directory = tmp_path / "nvme" / "backups"
    result_path = tmp_path / "exports" / "cutover.json"
    create_source_database(database)
    create_migration_set(migrations)
    probed: list[Path] = []

    monkeypatch.setattr(
        cutover_cli,
        "_probe_writable_directory",
        lambda path: probed.append(path),
    )

    cutover_cli._validate_operational_preflight(
        database,
        migrations,
        (),
        backup_directory=backup_directory,
        result_path=result_path,
    )

    assert set(probed) == {
        database.parent.resolve(),
        backup_directory.resolve(),
        result_path.parent.resolve(),
    }


def test_operational_preflight_rejects_output_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    migrations = tmp_path / "migrations"
    backup_directory = tmp_path / "read-only-backups"
    create_source_database(database)
    create_migration_set(migrations)

    def fail_backup_probe(path: Path) -> None:
        if path == backup_directory.resolve():
            raise CutoverSafetyError("backup directory is not writable")

    monkeypatch.setattr(cutover_cli, "_probe_writable_directory", fail_backup_probe)

    with pytest.raises(CutoverSafetyError, match="backup directory is not writable"):
        cutover_cli._validate_operational_preflight(
            database,
            migrations,
            (),
            backup_directory=backup_directory,
            result_path=tmp_path / "cutover.json",
        )


def test_operational_preflight_rejects_insufficient_output_space(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operational.db"
    migrations = tmp_path / "migrations"
    create_source_database(database)
    create_migration_set(migrations)
    monkeypatch.setattr(cutover_cli, "_probe_writable_directory", lambda _: None)
    monkeypatch.setattr(
        cutover_cli.shutil,
        "disk_usage",
        lambda _: type("DiskUsage", (), {"free": 0})(),
    )

    with pytest.raises(CutoverSafetyError, match="Insufficient disk space"):
        cutover_cli._validate_operational_preflight(
            database,
            migrations,
            (),
            backup_directory=tmp_path / "backups",
            result_path=tmp_path / "cutover.json",
        )
