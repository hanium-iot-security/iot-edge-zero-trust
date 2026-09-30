from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import packet_checkpoint_recovery
from edge.detection.packet_checkpoint_recovery import (
    PacketCheckpointRecoveryError,
    attach_plan_sha256,
    build_recovery_plan,
    execute_packet_checkpoint_recovery,
    verify_plan_sha256,
)
from edge.detection import packet_checkpoint_recovery_repository as recovery_repository
from edge.detection.packet_checkpoint_recovery_repository import (
    calculate_packet_feature_readiness,
    snapshot_protected_rows,
)
from edge.packet.capture_session_repository import get_packet_feature_ready_through


UTC_A = datetime(2026, 8, 6, 10, 0, 0, tzinfo=timezone.utc)
UTC_B = datetime(2026, 8, 6, 11, 0, 0, tzinfo=timezone.utc)
OTHER_UTC = "2026-08-06T12:00:00Z"
CURRENT_SESSION = "11111111-1111-4111-8111-111111111111"
TARGET_SESSION = "22222222-2222-4222-8222-222222222222"
RUNNING_SESSION_A = "33333333-3333-4333-8333-333333333333"
RUNNING_SESSION_B = "44444444-4444-4444-8444-444444444444"
CURRENT_FIRST = datetime(2026, 8, 6, 10, 0, 0, tzinfo=timezone.utc)
CURRENT_READY_THROUGH = datetime(2026, 8, 6, 10, 0, 20, tzinfo=timezone.utc)
TARGET_FIRST = datetime(2026, 8, 6, 10, 1, 0, tzinfo=timezone.utc)
TARGET_READY_THROUGH = datetime(2026, 8, 6, 10, 1, 20, tzinfo=timezone.utc)
PROCESSABLE_SKIP_SESSION = "55555555-5555-4555-8555-555555555555"
FAILED_SKIP_SESSION = "66666666-6666-4666-8666-666666666666"
NOT_READY_SKIP_SESSION = "77777777-7777-4777-8777-777777777777"


def _git(repository_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout


def _repository(tmp_path: Path) -> Path:
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    _git(repository_root, "init")
    _git(repository_root, "config", "user.email", "test@example.com")
    _git(repository_root, "config", "user.name", "Test User")
    (repository_root / "tracked.txt").write_bytes(b"tracked\n")
    _git(repository_root, "add", "tracked.txt")
    _git(repository_root, "commit", "-m", "initial")
    return repository_root


def _db_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_migrated_database(path: Path) -> sqlite3.Connection:
    apply_migrations(path, MIGRATIONS_DIR)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _insert_capture_session(
    connection: sqlite3.Connection,
    *,
    session_id: str,
    capture_interface: str,
    first_window_start: datetime,
    status: str = "COMPLETED",
    started_at: datetime | None = None,
) -> int:
    started = started_at or first_window_start - timedelta(seconds=10)
    ended_at = None if status == "RUNNING" else first_window_start + timedelta(minutes=1)
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_sessions (
            session_id, capture_interface, started_at,
            first_window_start, ended_at, status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            capture_interface,
            _db_utc(started),
            _db_utc(first_window_start),
            _db_utc(ended_at) if ended_at is not None else None,
            status,
        ),
    )
    return int(cursor.lastrowid)


def _insert_capture_segment(
    connection: sqlite3.Connection,
    *,
    session_pk: int,
    capture_interface: str,
    window_start: datetime,
    status: str,
    feature_count: int = 0,
    error_code: str | None = None,
    file_suffix: str = "",
) -> int:
    window_end = window_start + timedelta(seconds=10)
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_segments (
            capture_session_id, file_name, capture_interface,
            window_start, window_end, status, error_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_pk,
            f"{session_pk}-{_db_utc(window_start)}{file_suffix}.pcap",
            capture_interface,
            _db_utc(window_start),
            _db_utc(window_end),
            status,
            error_code,
        ),
    )
    segment_id = int(cursor.lastrowid)
    for index in range(feature_count):
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id, peer_ip, direction,
                window_start, window_end, packet_count,
                total_bytes, avg_packet_size, max_packet_size
            )
            VALUES (?, ?, 'INBOUND', ?, ?, 1, 60, 60.0, 60)
            """,
            (
                segment_id,
                f"10.0.{session_pk}.{index + 1}",
                _db_utc(window_start),
                _db_utc(window_end),
            ),
        )
    return segment_id


def _insert_feature_for_existing_segment(
    connection: sqlite3.Connection, segment_id: int
) -> None:
    row = connection.execute(
        "SELECT window_start, window_end FROM packet_capture_segments WHERE id = ?",
        (segment_id,),
    ).fetchone()
    assert row is not None
    connection.execute(
        """
        INSERT INTO packet_feature_logs (
            capture_segment_id, peer_ip, direction,
            window_start, window_end, packet_count,
            total_bytes, avg_packet_size, max_packet_size
        )
        VALUES (?, '10.255.255.1', 'INBOUND', ?, ?, 1, 60, 60.0, 60)
        """,
        (segment_id, row["window_start"], row["window_end"]),
    )


def _seed_valid_recovery_database(path: Path) -> sqlite3.Connection:
    connection = _open_migrated_database(path)
    current_pk = _insert_capture_session(
        connection,
        session_id=CURRENT_SESSION,
        capture_interface="eth-current",
        first_window_start=CURRENT_FIRST,
    )
    _insert_capture_segment(
        connection,
        session_pk=current_pk,
        capture_interface="eth-current",
        window_start=CURRENT_FIRST,
        status="PROCESSED",
        feature_count=1,
    )
    _insert_capture_segment(
        connection,
        session_pk=current_pk,
        capture_interface="eth-current",
        window_start=CURRENT_FIRST + timedelta(seconds=10),
        status="EMPTY",
    )
    target_pk = _insert_capture_session(
        connection,
        session_id=TARGET_SESSION,
        capture_interface="eth-target",
        first_window_start=TARGET_FIRST,
    )
    _insert_capture_segment(
        connection,
        session_pk=target_pk,
        capture_interface="eth-target",
        window_start=TARGET_FIRST,
        status="PROCESSED",
        feature_count=2,
    )
    _insert_capture_segment(
        connection,
        session_pk=target_pk,
        capture_interface="eth-target",
        window_start=TARGET_FIRST + timedelta(seconds=10),
        status="EMPTY",
    )
    connection.execute(
        """
        INSERT INTO detector_checkpoints (
            detector_name, source_table, last_processed_id,
            last_completed_window_end, updated_at
        )
        VALUES ('packet_rule', 'packet_feature_logs', 42, ?, ?)
        """,
        (_db_utc(CURRENT_READY_THROUGH), _db_utc(CURRENT_READY_THROUGH)),
    )
    connection.commit()
    return connection


def _insert_packet_if_checkpoint(
    connection: sqlite3.Connection,
    *,
    last_processed_id: int = 84,
) -> None:
    connection.execute(
        """
        INSERT INTO detector_checkpoints (
            detector_name, source_table, last_processed_id,
            last_completed_window_end, updated_at
        )
        VALUES ('packet_if', 'packet_feature_logs', ?, ?, ?)
        """,
        (
            last_processed_id,
            _db_utc(CURRENT_READY_THROUGH),
            _db_utc(CURRENT_READY_THROUGH),
        ),
    )
    connection.commit()


def _repository_state_for_plan(tmp_path: Path) -> dict[str, object]:
    return {
        "repository_root": str(tmp_path.resolve()),
        "repository_commit": "a" * 40,
        "tracked_worktree_clean": True,
        "staged_worktree_clean": True,
        "untracked_inventory": [],
    }


def _build_plan(
    connection: sqlite3.Connection,
    *,
    tmp_path: Path,
    detector_name: str = "packet_rule",
    current_session_id: str = CURRENT_SESSION,
    target_session_id: str = TARGET_SESSION,
    mode: str | None = None,
    allow_failed_current_session: bool = False,
) -> dict[str, object]:
    database_path = Path(
        connection.execute("PRAGMA database_list").fetchone()["file"]
    ).resolve()
    arguments = {
        "repository_state": _repository_state_for_plan(tmp_path),
        "database_path": database_path,
        "detector_name": detector_name,
        "current_session_id": current_session_id,
        "target_session_id": target_session_id,
        "approved_by": "operator@example.com",
        "reason": "recover capture-session gap",
        "lock_entries": (
            {"path": str(tmp_path / "recovery.lock"), "roles": ["test"]},
        ),
        "allow_failed_current_session": allow_failed_current_session,
    }
    if mode is not None:
        arguments["mode"] = mode
    return build_recovery_plan(connection, **arguments)


def _add_uncaptured_failed_tail(connection: sqlite3.Connection) -> int:
    session_pk = connection.execute(
        "SELECT id FROM packet_capture_sessions WHERE session_id = ?", (CURRENT_SESSION,)
    ).fetchone()[0]
    connection.execute(
        "UPDATE packet_capture_sessions SET status='FAILED', ended_at=? WHERE id=?",
        (_db_utc(CURRENT_READY_THROUGH + timedelta(seconds=1)), session_pk),
    )
    tail_id = _insert_capture_segment(
        connection, session_pk=session_pk, capture_interface="eth-current",
        window_start=CURRENT_READY_THROUGH, status="FAILED",
    )
    connection.execute(
        "UPDATE packet_capture_segments SET file_name=NULL, captured_duration_seconds=0, error_code='LATE_CAPTURE' WHERE id=?",
        (tail_id,),
    )
    connection.commit()
    return tail_id


@pytest.mark.parametrize("detector", ["packet_rule", "packet_if"])
def test_failed_tail_resume_requires_explicit_opt_in_and_confirmation(tmp_path: Path, detector: str) -> None:
    fixture = _live_execute_fixture(tmp_path, detector_name=detector)
    with sqlite3.connect(fixture["database"]) as connection:
        connection.row_factory = sqlite3.Row
        tail_id = _add_uncaptured_failed_tail(connection)
        default = _build_plan(connection, tmp_path=tmp_path, detector_name=detector, mode="live-resume")
        assert "CURRENT_SESSION_NOT_COMPLETED" in default["blocking_reasons"]
        plan = _build_plan(connection, tmp_path=tmp_path, detector_name=detector, mode="live-resume", allow_failed_current_session=True)
        assert plan["can_execute"]
        assert plan["failed_current_tail"]["segment_id"] == tail_id
        assert plan["current_session"]["status"] == "FAILED"
        signed = attach_plan_sha256(plan, generated_at=UTC_A)
        with pytest.raises(PacketCheckpointRecoveryError, match="confirmation mismatch"):
            packet_checkpoint_recovery.require_execute_confirmations(signed, confirm=packet_checkpoint_recovery.LIVE_RESUME_CONFIRMATION, confirm_skip_processable=None)
        packet_checkpoint_recovery.require_execute_confirmations(signed, confirm=packet_checkpoint_recovery.FAILED_TAIL_RESUME_CONFIRMATION, confirm_skip_processable=None)


@pytest.mark.parametrize("change", [
    "UPDATE packet_capture_segments SET error_code='EXTRACTOR_ERROR' WHERE status='FAILED'",
    "UPDATE packet_capture_segments SET packet_count=1 WHERE status='FAILED'",
    "INSERT INTO packet_feature_logs (capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) SELECT id,'10.0.0.1','INBOUND',window_start,window_end,1,60,60,60 FROM packet_capture_segments WHERE status='FAILED'",
    "UPDATE packet_capture_sessions SET ended_at=NULL WHERE status='FAILED'",
    "UPDATE packet_capture_sessions SET ended_at='2026-08-06T10:01:00Z' WHERE status='FAILED'",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-08-06T10:00:10Z' WHERE detector_name='packet_rule'",
])
def test_failed_tail_resume_rejects_unsafe_source_shapes(tmp_path: Path, change: str) -> None:
    fixture = _live_execute_fixture(tmp_path)
    with sqlite3.connect(fixture["database"]) as connection:
        connection.row_factory = sqlite3.Row
        _add_uncaptured_failed_tail(connection)
        connection.execute(change)
        connection.commit()
        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume", allow_failed_current_session=True)
        assert not plan["can_execute"]


@pytest.mark.parametrize("detector", ["packet_rule", "packet_if"])
def test_failed_tail_resume_execute_preserves_failed_data_and_records_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, detector: str) -> None:
    fixture = _live_execute_fixture(tmp_path, detector_name=detector)
    with sqlite3.connect(fixture["database"]) as connection:
        connection.row_factory = sqlite3.Row
        _add_uncaptured_failed_tail(connection)
        before = snapshot_protected_rows(connection, requested_checkpoint_key=(detector, "packet_feature_logs"))
    arguments = _dry_run_arguments(tmp_path, database=fixture["database"], repository_root=fixture["repository_root"], plan_output=fixture["plan_output"], mode="live-resume", detector_name=detector)
    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(**arguments, allow_failed_current_session=True)
    assert plan["can_execute"]
    _allow_execute_on_test_platform(monkeypatch)
    result = execute_packet_checkpoint_recovery(plan_file=fixture["plan_output"], db_path=fixture["database"], artifact_dir=fixture["artifact_dir"], confirm=packet_checkpoint_recovery.FAILED_TAIL_RESUME_CONFIRMATION)
    with sqlite3.connect(fixture["database"]) as connection:
        connection.row_factory = sqlite3.Row
        assert snapshot_protected_rows(connection, requested_checkpoint_key=(detector, "packet_feature_logs")) == before
        audit = connection.execute("SELECT plan_json FROM packet_checkpoint_recoveries").fetchone()
        assert json.loads(audit[0])["failed_current_tail"]["error_code"] == "LATE_CAPTURE"
    assert _checkpoint(fixture["database"], detector)["last_completed_window_end"] == _db_utc(TARGET_FIRST)


def _blocking_codes(plan: dict[str, object]) -> set[str]:
    return set(plan["blocking_reasons"])


def test_plan_classifies_full_ready_completed_session_as_processable_skip(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "processable-skip.db")
    try:
        skipped_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        skipped_pk = _insert_capture_session(
            connection,
            session_id=PROCESSABLE_SKIP_SESSION,
            capture_interface="eth-skipped",
            first_window_start=skipped_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-skipped",
            window_start=skipped_first,
            status="PROCESSED",
            feature_count=1,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-skipped",
            window_start=skipped_first + timedelta(seconds=10),
            status="EMPTY",
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["sessions_between"] == [
            {
                "classification": "SKIPPED_FULL_READY_COMPLETED",
                "session_id": PROCESSABLE_SKIP_SESSION,
                "first_window_start": _db_utc(skipped_first),
                "packet_feature_ready_through": _db_utc(
                    skipped_first + timedelta(seconds=20)
                ),
                "segment_count": 2,
                "feature_row_count": 1,
                "warning_codes": ["PROCESSABLE_SESSION_SKIP"],
            }
        ]
        assert plan["summary"]["skips_processable_sessions"] is True
        assert plan["summary"]["warning_codes"] == [
            "PROCESSABLE_SESSION_SKIP"
        ]
        assert plan["summary"]["current_session_classification"] == "EXHAUSTED_CURRENT"
        assert (
            plan["summary"]["target_session_classification"]
            == "TARGET_FULL_READY_COMPLETED"
        )
    finally:
        connection.close()


def test_plan_classifies_failed_and_not_ready_sessions_separately(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "nonprocessable-skips.db")
    try:
        failed_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        not_ready_first = failed_first + timedelta(seconds=10)
        _insert_capture_session(
            connection,
            session_id=FAILED_SKIP_SESSION,
            capture_interface="eth-failed",
            first_window_start=failed_first,
            status="FAILED",
        )
        not_ready_pk = _insert_capture_session(
            connection,
            session_id=NOT_READY_SKIP_SESSION,
            capture_interface="eth-not-ready",
            first_window_start=not_ready_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=not_ready_pk,
            capture_interface="eth-not-ready",
            window_start=not_ready_first,
            status="READY",
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert [row["classification"] for row in plan["sessions_between"]] == [
            "SKIPPED_FAILED",
            "SKIPPED_NOT_READY",
        ]
        assert plan["summary"]["skips_processable_sessions"] is False
        assert plan["summary"]["warning_codes"] == []
    finally:
        connection.close()


def test_processable_skip_requires_plan_sha_bound_confirmation(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "confirm-processable.db")
    try:
        skipped_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        skipped_pk = _insert_capture_session(
            connection,
            session_id=PROCESSABLE_SKIP_SESSION,
            capture_interface="eth-skipped",
            first_window_start=skipped_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-skipped",
            window_start=skipped_first,
            status="EMPTY",
        )
        connection.commit()
        plan = attach_plan_sha256(_build_plan(connection, tmp_path=tmp_path), generated_at=UTC_A)

        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable=(
                f"SKIP-PROCESSABLE-SESSIONS:{plan['plan_sha256']}"
            ),
        )
    finally:
        connection.close()


def test_processable_skip_rejects_missing_or_wrong_confirmation(tmp_path: Path) -> None:
    plan = {
        "plan_sha256": "a" * 64,
        "summary": {"skips_processable_sessions": True},
    }

    with pytest.raises(
        PacketCheckpointRecoveryError, match="processable-session confirmation mismatch"
    ):
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable=None,
        )
    with pytest.raises(
        PacketCheckpointRecoveryError, match="processable-session confirmation mismatch"
    ):
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable="SKIP-PROCESSABLE-SESSIONS:" + "b" * 64,
        )


def test_nonprocessable_gap_does_not_require_processable_skip_confirmation(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "confirm-nonprocessable.db")
    try:
        _insert_capture_session(
            connection,
            session_id=FAILED_SKIP_SESSION,
            capture_interface="eth-failed",
            first_window_start=CURRENT_READY_THROUGH + timedelta(seconds=10),
            status="FAILED",
        )
        connection.commit()
        plan = attach_plan_sha256(_build_plan(connection, tmp_path=tmp_path), generated_at=UTC_A)

        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable=None,
        )
    finally:
        connection.close()


def test_confirmation_is_rejected_when_plan_has_no_processable_skip() -> None:
    plan = {
        "plan_sha256": "a" * 64,
        "summary": {"skips_processable_sessions": False},
    }

    with pytest.raises(
        PacketCheckpointRecoveryError, match="processable-session confirmation not allowed"
    ):
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable="SKIP-PROCESSABLE-SESSIONS:" + "a" * 64,
        )


def _insert_recovery_audit(
    connection: sqlite3.Connection,
    *,
    detector_name: str = "packet_rule",
    last_processed_id: int = 42,
) -> None:
    connection.execute(
        """
        INSERT INTO packet_checkpoint_recoveries (
            operation_id, detector_name, source_table,
            current_capture_session_id, target_capture_session_id,
            last_processed_id_before, last_processed_id_after,
            last_completed_window_end_before, last_completed_window_end_after,
            updated_at_before, updated_at_after, plan_sha256, plan_json,
            skipped_session_count, skipped_processable_session_count,
            approved_by, reason, repository_commit, database_path,
            backup_path, backup_sha256
        )
        VALUES (
            ?, ?, 'packet_feature_logs',
            ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 0, 0,
            'operator@example.com', 'already recovered', ?, ?, ?, ?
        )
        """,
        (
            f"20260806T100000Z-{detector_name}",
            detector_name,
            CURRENT_SESSION,
            TARGET_SESSION,
            last_processed_id,
            last_processed_id,
            _db_utc(CURRENT_READY_THROUGH),
            _db_utc(TARGET_FIRST),
            _db_utc(CURRENT_READY_THROUGH),
            _db_utc(TARGET_FIRST),
            "b" * 64,
            "a" * 40,
            str(Path("fixture.db").resolve()),
            str(Path("fixture.backup.db").resolve()),
            "c" * 64,
        ),
    )
    connection.commit()


def _assert_readiness_parity(database: Path, session_ids: tuple[str, ...]) -> None:
    engine = create_engine(f"sqlite:///{database}")
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        with session_factory() as sqlalchemy_session, sqlite3.connect(database) as raw:
            raw.row_factory = sqlite3.Row
            for session_id in session_ids:
                existing = get_packet_feature_ready_through(
                    sqlalchemy_session, session_id=session_id
                )
                recovery = calculate_packet_feature_readiness(raw, session_id)
                assert existing is not None
                assert recovery is not None
                assert recovery.first_window_start == existing.first_window_start
                assert (
                    recovery.packet_feature_ready_through
                    == existing.packet_feature_ready_through
                )
                assert recovery.first_window_start is not None
                assert recovery.first_window_start.utcoffset() == timedelta(0)
                if recovery.packet_feature_ready_through is not None:
                    assert recovery.packet_feature_ready_through.utcoffset() == timedelta(0)
    finally:
        engine.dispose()


@pytest.fixture
def untracked_fifo_repository(tmp_path: Path) -> Path:
    repository_root = _repository(tmp_path)
    try:
        os.mkfifo(repository_root / "queue")
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"FIFO unsupported: {exc}")
    return repository_root


def test_canonical_plan_sha_is_independent_of_key_order_and_volatile_fields() -> None:
    payload = {
        "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
        "repository_commit": "a" * 40,
        "repository_root": "/repo",
        "database_path": "/data/iot.db",
        "detector_name": "packet_rule",
        "source_table": "packet_feature_logs",
    }
    first = attach_plan_sha256(payload, generated_at=UTC_A)
    second = attach_plan_sha256(dict(reversed(tuple(payload.items()))), generated_at=UTC_B)

    assert first["plan_sha256"] == second["plan_sha256"]


def test_verify_plan_sha256_rejects_bound_field_tampering() -> None:
    plan = attach_plan_sha256(
        {
            "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
            "repository_commit": "a" * 40,
            "repository_root": "/repo",
            "database_path": "/data/iot.db",
            "detector_name": "packet_rule",
            "source_table": "packet_feature_logs",
            "checkpoint": {
                "before": {"last_completed_window_end": "2026-08-06T10:00:00Z"},
                "after": {"last_completed_window_end": "2026-08-06T11:00:00Z"},
            },
        },
        generated_at=UTC_A,
    )
    plan["checkpoint"]["after"]["last_completed_window_end"] = OTHER_UTC

    with pytest.raises(PacketCheckpointRecoveryError, match="plan SHA256"):
        verify_plan_sha256(plan)


def test_plan_sha_binds_recovery_mode_and_live_resume_fields() -> None:
    gap = attach_plan_sha256(
        {
            "mode": "gap-recovery",
            "target_session": {
                "status": "COMPLETED",
                "first_window_start": _db_utc(TARGET_FIRST),
            },
        },
        generated_at=UTC_A,
    )
    live = attach_plan_sha256(
        {
            "mode": "live-resume",
            "target_session": {
                "status": "RUNNING",
                "first_window_start": _db_utc(TARGET_FIRST),
            },
        },
        generated_at=UTC_A,
    )

    assert gap["plan_sha256"] != live["plan_sha256"]
    live["target_session"]["first_window_start"] = _db_utc(
        TARGET_FIRST + timedelta(seconds=10)
    )
    with pytest.raises(PacketCheckpointRecoveryError, match="plan SHA256"):
        verify_plan_sha256(live)


def test_live_resume_requires_distinct_execute_confirmation(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-confirm.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()
        plan = attach_plan_sha256(
            _build_plan(connection, tmp_path=tmp_path, mode="live-resume"),
            generated_at=UTC_A,
        )

        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-LIVE-RESUME",
            confirm_skip_processable=None,
        )
        with pytest.raises(
            PacketCheckpointRecoveryError, match="execute confirmation mismatch"
        ):
            packet_checkpoint_recovery.require_execute_confirmations(
                plan,
                confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
                confirm_skip_processable=None,
            )
    finally:
        connection.close()


def test_live_resume_reuses_processable_skip_confirmation(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-skip-confirm.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        skipped_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        skipped_pk = _insert_capture_session(
            connection,
            session_id=PROCESSABLE_SKIP_SESSION,
            capture_interface="eth-live-skipped",
            first_window_start=skipped_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-live-skipped",
            window_start=skipped_first,
            status="EMPTY",
        )
        connection.commit()
        plan = attach_plan_sha256(
            _build_plan(connection, tmp_path=tmp_path, mode="live-resume"),
            generated_at=UTC_A,
        )
        confirmation = f"SKIP-PROCESSABLE-SESSIONS:{plan['plan_sha256']}"

        assert plan["summary"]["skips_processable_sessions"] is True
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-LIVE-RESUME",
            confirm_skip_processable=confirmation,
        )
        with pytest.raises(
            PacketCheckpointRecoveryError,
            match="processable-session confirmation mismatch",
        ):
            packet_checkpoint_recovery.require_execute_confirmations(
                plan,
                confirm="APPLY-PACKET-LIVE-RESUME",
                confirm_skip_processable=None,
            )
    finally:
        connection.close()


def test_canonical_plan_sha_changes_when_resolved_database_path_changes(
    tmp_path: Path,
) -> None:
    first_db = tmp_path / "first.db"
    second_db = tmp_path / "second.db"
    first_db.write_bytes(b"first")
    second_db.write_bytes(b"second")

    first_plan = attach_plan_sha256(
        {"database_path": str(first_db.resolve())}, generated_at=UTC_A
    )
    second_plan = attach_plan_sha256(
        {"database_path": str(second_db.resolve())}, generated_at=UTC_A
    )

    assert first_plan["plan_sha256"] != second_plan["plan_sha256"]


def test_database_path_requires_existing_regular_file(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()

    with pytest.raises(PacketCheckpointRecoveryError, match="regular file"):
        packet_checkpoint_recovery.resolve_database_path(directory)


def test_require_plan_database_path_rejects_different_resolved_path(
    tmp_path: Path,
) -> None:
    first_db = tmp_path / "first.db"
    second_db = tmp_path / "second.db"
    first_db.write_bytes(b"first")
    second_db.write_bytes(b"second")
    plan = {"database_path": str(first_db.resolve())}

    with pytest.raises(PacketCheckpointRecoveryError, match="database path"):
        packet_checkpoint_recovery.require_plan_database_path(plan, second_db)


def test_require_plan_database_path_accepts_same_resolved_path(tmp_path: Path) -> None:
    database = tmp_path / "iot.db"
    database.write_bytes(b"sqlite fixture")
    plan = {"database_path": str(database.resolve())}

    assert (
        packet_checkpoint_recovery.require_plan_database_path(plan, database)
        == database.resolve()
    )


def test_repository_state_rejects_tracked_changes(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / "tracked.txt").write_bytes(b"changed\n")

    with pytest.raises(PacketCheckpointRecoveryError, match="tracked/staged"):
        packet_checkpoint_recovery.inspect_repository_state(repository_root)


def test_repository_state_rejects_staged_changes(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / "tracked.txt").write_bytes(b"staged\n")
    _git(repository_root, "add", "tracked.txt")

    with pytest.raises(PacketCheckpointRecoveryError, match="tracked/staged"):
        packet_checkpoint_recovery.inspect_repository_state(repository_root)


def test_repository_state_records_untracked_path_size_and_sha256(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    payload = b"untracked payload\n"
    (repository_root / "untracked.bin").write_bytes(payload)

    state = packet_checkpoint_recovery.inspect_repository_state(repository_root)

    assert state["repository_root"] == str(repository_root.resolve())
    assert state["tracked_worktree_clean"] is True
    assert state["staged_worktree_clean"] is True
    assert state["untracked_inventory"] == [{
        "path": "untracked.bin",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }]


def test_repository_state_does_not_modify_untracked_file_named_zero(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    zero = repository_root / "0"
    zero.write_bytes(b"must remain untouched\n")
    before_bytes = zero.read_bytes()
    before_sha256 = hashlib.sha256(before_bytes).hexdigest()

    packet_checkpoint_recovery.inspect_repository_state(repository_root)

    assert zero.read_bytes() == before_bytes
    assert hashlib.sha256(zero.read_bytes()).hexdigest() == before_sha256


def test_repository_state_rejects_untracked_symlink(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    target = repository_root / "target.txt"
    target.write_bytes(b"target\n")
    link = repository_root / "untracked-link"
    try:
        os.symlink(target, link)
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink unsupported: {exc}")

    with pytest.raises(PacketCheckpointRecoveryError, match="regular file"):
        packet_checkpoint_recovery.inspect_repository_state(repository_root)


def test_inventory_entry_rejects_non_regular_file(
    untracked_fifo_repository: Path,
) -> None:
    with pytest.raises(PacketCheckpointRecoveryError, match="regular file"):
        packet_checkpoint_recovery.inspect_repository_state(untracked_fifo_repository)


def test_generated_path_allows_path_outside_repository(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    outside = tmp_path / "outside" / "result.json"

    assert packet_checkpoint_recovery.validate_generated_path(
        repository_root, outside, field_name="result_path"
    ) == outside.resolve()
    assert not outside.exists()


def test_generated_path_allows_gitignored_path_inside_repository(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / ".gitignore").write_text("generated/\n", encoding="utf-8")
    plan = repository_root / "generated" / "plan.json"
    artifact_dir = repository_root / "generated"
    result = repository_root / "generated" / "result.json"
    lock = repository_root / "generated" / "run.lock"
    artifact_dir.mkdir()

    checked = packet_checkpoint_recovery.validate_generated_paths(
        repository_root=repository_root,
        plan_output=plan,
        artifact_dir=artifact_dir,
        result_path=result,
        lock_paths=(lock,),
    )

    assert checked == {
        "plan_output": plan.resolve(),
        "artifact_dir": artifact_dir.resolve(),
        "result_path": result.resolve(),
        "lock_paths": (lock.resolve(),),
    }
    assert not plan.exists()
    assert not result.exists()
    assert not lock.exists()


def test_generated_path_rejects_unignored_path_before_creation(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    candidate = repository_root / "generated" / "result.json"

    with pytest.raises(PacketCheckpointRecoveryError, match="result_path must be Git-ignored"):
        packet_checkpoint_recovery.validate_generated_path(
            repository_root, candidate, field_name="result_path"
        )

    assert not candidate.parent.exists()
    assert not candidate.exists()


def test_generated_path_checks_backup_sha256_sidecar(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / ".gitignore").write_text("backups/*.db\n", encoding="utf-8")
    backup = repository_root / "backups" / "checkpoint.db"
    sidecar = repository_root / "backups" / "checkpoint.db.sha256"

    with pytest.raises(
        PacketCheckpointRecoveryError, match="backup_sha256_path must be Git-ignored"
    ):
        packet_checkpoint_recovery.validate_generated_paths(
            repository_root=repository_root, backup_path=backup
        )

    assert not backup.parent.exists()
    assert not backup.exists()
    assert not sidecar.exists()


def test_lock_resolution_uses_orchestrator_manual_and_extractor_contracts(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path.resolve()

    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=repository_root,
        database_url="sqlite:///data/recovery.db",
        orchestrator_lock_path=None,
        manual_lock_path=None,
        extractor_lock_path=None,
    )

    assert packet_checkpoint_recovery.serialize_resolved_locks(locks) == (
        {
            "path": str((repository_root / "data/pcap/.extractor.lock").resolve()),
            "roles": ["packet_feature_extractor"],
        },
        {
            "path": str(
                (repository_root / "data/phase4-detection-cycle.lock").resolve()
            ),
            "roles": ["packet_if_manual", "packet_rule_manual"],
        },
        {
            "path": str(
                (repository_root / "data/recovery.db.orchestrator.lock").resolve()
            ),
            "roles": ["detection_orchestrator"],
        },
    )


def test_lock_resolution_preserves_orchestrator_non_sqlite_fallback(
    tmp_path: Path,
) -> None:
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=None,
        manual_lock_path=None,
        extractor_lock_path=None,
    )

    orchestrator = next(
        lock for lock in locks if lock.roles == ("detection_orchestrator",)
    )
    assert orchestrator.path == (
        tmp_path / "data/detection-orchestrator.lock"
    ).resolve()


def test_relative_lock_paths_resolve_from_repository_root(tmp_path: Path) -> None:
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=Path("locks/orchestrator.lock"),
        manual_lock_path=Path("locks/manual.lock"),
        extractor_lock_path=Path("locks/extractor.lock"),
    )

    assert {lock.path for lock in locks} == {
        (tmp_path / "locks/orchestrator.lock").resolve(),
        (tmp_path / "locks/manual.lock").resolve(),
        (tmp_path / "locks/extractor.lock").resolve(),
    }


def test_shared_rule_if_lock_is_acquired_once_with_both_roles(tmp_path: Path) -> None:
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=None,
        manual_lock_path=None,
        extractor_lock_path=None,
    )

    manual = [lock for lock in locks if "packet_rule_manual" in lock.roles]
    assert manual == [
        packet_checkpoint_recovery.ResolvedRecoveryLock(
            path=(tmp_path / "data/phase4-detection-cycle.lock").resolve(),
            roles=("packet_if_manual", "packet_rule_manual"),
        )
    ]


def test_duplicate_orchestrator_and_manual_path_is_acquired_once(
    tmp_path: Path,
) -> None:
    shared = Path("locks/shared.lock")
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=shared,
        manual_lock_path=shared,
        extractor_lock_path=Path("locks/extractor.lock"),
    )

    assert locks == tuple(sorted(locks, key=lambda lock: str(lock.path)))
    assert next(lock for lock in locks if lock.path == (tmp_path / shared).resolve()) == (
        packet_checkpoint_recovery.ResolvedRecoveryLock(
            path=(tmp_path / shared).resolve(),
            roles=(
                "detection_orchestrator",
                "packet_if_manual",
                "packet_rule_manual",
            ),
        )
    )
    assert len(locks) == 2


def test_unique_locks_are_acquired_in_sorted_absolute_path_order_with_injected_lock(
    tmp_path: Path,
) -> None:
    first = (tmp_path / "a.lock").resolve()
    second = (tmp_path / "b.lock").resolve()
    events: list[tuple[str, Path]] = []

    @contextmanager
    def fake_lock(path: Path):
        events.append(("enter", path))
        try:
            yield
        finally:
            events.append(("exit", path))

    locks = (
        packet_checkpoint_recovery.ResolvedRecoveryLock(second, ("second",)),
        packet_checkpoint_recovery.ResolvedRecoveryLock(first, ("first",)),
    )

    with packet_checkpoint_recovery.acquire_recovery_locks(
        locks, lock_factory=fake_lock
    ):
        assert events == [("enter", first), ("enter", second)]

    assert events == [
        ("enter", first),
        ("enter", second),
        ("exit", second),
        ("exit", first),
    ]


def test_acquire_recovery_locks_releases_already_acquired_locks_on_conflict(
    tmp_path: Path,
) -> None:
    first = (tmp_path / "a.lock").resolve()
    conflict = (tmp_path / "b.lock").resolve()
    last = (tmp_path / "c.lock").resolve()
    events: list[tuple[str, Path]] = []

    @contextmanager
    def fake_lock(path: Path):
        events.append(("enter", path))
        if path == conflict:
            raise RuntimeError("lock conflict")
        try:
            yield
        finally:
            events.append(("exit", path))

    locks = (
        packet_checkpoint_recovery.ResolvedRecoveryLock(last, ("last",)),
        packet_checkpoint_recovery.ResolvedRecoveryLock(conflict, ("conflict",)),
        packet_checkpoint_recovery.ResolvedRecoveryLock(first, ("first",)),
    )

    with pytest.raises(RuntimeError, match="lock conflict"):
        with packet_checkpoint_recovery.acquire_recovery_locks(
            locks, lock_factory=fake_lock
        ):
            pytest.fail("conflicting lock must prevent entry")

    assert events == [
        ("enter", first),
        ("enter", conflict),
        ("exit", first),
    ]


def test_plan_output_requires_existing_parent_directory(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    plan = tmp_path / "missing" / "plan.json"

    with pytest.raises(
        PacketCheckpointRecoveryError, match="plan_output parent must already exist"
    ):
        packet_checkpoint_recovery.validate_generated_paths(
            repository_root=repository_root, plan_output=plan
        )

    assert not plan.parent.exists()


def test_artifact_directory_must_already_exist(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    artifact_dir = tmp_path / "missing-artifacts"

    with pytest.raises(
        PacketCheckpointRecoveryError, match="artifact_dir must be an existing directory"
    ):
        packet_checkpoint_recovery.validate_generated_paths(
            repository_root=repository_root, artifact_dir=artifact_dir
        )

    assert not artifact_dir.exists()


def test_plan_requires_supported_detector_and_source_table(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "supported.db")
    try:
        with pytest.raises(PacketCheckpointRecoveryError, match="unsupported detector"):
            _build_plan(connection, tmp_path=tmp_path, detector_name="mqtt_rule")

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["detector_name"] == "packet_rule"
        assert plan["source_table"] == "packet_feature_logs"
    finally:
        connection.close()


def test_plan_requires_existing_completed_current_and_target_sessions(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "sessions.db")
    try:
        missing_current = _build_plan(
            connection,
            tmp_path=tmp_path,
            current_session_id="99999999-9999-4999-8999-999999999999",
        )
        missing_target = _build_plan(
            connection,
            tmp_path=tmp_path,
            target_session_id="88888888-8888-4888-8888-888888888888",
        )
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'FAILED' WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()
        failed_target = _build_plan(connection, tmp_path=tmp_path)

        assert "CURRENT_SESSION_NOT_FOUND" in _blocking_codes(missing_current)
        assert "TARGET_SESSION_NOT_FOUND" in _blocking_codes(missing_target)
        assert "TARGET_SESSION_NOT_COMPLETED" in _blocking_codes(failed_target)
        assert missing_current["can_execute"] is False
        assert missing_target["can_execute"] is False
        assert failed_target["can_execute"] is False
    finally:
        connection.close()


def test_gap_recovery_still_rejects_running_target(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "gap-running-target.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["mode"] == "gap-recovery"
        assert "TARGET_SESSION_NOT_COMPLETED" in _blocking_codes(plan)
        assert "RUNNING_CAPTURE_SESSIONS" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_live_resume_allows_one_running_target_with_terminal_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-running-target.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert plan["mode"] == "live-resume"
        assert plan["can_execute"] is True
        assert plan["blocking_reasons"] == []
        assert plan["target_session"]["status"] == "RUNNING"
        assert plan["target_session"]["first_window_start"] == _db_utc(TARGET_FIRST)
        assert plan["target_session"]["packet_feature_ready_through"] == _db_utc(
            TARGET_READY_THROUGH
        )
        assert plan["summary"]["running_sessions"] == [
            {
                "classification": "LIVE_RESUME_TARGET",
                "session_id": TARGET_SESSION,
                "started_at": _db_utc(TARGET_FIRST - timedelta(seconds=10)),
            }
        ]
        assert plan["checkpoint"]["after"] == {
            "detector_name": "packet_rule",
            "source_table": "packet_feature_logs",
            "last_processed_id": 42,
            "last_completed_window_end": _db_utc(TARGET_FIRST),
        }
    finally:
        connection.close()


def test_live_resume_rejects_completed_target(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-completed-target.db")
    try:
        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert "TARGET_SESSION_NOT_RUNNING" in _blocking_codes(plan)
        assert "LIVE_RESUME_RUNNING_SESSION_MISMATCH" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_packet_if_live_resume_allows_one_running_target_with_terminal_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-packet-if.db")
    try:
        _insert_packet_if_checkpoint(connection)
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(
            connection,
            tmp_path=tmp_path,
            detector_name="packet_if",
            mode="live-resume",
        )

        assert plan["can_execute"] is True
        assert plan["blocking_reasons"] == []
        assert plan["checkpoint"]["before"]["last_processed_id"] == 84
        assert plan["checkpoint"]["after"] == {
            "detector_name": "packet_if",
            "source_table": "packet_feature_logs",
            "last_processed_id": 84,
            "last_completed_window_end": _db_utc(TARGET_FIRST),
        }
    finally:
        connection.close()


def test_packet_if_live_resume_requires_confirmation_for_twelve_processable_skips(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-packet-if-skips.db")
    try:
        _insert_packet_if_checkpoint(connection)
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        for index in range(12):
            first = CURRENT_READY_THROUGH + timedelta(seconds=index + 1)
            session_pk = _insert_capture_session(
                connection,
                session_id=f"88888888-8888-4888-8{index:03d}-888888888888",
                capture_interface=f"eth-skipped-{index}",
                first_window_start=first,
            )
            _insert_capture_segment(
                connection,
                session_pk=session_pk,
                capture_interface=f"eth-skipped-{index}",
                window_start=first,
                status="EMPTY",
            )
        connection.commit()

        plan = attach_plan_sha256(
            _build_plan(
                connection,
                tmp_path=tmp_path,
                detector_name="packet_if",
                mode="live-resume",
            ),
            generated_at=UTC_A,
        )

        assert plan["can_execute"] is True
        assert len(plan["sessions_between"]) == 12
        assert {
            row["classification"] for row in plan["sessions_between"]
        } == {"SKIPPED_FULL_READY_COMPLETED"}
        assert plan["summary"]["warning_codes"] == ["PROCESSABLE_SESSION_SKIP"]
        with pytest.raises(
            PacketCheckpointRecoveryError,
            match="processable-session confirmation mismatch",
        ):
            packet_checkpoint_recovery.require_execute_confirmations(
                plan,
                confirm="APPLY-PACKET-LIVE-RESUME",
                confirm_skip_processable=None,
            )
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-LIVE-RESUME",
            confirm_skip_processable=(
                f"SKIP-PROCESSABLE-SESSIONS:{plan['plan_sha256']}"
            ),
        )
    finally:
        connection.close()


def test_packet_if_live_resume_rejects_checkpoint_before_current_ready_through(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-packet-if-lag.db")
    try:
        _insert_packet_if_checkpoint(connection)
        connection.execute(
            "UPDATE detector_checkpoints SET last_completed_window_end = ? "
            "WHERE detector_name = 'packet_if' AND source_table = 'packet_feature_logs'",
            (_db_utc(CURRENT_FIRST + timedelta(seconds=10)),),
        )
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(
            connection,
            tmp_path=tmp_path,
            detector_name="packet_if",
            mode="live-resume",
        )

        assert "CURRENT_SESSION_HAS_READY_PREFIX_AFTER_CHECKPOINT" in _blocking_codes(
            plan
        )
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_packet_if_live_resume_rejects_non_running_target(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-packet-if-target.db")
    try:
        _insert_packet_if_checkpoint(connection)

        plan = _build_plan(
            connection,
            tmp_path=tmp_path,
            detector_name="packet_if",
            mode="live-resume",
        )

        assert "TARGET_SESSION_NOT_RUNNING" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_packet_if_live_resume_rejects_target_without_ready_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-packet-if-prefix.db")
    try:
        _insert_packet_if_checkpoint(connection)
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.execute(
            """
            UPDATE packet_capture_segments
            SET status = 'READY'
            WHERE capture_session_id = (
                SELECT id FROM packet_capture_sessions WHERE session_id = ?
            )
            """,
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(
            connection,
            tmp_path=tmp_path,
            detector_name="packet_if",
            mode="live-resume",
        )

        assert "TARGET_SESSION_READY_PREFIX_MISSING" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_packet_if_live_resume_rejects_duplicate_recovery(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-packet-if-duplicate.db")
    try:
        _insert_packet_if_checkpoint(connection)
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        _insert_recovery_audit(
            connection,
            detector_name="packet_if",
            last_processed_id=84,
        )

        plan = _build_plan(
            connection,
            tmp_path=tmp_path,
            detector_name="packet_if",
            mode="live-resume",
        )

        assert "DUPLICATE_RECOVERY" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_live_resume_rejects_another_running_session(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-two-running.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_A,
            capture_interface="eth-other-running",
            first_window_start=TARGET_READY_THROUGH + timedelta(seconds=10),
            status="RUNNING",
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert "LIVE_RESUME_RUNNING_SESSION_MISMATCH" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_live_resume_rejects_missing_first_window_start(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-no-first.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions "
            "SET status = 'RUNNING', ended_at = NULL, first_window_start = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert "TARGET_SESSION_READY_PREFIX_MISSING" in _blocking_codes(plan)
        assert "TARGET_SESSION_READINESS_BLOCKED" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_live_resume_rejects_running_target_without_terminal_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-no-prefix.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.execute(
            """
            UPDATE packet_capture_segments
            SET status = 'READY'
            WHERE capture_session_id = (
                SELECT id FROM packet_capture_sessions WHERE session_id = ?
            )
            """,
            (TARGET_SESSION,),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert "TARGET_SESSION_READY_PREFIX_MISSING" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_live_resume_allows_trailing_ready_after_terminal_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-ready-tail.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        target_pk = int(
            connection.execute(
                "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                (TARGET_SESSION,),
            ).fetchone()[0]
        )
        _insert_capture_segment(
            connection,
            session_pk=target_pk,
            capture_interface="eth-target",
            window_start=TARGET_READY_THROUGH,
            status="READY",
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert plan["can_execute"] is True
        assert plan["blocking_reasons"] == []
        assert plan["target_session"]["packet_feature_ready_through"] == _db_utc(
            TARGET_READY_THROUGH
        )
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("mutation", "live_reason"),
    (
        ("failed", "FAILED_OR_EXTRACTOR_ERROR"),
        ("extractor_error", "FAILED_OR_EXTRACTOR_ERROR"),
        ("missing_window", "MISSING_WINDOW"),
        ("overlapping_window", "SEGMENT_BEFORE_OR_OVERLAPPING_PREFIX"),
        ("invalid_window_duration", "INVALID_WINDOW_DURATION"),
        ("terminal_after_ready", "TERMINAL_AFTER_READY_TAIL"),
        ("processed_without_feature", "FEATURE_COUNT_MISMATCH"),
    ),
)
def test_live_resume_rejects_failed_error_or_broken_continuity(
    tmp_path: Path,
    mutation: str,
    live_reason: str,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / f"live-{mutation}.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        rows = connection.execute(
            """
            SELECT pcsg.id
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
            WHERE pcs.session_id = ?
            ORDER BY pcsg.window_start
            """,
            (TARGET_SESSION,),
        ).fetchall()
        second_id = int(rows[1]["id"])
        if mutation == "failed":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'FAILED' WHERE id = ?",
                (second_id,),
            )
        elif mutation == "extractor_error":
            connection.execute(
                "UPDATE packet_capture_segments SET error_code = 'EXTRACTOR_ERROR' "
                "WHERE id = ?",
                (second_id,),
            )
        elif mutation == "missing_window":
            connection.execute(
                """
                UPDATE packet_capture_segments
                SET window_start = ?, window_end = ?
                WHERE id = ?
                """,
                (
                    _db_utc(TARGET_FIRST + timedelta(seconds=20)),
                    _db_utc(TARGET_FIRST + timedelta(seconds=30)),
                    second_id,
                ),
            )
        elif mutation == "overlapping_window":
            connection.execute(
                """
                UPDATE packet_capture_segments
                SET window_start = ?, window_end = ?
                WHERE id = ?
                """,
                (
                    _db_utc(TARGET_FIRST + timedelta(seconds=5)),
                    _db_utc(TARGET_FIRST + timedelta(seconds=15)),
                    second_id,
                ),
            )
        elif mutation == "invalid_window_duration":
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE packet_capture_segments SET window_end = ? WHERE id = ?",
                (_db_utc(TARGET_READY_THROUGH + timedelta(seconds=1)), second_id),
            )
            connection.commit()
            connection.execute("PRAGMA ignore_check_constraints = OFF")
        elif mutation == "terminal_after_ready":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'READY' WHERE id = ?",
                (second_id,),
            )
            target_pk = int(
                connection.execute(
                    "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                    (TARGET_SESSION,),
                ).fetchone()[0]
            )
            _insert_capture_segment(
                connection,
                session_pk=target_pk,
                capture_interface="eth-target",
                window_start=TARGET_READY_THROUGH,
                status="PROCESSED",
                feature_count=1,
            )
        else:
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' WHERE id = ?",
                (second_id,),
            )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert "TARGET_SESSION_READINESS_BLOCKED" in _blocking_codes(plan)
        assert live_reason in plan["target_session"]["live_resume_blocking_reasons"]
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_live_resume_rejects_checkpoint_at_or_after_target_first(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "live-no-advance.db")
    try:
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.execute(
            """
            UPDATE detector_checkpoints
            SET last_completed_window_end = ?
            WHERE detector_name = 'packet_rule'
              AND source_table = 'packet_feature_logs'
            """,
            (_db_utc(TARGET_FIRST),),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path, mode="live-resume")

        assert "CHECKPOINT_WOULD_NOT_ADVANCE" in _blocking_codes(plan)
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_plan_requires_current_checkpoint_at_current_ready_through(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "checkpoint.db")
    try:
        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["can_execute"] is True
        assert plan["checkpoint"]["before"]["last_completed_window_end"] == _db_utc(
            CURRENT_READY_THROUGH
        )
        assert plan["checkpoint"]["after"]["last_completed_window_end"] == _db_utc(
            TARGET_FIRST
        )

        connection.execute(
            "DELETE FROM detector_checkpoints WHERE detector_name = 'packet_rule'"
        )
        connection.commit()
        missing = _build_plan(connection, tmp_path=tmp_path)
        assert "CHECKPOINT_NOT_FOUND" in _blocking_codes(missing)
        assert missing["can_execute"] is False
    finally:
        connection.close()


def test_plan_rejects_current_session_with_remaining_ready_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "remaining-prefix.db")
    try:
        connection.execute(
            """
            UPDATE detector_checkpoints
            SET last_completed_window_end = ?
            WHERE detector_name = 'packet_rule' AND source_table = 'packet_feature_logs'
            """,
            (_db_utc(CURRENT_FIRST + timedelta(seconds=10)),),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert "CURRENT_SESSION_HAS_READY_PREFIX_AFTER_CHECKPOINT" in _blocking_codes(
            plan
        )
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_plan_requires_target_full_ready_processed_or_empty_range(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "target-ready.db")
    try:
        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["can_execute"] is True
        assert plan["target_session"] == {
            "session_id": TARGET_SESSION,
            "status": "COMPLETED",
            "first_window_start": _db_utc(TARGET_FIRST),
            "packet_feature_ready_through": _db_utc(TARGET_READY_THROUGH),
            "segment_count": 2,
            "feature_row_count": 2,
            "full_ready": True,
            "blocking_reasons": [],
        }
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("mutation", "readiness_reason"),
    (
        ("missing", "MISSING_WINDOW"),
        ("ready", "NON_TERMINAL_OR_ERROR"),
        ("failed", "NON_TERMINAL_OR_ERROR"),
        ("processed_without_feature", "FEATURE_COUNT_MISMATCH"),
        ("empty_with_feature", "FEATURE_COUNT_MISMATCH"),
    ),
)
def test_plan_rejects_missing_ready_failed_or_inconsistent_feature_segments(
    tmp_path: Path,
    mutation: str,
    readiness_reason: str,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / f"target-{mutation}.db")
    try:
        rows = connection.execute(
            """
            SELECT pcsg.id, pcsg.window_start
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
            WHERE pcs.session_id = ?
            ORDER BY pcsg.window_start
            """,
            (TARGET_SESSION,),
        ).fetchall()
        first_id, second_id = int(rows[0]["id"]), int(rows[1]["id"])
        if mutation == "missing":
            connection.execute(
                "DELETE FROM packet_feature_logs WHERE capture_segment_id = ?",
                (first_id,),
            )
            connection.execute(
                "DELETE FROM packet_capture_segments WHERE id = ?", (first_id,)
            )
        elif mutation == "ready":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'READY' WHERE id = ?",
                (second_id,),
            )
        elif mutation == "failed":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'FAILED' WHERE id = ?",
                (second_id,),
            )
        elif mutation == "processed_without_feature":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' WHERE id = ?",
                (second_id,),
            )
        else:
            _insert_feature_for_existing_segment(connection, second_id)
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert "TARGET_SESSION_NOT_FULL_READY" in _blocking_codes(plan)
        assert readiness_reason in plan["target_session"]["blocking_reasons"]
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_plan_lists_all_running_sessions_as_blocking(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "running.db")
    try:
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_B,
            capture_interface="eth-running-b",
            first_window_start=TARGET_FIRST + timedelta(minutes=2),
            status="RUNNING",
            started_at=CURRENT_FIRST + timedelta(minutes=2),
        )
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_A,
            capture_interface="eth-running-a",
            first_window_start=TARGET_FIRST + timedelta(minutes=1),
            status="RUNNING",
            started_at=CURRENT_FIRST + timedelta(minutes=1),
        )
        connection.commit()
        before = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM packet_capture_sessions ORDER BY id"
            ).fetchall()
        )

        plan = _build_plan(connection, tmp_path=tmp_path)

        after = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM packet_capture_sessions ORDER BY id"
            ).fetchall()
        )
        assert plan["running_sessions"] == [
            {
                "session_id": RUNNING_SESSION_A,
                "started_at": _db_utc(CURRENT_FIRST + timedelta(minutes=1)),
            },
            {
                "session_id": RUNNING_SESSION_B,
                "started_at": _db_utc(CURRENT_FIRST + timedelta(minutes=2)),
            },
        ]
        assert "RUNNING_CAPTURE_SESSIONS" in _blocking_codes(plan)
        assert plan["can_execute"] is False
        assert after == before
    finally:
        connection.close()


def test_plan_rejects_checkpoint_regression_same_session_and_duplicate_recovery(
    tmp_path: Path,
) -> None:
    regression = _seed_valid_recovery_database(tmp_path / "regression.db")
    same_session = _seed_valid_recovery_database(tmp_path / "same-session.db")
    duplicate = _seed_valid_recovery_database(tmp_path / "duplicate.db")
    try:
        regression.execute(
            "UPDATE packet_capture_sessions SET first_window_start = ? WHERE session_id = ?",
            (_db_utc(CURRENT_FIRST), TARGET_SESSION),
        )
        regression.commit()
        regression_plan = _build_plan(regression, tmp_path=tmp_path)
        same_plan = _build_plan(
            same_session,
            tmp_path=tmp_path,
            target_session_id=CURRENT_SESSION,
        )
        _insert_recovery_audit(duplicate)
        duplicate_plan = _build_plan(duplicate, tmp_path=tmp_path)

        assert "CHECKPOINT_WOULD_NOT_ADVANCE" in _blocking_codes(regression_plan)
        assert "CURRENT_AND_TARGET_SESSION_MATCH" in _blocking_codes(same_plan)
        assert "DUPLICATE_RECOVERY" in _blocking_codes(duplicate_plan)
        assert regression_plan["can_execute"] is False
        assert same_plan["can_execute"] is False
        assert duplicate_plan["can_execute"] is False
    finally:
        regression.close()
        same_session.close()
        duplicate.close()


def test_recovery_readiness_matches_existing_helper_for_normal_and_empty_segments(
    tmp_path: Path,
) -> None:
    database = tmp_path / "parity-normal.db"
    connection = _seed_valid_recovery_database(database)
    connection.close()

    _assert_readiness_parity(database, (CURRENT_SESSION, TARGET_SESSION))


def test_recovery_readiness_matches_existing_helper_for_ready_failed_and_missing_window(
    tmp_path: Path,
) -> None:
    database = tmp_path / "parity-nonterminal.db"
    connection = _open_migrated_database(database)
    session_ids = (
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
    )
    try:
        for index, (session_id, terminal_status) in enumerate(
            zip(session_ids, ("READY", "FAILED", "PROCESSED")), start=1
        ):
            session_pk = _insert_capture_session(
                connection,
                session_id=session_id,
                capture_interface=f"parity-{index}",
                first_window_start=TARGET_FIRST,
            )
            _insert_capture_segment(
                connection,
                session_pk=session_pk,
                capture_interface=f"parity-{index}",
                window_start=TARGET_FIRST,
                status="PROCESSED",
                feature_count=1,
            )
            second_start = TARGET_FIRST + timedelta(
                seconds=20 if terminal_status == "PROCESSED" else 10
            )
            _insert_capture_segment(
                connection,
                session_pk=session_pk,
                capture_interface=f"parity-{index}",
                window_start=second_start,
                status=terminal_status,
                feature_count=1 if terminal_status == "PROCESSED" else 0,
            )
        connection.commit()
    finally:
        connection.close()

    _assert_readiness_parity(database, session_ids)


def test_recovery_readiness_matches_existing_helper_for_error_code_and_feature_mismatch(
    tmp_path: Path,
) -> None:
    database = tmp_path / "parity-inconsistent.db"
    connection = _open_migrated_database(database)
    session_ids = (
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    )
    try:
        for index, session_id in enumerate(session_ids, start=1):
            session_pk = _insert_capture_session(
                connection,
                session_id=session_id,
                capture_interface=f"mismatch-{index}",
                first_window_start=TARGET_FIRST,
            )
            if index == 1:
                _insert_capture_segment(
                    connection,
                    session_pk=session_pk,
                    capture_interface=f"mismatch-{index}",
                    window_start=TARGET_FIRST,
                    status="PROCESSED",
                    feature_count=1,
                    error_code="EXTRACTOR_ERROR",
                )
            elif index == 2:
                _insert_capture_segment(
                    connection,
                    session_pk=session_pk,
                    capture_interface=f"mismatch-{index}",
                    window_start=TARGET_FIRST,
                    status="PROCESSED",
                )
            else:
                _insert_capture_segment(
                    connection,
                    session_pk=session_pk,
                    capture_interface=f"mismatch-{index}",
                    window_start=TARGET_FIRST,
                    status="EMPTY",
                    feature_count=1,
                )
        connection.commit()
    finally:
        connection.close()

    _assert_readiness_parity(database, session_ids)


def test_target_full_ready_rejects_segment_before_first_window(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "before-first.db")
    try:
        target_pk = int(
            connection.execute(
                "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                (TARGET_SESSION,),
            ).fetchone()["id"]
        )
        _insert_capture_segment(
            connection,
            session_pk=target_pk,
            capture_interface="eth-target",
            window_start=TARGET_FIRST - timedelta(seconds=10),
            status="PROCESSED",
            feature_count=1,
        )
        connection.commit()

        readiness = calculate_packet_feature_readiness(connection, TARGET_SESSION)
        plan = _build_plan(connection, tmp_path=tmp_path)

        assert readiness is not None
        assert readiness.packet_feature_ready_through == TARGET_READY_THROUGH
        assert readiness.full_ready is False
        assert "SEGMENT_BEFORE_OR_OVERLAPPING_PREFIX" in readiness.blocking_reasons
        assert "TARGET_SESSION_NOT_FULL_READY" in _blocking_codes(plan)
    finally:
        connection.close()


@pytest.mark.parametrize("extra_kind", ("overlap", "extra"))
def test_target_full_ready_rejects_overlapping_or_extra_segment(
    tmp_path: Path,
    extra_kind: str,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / f"{extra_kind}.db")
    try:
        target_pk = int(
            connection.execute(
                "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                (TARGET_SESSION,),
            ).fetchone()["id"]
        )
        start = (
            TARGET_FIRST + timedelta(seconds=5)
            if extra_kind == "overlap"
            else TARGET_READY_THROUGH + timedelta(seconds=10)
        )
        _insert_capture_segment(
            connection,
            session_pk=target_pk,
            capture_interface="eth-target",
            window_start=start,
            status="PROCESSED",
            feature_count=1,
            file_suffix=f"-{extra_kind}",
        )
        connection.commit()

        readiness = calculate_packet_feature_readiness(connection, TARGET_SESSION)

        assert readiness is not None
        assert readiness.full_ready is False
        assert readiness.segment_count < len(
            connection.execute(
                """
                SELECT pcsg.id
                FROM packet_capture_segments pcsg
                JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
                WHERE pcs.session_id = ?
                """,
                (TARGET_SESSION,),
            ).fetchall()
        )
        assert readiness.blocking_reasons
    finally:
        connection.close()


def _dry_run_arguments(
    tmp_path: Path,
    *,
    database: Path,
    repository_root: Path,
    plan_output: Path,
    mode: str | None = None,
    detector_name: str = "packet_rule",
) -> dict[str, object]:
    arguments: dict[str, object] = {
        "db_path": database,
        "repository_root": repository_root,
        "detector_name": detector_name,
        "current_session_id": CURRENT_SESSION,
        "target_session_id": TARGET_SESSION,
        "approved_by": "operator@example.com",
        "reason": "recover capture-session gap",
        "plan_output": plan_output,
        "orchestrator_lock_path": tmp_path / "locks" / "orchestrator.lock",
        "manual_lock_path": tmp_path / "locks" / "manual.lock",
        "extractor_lock_path": tmp_path / "locks" / "extractor.lock",
    }
    if mode is not None:
        arguments["mode"] = mode
    return arguments


def test_dry_run_writes_canonical_plan_atomically_after_all_gates_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = _repository(tmp_path)
    database = tmp_path / "recovery.db"
    _seed_valid_recovery_database(database).close()
    plan_output = tmp_path / "recovery-plan.json"
    fsync_calls: list[int] = []
    replace_calls: list[tuple[Path, Path]] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def record_fsync(descriptor: int) -> None:
        fsync_calls.append(descriptor)
        real_fsync(descriptor)

    def record_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
        replace_calls.append((Path(source), Path(target)))
        real_replace(source, target)

    monkeypatch.setattr(packet_checkpoint_recovery, "_utc_now", lambda: UTC_A)
    monkeypatch.setattr(packet_checkpoint_recovery.os, "fsync", record_fsync)
    monkeypatch.setattr(packet_checkpoint_recovery.os, "replace", record_replace)

    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
        **_dry_run_arguments(
            tmp_path,
            database=database,
            repository_root=repository_root,
            plan_output=plan_output,
        )
    )

    assert json.loads(plan_output.read_text(encoding="utf-8")) == plan
    assert plan_output.read_bytes().endswith(b"\n")
    verify_plan_sha256(plan)
    assert plan["plan_sha256"] == packet_checkpoint_recovery.calculate_plan_sha256(
        plan
    )
    assert shlex.split(plan["execute_command"]) == [
        "python",
        "-m",
        "edge.detection.run_packet_checkpoint_recovery",
        "execute",
        "--plan-file",
        str(plan_output.resolve()),
        "--db-path",
        str(database.resolve()),
        "--artifact-dir",
        "<ARTIFACT_DIR>",
        "--confirm",
        packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
    ]
    assert len(fsync_calls) == 1
    assert len(replace_calls) == 1
    temporary_path, final_path = replace_calls[0]
    assert temporary_path.parent == plan_output.parent
    assert final_path == plan_output
    assert not temporary_path.exists()
    assert [path for path in plan_output.parent.iterdir() if path == plan_output] == [
        plan_output
    ]


@pytest.mark.parametrize("live_wal", (False, True))
def test_dry_run_is_query_only_and_does_not_create_artifact_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    live_wal: bool,
) -> None:
    repository_root = _repository(tmp_path)
    database = tmp_path / "query-only.db"
    writer = _seed_valid_recovery_database(database)
    if live_wal:
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        _insert_capture_session(
            writer,
            session_id=RUNNING_SESSION_A,
            capture_interface="eth-live-wal",
            first_window_start=TARGET_READY_THROUGH + timedelta(seconds=10),
            status="RUNNING",
        )
        writer.commit()
    else:
        writer.close()
    plan_output = tmp_path / "query-only-plan.json"
    artifact_directory = tmp_path / "artifacts"
    before_database = database.read_bytes()
    before_sidecars = {
        suffix: (tmp_path / f"{database.name}{suffix}").exists()
        for suffix in ("-journal", "-wal", "-shm")
    }
    wal_path = tmp_path / f"{database.name}-wal"
    before_wal = wal_path.read_bytes() if wal_path.exists() else None
    connect_calls: list[tuple[object, dict[str, object]]] = []
    real_connect = sqlite3.connect

    def record_connect(database_arg: object, *args: object, **kwargs: object):
        connect_calls.append((database_arg, dict(kwargs)))
        return real_connect(database_arg, *args, **kwargs)

    monkeypatch.setattr(packet_checkpoint_recovery.sqlite3, "connect", record_connect)

    try:
        plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
            **_dry_run_arguments(
                tmp_path,
                database=database,
                repository_root=repository_root,
                plan_output=plan_output,
            )
        )
        after_database = database.read_bytes()
        after_sidecars = {
            suffix: (tmp_path / f"{database.name}{suffix}").exists()
            for suffix in ("-journal", "-wal", "-shm")
        }
        after_wal = wal_path.read_bytes() if wal_path.exists() else None
    finally:
        if live_wal:
            writer.close()

    assert len(connect_calls) == 1
    connection_uri, connection_options = connect_calls[0]
    assert connection_uri.startswith(f"file:{database.resolve()}?mode=ro")
    assert connection_options == {"uri": True}
    assert after_database == before_database
    if live_wal:
        assert "immutable=1" not in connection_uri
        assert before_wal is not None
        assert after_wal == before_wal
        assert plan["can_execute"] is False
        assert plan["running_sessions"] == [
            {
                "session_id": RUNNING_SESSION_A,
                "started_at": _db_utc(TARGET_READY_THROUGH),
            }
        ]
    else:
        assert "immutable=1" in connection_uri
        assert after_sidecars == before_sidecars
    assert not artifact_directory.exists()


def test_dry_run_reports_checkpoint_before_after_running_gate_and_skip_summary(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    database = tmp_path / "report.db"
    connection = _seed_valid_recovery_database(database)
    try:
        failed_start = CURRENT_READY_THROUGH + timedelta(seconds=10)
        _insert_capture_session(
            connection,
            session_id=FAILED_SKIP_SESSION,
            capture_interface="eth-failed",
            first_window_start=failed_start,
            status="FAILED",
        )
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_A,
            capture_interface="eth-running",
            first_window_start=failed_start + timedelta(seconds=10),
            status="RUNNING",
            started_at=failed_start,
        )
        processable_start = failed_start + timedelta(seconds=20)
        processable_pk = _insert_capture_session(
            connection,
            session_id=PROCESSABLE_SKIP_SESSION,
            capture_interface="eth-processable",
            first_window_start=processable_start,
        )
        _insert_capture_segment(
            connection,
            session_pk=processable_pk,
            capture_interface="eth-processable",
            window_start=processable_start,
            status="EMPTY",
        )
        connection.commit()
    finally:
        connection.close()
    plan_output = tmp_path / "report-plan.json"

    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
        **_dry_run_arguments(
            tmp_path,
            database=database,
            repository_root=repository_root,
            plan_output=plan_output,
        )
    )

    assert plan["can_execute"] is False
    assert "RUNNING_CAPTURE_SESSIONS" in plan["blocking_reasons"]
    assert plan["running_sessions"] == [
        {"session_id": RUNNING_SESSION_A, "started_at": _db_utc(failed_start)}
    ]
    assert plan["checkpoint"]["before"]["last_completed_window_end"] == _db_utc(
        CURRENT_READY_THROUGH
    )
    assert plan["checkpoint"]["after"]["last_completed_window_end"] == _db_utc(
        TARGET_FIRST
    )
    classifications = {
        row["session_id"]: row["classification"]
        for row in plan["summary"]["skipped_sessions"]
    }
    assert classifications == {
        FAILED_SKIP_SESSION: "SKIPPED_FAILED",
        RUNNING_SESSION_A: "BLOCKING_RUNNING",
        PROCESSABLE_SKIP_SESSION: "SKIPPED_FULL_READY_COMPLETED",
    }
    assert {role for lock in plan["locks"] for role in lock["roles"]} == {
        "detection_orchestrator",
        "packet_rule_manual",
        "packet_if_manual",
        "packet_feature_extractor",
    }
    assert shlex.split(plan["execute_command"]) == [
        "python",
        "-m",
        "edge.detection.run_packet_checkpoint_recovery",
        "execute",
        "--plan-file",
        str(plan_output.resolve()),
        "--db-path",
        str(database.resolve()),
        "--artifact-dir",
        "<ARTIFACT_DIR>",
        "--confirm",
        packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        "--confirm-skip-processable",
        (
            f"{packet_checkpoint_recovery.PROCESSABLE_SKIP_PREFIX}"
            f"{plan['plan_sha256']}"
        ),
    ]


@pytest.mark.parametrize("schema_mutation", ("migration", "table", "index"))
def test_dry_run_rejects_missing_005_row_or_table_before_plan_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema_mutation: str,
) -> None:
    repository_root = _repository(tmp_path)
    database = tmp_path / f"missing-{schema_mutation}.db"
    connection = _seed_valid_recovery_database(database)
    try:
        if schema_mutation == "migration":
            connection.execute("DELETE FROM schema_migrations WHERE version = 5")
        elif schema_mutation == "table":
            connection.execute("DROP TABLE packet_checkpoint_recoveries")
        else:
            connection.execute(
                "DROP INDEX uq_packet_checkpoint_recovery_detector_target"
            )
        connection.commit()
    finally:
        connection.close()
    plan_output = tmp_path / f"missing-{schema_mutation}-plan.json"

    def reject_subprocess(*args: object, **kwargs: object) -> None:
        pytest.fail("schema gate must run before repository subprocess gates")

    monkeypatch.setattr(packet_checkpoint_recovery.subprocess, "run", reject_subprocess)

    with pytest.raises(PacketCheckpointRecoveryError, match="Migration 005 schema"):
        packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
            **_dry_run_arguments(
                tmp_path,
                database=database,
                repository_root=repository_root,
                plan_output=plan_output,
            )
        )

    assert not plan_output.exists()


def test_dry_run_rejects_missing_plan_parent_before_temporary_file_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = _repository(tmp_path)
    database = tmp_path / "missing-parent.db"
    _seed_valid_recovery_database(database).close()
    plan_output = tmp_path / "missing" / "plan.json"

    def reject_connect(*args: object, **kwargs: object) -> None:
        pytest.fail("plan parent gate must run before database schema inspection")

    def reject_temporary_file(*args: object, **kwargs: object) -> None:
        pytest.fail("temporary file must not be created for a missing plan parent")

    monkeypatch.setattr(packet_checkpoint_recovery.sqlite3, "connect", reject_connect)
    monkeypatch.setattr(
        packet_checkpoint_recovery, "NamedTemporaryFile", reject_temporary_file
    )

    with pytest.raises(
        PacketCheckpointRecoveryError, match="plan_output parent must already exist"
    ):
        packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
            **_dry_run_arguments(
                tmp_path,
                database=database,
                repository_root=repository_root,
                plan_output=plan_output,
            )
        )

    assert not plan_output.parent.exists()


def test_dry_run_plan_output_does_not_change_untracked_inventory(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / ".gitignore").write_text("generated/\n", encoding="utf-8")
    _git(repository_root, "add", ".gitignore")
    _git(repository_root, "commit", "-m", "ignore generated plans")
    (repository_root / "evidence.bin").write_bytes(b"evidence\n")
    plan_parent = repository_root / "generated"
    plan_parent.mkdir()
    plan_output = plan_parent / "plan.json"
    database = tmp_path / "inventory.db"
    _seed_valid_recovery_database(database).close()
    before = packet_checkpoint_recovery.inspect_repository_state(repository_root)

    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
        **_dry_run_arguments(
            tmp_path,
            database=database,
            repository_root=repository_root,
            plan_output=plan_output,
        )
    )

    after = packet_checkpoint_recovery.inspect_repository_state(repository_root)
    assert plan["repository_state"]["untracked_inventory"] == (
        before["untracked_inventory"]
    )
    assert after["untracked_inventory"] == before["untracked_inventory"]


def test_dry_run_does_not_call_posix_execute_platform_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = _repository(tmp_path)
    database = tmp_path / "cross-platform.db"
    _seed_valid_recovery_database(database).close()
    plan_output = tmp_path / "cross-platform-plan.json"

    def reject_execute_gate() -> None:
        pytest.fail("dry-run must not call the POSIX-only Execute platform gate")

    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "_require_posix_execute_platform",
        reject_execute_gate,
        raising=False,
    )

    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
        **_dry_run_arguments(
            tmp_path,
            database=database,
            repository_root=repository_root,
            plan_output=plan_output,
        )
    )

    assert plan["can_execute"] is True


@pytest.mark.parametrize(
    "missing_flag",
    (
        "--db-path",
        "--repository-root",
        "--detector",
        "--current-session-id",
        "--target-session-id",
        "--approved-by",
        "--reason",
        "--plan-output",
    ),
)
def test_dry_run_cli_requires_all_identity_and_output_arguments(
    tmp_path: Path,
    missing_flag: str,
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    values = {
        "--db-path": str(tmp_path / "iot.db"),
        "--repository-root": str(tmp_path),
        "--detector": "packet_rule",
        "--current-session-id": CURRENT_SESSION,
        "--target-session-id": TARGET_SESSION,
        "--approved-by": "operator@example.com",
        "--reason": "recover capture-session gap",
        "--plan-output": str(tmp_path / "plan.json"),
    }
    argv = [
        "dry-run",
        *[item for flag, value in values.items() for item in (flag, value)],
    ]
    missing_index = argv.index(missing_flag)
    del argv[missing_index : missing_index + 2]

    with pytest.raises(SystemExit) as exc_info:
        cli.build_parser().parse_args(argv)

    assert exc_info.value.code == 2


def test_dry_run_cli_returns_two_for_precommit_validation_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    repository_root = _repository(tmp_path)
    missing_database = tmp_path / "missing.db"
    plan_output = tmp_path / "plan.json"

    exit_code = cli.main(
        [
            "dry-run",
            "--db-path",
            str(missing_database),
            "--repository-root",
            str(repository_root),
            "--detector",
            "packet_rule",
            "--current-session-id",
            CURRENT_SESSION,
            "--target-session-id",
            TARGET_SESSION,
            "--approved-by",
            "operator@example.com",
            "--reason",
            "recover capture-session gap",
            "--plan-output",
            str(plan_output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err == ""
    error_payload = json.loads(captured.out)
    assert error_payload["database_committed"] is False
    assert error_payload["ok"] is False
    assert error_payload["error"]
    assert not plan_output.exists()


def test_dry_run_cli_forwards_explicit_live_resume_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    captured: dict[str, object] = {}

    def record_inspect(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"mode": kwargs["mode"], "can_execute": True}

    monkeypatch.setattr(cli, "inspect_packet_checkpoint_recovery", record_inspect)
    exit_code = cli.main(
        [
            "dry-run",
            "--mode",
            "live-resume",
            "--db-path",
            str(tmp_path / "iot.db"),
            "--repository-root",
            str(tmp_path),
            "--detector",
            "packet_rule",
            "--current-session-id",
            CURRENT_SESSION,
            "--target-session-id",
            TARGET_SESSION,
            "--approved-by",
            "operator@example.com",
            "--reason",
            "resume packet rule at live capture",
            "--plan-output",
            str(tmp_path / "plan.json"),
        ]
    )

    assert exit_code == 0
    assert captured["mode"] == "live-resume"
    assert json.loads(capsys.readouterr().out) == {
        "can_execute": True,
        "mode": "live-resume",
    }


def _execute_fixture(tmp_path: Path) -> dict[str, object]:
    repository_root = _repository(tmp_path)
    database = tmp_path / "execute.db"
    _seed_valid_recovery_database(database).close()
    plan_output = tmp_path / "execute-plan.json"
    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
        **_dry_run_arguments(
            tmp_path,
            database=database,
            repository_root=repository_root,
            plan_output=plan_output,
        )
    )
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    return {
        "repository_root": repository_root,
        "database": database,
        "plan_output": plan_output,
        "plan": plan,
        "artifact_dir": artifact_dir,
    }


def _live_execute_fixture(
    tmp_path: Path,
    *,
    detector_name: str = "packet_rule",
) -> dict[str, object]:
    repository_root = _repository(tmp_path)
    database = tmp_path / "live-execute.db"
    connection = _seed_valid_recovery_database(database)
    try:
        if detector_name == "packet_if":
            _insert_packet_if_checkpoint(connection)
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'RUNNING', ended_at = NULL "
            "WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()
    finally:
        connection.close()
    plan_output = tmp_path / "live-execute-plan.json"
    plan = packet_checkpoint_recovery.inspect_packet_checkpoint_recovery(
        **_dry_run_arguments(
            tmp_path,
            database=database,
            repository_root=repository_root,
            plan_output=plan_output,
            mode="live-resume",
            detector_name=detector_name,
        )
    )
    artifact_dir = tmp_path / "live-artifacts"
    artifact_dir.mkdir()
    return {
        "repository_root": repository_root,
        "database": database,
        "plan_output": plan_output,
        "plan": plan,
        "artifact_dir": artifact_dir,
    }


def _valid_execute_kwargs(fixture: dict[str, object]) -> dict[str, object]:
    confirmation = (
        packet_checkpoint_recovery.LIVE_RESUME_CONFIRMATION
        if fixture["plan"].get("mode") == "live-resume"
        else packet_checkpoint_recovery.EXECUTE_CONFIRMATION
    )
    return {
        "plan_file": fixture["plan_output"],
        "db_path": fixture["database"],
        "artifact_dir": fixture["artifact_dir"],
        "confirm": confirmation,
    }


def _allow_execute_on_test_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        packet_checkpoint_recovery, "_current_platform_name", lambda: "posix"
    )
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "acquire_recovery_locks",
        lambda locks: nullcontext(),
    )


def _checkpoint(
    database: Path,
    detector_name: str = "packet_rule",
) -> sqlite3.Row:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        row = recovery_repository.get_checkpoint(
            connection, detector_name, "packet_feature_logs"
        )
    assert row is not None
    return row


def test_snapshot_protected_rows_excludes_only_requested_checkpoint(
    tmp_path: Path,
) -> None:
    fixture = _execute_fixture(tmp_path)
    with sqlite3.connect(fixture["database"]) as connection:
        snapshot = snapshot_protected_rows(
            connection,
            requested_checkpoint_key=("packet_rule", "packet_feature_logs"),
        )

    assert "detector_checkpoints" in snapshot
    assert all(
        row[:2] != ("packet_rule", "packet_feature_logs")
        for row in snapshot["detector_checkpoints"]
    )


def test_execute_changes_only_requested_checkpoint_and_one_audit_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    key = ("packet_rule", "packet_feature_logs")
    with sqlite3.connect(fixture["database"]) as connection:
        before = snapshot_protected_rows(connection, requested_checkpoint_key=key)

    execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    with sqlite3.connect(fixture["database"]) as connection:
        after = snapshot_protected_rows(connection, requested_checkpoint_key=key)
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM packet_checkpoint_recoveries"
        ).fetchone()[0]
    assert after == before
    assert audit_count == 1


def test_execute_creates_verified_backup_before_begin_immediate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    events: list[str] = []
    real_backup = packet_checkpoint_recovery.create_sqlite_backup
    real_verify = packet_checkpoint_recovery.verify_database
    real_update = recovery_repository.update_checkpoint_conditionally

    def record_backup(source: Path, backup: Path):
        events.append("backup")
        return real_backup(source, backup)

    def record_verify(database: Path):
        if Path(database).name == "database.backup.db":
            events.append("backup_verified")
        return real_verify(database)

    def record_update(connection: sqlite3.Connection, **kwargs: object) -> int:
        assert connection.in_transaction is True
        events.append("transaction_mutation")
        return real_update(connection, **kwargs)

    monkeypatch.setattr(packet_checkpoint_recovery, "create_sqlite_backup", record_backup)
    monkeypatch.setattr(packet_checkpoint_recovery, "verify_database", record_verify)
    monkeypatch.setattr(recovery_repository, "update_checkpoint_conditionally", record_update)
    kwargs = _valid_execute_kwargs(fixture)

    result = execute_packet_checkpoint_recovery(**kwargs)

    assert "platform_name" not in kwargs
    assert "lock_factory" not in kwargs
    assert result["database_committed"] is True
    assert events.index("backup") < events.index("backup_verified")
    assert events.index("backup_verified") < events.index("transaction_mutation")


def test_execute_rechecks_full_canonical_plan_inside_begin_immediate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    real_build = packet_checkpoint_recovery.build_recovery_plan
    transaction_states: list[bool] = []

    def record_build(connection: sqlite3.Connection, **kwargs: object):
        transaction_states.append(connection.in_transaction)
        return real_build(connection, **kwargs)

    monkeypatch.setattr(packet_checkpoint_recovery, "build_recovery_plan", record_build)

    execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert transaction_states == [False, True]


def test_execute_rejects_changed_checkpoint_updated_at_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    before = dict(_checkpoint(fixture["database"]))
    real_update = recovery_repository.update_checkpoint_conditionally

    def change_updated_at_then_update(
        connection: sqlite3.Connection, **kwargs: object
    ) -> int:
        connection.execute(
            """
            UPDATE detector_checkpoints
            SET updated_at = ?
            WHERE detector_name = 'packet_rule'
              AND source_table = 'packet_feature_logs'
            """,
            (OTHER_UTC,),
        )
        return real_update(connection, **kwargs)

    monkeypatch.setattr(
        recovery_repository,
        "update_checkpoint_conditionally",
        change_updated_at_then_update,
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="conditional checkpoint"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert dict(_checkpoint(fixture["database"])) == before
    with sqlite3.connect(fixture["database"]) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM packet_checkpoint_recoveries"
        ).fetchone()[0] == 0


def test_execute_keeps_last_processed_id_and_advances_only_time_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    before = dict(_checkpoint(fixture["database"]))

    execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    after = dict(_checkpoint(fixture["database"]))
    assert after["last_processed_id"] == before["last_processed_id"] == 42
    assert after["last_completed_window_end"] == _db_utc(TARGET_FIRST)
    assert after["updated_at"] != before["updated_at"]


def test_live_resume_execute_preserves_target_features_and_advances_to_first_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _live_execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    with sqlite3.connect(fixture["database"]) as connection:
        features_before = tuple(
            connection.execute(
                """
                SELECT pfl.*
                FROM packet_feature_logs pfl
                JOIN packet_capture_segments pcsg
                    ON pcsg.id = pfl.capture_segment_id
                JOIN packet_capture_sessions pcs
                    ON pcs.id = pcsg.capture_session_id
                WHERE pcs.session_id = ?
                ORDER BY pfl.id
                """,
                (TARGET_SESSION,),
            )
        )

    execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    after = dict(_checkpoint(fixture["database"]))
    with sqlite3.connect(fixture["database"]) as connection:
        features_after = tuple(
            connection.execute(
                """
                SELECT pfl.*
                FROM packet_feature_logs pfl
                JOIN packet_capture_segments pcsg
                    ON pcsg.id = pfl.capture_segment_id
                JOIN packet_capture_sessions pcs
                    ON pcs.id = pcsg.capture_session_id
                WHERE pcs.session_id = ?
                ORDER BY pfl.id
                """,
                (TARGET_SESSION,),
            )
        )
        plan_json = connection.execute(
            "SELECT plan_json FROM packet_checkpoint_recoveries"
        ).fetchone()[0]
    assert after["last_processed_id"] == 42
    assert after["last_completed_window_end"] == _db_utc(TARGET_FIRST)
    assert features_after == features_before
    assert json.loads(plan_json)["mode"] == "live-resume"


def test_packet_if_live_resume_execute_changes_only_checkpoint_boundary_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _live_execute_fixture(tmp_path, detector_name="packet_if")
    _allow_execute_on_test_platform(monkeypatch)
    key = ("packet_if", "packet_feature_logs")
    checkpoint_before = dict(_checkpoint(fixture["database"], "packet_if"))
    with sqlite3.connect(fixture["database"]) as connection:
        protected_before = snapshot_protected_rows(
            connection,
            requested_checkpoint_key=key,
        )

    execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    checkpoint_after = dict(_checkpoint(fixture["database"], "packet_if"))
    with sqlite3.connect(fixture["database"]) as connection:
        protected_after = snapshot_protected_rows(
            connection,
            requested_checkpoint_key=key,
        )
        audits = connection.execute(
            """
            SELECT detector_name, source_table, target_capture_session_id,
                   last_processed_id_before, last_processed_id_after,
                   last_completed_window_end_after, plan_json
            FROM packet_checkpoint_recoveries
            """
        ).fetchall()

    assert checkpoint_after["last_processed_id"] == checkpoint_before[
        "last_processed_id"
    ] == 84
    assert checkpoint_after["last_completed_window_end"] == _db_utc(TARGET_FIRST)
    assert protected_after == protected_before
    assert len(audits) == 1
    assert tuple(audits[0][0:6]) == (
        "packet_if",
        "packet_feature_logs",
        TARGET_SESSION,
        84,
        84,
        _db_utc(TARGET_FIRST),
    )
    assert json.loads(audits[0][6])["mode"] == "live-resume"


def test_live_resume_execute_allows_benign_growing_ready_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _live_execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    with sqlite3.connect(fixture["database"]) as connection:
        target_pk = int(
            connection.execute(
                "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                (TARGET_SESSION,),
            ).fetchone()[0]
        )
        _insert_capture_segment(
            connection,
            session_pk=target_pk,
            capture_interface="eth-target",
            window_start=TARGET_READY_THROUGH,
            status="READY",
        )
        connection.commit()

    result = execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert result["database_committed"] is True
    assert dict(_checkpoint(fixture["database"]))["last_completed_window_end"] == _db_utc(
        TARGET_FIRST
    )


def test_live_resume_execute_rejects_external_write_after_backup_before_begin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _live_execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    database = Path(fixture["database"])
    checkpoint_before = dict(_checkpoint(database))
    real_connect = sqlite3.connect
    with real_connect(database) as connection:
        target_segments_before = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM packet_capture_segments pcsg
                JOIN packet_capture_sessions pcs
                    ON pcs.id = pcsg.capture_session_id
                WHERE pcs.session_id = ?
                """,
                (TARGET_SESSION,),
            ).fetchone()[0]
        )
    injected = False

    class BeginRaceConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            object.__setattr__(self, "_connection", connection)

        def __getattr__(self, name: str) -> object:
            return getattr(self._connection, name)

        def __setattr__(self, name: str, value: object) -> None:
            setattr(self._connection, name, value)

        def __enter__(self) -> "BeginRaceConnection":
            self._connection.__enter__()
            return self

        def __exit__(self, *args: object) -> object:
            return self._connection.__exit__(*args)

        def execute(self, sql: str, *args: object) -> sqlite3.Cursor:
            nonlocal injected
            if sql.strip().upper() == "BEGIN IMMEDIATE" and not injected:
                with real_connect(database) as writer:
                    target_pk = int(
                        writer.execute(
                            "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                            (TARGET_SESSION,),
                        ).fetchone()[0]
                    )
                    _insert_capture_segment(
                        writer,
                        session_pk=target_pk,
                        capture_interface="eth-target",
                        window_start=TARGET_READY_THROUGH,
                        status="READY",
                    )
                injected = True
            return self._connection.execute(sql, *args)

    def connect_with_begin_race(*args: object, **kwargs: object) -> object:
        connection = real_connect(*args, **kwargs)
        if kwargs.get("isolation_level") is None and Path(args[0]) == database:
            return BeginRaceConnection(connection)
        return connection

    monkeypatch.setattr(
        packet_checkpoint_recovery.sqlite3, "connect", connect_with_begin_race
    )

    with pytest.raises(
        PacketCheckpointRecoveryError,
        match="database changed after backup before transaction",
    ):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert injected is True
    assert dict(_checkpoint(database)) == checkpoint_before
    with real_connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM packet_checkpoint_recoveries"
        ).fetchone()[0] == 0
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs
                ON pcs.id = pcsg.capture_session_id
            WHERE pcs.session_id = ?
            """,
            (TARGET_SESSION,),
        ).fetchone()[0] == target_segments_before + 1
    operation_dirs = list(Path(fixture["artifact_dir"]).iterdir())
    assert len(operation_dirs) == 1
    with real_connect(operation_dirs[0] / "database.backup.db") as backup:
        assert backup.execute(
            """
            SELECT COUNT(*)
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs
                ON pcs.id = pcsg.capture_session_id
            WHERE pcs.session_id = ?
            """,
            (TARGET_SESSION,),
        ).fetchone()[0] == target_segments_before


@pytest.mark.parametrize(
    "stale_mutation", ("status", "first_window", "readiness", "other_running")
)
def test_live_resume_execute_rejects_stale_target_before_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stale_mutation: str,
) -> None:
    fixture = _live_execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    with sqlite3.connect(fixture["database"]) as connection:
        if stale_mutation == "status":
            connection.execute(
                """
                UPDATE packet_capture_sessions
                SET status = 'COMPLETED', ended_at = ?
                WHERE session_id = ?
                """,
                (_db_utc(TARGET_READY_THROUGH), TARGET_SESSION),
            )
        elif stale_mutation == "first_window":
            connection.execute(
                "UPDATE packet_capture_sessions SET first_window_start = ? "
                "WHERE session_id = ?",
                (_db_utc(TARGET_FIRST + timedelta(seconds=10)), TARGET_SESSION),
            )
        elif stale_mutation == "readiness":
            second_id = int(
                connection.execute(
                    """
                    SELECT pcsg.id
                    FROM packet_capture_segments pcsg
                    JOIN packet_capture_sessions pcs
                        ON pcs.id = pcsg.capture_session_id
                    WHERE pcs.session_id = ?
                    ORDER BY pcsg.window_start
                    LIMIT 1 OFFSET 1
                    """,
                    (TARGET_SESSION,),
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'READY' WHERE id = ?",
                (second_id,),
            )
        else:
            _insert_capture_session(
                connection,
                session_id=RUNNING_SESSION_A,
                capture_interface="eth-running",
                first_window_start=TARGET_READY_THROUGH + timedelta(seconds=10),
                status="RUNNING",
            )
        connection.commit()
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "create_sqlite_backup",
        lambda *args, **kwargs: pytest.fail("backup must not start"),
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="canonical plan changed"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))


def test_live_resume_replay_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _live_execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    kwargs = _valid_execute_kwargs(fixture)

    execute_packet_checkpoint_recovery(**kwargs)
    with pytest.raises(PacketCheckpointRecoveryError):
        execute_packet_checkpoint_recovery(**kwargs)

    with sqlite3.connect(fixture["database"]) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM packet_checkpoint_recoveries"
        ).fetchone()[0] == 1


def test_execute_inserts_exactly_one_audit_row_in_same_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    real_insert = recovery_repository.insert_recovery_audit
    transaction_states: list[bool] = []

    def record_insert(connection: sqlite3.Connection, **kwargs: object) -> int:
        transaction_states.append(connection.in_transaction)
        return real_insert(connection, **kwargs)

    monkeypatch.setattr(recovery_repository, "insert_recovery_audit", record_insert)

    result = execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    with sqlite3.connect(fixture["database"]) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM packet_checkpoint_recoveries"
        ).fetchall()
    assert transaction_states == [True]
    assert len(rows) == 1
    assert rows[0]["operation_id"] == result["operation_id"]
    assert rows[0]["backup_sha256"] == result["backup_sha256"]


def test_execute_requires_total_changes_delta_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)

    result = execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert result["transaction_total_changes_delta"] == 2


def test_backup_failure_leaves_live_database_and_artifacts_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    before = fixture["database"].read_bytes()

    def fail_backup(*args: object, **kwargs: object) -> None:
        raise RuntimeError("backup failed")

    monkeypatch.setattr(packet_checkpoint_recovery, "create_sqlite_backup", fail_backup)

    with pytest.raises(RuntimeError, match="backup failed"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert fixture["database"].read_bytes() == before
    assert list(fixture["artifact_dir"].iterdir()) == []


def test_precommit_failure_preserves_verified_backup_and_rolls_back_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    before = dict(_checkpoint(fixture["database"]))

    def fail_audit(*args: object, **kwargs: object) -> int:
        raise RuntimeError("precommit failure")

    monkeypatch.setattr(recovery_repository, "insert_recovery_audit", fail_audit)

    with pytest.raises(RuntimeError, match="precommit failure"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    operation_dirs = list(fixture["artifact_dir"].iterdir())
    assert len(operation_dirs) == 1
    backup = operation_dirs[0] / "database.backup.db"
    assert backup.is_file()
    assert backup.with_suffix(".db.sha256").is_file()
    verification = packet_checkpoint_recovery.verify_database(backup)
    assert verification.integrity_check == "ok"
    assert verification.foreign_key_violations == ()
    assert dict(_checkpoint(fixture["database"])) == before


def test_duplicate_operation_or_detector_target_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    with sqlite3.connect(fixture["database"]) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_recovery_audit(connection)
    backup_calls = 0

    def reject_backup(*args: object, **kwargs: object) -> None:
        nonlocal backup_calls
        backup_calls += 1

    monkeypatch.setattr(packet_checkpoint_recovery, "create_sqlite_backup", reject_backup)

    with pytest.raises(PacketCheckpointRecoveryError, match="DUPLICATE_RECOVERY"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert backup_calls == 0


def test_execute_rejects_changed_untracked_inventory_before_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    (fixture["repository_root"] / "new-evidence.bin").write_bytes(b"changed\n")
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "create_sqlite_backup",
        lambda *args, **kwargs: pytest.fail("backup must not start"),
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="repository state"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))


def test_execute_rejects_database_path_different_from_plan_before_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    other_database = tmp_path / "other.db"
    _seed_valid_recovery_database(other_database).close()
    kwargs = _valid_execute_kwargs(fixture)
    kwargs["db_path"] = other_database
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "create_sqlite_backup",
        lambda *args, **kwargs: pytest.fail("backup must not start"),
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="database path"):
        execute_packet_checkpoint_recovery(**kwargs)


def test_execute_rejects_global_running_session_before_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    with sqlite3.connect(fixture["database"]) as connection:
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_A,
            capture_interface="eth-running",
            first_window_start=TARGET_READY_THROUGH + timedelta(seconds=10),
            status="RUNNING",
        )
        connection.commit()
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "create_sqlite_backup",
        lambda *args, **kwargs: pytest.fail("backup must not start"),
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="RUNNING_CAPTURE_SESSIONS"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))


def test_execute_rejects_wrong_processable_skip_confirmation_before_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    plan = fixture["plan"]
    plan["summary"]["skips_processable_sessions"] = True
    plan["summary"]["warning_codes"] = ["PROCESSABLE_SESSION_SKIP"]
    plan["plan_sha256"] = packet_checkpoint_recovery.calculate_plan_sha256(plan)
    fixture["plan_output"].write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "create_sqlite_backup",
        lambda *args, **kwargs: pytest.fail("backup must not start"),
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="confirmation mismatch"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))


def test_execute_rejects_missing_artifact_directory_without_creating_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    missing = tmp_path / "missing-artifacts"
    kwargs = _valid_execute_kwargs(fixture)
    kwargs["artifact_dir"] = missing

    with pytest.raises(PacketCheckpointRecoveryError, match="existing directory"):
        execute_packet_checkpoint_recovery(**kwargs)

    assert not missing.exists()


def test_execute_lock_conflict_prevents_backup_artifact_and_database_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    monkeypatch.setattr(
        packet_checkpoint_recovery, "_current_platform_name", lambda: "posix"
    )
    before = fixture["database"].read_bytes()

    @contextmanager
    def conflicting_locks(locks: object):
        raise PacketCheckpointRecoveryError("lock conflict")
        yield

    monkeypatch.setattr(
        packet_checkpoint_recovery, "acquire_recovery_locks", conflicting_locks
    )

    with pytest.raises(PacketCheckpointRecoveryError, match="lock conflict"):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert fixture["database"].read_bytes() == before
    assert list(fixture["artifact_dir"].iterdir()) == []


def test_execute_rejects_windows_before_lock_backup_artifact_and_database_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "untouched.db"
    database.write_bytes(b"not sqlite")
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    monkeypatch.setattr(
        packet_checkpoint_recovery, "_current_platform_name", lambda: "nt"
    )
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "acquire_recovery_locks",
        lambda locks: pytest.fail("locks must not be acquired"),
    )
    before = database.read_bytes()

    with pytest.raises(PacketCheckpointRecoveryError, match="POSIX"):
        execute_packet_checkpoint_recovery(
            plan_file=tmp_path / "missing-plan.json",
            db_path=database,
            artifact_dir=artifact_dir,
            confirm=packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        )

    assert database.read_bytes() == before
    assert list(artifact_dir.iterdir()) == []


def test_execute_public_signature_has_no_platform_override() -> None:
    assert "platform_name" not in inspect.signature(
        execute_packet_checkpoint_recovery
    ).parameters


def test_execute_rejects_platform_name_keyword_in_general_python_call(
    tmp_path: Path,
) -> None:
    fixture = _execute_fixture(tmp_path)
    kwargs = _valid_execute_kwargs(fixture)
    with pytest.raises(TypeError):
        execute_packet_checkpoint_recovery(**kwargs, platform_name="posix")


def test_execute_public_signature_has_no_lock_factory_override() -> None:
    assert "lock_factory" not in inspect.signature(
        execute_packet_checkpoint_recovery
    ).parameters


def test_execute_rejects_lock_factory_keyword_in_general_python_call(
    tmp_path: Path,
) -> None:
    fixture = _execute_fixture(tmp_path)
    kwargs = _valid_execute_kwargs(fixture)
    with pytest.raises(TypeError):
        execute_packet_checkpoint_recovery(
            **kwargs,
            lock_factory=lambda path: nullcontext(),
        )


def test_execute_cli_success_returns_zero_and_writes_result_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    expected = {
        "operation_id": "operation-success",
        "database_committed": True,
        "result_path": str(tmp_path / "result.json"),
    }
    monkeypatch.setattr(
        cli, "execute_packet_checkpoint_recovery", lambda **kwargs: expected, raising=False
    )

    exit_code = cli.main(
        [
            "execute",
            "--plan-file",
            str(tmp_path / "plan.json"),
            "--db-path",
            str(tmp_path / "iot.db"),
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            "--confirm",
            packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out) == expected


def test_execute_cli_precommit_failure_returns_two_without_database_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    database = tmp_path / "iot.db"
    database.write_bytes(b"unchanged")

    def fail_execute(**kwargs: object) -> dict[str, object]:
        raise PacketCheckpointRecoveryError("precommit rejected")

    monkeypatch.setattr(
        cli, "execute_packet_checkpoint_recovery", fail_execute, raising=False
    )

    exit_code = cli.main(
        [
            "execute",
            "--plan-file",
            str(tmp_path / "plan.json"),
            "--db-path",
            str(database),
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            "--confirm",
            packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "database_committed": False,
        "error": "precommit rejected",
        "ok": False,
    }
    assert database.read_bytes() == b"unchanged"


def test_execute_cli_postcommit_integrity_failure_returns_three_and_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")

    class FakeCommittedArtifactError(PacketCheckpointRecoveryError):
        def __init__(self) -> None:
            self.operation_id = "operation-hold"
            self.backup_path = tmp_path / "database.backup.db"
            super().__init__("post-commit integrity failure")

    def fail_execute(**kwargs: object) -> dict[str, object]:
        raise FakeCommittedArtifactError()

    monkeypatch.setattr(
        cli,
        "PacketCheckpointRecoveryCommittedArtifactError",
        FakeCommittedArtifactError,
        raising=False,
    )
    monkeypatch.setattr(
        cli, "execute_packet_checkpoint_recovery", fail_execute, raising=False
    )

    exit_code = cli.main(
        [
            "execute",
            "--plan-file",
            str(tmp_path / "plan.json"),
            "--db-path",
            str(tmp_path / "iot.db"),
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            "--confirm",
            packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 3
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "backup_path": str(tmp_path / "database.backup.db"),
        "database_committed": True,
        "error": "post-commit integrity failure",
        "ok": False,
        "operation_id": "operation-hold",
        "operation_status": "HOLD",
    }


def test_execute_cli_result_json_failure_returns_three_and_preserves_commit_audit_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "_write_json_atomically",
        lambda path, payload: (_ for _ in ()).throw(OSError("result write failed")),
    )

    exit_code = cli.main(
        [
            "execute",
            "--plan-file",
            str(fixture["plan_output"]),
            "--db-path",
            str(fixture["database"]),
            "--artifact-dir",
            str(fixture["artifact_dir"]),
            "--confirm",
            packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 3
    assert payload["database_committed"] is True
    assert payload["operation_status"] == "HOLD"
    assert Path(payload["backup_path"]).is_file()
    assert dict(_checkpoint(fixture["database"]))["last_completed_window_end"] == _db_utc(
        TARGET_FIRST
    )
    with sqlite3.connect(fixture["database"]) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM packet_checkpoint_recoveries"
        ).fetchone()[0] == 1


def test_execute_cli_never_auto_restores_committed_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    fixture = _execute_fixture(tmp_path)
    _allow_execute_on_test_platform(monkeypatch)
    real_verify = packet_checkpoint_recovery.verify_database
    live_verification_count = 0

    def fail_postcommit_verification(path: Path):
        nonlocal live_verification_count
        verification = real_verify(path)
        if Path(path) == fixture["database"]:
            live_verification_count += 1
            if live_verification_count == 2:
                return type(verification)("failed", ())
        return verification

    monkeypatch.setattr(
        packet_checkpoint_recovery, "verify_database", fail_postcommit_verification
    )

    exit_code = cli.main(
        [
            "execute",
            "--plan-file",
            str(fixture["plan_output"]),
            "--db-path",
            str(fixture["database"]),
            "--artifact-dir",
            str(fixture["artifact_dir"]),
            "--confirm",
            packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 3
    assert payload["operation_status"] == "HOLD"
    assert dict(_checkpoint(fixture["database"]))["last_completed_window_end"] == _db_utc(
        TARGET_FIRST
    )
    with sqlite3.connect(fixture["database"]) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM packet_checkpoint_recoveries"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    "missing_flag", ("--plan-file", "--db-path", "--artifact-dir", "--confirm")
)
def test_execute_cli_requires_plan_file_database_artifact_and_confirmation(
    tmp_path: Path, missing_flag: str
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    values = {
        "--plan-file": str(tmp_path / "plan.json"),
        "--db-path": str(tmp_path / "iot.db"),
        "--artifact-dir": str(tmp_path / "artifacts"),
        "--confirm": packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
    }
    argv = [
        "execute",
        *[item for flag, value in values.items() for item in (flag, value)],
    ]
    parsed = cli.build_parser().parse_args(argv)
    assert parsed.command == "execute"
    parsed_with_skip = cli.build_parser().parse_args(
        [*argv, "--confirm-skip-processable", "SKIP-PROCESSABLE-SESSIONS:digest"]
    )
    assert (
        parsed_with_skip.confirm_skip_processable
        == "SKIP-PROCESSABLE-SESSIONS:digest"
    )
    missing_index = argv.index(missing_flag)
    del argv[missing_index : missing_index + 2]

    with pytest.raises(SystemExit) as exc_info:
        cli.build_parser().parse_args(argv)

    assert exc_info.value.code == 2


def test_execute_cli_returns_two_for_windows_platform_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    database = tmp_path / "untouched.db"
    database.write_bytes(b"not sqlite")
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    monkeypatch.setattr(
        packet_checkpoint_recovery, "_current_platform_name", lambda: "nt"
    )
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "acquire_recovery_locks",
        lambda locks: pytest.fail("locks must not be acquired"),
    )
    monkeypatch.setattr(
        packet_checkpoint_recovery,
        "create_sqlite_backup",
        lambda *args, **kwargs: pytest.fail("backup must not be created"),
    )

    exit_code = cli.main(
        [
            "execute",
            "--plan-file",
            str(tmp_path / "missing-plan.json"),
            "--db-path",
            str(database),
            "--artifact-dir",
            str(artifact_dir),
            "--confirm",
            packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err == ""
    assert json.loads(captured.out)["database_committed"] is False
    assert database.read_bytes() == b"not sqlite"
    assert list(artifact_dir.iterdir()) == []


def test_execute_cli_rejects_platform_name_option(tmp_path: Path) -> None:
    cli = importlib.import_module("edge.detection.run_packet_checkpoint_recovery")
    argv = [
        "execute",
        "--plan-file",
        str(tmp_path / "plan.json"),
        "--db-path",
        str(tmp_path / "iot.db"),
        "--artifact-dir",
        str(tmp_path / "artifacts"),
        "--confirm",
        packet_checkpoint_recovery.EXECUTE_CONFIRMATION,
    ]
    parsed = cli.build_parser().parse_args(argv)
    assert not hasattr(parsed, "platform_name")

    with pytest.raises(SystemExit) as exc_info:
        cli.build_parser().parse_args(
            [
                *argv,
                "--platform-name",
                "posix",
            ]
        )

    assert exc_info.value.code == 2


def test_execute_holds_all_locks_through_post_commit_verification_and_result_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _execute_fixture(tmp_path)
    monkeypatch.setattr(
        packet_checkpoint_recovery, "_current_platform_name", lambda: "posix"
    )
    lock_held = False
    real_verify = packet_checkpoint_recovery.verify_database
    real_write = packet_checkpoint_recovery._write_json_atomically
    postcommit_verifications = 0
    result_writes = 0
    lock_exit_exception = ""

    @contextmanager
    def recording_locks(locks: object):
        nonlocal lock_held, lock_exit_exception
        lock_held = True
        try:
            yield
        except BaseException as exc:
            lock_exit_exception = type(exc).__name__
            raise
        finally:
            lock_held = False

    def recording_verify(path: Path):
        nonlocal postcommit_verifications
        verification = real_verify(path)
        if Path(path) == fixture["database"] and dict(_checkpoint(path))[
            "last_completed_window_end"
        ] == _db_utc(TARGET_FIRST):
            assert lock_held is True
            postcommit_verifications += 1
        return verification

    def recording_write(path: Path, payload: object) -> None:
        nonlocal result_writes
        assert lock_held is True
        result_writes += 1
        real_write(path, payload)
        raise OSError("hold after result write")

    monkeypatch.setattr(
        packet_checkpoint_recovery, "acquire_recovery_locks", recording_locks
    )
    monkeypatch.setattr(packet_checkpoint_recovery, "verify_database", recording_verify)
    monkeypatch.setattr(packet_checkpoint_recovery, "_write_json_atomically", recording_write)

    with pytest.raises(PacketCheckpointRecoveryError):
        execute_packet_checkpoint_recovery(**_valid_execute_kwargs(fixture))

    assert lock_held is False
    assert postcommit_verifications == 1
    assert result_writes == 1
    assert lock_exit_exception == "PacketCheckpointRecoveryCommittedArtifactError"


def _recovery_docs() -> tuple[str, str, str]:
    root = Path(__file__).parents[1]
    return tuple(
        (root / path).read_text(encoding="utf-8")
        for path in (
            "docs/packet-checkpoint-gap-recovery-runbook.md",
            "docs/db-schema.md",
            "docs/phase4-detection-core.md",
        )
    )


def test_gap_recovery_runbook_separates_migration_dry_run_and_execute() -> None:
    runbook, _, _ = _recovery_docs()
    assert "Migration 005" in runbook
    assert "dry-run" in runbook
    assert "execute" in runbook


def test_gap_recovery_runbook_documents_service_process_and_running_session_gates() -> None:
    runbook, _, _ = _recovery_docs()
    assert "RUNNING" in runbook
    assert "packet-capture.service" in runbook


def test_gap_recovery_runbook_documents_exit_three_hold_and_no_auto_restore() -> None:
    runbook, _, _ = _recovery_docs()
    assert "Exit Code 3" in runbook
    assert "HOLD" in runbook
    assert "자동 Restore하지" in runbook


def test_gap_recovery_runbook_documents_cross_platform_dry_run_and_posix_only_execute() -> None:
    runbook, _, _ = _recovery_docs()
    assert "Windows와 POSIX" in runbook
    assert "Execute는 POSIX" in runbook


def test_gap_recovery_runbook_requires_existing_plan_parent_and_artifact_directory() -> None:
    runbook, _, _ = _recovery_docs()
    assert "plan_output.parent" in runbook
    assert "artifact_dir" in runbook


def test_gap_recovery_docs_preserve_orchestrator_gap_block_and_holdout_e2e_scope() -> None:
    _, schema, core = _recovery_docs()
    assert "packet_checkpoint_recoveries" in schema
    assert "run_until_for_capture_session" in core
    assert "Holdout" in core
