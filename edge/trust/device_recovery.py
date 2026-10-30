"""Atomic, device-scoped recovery; full backups belong to maintenance instead."""

from __future__ import annotations

from contextlib import ExitStack, closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from backend.app.config import settings
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust import baseline_recovery as baseline
from edge.trust.run_firewall_worker import firewall_lock_path


AUDIT_TABLE = "device_recovery_audits"


def audit_storage_check(db_path: str | Path) -> dict[str, Any]:
    """Check schema readiness without creating or writing a database."""
    database = Path(db_path).expanduser().resolve()
    try:
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(device_recovery_audits)")}
        available = {"operation_id", "device_id", "requested_at", "payload_json"} <= columns
        reason = None if available else "Device recovery audit migration 017 is required."
    except sqlite3.DatabaseError as exc:
        available, reason = False, f"Device recovery audit database unavailable: {exc}"
    return {"storage": "database", "available": available, "failure_reason": reason}


def insert_audit(connection: sqlite3.Connection, payload: Mapping[str, Any]) -> None:
    """The caller owns the transaction; never commit independently of the reset."""
    connection.execute(
        "INSERT INTO device_recovery_audits(operation_id, device_id, requested_at, payload_json) "
        "VALUES (?, ?, ?, ?)",
        (payload["operation_id"], payload["device_id"], payload["requested_at"],
         json.dumps(dict(payload), ensure_ascii=False, allow_nan=False)),
    )


def execute_device_recovery(
    *, db_path: str | Path, device_ids: list[str],
    expected_trust_scores: Mapping[str, int],
    confirm: str, operation_id: str, reason: str, requested_by: str,
    approved_by: str, requested_at: str,
    preflight: Mapping[str, Any],
) -> dict[str, Any]:
    """Commit one device reset and immutable evidence together, without a backup.

    Existing baseline/Worker guards are deliberately shared. No filesystem audit,
    full-DB scan or backup occurs after the commit, so a lost HTTP response cannot
    turn a successful reset into a failed audit or trigger an automatic reset retry.
    """
    if confirm != baseline.CONFIRMATION:
        raise baseline.BaselineRecoveryError("Explicit recovery confirmation is required")
    targets = baseline._validate_expected_mapping(device_ids, expected_trust_scores)
    if len(targets) != 1:
        raise baseline.BaselineRecoveryError("Ordinary recovery requires exactly one device")
    if not all(str(value).strip() for value in (operation_id, reason, requested_by, approved_by, requested_at)):
        raise baseline.BaselineRecoveryError("Recovery approval and reason are required")
    database = Path(db_path).expanduser().resolve()
    storage = audit_storage_check(database)
    if not storage["available"]:
        raise baseline.BaselineRecoveryHoldError(storage["failure_reason"])

    with ExitStack() as locks, closing(sqlite3.connect(
        database.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=5,
    )) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
            raise baseline.BaselineRecoveryHoldError("Live device recovery requires WAL journal mode")
        try:
            locks.enter_context(single_instance_lock(
                database.with_suffix(database.suffix + ".baseline-recovery.lock"),
            ))
        except RuntimeLockError as exc:
            raise baseline.BaselineRecoveryInProgressError(f"Recovery command lock busy: {exc}") from exc
        except OSError as exc:
            raise baseline.BaselineRecoveryHoldError(f"Recovery command lock unavailable: {exc}") from exc

        # Pin the initial identity before waiting, then release the read snapshot.
        connection.execute("BEGIN")
        try:
            initial = baseline._require_recovery_ready(connection, targets)
            initial_runtime = baseline._runtime_verification_devices(connection, initial)
            baseline._require_runtime_released(connection, initial)
        finally:
            connection.rollback()
        lock_settings = settings.model_copy(update={"database_url": f"sqlite:///{database}"})
        try:
            locks.enter_context(single_instance_lock(
                firewall_lock_path(lock_settings), wait_seconds=settings.firewall_lock_wait_seconds,
            ))
        except (RuntimeLockError, OSError) as exc:
            raise baseline.BaselineRecoveryHoldError(f"Runtime firewall lock unavailable: {exc}") from exc

        committing = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = baseline._require_recovery_ready(connection, targets)
            baseline._require_same_device_identity(initial, current)
            checked_devices = baseline._runtime_verification_devices(connection, current)
            if checked_devices != initial_runtime:
                raise baseline.BaselineRecoveryHoldError("Firewall activity changed during recovery")
            baseline._require_runtime_released(connection, current)
            device_id = device_ids[0]
            previous = current[device_id]
            changed = connection.execute(
                "UPDATE devices SET status = 'normal', trust_score = 100 "
                "WHERE device_id = ? AND status = 'isolated' AND trust_score = ?",
                (device_id, targets[device_id]),
            )
            if changed.rowcount != 1:
                raise baseline.BaselineRecoveryError("Recovery target state changed")
            after = baseline._fetch_target_devices(connection, device_ids)
            baseline._require_recovered_device_state(after, device_ids)
            baseline._require_same_device_identity(current, after)
            runtime = baseline._require_runtime_released(connection, current)
            payload = {
                "operation_id": operation_id, "result": "SUCCESS", "device_id": device_id,
                "reason": reason, "requested_by": requested_by, "approved_by": approved_by,
                "requested_at": requested_at,
                "before_status": previous["status"], "before_trust_score": int(previous["trust_score"]),
                "after_status": "normal", "after_trust_score": 100,
                "firewall_release_status": "VERIFIED_RELEASED",
                "backup_reference": None, "backup_sha256": None,
                "audit_reference": f"{AUDIT_TABLE}:{operation_id}",
                "log_reference": f"{AUDIT_TABLE}:{operation_id}",
                "failure_code": None, "failure_reason": None,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "before_device": dict(previous), "after_device": dict(after[device_id]),
                "runtime_firewall_check": runtime, "checked_devices": checked_devices,
                "preflight": dict(preflight),
            }
            insert_audit(connection, payload)
            # Audit serialization/INSERT can fail or take time. Recheck freshness
            # immediately before commit, while both write and firewall locks hold.
            baseline._require_runtime_released(connection, current)
            committing = True
            connection.commit()
        except Exception as exc:
            committed = committing and not connection.in_transaction
            if connection.in_transaction:
                connection.rollback()
            if committed:
                raise baseline.BaselineRecoveryCommittedError(
                    "Recovery commit response failed; inspect the stored operation before retrying"
                ) from exc
            if isinstance(exc, baseline.BaselineRecoveryError):
                raise
            raise baseline.BaselineRecoveryError(f"Device recovery transaction failed: {exc}") from exc
        return payload
