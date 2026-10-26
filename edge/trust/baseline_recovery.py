"""Explicit, evidence-preserving Device baseline recovery primitives."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import ExitStack, closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
import time
from uuid import uuid4

from backend.app.config import settings
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust.firewall_runtime_snapshot import verify_firewall_runtime_snapshot
from edge.trust.run_firewall_worker import firewall_lock_path


CONFIRMATION = "RESET-TO-NORMAL-100"


class BaselineRecoveryError(RuntimeError):
    """Raised when a requested baseline reset violates a safety contract."""


class BaselineRecoveryHoldError(BaselineRecoveryError):
    """Runtime evidence or exclusive access is unavailable; keep isolation."""


class BaselineRecoveryInProgressError(BaselineRecoveryHoldError):
    """Another baseline recovery command owns this database."""


class BaselineRecoveryCommittedError(BaselineRecoveryError):
    """The reset committed, but post-commit verification or audit failed."""


def parse_device_expectations(
    device_ids: Sequence[str],
    expectation_entries: Sequence[str],
) -> dict[str, int]:
    """Validate repeatable Device and expected Trust Score CLI values."""

    if not device_ids:
        raise BaselineRecoveryError("하나 이상의 --device가 필요합니다")
    if len(set(device_ids)) != len(device_ids):
        raise BaselineRecoveryError("--device 중복은 허용하지 않습니다")

    target_devices = set(device_ids)
    parsed: dict[str, int] = {}
    for entry in expectation_entries:
        device_id, separator, raw_score = entry.partition("=")
        if not separator or not device_id or not raw_score:
            raise BaselineRecoveryError(
                "--expected-trust-score는 DEVICE=SCORE 형식이어야 합니다"
            )
        if device_id not in target_devices:
            raise BaselineRecoveryError(
                f"--device 대상에 없는 예상값입니다: {device_id}"
            )
        if device_id in parsed:
            raise BaselineRecoveryError(
                f"같은 Device의 예상 Trust Score 중복: {device_id}"
            )
        try:
            score = int(raw_score)
        except ValueError as exc:
            raise BaselineRecoveryError(
                f"예상 Trust Score는 정수여야 합니다: {entry}"
            ) from exc
        if not 0 <= score <= 100:
            raise BaselineRecoveryError(
                f"예상 Trust Score는 0~100 범위여야 합니다: {entry}"
            )
        parsed[device_id] = score

    missing = [device_id for device_id in device_ids if device_id not in parsed]
    if missing or len(parsed) != len(device_ids):
        raise BaselineRecoveryError(
            "모든 --device에 정확히 하나의 --expected-trust-score가 필요합니다: "
            f"missing={missing}"
        )
    return {device_id: parsed[device_id] for device_id in device_ids}


def inspect_baseline_recovery(
    *,
    db_path: str | Path,
    device_ids: Sequence[str],
    expected_trust_scores: Mapping[str, int],
    artifact_dir: str | Path,
) -> dict[str, object]:
    """Read and validate a proposed reset without changing DB or artifacts."""

    targets = _validate_expected_mapping(device_ids, expected_trust_scores)
    database = Path(db_path).expanduser().resolve()
    artifacts = Path(artifact_dir).expanduser().resolve()
    if not database.is_file():
        raise BaselineRecoveryError(f"Database가 존재하지 않습니다: {database}")

    try:
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            devices = _fetch_target_devices(connection, device_ids)
            active_rules = _fetch_active_firewall_rules(
                connection,
                device_ids=device_ids,
                source_ips=[row["ip_address"] for row in devices.values()],
            )
            pending_release_requests = _fetch_pending_firewall_release_requests(
                connection,
                device_ids=device_ids,
                source_ips=[row["ip_address"] for row in devices.values()],
            )
            pending_events = _fetch_pending_trust_events(connection, device_ids)
            runtime_devices = _runtime_verification_devices(connection, devices)
    except sqlite3.DatabaseError as exc:
        raise BaselineRecoveryError(f"Database 사전 검증 실패: {exc}") from exc

    missing = [device_id for device_id in device_ids if device_id not in devices]
    if missing:
        raise BaselineRecoveryError(f"Device가 존재하지 않습니다: {missing}")
    preflight_errors = _device_state_errors(devices, targets)
    if active_rules:
        rule_ids = [int(rule["id"]) for rule in active_rules]
        preflight_errors.append(
            "대상 Device 또는 IP에 활성 Firewall Rule이 있습니다: "
            f"rule_ids={rule_ids}"
        )
    if pending_release_requests:
        request_ids = [int(request["id"]) for request in pending_release_requests]
        preflight_errors.append(
            "대상 Device 또는 IP에 처리 중인 Firewall Release Request가 있습니다: "
            f"request_ids={request_ids}"
        )
    if pending_events:
        event_ids = [int(event["id"]) for event in pending_events]
        preflight_errors.append(
            "대상 Device에 Trust Score v2 미처리 Detection Event가 있습니다: "
            f"event_ids={event_ids}"
        )

    device_report = [
        {
            "device_id": device_id,
            "ip_address": devices[device_id]["ip_address"],
            "last_firewall_activity_at": runtime_devices[device_id]["last_firewall_activity_at"],
            "current": {
                "status": devices[device_id]["status"],
                "trust_score": int(devices[device_id]["trust_score"]),
            },
            "expected": {
                "status": "isolated",
                "trust_score": targets[device_id],
            },
            "proposed": {"status": "normal", "trust_score": 100},
        }
        for device_id in device_ids
    ]
    firewall_check: dict[str, object] = {
        "passed": not active_rules,
        "count": len(active_rules),
        "statuses": ["PENDING", "APPLIED"],
    }
    if active_rules:
        firewall_check["rules"] = [
            {
                "id": int(rule["id"]),
                "device_id": rule["device_id"],
                "source_ip": str(rule["source_ip"]),
                "status": str(rule["status"]),
            }
            for rule in active_rules
        ]
    release_request_check: dict[str, object] = {
        "passed": not pending_release_requests,
        "count": len(pending_release_requests),
        "statuses": ["PENDING"],
        "request_ids": [int(request["id"]) for request in pending_release_requests],
        "requests": [
            {
                "id": int(request["id"]),
                "firewall_rule_id": int(request["firewall_rule_id"]),
                "status": str(request["status"]),
                "firewall_rule_status": str(request["firewall_rule_status"]),
                "requested_at": request["requested_at"],
            }
            for request in pending_release_requests
        ],
    }
    pending_event_check: dict[str, object] = {
        "passed": not pending_events,
        "count": len(pending_events),
        "event_ids": [int(event["id"]) for event in pending_events],
        "events": [_pending_event_report(event) for event in pending_events],
    }
    runtime_check = {
        device_id: _verify_runtime_firewall(device)
        for device_id, device in runtime_devices.items()
    }
    return {
        "mode": "dry-run",
        "database_path": str(database),
        "artifact_dir": str(artifacts),
        "database_changed": False,
        "can_execute": not preflight_errors and all(
            result.get("available") and result.get("passed") for result in runtime_check.values()
        ),
        "preflight_errors": preflight_errors,
        "devices": device_report,
        "active_firewall_rule_check": firewall_check,
        "pending_firewall_release_request_check": release_request_check,
        "pending_trust_event_check": pending_event_check,
        "runtime_firewall_check": runtime_check,
        "execute_command": _build_execute_command(
            database=database,
            artifacts=artifacts,
            device_ids=device_ids,
            expected_trust_scores=targets,
        ),
    }


def execute_baseline_recovery(
    *,
    db_path: str | Path,
    device_ids: Sequence[str],
    expected_trust_scores: Mapping[str, int],
    artifact_dir: str | Path,
    confirm: str,
    operation_id: str | None = None,
    reason: str | None = None,
    requested_by: str | None = None,
    approved_by: str | None = None,
    requested_at: str | None = None,
    firewall_release_status: str | None = None,
    preflight: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Validate an online backup before locked revalidation and Device reset."""

    if confirm != CONFIRMATION:
        raise BaselineRecoveryError(
            f'--confirm에 정확히 "{CONFIRMATION}"을 입력해야 합니다'
        )
    targets = _validate_expected_mapping(device_ids, expected_trust_scores)
    database = Path(db_path).expanduser().resolve()
    artifacts = Path(artifact_dir).expanduser().resolve()
    if not database.is_file():
        raise BaselineRecoveryError(f"Database가 존재하지 않습니다: {database}")

    # This command lock is distinct from the Worker/Observer lock and remains
    # held through post-commit verification and audit publication.
    with ExitStack() as command_locks:
        return _execute_baseline_recovery(
            database=database, artifacts=artifacts, device_ids=device_ids,
            targets=targets, command_locks=command_locks,
            operation_id=operation_id or _new_operation_id(), reason=reason,
            requested_by=requested_by, approved_by=approved_by,
            requested_at=requested_at, firewall_release_status=firewall_release_status,
            preflight=preflight,
        )


def _execute_baseline_recovery(
    *,
    database: Path,
    artifacts: Path,
    device_ids: Sequence[str],
    targets: Mapping[str, int],
    command_locks: ExitStack,
    operation_id: str,
    reason: str | None,
    requested_by: str | None,
    approved_by: str | None,
    requested_at: str | None,
    firewall_release_status: str | None,
    preflight: Mapping[str, object] | None,
) -> dict[str, object]:
    backup_path = artifacts / f"baseline-recovery-{operation_id}.db"
    log_path = artifacts / f"baseline-recovery-{operation_id}.json"
    backup_sha256: str | None = None
    previous_devices: dict[str, sqlite3.Row] | None = None
    connection = sqlite3.connect(database, isolation_level=None, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    locks = ExitStack()

    try:
        try:
            command_locks.enter_context(single_instance_lock(
                database.with_suffix(database.suffix + ".baseline-recovery.lock"),
            ))
        except RuntimeLockError as exc:
            raise BaselineRecoveryInProgressError(f"Baseline recovery command lock busy: {exc}") from exc
        except OSError as exc:
            raise BaselineRecoveryHoldError(f"Baseline recovery command lock unavailable: {exc}") from exc
        # A read snapshot rejects an ineligible request before any artifact is
        # created. Release it before online backup/validation: Capture must be
        # able to commit its segment and launch the next Window during that I/O.
        connection.execute("BEGIN")
        previous_devices = _require_recovery_ready(connection, targets)
        previous_runtime_devices = _runtime_verification_devices(connection, previous_devices)
        _require_runtime_released(connection, previous_devices)
        connection.rollback()

        artifacts.mkdir(parents=True, exist_ok=True)
        if backup_path.exists() or log_path.exists():
            raise BaselineRecoveryError(
                f"Baseline Recovery Artifact가 이미 존재합니다: {operation_id}"
            )
        try:
            _create_backup(database, backup_path)
        except Exception as exc:
            raise BaselineRecoveryError(f"Backup 생성 실패: {exc}") from exc
        backup_sha256 = _file_sha256(backup_path)
        backup_integrity, backup_foreign_keys = _verify_database_path(backup_path)
        if backup_integrity != "ok" or backup_foreign_keys:
            raise BaselineRecoveryError(
                "Backup 검증 실패: "
                f"integrity_check={backup_integrity}, "
                f"foreign_key_violations={backup_foreign_keys}"
            )

        # The online backup is a consistent pre-reset snapshot, not a promise
        # that unrelated MQTT/Capture rows will stop arriving. Prove that its
        # recovery targets still contain the approved identity/state as well.
        with sqlite3.connect(backup_path) as backup_connection:
            backup_connection.row_factory = sqlite3.Row
            backup_connection.execute("PRAGMA query_only = ON")
            backup_devices = _require_recovery_ready(backup_connection, targets)
            _require_same_device_identity(previous_devices, backup_devices)
            backup_runtime_devices = _runtime_verification_devices(backup_connection, backup_devices)
            if backup_runtime_devices != previous_runtime_devices:
                raise BaselineRecoveryHoldError("Runtime firewall activity changed during recovery backup")

        # Full health scans may take seconds on the live DB. Keep both the
        # SQLite writer slot and the Observer's firewall lock available here.
        # This is a pre-reset health check, not validation of the later write
        # transaction; the full post-commit check below remains necessary.
        integrity_check, foreign_key_violations = _verify_database_path(database)
        if integrity_check != "ok" or foreign_key_violations:
            raise BaselineRecoveryError(
                "실행 전 Database 검증 실패: "
                f"integrity_check={integrity_check}, "
                f"foreign_key_violations={foreign_key_violations}"
            )

        # Same order as Worker: firewall lock first, then SQLite write lock.
        # Only the observer invokes OS commands; Recovery reads a JSON file.
        lock_settings = settings.model_copy(update={"database_url": f"sqlite:///{database}"})
        try:
            locks.enter_context(single_instance_lock(
                firewall_lock_path(lock_settings), wait_seconds=settings.firewall_lock_wait_seconds,
            ))
        except (RuntimeLockError, OSError) as exc:
            raise BaselineRecoveryHoldError(f"Runtime firewall lock unavailable: {exc}") from exc
        connection.execute("BEGIN IMMEDIATE")
        current_devices = _require_recovery_ready(connection, targets)
        _require_same_device_identity(previous_devices, current_devices)
        if _runtime_verification_devices(connection, current_devices) != backup_runtime_devices:
            raise BaselineRecoveryHoldError("Runtime firewall activity changed after recovery backup")
        _require_runtime_released(connection, current_devices)

        for device_id in device_ids:
            result = connection.execute(
                """
                UPDATE devices
                SET status = 'normal', trust_score = 100
                WHERE device_id = ?
                  AND status = 'isolated'
                  AND trust_score = ?
                """,
                (device_id, targets[device_id]),
            )
            if result.rowcount != 1:
                raise BaselineRecoveryError(
                    "조건부 Update 대상이 예상 상태와 다릅니다: "
                    f"device_id={device_id}, rowcount={result.rowcount}"
                )

        recovered_devices = _fetch_target_devices(connection, device_ids)
        _require_recovered_device_state(recovered_devices, device_ids)
        _require_same_device_identity(current_devices, recovered_devices)
        # Only target checks belong in this short write transaction. A full
        # DB scan here would block Capture and prevent Observer TTL refresh.
        # Recheck immediately before commit; expired evidence still rolls back.
        runtime_check = _require_runtime_released(connection, current_devices)
        connection.commit()
    except Exception as exc:
        if connection.in_transaction:
            connection.rollback()
        _write_failure_log_if_possible(
            log_path=log_path,
            operation_id=operation_id,
            database=database,
            backup_path=backup_path if backup_path.exists() else None,
            backup_sha256=backup_sha256,
            device_ids=device_ids,
            error=str(exc),
            result="HOLD" if isinstance(exc, BaselineRecoveryHoldError) else "FAILED",
            failure_code="RECOVERY_IN_PROGRESS" if isinstance(exc, BaselineRecoveryInProgressError) else None,
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            requested_at=requested_at,
            firewall_release_status=("NOT_VERIFIED" if isinstance(exc, BaselineRecoveryHoldError)
                                     and not isinstance(exc, BaselineRecoveryInProgressError)
                                     else firewall_release_status),
            preflight=preflight,
        )
        if isinstance(exc, BaselineRecoveryError):
            raise
        if isinstance(exc, sqlite3.DatabaseError):
            raise BaselineRecoveryError(f"Update 또는 Transaction 실패: {exc}") from exc
        raise BaselineRecoveryError(f"Baseline Recovery 실행 실패: {exc}") from exc
    finally:
        connection.close()
        locks.close()

    try:
        post_integrity, post_foreign_keys = _verify_database_path(database)
        with sqlite3.connect(database) as verification_connection:
            verification_connection.row_factory = sqlite3.Row
            committed_devices = _fetch_target_devices(
                verification_connection,
                device_ids,
            )
            _require_recovered_device_state(committed_devices, device_ids)
        if post_integrity != "ok" or post_foreign_keys:
            raise BaselineRecoveryError(
                "Commit 후 Database 검증 실패: "
                f"integrity_check={post_integrity}, "
                f"foreign_key_violations={post_foreign_keys}"
            )
    except Exception as exc:
        _write_failure_log_if_possible(
            log_path=log_path,
            operation_id=operation_id,
            database=database,
            backup_path=backup_path,
            backup_sha256=backup_sha256,
            device_ids=device_ids,
            error=str(exc),
            database_committed=True,
            previous_devices=previous_devices,
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            requested_at=requested_at,
            firewall_release_status=firewall_release_status,
            preflight=preflight,
        )
        raise BaselineRecoveryCommittedError(f"Commit 후 검증 실패; DB 변경은 Commit되었습니다: {exc}") from exc

    assert previous_devices is not None
    device_changes = [
        {
            "device_id": device_id,
            "previous": {
                "status": str(previous_devices[device_id]["status"]),
                "trust_score": int(previous_devices[device_id]["trust_score"]),
            },
            "current": {"status": "normal", "trust_score": 100},
        }
        for device_id in device_ids
    ]
    report: dict[str, object] = {
        "mode": "execute",
        "result": "SUCCESS",
        "operation_id": operation_id,
        "database_path": str(database),
        "backup_path": str(backup_path),
        "backup_sha256": backup_sha256,
        "backup_integrity_check": backup_integrity,
        "backup_foreign_key_violations": [
            list(row) for row in backup_foreign_keys
        ],
        "pre_integrity_check": integrity_check,
        "pre_foreign_key_violations": [list(row) for row in foreign_key_violations],
        "integrity_check": post_integrity,
        "foreign_key_violations": [list(row) for row in post_foreign_keys],
        "devices": device_changes,
        "runtime_firewall_check": runtime_check,
        "log_path": str(log_path),
    }
    if any(
        value is not None
        for value in (
            reason,
            requested_by,
            approved_by,
            requested_at,
            firewall_release_status,
            preflight,
        )
    ):
        report["audit"] = _audit_metadata(
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            requested_at=requested_at,
            firewall_release_status=firewall_release_status,
            preflight=preflight,
        )
    try:
        _write_json_log(log_path, report)
    except Exception as exc:
        _write_failure_log_if_possible(
            log_path=log_path, operation_id=operation_id, database=database,
            backup_path=backup_path, backup_sha256=backup_sha256,
            device_ids=device_ids, error=str(exc), database_committed=True,
            previous_devices=previous_devices, reason=reason,
            requested_by=requested_by, approved_by=approved_by,
            requested_at=requested_at, firewall_release_status=firewall_release_status,
            preflight=preflight,
        )
        raise BaselineRecoveryCommittedError(
            "JSON Log 저장 실패; DB 변경은 Commit되었으므로 Backup을 보존하고 "
            f"Pilot을 중단해야 합니다: backup_path={backup_path}, error={exc}"
        ) from exc
    return report


def _validate_expected_mapping(
    device_ids: Sequence[str],
    expected_trust_scores: Mapping[str, int],
) -> dict[str, int]:
    entries = [
        f"{device_id}={score}" for device_id, score in expected_trust_scores.items()
    ]
    return parse_device_expectations(device_ids, entries)


def _new_operation_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{uuid4().hex[:12]}"


def _create_backup(database: Path, backup_path: Path) -> None:
    """Pace and periodically sync a fixed WAL snapshot."""
    deadline = time.monotonic() + 600
    synced_pages = 0

    def require_time_remaining() -> None:
        if time.monotonic() >= deadline:
            raise BaselineRecoveryError("Online backup timed out after 600 seconds")

    def paced_copy(status: int, pages_remaining: int, total_pages: int) -> None:
        nonlocal synced_pages
        require_time_remaining()
        if status in (sqlite3.SQLITE_OK, sqlite3.SQLITE_DONE):
            copied_pages = total_pages - pages_remaining
            unsynced_bytes = (copied_pages - synced_pages) * page_size
            # Count copied bytes, not callbacks: BUSY/LOCKED can repeat with
            # unchanged counters. This schedules flushes, not a kernel Dirty bound.
            if unsynced_bytes >= 2 * 1024 * 1024 or (pages_remaining == 0 and unsynced_bytes > 0):
                os.fsync(backup_fd)
                require_time_remaining()
                synced_pages = copied_pages
        if pages_remaining > 0:
            time.sleep(0.02)
            require_time_remaining()

    with closing(sqlite3.connect(
        database.as_uri() + "?mode=ro", uri=True, isolation_level=None, timeout=5,
    )) as source:
        source.execute("PRAGMA query_only = ON")
        if source.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
            raise BaselineRecoveryError("Live baseline recovery backup requires WAL journal mode")
        # A real read pins one snapshot; otherwise concurrent commits can
        # restart every paced backup step. Closing source releases retained WAL.
        source.execute("BEGIN")
        source.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()
        page_size = source.execute("PRAGMA page_size").fetchone()[0]
        require_time_remaining()
        # Closing any fd for this file can drop the process's POSIX SQLite locks.
        # Keep one sync-only fd open from before destination connect until close.
        backup_fd = os.open(backup_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with closing(sqlite3.connect(backup_path)) as backup:
                source.backup(backup, pages=16, progress=paced_copy, sleep=0.05)
                require_time_remaining()
        finally:
            os.close(backup_fd)
        require_time_remaining()
    require_time_remaining()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_database_connection(
    connection: sqlite3.Connection,
) -> tuple[str, list[tuple[object, ...]]]:
    integrity_row = connection.execute("PRAGMA integrity_check").fetchone()
    integrity = str(integrity_row[0]) if integrity_row is not None else "missing"
    foreign_keys = [
        tuple(row) for row in connection.execute("PRAGMA foreign_key_check").fetchall()
    ]
    return integrity, foreign_keys


def _verify_database_path(
    database: Path,
) -> tuple[str, list[tuple[object, ...]]]:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA query_only = ON")
        return _verify_database_connection(connection)


def _require_recovered_device_state(
    devices: Mapping[str, sqlite3.Row],
    device_ids: Sequence[str],
) -> None:
    missing = [device_id for device_id in device_ids if device_id not in devices]
    if missing:
        raise BaselineRecoveryError(f"실행 후 Device가 존재하지 않습니다: {missing}")
    invalid = [
        device_id
        for device_id in device_ids
        if devices[device_id]["status"] != "normal"
        or int(devices[device_id]["trust_score"]) != 100
    ]
    if invalid:
        raise BaselineRecoveryError(
            f"실행 후 Device Baseline 검증 실패: device_ids={invalid}"
        )


def _write_failure_log_if_possible(
    *,
    log_path: Path,
    operation_id: str,
    database: Path,
    backup_path: Path | None,
    backup_sha256: str | None,
    device_ids: Sequence[str],
    error: str,
    result: str = "FAILED",
    failure_code: str | None = None,
    database_committed: bool = False,
    previous_devices: Mapping[str, sqlite3.Row] | None = None,
    reason: str | None = None,
    requested_by: str | None = None,
    approved_by: str | None = None,
    requested_at: str | None = None,
    firewall_release_status: str | None = None,
    preflight: Mapping[str, object] | None = None,
) -> None:
    if not log_path.parent.is_dir():
        return
    failure_report = {
        "mode": "execute",
        "result": result,
        "operation_id": operation_id,
        "database_path": str(database),
        "backup_path": str(backup_path) if backup_path is not None else None,
        "backup_sha256": backup_sha256,
        "device_ids": list(device_ids),
        "error": error,
        "log_path": str(log_path),
    }
    if failure_code is not None:
        failure_report["failure_code"] = failure_code
    if database_committed:
        failure_report["database_committed"] = True
        failure_report["failure_code"] = "BASELINE_RECOVERY_COMMITTED_UNVERIFIED"
        try:
            with sqlite3.connect(database) as observed_connection:
                observed_connection.row_factory = sqlite3.Row
                observed_connection.execute("PRAGMA query_only = ON")
                observed_devices = _fetch_target_devices(observed_connection, device_ids)
            failure_report["devices"] = [
                {
                    "device_id": device_id,
                    "previous": {
                        "status": previous_devices[device_id]["status"],
                        "trust_score": int(previous_devices[device_id]["trust_score"]),
                    } if previous_devices and device_id in previous_devices else {},
                    "current": {
                        "status": observed_devices[device_id]["status"],
                        "trust_score": int(observed_devices[device_id]["trust_score"]),
                    } if device_id in observed_devices else {},
                }
                for device_id in device_ids
            ]
        except sqlite3.DatabaseError as exc:
            failure_report["device_state_read_error"] = str(exc)
    if any(
        value is not None
        for value in (
            reason,
            requested_by,
            approved_by,
            requested_at,
            firewall_release_status,
            preflight,
        )
    ):
        failure_report["audit"] = _audit_metadata(
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            requested_at=requested_at,
            firewall_release_status=firewall_release_status,
            preflight=preflight,
        )
    try:
        _write_json_log(log_path, failure_report)
    except Exception:
        return


def _audit_metadata(
    *,
    reason: str | None,
    requested_by: str | None,
    approved_by: str | None,
    requested_at: str | None,
    firewall_release_status: str | None,
    preflight: Mapping[str, object] | None,
) -> dict[str, object]:
    return {
        "reason": reason,
        "requested_by": requested_by,
        "approved_by": approved_by,
        "requested_at": requested_at,
        "firewall_release_status": firewall_release_status,
        "preflight": dict(preflight) if preflight is not None else None,
    }


def _write_json_log(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _fetch_target_devices(
    connection: sqlite3.Connection,
    device_ids: Sequence[str],
) -> dict[str, sqlite3.Row]:
    placeholders = ", ".join("?" for _ in device_ids)
    rows = connection.execute(
        f"""
        SELECT device_id, ip_address, status, trust_score
        FROM devices
        WHERE device_id IN ({placeholders})
        """,
        tuple(device_ids),
    ).fetchall()
    return {str(row["device_id"]): row for row in rows}


def _runtime_verification_devices(
    connection: sqlite3.Connection, devices: Mapping[str, sqlite3.Row],
) -> dict[str, dict[str, object]]:
    """Bind runtime proof and freshness to every current/unresolved source IP."""
    result = {}
    for device_id, device in devices.items():
        # FAILED can mean the OS inserted a rule before its response was lost.
        # Include other devices' activity at these addresses until exact release
        # transitions our FAILED rules to REMOVED and allows independent reuse.
        failed_source_ips = sorted({
            str(row["source_ip"]) for row in connection.execute(
                "SELECT DISTINCT source_ip FROM firewall_rules "
                "WHERE device_id = ? AND status = 'FAILED'", (device_id,),
            ).fetchall()
            if row["source_ip"] != device["ip_address"]
        })
        checked_ips = [device["ip_address"], *failed_source_ips]
        ip_placeholders = ", ".join("?" for _ in checked_ips)
        parameters = (device_id, *checked_ips)
        values = []
        rules = connection.execute(
            "SELECT last_attempted_at, applied_at, released_at, updated_at "
            f"FROM firewall_rules WHERE device_id = ? OR source_ip IN ({ip_placeholders})",
            parameters,
        ).fetchall()
        for rule in rules:
            attempts = [rule[key] for key in ("last_attempted_at", "applied_at", "released_at") if rule[key]]
            values.extend(attempts or [rule["updated_at"]])
        requests = connection.execute(
            "SELECT request.processed_at FROM firewall_release_requests AS request "
            "JOIN firewall_rules AS rule ON rule.id = request.firewall_rule_id "
            f"WHERE (rule.device_id = ? OR rule.source_ip IN ({ip_placeholders})) "
            "AND request.processed_at IS NOT NULL",
            parameters,
        ).fetchall()
        values.extend(row[0] for row in requests)
        try:
            # SQLite defaults use UTC without a suffix; explicit Worker values
            # use ISO UTC. Compare instants, not lexicographic text ordering.
            instants = [datetime.fromisoformat(str(value).replace("Z", "+00:00")) for value in values]
            latest = max((value.replace(tzinfo=timezone.utc) if value.tzinfo is None
                          else value.astimezone(timezone.utc) for value in instants), default=None)
        except (ValueError, TypeError) as exc:
            raise BaselineRecoveryError("Runtime firewall attempt timestamp is invalid") from exc
        result[device_id] = {
            "device_id": device_id, "ip_address": device["ip_address"],
            "failed_rule_source_ips": failed_source_ips,
            "last_firewall_activity_at": latest.isoformat() if latest else None,
        }
    return result


def _verify_runtime_firewall(device: Mapping[str, object]) -> dict[str, object]:
    verification = verify_firewall_runtime_snapshot(
        device, snapshot_path=settings.firewall_runtime_snapshot_path,
        max_age_seconds=settings.firewall_runtime_snapshot_max_age_seconds,
    )
    if not verification.get("available") or not verification.get("passed"):
        return verification
    for source_ip in device.get("failed_rule_source_ips", []):
        historical = verify_firewall_runtime_snapshot(
            {**device, "ip_address": source_ip},
            snapshot_path=settings.firewall_runtime_snapshot_path,
            max_age_seconds=settings.firewall_runtime_snapshot_max_age_seconds,
        )
        if not historical.get("available") or not historical.get("passed"):
            return historical
        verification["details"] += " " + historical["details"]
    return verification


def _require_runtime_released(
    connection: sqlite3.Connection, devices: Mapping[str, sqlite3.Row],
) -> dict[str, object]:
    checks = {}
    for device in _runtime_verification_devices(connection, devices).values():
        verification = _verify_runtime_firewall(device)
        if not verification.get("available") or not verification.get("passed"):
            raise BaselineRecoveryHoldError(
                f"Runtime firewall release is not verified for {device['device_id']}: "
                f"{verification.get('details', 'unavailable')}"
            )
        checks[str(device["device_id"])] = {**verification, "last_firewall_activity_at": device["last_firewall_activity_at"]}
    return checks


def _fetch_active_firewall_rules(
    connection: sqlite3.Connection,
    *,
    device_ids: Sequence[str],
    source_ips: Sequence[str | None],
) -> list[sqlite3.Row]:
    non_null_ips = sorted({ip_address for ip_address in source_ips if ip_address})
    device_placeholders = ", ".join("?" for _ in device_ids)
    parameters: list[object] = [*device_ids]
    match_clauses = [f"device_id IN ({device_placeholders})"]
    if non_null_ips:
        ip_placeholders = ", ".join("?" for _ in non_null_ips)
        match_clauses.append(f"source_ip IN ({ip_placeholders})")
        parameters.extend(non_null_ips)
    return connection.execute(
        f"""
        SELECT id, device_id, source_ip, status
        FROM firewall_rules
        WHERE status IN ('PENDING', 'APPLIED')
          AND ({' OR '.join(match_clauses)})
        ORDER BY id
        """,
        tuple(parameters),
    ).fetchall()


def _fetch_pending_firewall_release_requests(
    connection: sqlite3.Connection,
    *,
    device_ids: Sequence[str],
    source_ips: Sequence[str | None],
) -> list[sqlite3.Row]:
    non_null_ips = sorted({ip_address for ip_address in source_ips if ip_address})
    device_placeholders = ", ".join("?" for _ in device_ids)
    parameters: list[object] = [*device_ids]
    match_clauses = [f"rule.device_id IN ({device_placeholders})"]
    if non_null_ips:
        ip_placeholders = ", ".join("?" for _ in non_null_ips)
        match_clauses.append(f"rule.source_ip IN ({ip_placeholders})")
        parameters.extend(non_null_ips)
    return connection.execute(
        f"""
        SELECT
            request.id,
            request.firewall_rule_id,
            request.status,
            request.requested_at,
            rule.status AS firewall_rule_status
        FROM firewall_release_requests AS request
        JOIN firewall_rules AS rule
          ON rule.id = request.firewall_rule_id
        WHERE request.status = 'PENDING'
          AND ({' OR '.join(match_clauses)})
        ORDER BY request.id
        """,
        tuple(parameters),
    ).fetchall()


def _fetch_pending_trust_events(
    connection: sqlite3.Connection,
    device_ids: Sequence[str],
) -> list[sqlite3.Row]:
    placeholders = ", ".join("?" for _ in device_ids)
    return connection.execute(
        f"""
        SELECT id, device_id, detector_type, event_type,
               analysis_window_start, analysis_window_end, detected_at,
               processing_reason
        FROM detection_events
        WHERE device_id IN ({placeholders})
          AND processed_at IS NULL
        ORDER BY id ASC
        """,
        tuple(device_ids),
    ).fetchall()


def _pending_event_report(event: sqlite3.Row) -> dict[str, object]:
    return {
        "id": int(event["id"]),
        "device_id": str(event["device_id"]),
        "detector_type": str(event["detector_type"]),
        "event_type": str(event["event_type"]),
        "analysis_window_start": event["analysis_window_start"],
        "analysis_window_end": event["analysis_window_end"],
        "detected_at": event["detected_at"],
        "processing_reason": event["processing_reason"],
    }


def _require_expected_device_state(
    devices: Mapping[str, sqlite3.Row],
    expected_trust_scores: Mapping[str, int],
) -> None:
    missing = [device_id for device_id in expected_trust_scores if device_id not in devices]
    if missing:
        raise BaselineRecoveryError(f"Device가 존재하지 않습니다: {missing}")
    errors = _device_state_errors(devices, expected_trust_scores)
    if errors:
        raise BaselineRecoveryError(errors[0])


def _require_recovery_ready(
    connection: sqlite3.Connection,
    expected_trust_scores: Mapping[str, int],
) -> dict[str, sqlite3.Row]:
    """Check the same safety predicates in preflight, backup and final lock."""
    device_ids = list(expected_trust_scores)
    devices = _fetch_target_devices(connection, device_ids)
    _require_expected_device_state(devices, expected_trust_scores)
    source_ips = [row["ip_address"] for row in devices.values()]
    active_rules = _fetch_active_firewall_rules(
        connection, device_ids=device_ids, source_ips=source_ips,
    )
    if active_rules:
        raise BaselineRecoveryError(
            "대상 Device 또는 IP에 활성 Firewall Rule이 있습니다: "
            f"rule_ids={[int(rule['id']) for rule in active_rules]}"
        )
    requests = _fetch_pending_firewall_release_requests(
        connection, device_ids=device_ids, source_ips=source_ips,
    )
    if requests:
        raise BaselineRecoveryError(
            "대상 Device 또는 IP에 처리 중인 Firewall Release Request가 있습니다: "
            f"request_ids={[int(request['id']) for request in requests]}"
        )
    events = _fetch_pending_trust_events(connection, device_ids)
    if events:
        raise BaselineRecoveryError(
            "대상 Device에 Trust Score v2 미처리 Detection Event가 있습니다: "
            f"event_ids={[int(event['id']) for event in events]}"
        )
    return devices


def _require_same_device_identity(
    expected: Mapping[str, sqlite3.Row],
    actual: Mapping[str, sqlite3.Row],
) -> None:
    changed = [
        device_id for device_id, device in expected.items()
        if actual[device_id]["ip_address"] != device["ip_address"]
    ]
    if changed:
        raise BaselineRecoveryError(
            f"Backup 또는 최종 검증 중 Device IP가 변경됐습니다: device_ids={changed}"
        )


def _device_state_errors(
    devices: Mapping[str, sqlite3.Row],
    expected_trust_scores: Mapping[str, int],
) -> list[str]:
    errors: list[str] = []
    for device_id, expected_score in expected_trust_scores.items():
        device = devices[device_id]
        if device["status"] != "isolated":
            errors.append(
                "Device status가 isolated가 아닙니다: "
                f"device_id={device_id}, actual={device['status']}"
            )
        actual_score = int(device["trust_score"])
        if actual_score != expected_score:
            errors.append(
                "예상 Trust Score와 실제 값이 다릅니다: "
                f"device_id={device_id}, expected={expected_score}, actual={actual_score}"
            )
    return errors


def _build_execute_command(
    *,
    database: Path,
    artifacts: Path,
    device_ids: Sequence[str],
    expected_trust_scores: Mapping[str, int],
) -> str:
    arguments = [
        "python",
        "-m",
        "edge.trust.run_baseline_recovery",
        "execute",
        "--db-path",
        str(database),
    ]
    for device_id in device_ids:
        arguments.extend(("--device", device_id))
    for device_id in device_ids:
        arguments.extend(
            ("--expected-trust-score", f"{device_id}={expected_trust_scores[device_id]}")
        )
    arguments.extend(
        (
            "--artifact-dir",
            str(artifacts),
            "--confirm",
            "RESET-TO-NORMAL-100",
        )
    )
    return shlex.join(arguments)
