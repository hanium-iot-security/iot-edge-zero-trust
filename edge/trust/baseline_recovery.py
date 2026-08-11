"""Explicit, evidence-preserving Device baseline recovery primitives."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
from uuid import uuid4


CONFIRMATION = "RESET-TO-NORMAL-100"


class BaselineRecoveryError(RuntimeError):
    """Raised when a requested baseline reset violates a safety contract."""


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
            pending_events = _fetch_pending_trust_events(connection, device_ids)
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
    pending_event_check: dict[str, object] = {
        "passed": not pending_events,
        "count": len(pending_events),
        "event_ids": [int(event["id"]) for event in pending_events],
        "events": [_pending_event_report(event) for event in pending_events],
    }
    return {
        "mode": "dry-run",
        "database_path": str(database),
        "artifact_dir": str(artifacts),
        "database_changed": False,
        "can_execute": not preflight_errors,
        "preflight_errors": preflight_errors,
        "devices": device_report,
        "active_firewall_rule_check": firewall_check,
        "pending_trust_event_check": pending_event_check,
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
    """Reset only selected Device status/score after locked backup validation."""

    if confirm != CONFIRMATION:
        raise BaselineRecoveryError(
            f'--confirm에 정확히 "{CONFIRMATION}"을 입력해야 합니다'
        )
    targets = _validate_expected_mapping(device_ids, expected_trust_scores)
    database = Path(db_path).expanduser().resolve()
    artifacts = Path(artifact_dir).expanduser().resolve()
    if not database.is_file():
        raise BaselineRecoveryError(f"Database가 존재하지 않습니다: {database}")

    operation_id = operation_id or _new_operation_id()
    backup_path = artifacts / f"baseline-recovery-{operation_id}.db"
    log_path = artifacts / f"baseline-recovery-{operation_id}.json"
    backup_sha256: str | None = None
    previous_devices: dict[str, sqlite3.Row] | None = None
    connection = sqlite3.connect(database, isolation_level=None, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")

    try:
        connection.execute("BEGIN IMMEDIATE")
        previous_devices = _fetch_target_devices(connection, device_ids)
        _require_expected_device_state(previous_devices, targets)
        active_rules = _fetch_active_firewall_rules(
            connection,
            device_ids=device_ids,
            source_ips=[row["ip_address"] for row in previous_devices.values()],
        )
        if active_rules:
            rule_ids = [int(rule["id"]) for rule in active_rules]
            raise BaselineRecoveryError(
                "대상 Device 또는 IP에 활성 Firewall Rule이 있습니다: "
                f"rule_ids={rule_ids}"
            )
        pending_events = _fetch_pending_trust_events(connection, device_ids)
        if pending_events:
            event_ids = [int(event["id"]) for event in pending_events]
            raise BaselineRecoveryError(
                "대상 Device에 Trust Score v2 미처리 Detection Event가 있습니다: "
                f"event_ids={event_ids}"
            )

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
        integrity_check, foreign_key_violations = _verify_database_connection(
            connection
        )
        if integrity_check != "ok" or foreign_key_violations:
            raise BaselineRecoveryError(
                "실행 후 Database 검증 실패: "
                f"integrity_check={integrity_check}, "
                f"foreign_key_violations={foreign_key_violations}"
            )
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
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            requested_at=requested_at,
            firewall_release_status=firewall_release_status,
            preflight=preflight,
        )
        if isinstance(exc, BaselineRecoveryError):
            raise
        if isinstance(exc, sqlite3.DatabaseError):
            raise BaselineRecoveryError(f"Update 또는 Transaction 실패: {exc}") from exc
        raise BaselineRecoveryError(f"Baseline Recovery 실행 실패: {exc}") from exc
    finally:
        connection.close()

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
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            requested_at=requested_at,
            firewall_release_status=firewall_release_status,
            preflight=preflight,
        )
        if isinstance(exc, BaselineRecoveryError):
            raise
        raise BaselineRecoveryError(f"Commit 후 검증 실패: {exc}") from exc

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
        "integrity_check": post_integrity,
        "foreign_key_violations": [list(row) for row in post_foreign_keys],
        "devices": device_changes,
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
    except OSError as exc:
        raise BaselineRecoveryError(
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
    with sqlite3.connect(database) as source, sqlite3.connect(backup_path) as backup:
        source.backup(backup)


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
        connection.execute("PRAGMA foreign_keys = ON")
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
        "result": "FAILED",
        "operation_id": operation_id,
        "database_path": str(database),
        "backup_path": str(backup_path) if backup_path is not None else None,
        "backup_sha256": backup_sha256,
        "device_ids": list(device_ids),
        "error": error,
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
    except OSError:
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
