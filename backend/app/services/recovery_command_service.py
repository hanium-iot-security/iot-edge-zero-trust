"""Recovery command adapter for the FastAPI backend.

The actual baseline reset remains in ``edge.trust.baseline_recovery``. This
module validates the management command boundary, normalizes preflight output,
and reads/writes JSON audit artifacts for the dashboard contract.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.security import RecoveryAdminContext
from edge.packet.pcap_naming import format_utc_iso
from edge.trust.baseline_recovery import (
    CONFIRMATION,
    BaselineRecoveryCommittedError,
    BaselineRecoveryError,
    BaselineRecoveryHoldError,
    BaselineRecoveryInProgressError,
    execute_baseline_recovery,
    inspect_baseline_recovery,
)


class RecoveryCommandError(RuntimeError):
    """Base class for Recovery Command API failures."""


class RecoveryNotExecutableError(RecoveryCommandError):
    """Raised when an approved execute request fails preflight."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.payload = dict(payload)
        super().__init__(str(self.payload.get("failure_reason") or "not executable"))


class RecoveryCoreFailedError(RecoveryCommandError):
    """Raised when the baseline recovery core fails after command admission."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.payload = dict(payload)
        super().__init__(str(self.payload.get("failure_reason") or "core failed"))


RuntimeFirewallVerifier = Callable[[Mapping[str, Any]], dict[str, Any]]

_DEVICE_LOCK_GUARD = threading.Lock()
_IN_FLIGHT_DEVICES: set[str] = set()

_BASELINE_LOG_PATTERN = re.compile(r"^baseline-recovery-(?P<operation_id>.+)\.json$")
_COMMAND_LOG_PATTERN = re.compile(r"^recovery-command-(?P<operation_id>.+)\.json$")


def _runtime_verification_unavailable(_device: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "available": False,
        "passed": False,
        "status": "UNAVAILABLE",
        "rule_count": None,
        "details": "No backend-owned read-only runtime firewall verifier is configured.",
    }


firewall_runtime_verifier: RuntimeFirewallVerifier = _runtime_verification_unavailable


def build_recovery_preflight(
    db: Session,
    *,
    device_id: str,
    expected_trust_score: int,
    artifact_dir: str | Path | None = None,
) -> dict[str, Any]:
    database = _sqlite_database_path(db)
    artifacts = _artifact_dir(artifact_dir)
    device_id = _require_non_empty(device_id, "device_id")
    _require_score(expected_trust_score)

    try:
        core = inspect_baseline_recovery(
            db_path=database,
            device_ids=[device_id],
            expected_trust_scores={device_id: expected_trust_score},
            artifact_dir=artifacts,
        )
    except BaselineRecoveryError as exc:
        return _missing_or_core_error_preflight(
            db,
            device_id=device_id,
            expected_trust_score=expected_trust_score,
            artifacts=artifacts,
            error=str(exc),
        )

    device_report = dict(core["devices"][0])
    current = dict(device_report["current"])
    firewall_db_state = _firewall_db_state(core)
    firewall_release_request_state = _firewall_release_request_state(core)
    pending_event_check = dict(core["pending_trust_event_check"])
    runtime = _normalize_runtime_verification(
        firewall_runtime_verifier(
            {
                "device_id": device_id,
                "ip_address": device_report.get("ip_address"),
                "current_status": current.get("status"),
                "current_trust_score": current.get("trust_score"),
                "last_firewall_activity_at": device_report.get("last_firewall_activity_at"),
            }
        )
    )
    core_runtime = core["runtime_firewall_check"][device_id]
    if not core_runtime.get("available") or not core_runtime.get("passed"):
        runtime = _normalize_runtime_verification(core_runtime)
    backup_check = _backup_check(artifacts)
    preflight_errors = list(core["preflight_errors"])

    failure_code, failure_reason, result = _select_failure(
        preflight_errors=preflight_errors,
        release_request_state=firewall_release_request_state,
        runtime=runtime,
        backup_check=backup_check,
    )
    can_execute = (
        bool(core["can_execute"])
        and bool(firewall_release_request_state["passed"])
        and bool(runtime["passed"])
        and bool(backup_check["available"])
    )
    return {
        "device_id": device_id,
        "current_status": current["status"],
        "current_trust_score": int(current["trust_score"]),
        "can_execute": can_execute,
        "result": "SUCCESS" if can_execute else result,
        "firewall_db_state": firewall_db_state,
        "firewall_release_request_state": firewall_release_request_state,
        "firewall_runtime_verification": runtime,
        "unprocessed_detection_count": int(pending_event_check["count"]),
        "backup_check": backup_check,
        "failure_code": None if can_execute else failure_code,
        "failure_reason": None if can_execute else failure_reason,
        "preflight_errors": preflight_errors,
    }


def execute_recovery_command(
    db: Session,
    *,
    device_id: str,
    expected_trust_score: int,
    reason: str,
    confirm: str,
    admin: RecoveryAdminContext,
    artifact_dir: str | Path | None = None,
) -> dict[str, Any]:
    device_id = _require_non_empty(device_id, "device_id")
    reason = _require_non_empty(reason, "reason")
    _require_score(expected_trust_score)
    requested_at = _now_utc()
    artifacts = _artifact_dir(artifact_dir)
    operation_id = _new_operation_id()

    if confirm != CONFIRMATION:
        payload = _write_command_audit(
            artifacts,
            operation_id=operation_id,
            device_id=device_id,
            reason=reason,
            requested_by=admin.principal,
            approved_by=admin.principal,
            requested_at=requested_at,
            result="DENIED",
            failure_code="APPROVAL_CONFIRMATION_MISSING",
            failure_reason=f'confirm must be "{CONFIRMATION}"',
            preflight=None,
        )
        raise RecoveryNotExecutableError(payload)

    if not _try_acquire_device_lock(device_id):
        payload = _write_command_audit(
            artifacts,
            operation_id=operation_id,
            device_id=device_id,
            reason=reason,
            requested_by=admin.principal,
            approved_by=admin.principal,
            requested_at=requested_at,
            result="DENIED",
            failure_code="RECOVERY_IN_PROGRESS",
            failure_reason="Recovery is already in progress for this device.",
            preflight=None,
        )
        raise RecoveryNotExecutableError(payload)

    try:
        preflight = build_recovery_preflight(
            db,
            device_id=device_id,
            expected_trust_score=expected_trust_score,
            artifact_dir=artifacts,
        )
        if not preflight["can_execute"]:
            payload = _write_command_audit(
                artifacts,
                operation_id=operation_id,
                device_id=device_id,
                reason=reason,
                requested_by=admin.principal,
                approved_by=admin.principal,
                requested_at=requested_at,
                result=preflight["result"],
                failure_code=preflight["failure_code"],
                failure_reason=preflight["failure_reason"],
                preflight=preflight,
            )
            raise RecoveryNotExecutableError(payload)

        database = _sqlite_database_path(db)
        db.rollback()
        try:
            core_result = execute_baseline_recovery(
                db_path=database,
                device_ids=[device_id],
                expected_trust_scores={device_id: expected_trust_score},
                artifact_dir=artifacts,
                confirm=confirm,
                operation_id=operation_id,
                reason=reason,
                requested_by=admin.principal,
                approved_by=admin.principal,
                requested_at=requested_at,
                firewall_release_status="VERIFIED_RELEASED",
                preflight=preflight,
            )
        except BaselineRecoveryError as exc:
            db.rollback()
            after = _device_snapshot(db, device_id)
            backup = _backup_artifact_metadata(artifacts, operation_id)
            if isinstance(exc, BaselineRecoveryInProgressError):
                failure_code = "RECOVERY_IN_PROGRESS"
                firewall_release_status = _firewall_release_status(preflight)
            elif isinstance(exc, BaselineRecoveryHoldError):
                failure_code = "FIREWALL_RUNTIME_UNVERIFIED"
                firewall_release_status = "NOT_VERIFIED"
            else:
                failure_code = (
                    "BASELINE_RECOVERY_COMMITTED_UNVERIFIED"
                    if isinstance(exc, BaselineRecoveryCommittedError)
                    else "BASELINE_RECOVERY_CORE_FAILED"
                )
                firewall_release_status = _firewall_release_status(preflight)
            payload = _write_command_audit(
                artifacts,
                operation_id=operation_id,
                device_id=device_id,
                reason=reason,
                requested_by=admin.principal,
                approved_by=admin.principal,
                requested_at=requested_at,
                result="HOLD" if isinstance(exc, BaselineRecoveryHoldError) else "FAILED",
                failure_code=failure_code,
                failure_reason=str(exc),
                preflight=preflight,
                firewall_release_status=firewall_release_status,
                after_status=after.get("status"),
                after_trust_score=after.get("trust_score"),
                backup_reference=backup["backup_reference"],
                backup_sha256=backup["backup_sha256"],
            )
            if isinstance(exc, BaselineRecoveryHoldError):
                raise RecoveryNotExecutableError(payload) from exc
            raise RecoveryCoreFailedError(payload) from exc

        return _normalize_baseline_audit(
            dict(core_result),
            log_reference=Path(str(core_result["log_path"])).name,
        )
    finally:
        _release_device_lock(device_id)


def list_recovery_audits(
    *,
    artifact_dir: str | Path | None = None,
    device_id: str | None = None,
    result: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    artifacts = _artifact_dir(artifact_dir)
    items = _load_recovery_audits(artifacts)
    if device_id is not None:
        items = [item for item in items if item["device_id"] == device_id]
    if result is not None:
        items = [item for item in items if item["result"] == result]
    return {"items": items[offset : offset + limit], "total": len(items)}


def get_recovery_audit(
    operation_id: str,
    *,
    artifact_dir: str | Path | None = None,
) -> dict[str, Any] | None:
    operation_id = _require_non_empty(operation_id, "operation_id")
    for item in _load_recovery_audits(_artifact_dir(artifact_dir)):
        if item["operation_id"] == operation_id:
            return item
    return None


def _missing_or_core_error_preflight(
    db: Session,
    *,
    device_id: str,
    expected_trust_score: int,
    artifacts: Path,
    error: str,
) -> dict[str, Any]:
    device = db.execute(
        text(
            """
            SELECT device_id, status, trust_score
            FROM devices
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).mappings().one_or_none()
    if device is None:
        return {
            "device_id": device_id,
            "current_status": None,
            "current_trust_score": None,
            "can_execute": False,
            "result": "DENIED",
            "firewall_db_state": {"passed": False, "count": None, "rules": []},
            "firewall_release_request_state": {
                "passed": False,
                "count": None,
                "statuses": [],
                "request_ids": [],
                "requests": [],
            },
            "firewall_runtime_verification": _runtime_verification_unavailable({}),
            "unprocessed_detection_count": None,
            "backup_check": _backup_check(artifacts),
            "failure_code": "DEVICE_NOT_FOUND",
            "failure_reason": f"Device not found: {device_id}",
            "preflight_errors": [error],
        }
    return {
        "device_id": device_id,
        "current_status": device["status"],
        "current_trust_score": int(device["trust_score"]),
        "can_execute": False,
        "result": "DENIED",
        "firewall_db_state": {"passed": False, "count": None, "rules": []},
        "firewall_release_request_state": {
            "passed": False,
            "count": None,
            "statuses": [],
            "request_ids": [],
            "requests": [],
        },
        "firewall_runtime_verification": _runtime_verification_unavailable({}),
        "unprocessed_detection_count": None,
        "backup_check": _backup_check(artifacts),
        "failure_code": "CORE_PREFLIGHT_ERROR",
        "failure_reason": error,
        "preflight_errors": [error],
    }


def _firewall_db_state(core: Mapping[str, Any]) -> dict[str, Any]:
    check = dict(core["active_firewall_rule_check"])
    return {
        "passed": bool(check["passed"]),
        "count": int(check["count"]),
        "active_statuses": list(check["statuses"]),
        "rules": list(check.get("rules", [])),
    }


def _firewall_release_request_state(core: Mapping[str, Any]) -> dict[str, Any]:
    check = dict(core["pending_firewall_release_request_check"])
    requests = list(check.get("requests", []))
    return {
        "passed": bool(check["passed"]),
        "count": int(check["count"]),
        "statuses": list(check.get("statuses", [])),
        "request_ids": list(check.get("request_ids", [])),
        "requests": requests,
    }


def _normalize_runtime_verification(value: Mapping[str, Any]) -> dict[str, Any]:
    status = str(value.get("status") or "UNAVAILABLE")
    passed = bool(value.get("passed"))
    available = bool(value.get("available", passed))
    return {
        "available": available,
        "passed": passed,
        "status": status,
        "rule_count": value.get("rule_count"),
        "details": value.get("details"),
    }


def _backup_check(artifacts: Path) -> dict[str, Any]:
    if artifacts.exists() and not artifacts.is_dir():
        return {
            "artifact_dir": str(artifacts),
            "available": False,
            "failure_reason": "artifact path exists but is not a directory",
        }

    parent = artifacts if artifacts.exists() else _nearest_existing_parent(artifacts)
    available = parent.is_dir() and os.access(parent, os.W_OK)
    return {
        "artifact_dir": str(artifacts),
        "available": bool(available),
        "failure_reason": None if available else "artifact directory parent is not writable",
    }


def _nearest_existing_parent(path: Path) -> Path:
    current = path
    while not current.exists() and current.parent != current:
        current = current.parent
    return current


def _select_failure(
    *,
    preflight_errors: list[str],
    release_request_state: Mapping[str, Any],
    runtime: Mapping[str, Any],
    backup_check: Mapping[str, Any],
) -> tuple[str | None, str | None, str]:
    if preflight_errors:
        reason = preflight_errors[0]
        if "Detection Event" in reason:
            return "UNPROCESSED_DETECTION_EVENTS", reason, "DENIED"
        if "isolated" in reason:
            return "INVALID_DEVICE_STATUS", reason, "DENIED"
        if "Trust Score" in reason:
            return "TRUST_SCORE_MISMATCH", reason, "DENIED"
        if "Firewall Release Request" in reason:
            return "ACTIVE_FIREWALL_RELEASE_REQUEST", reason, "DENIED"
        if "Firewall" in reason:
            return "ACTIVE_FIREWALL_RULE", reason, "DENIED"
        return "PREFLIGHT_DENIED", reason, "DENIED"
    if not release_request_state["passed"]:
        return (
            "ACTIVE_FIREWALL_RELEASE_REQUEST",
            "Firewall release request is still PENDING",
            "DENIED",
        )
    if not runtime["passed"]:
        status = str(runtime["status"])
        code = (
            "FIREWALL_RUNTIME_UNAVAILABLE"
            if status == "UNAVAILABLE"
            else "FIREWALL_RUNTIME_ACTIVE"
        )
        return code, str(runtime.get("details") or status), "HOLD"
    if not backup_check["available"]:
        return "BACKUP_UNAVAILABLE", str(backup_check["failure_reason"]), "HOLD"
    return None, None, "SUCCESS"


def _write_command_audit(
    artifacts: Path,
    *,
    operation_id: str,
    device_id: str,
    reason: str,
    requested_by: str,
    approved_by: str,
    requested_at: str,
    result: str,
    failure_code: str | None,
    failure_reason: str | None,
    preflight: Mapping[str, Any] | None,
    firewall_release_status: str | None = None,
    after_status: str | None = None,
    after_trust_score: int | None = None,
    backup_reference: str | None = None,
    backup_sha256: str | None = None,
) -> dict[str, Any]:
    before_status = None if preflight is None else preflight["current_status"]
    before_score = None if preflight is None else preflight["current_trust_score"]
    payload = {
        "operation_id": operation_id,
        "result": result,
        "device_id": device_id,
        "reason": reason,
        "requested_by": requested_by,
        "approved_by": approved_by,
        "requested_at": requested_at,
        "before_status": before_status,
        "before_trust_score": before_score,
        "after_status": after_status if after_status is not None else before_status,
        "after_trust_score": (
            after_trust_score if after_trust_score is not None else before_score
        ),
        "firewall_release_status": (
            firewall_release_status or (
                "NOT_VERIFIED" if preflight is None else _firewall_release_status(preflight)
            )
        ),
        "backup_reference": backup_reference,
        "backup_sha256": backup_sha256,
        "failure_code": failure_code,
        "failure_reason": failure_reason,
    }
    if artifacts.exists() and not artifacts.is_dir():
        payload["log_reference"] = None
        return payload
    artifacts.mkdir(parents=True, exist_ok=True)
    log_path = artifacts / f"recovery-command-{operation_id}.json"
    payload["log_reference"] = log_path.name
    _write_json_atomically(log_path, payload | {"preflight": preflight})
    return payload


def _load_recovery_audits(artifacts: Path) -> list[dict[str, Any]]:
    if not artifacts.is_dir():
        return []

    items_by_operation: dict[str, dict[str, Any]] = {}
    for path in sorted(artifacts.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        item = _normalize_audit_payload(payload, log_reference=path.name)
        if item is not None:
            operation_id = item["operation_id"]
            existing = items_by_operation.get(operation_id)
            items_by_operation[operation_id] = (
                item if existing is None else _merge_audit_items(existing, item)
            )
    items = list(items_by_operation.values())
    return sorted(
        items,
        key=lambda item: (str(item.get("requested_at") or ""), str(item["operation_id"])),
        reverse=True,
    )


def _merge_audit_items(
    existing: Mapping[str, Any],
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    primary, secondary = (
        (incoming, existing)
        if _audit_source_rank(incoming) >= _audit_source_rank(existing)
        else (existing, incoming)
    )
    merged = dict(primary)
    for key, value in secondary.items():
        if _is_missing(merged.get(key)) and not _is_missing(value):
            merged[key] = value
    if _is_missing(merged.get("backup_reference")):
        merged["backup_reference"] = secondary.get("backup_reference")
    if _is_missing(merged.get("backup_sha256")):
        merged["backup_sha256"] = secondary.get("backup_sha256")
    return merged


def _audit_source_rank(item: Mapping[str, Any]) -> int:
    log_reference = str(item.get("log_reference") or "")
    score = 0
    if log_reference.startswith("baseline-recovery-"):
        score += 10
    if log_reference.startswith("recovery-command-"):
        score += 20
    if item.get("backup_reference"):
        score += 4
    if item.get("backup_sha256"):
        score += 4
    if item.get("failure_code") and item.get("failure_code") != "BASELINE_RECOVERY_FAILED":
        score += 3
    if item.get("after_status") is not None:
        score += 2
    return score


def _is_missing(value: Any) -> bool:
    return value is None or value == ""


def _normalize_audit_payload(
    payload: Mapping[str, Any],
    *,
    log_reference: str,
) -> dict[str, Any] | None:
    if _BASELINE_LOG_PATTERN.match(log_reference):
        return _normalize_baseline_audit(dict(payload), log_reference=log_reference)
    if _COMMAND_LOG_PATTERN.match(log_reference):
        item = dict(payload)
        item.pop("preflight", None)
        item["log_reference"] = log_reference
        return _audit_defaults(item)
    return None


def _normalize_baseline_audit(
    payload: Mapping[str, Any],
    *,
    log_reference: str,
) -> dict[str, Any]:
    operation_id = str(payload["operation_id"])
    audit = dict(payload.get("audit") or {})
    devices = list(payload.get("devices") or [])
    device = dict(devices[0]) if devices else {}
    before = dict(device.get("previous") or {})
    after = dict(device.get("current") or {})
    if not before and "preflight" in audit and audit["preflight"]:
        before = {
            "status": audit["preflight"].get("current_status"),
            "trust_score": audit["preflight"].get("current_trust_score"),
        }
        if not after and not payload.get("database_committed"):
            after = before
    item = {
        "operation_id": operation_id,
        "result": str(payload.get("result") or "FAILED"),
        "device_id": str(device.get("device_id") or _first(payload.get("device_ids")) or ""),
        "reason": audit.get("reason") or "",
        "requested_by": audit.get("requested_by") or "",
        "approved_by": audit.get("approved_by") or "",
        "requested_at": audit.get("requested_at") or _operation_time(operation_id),
        "before_status": before.get("status"),
        "before_trust_score": _optional_int(before.get("trust_score")),
        "after_status": after.get("status"),
        "after_trust_score": _optional_int(after.get("trust_score")),
        "firewall_release_status": audit.get("firewall_release_status")
        or _firewall_release_status(audit.get("preflight")),
        "backup_reference": _basename(payload.get("backup_path")),
        "backup_sha256": payload.get("backup_sha256"),
        "failure_code": (
            None if payload.get("result") == "SUCCESS"
            else payload.get("failure_code") or (
                "BASELINE_RECOVERY_COMMITTED_UNVERIFIED"
                if payload.get("database_committed") else "BASELINE_RECOVERY_FAILED"
            )
        ),
        "failure_reason": payload.get("error"),
        "log_reference": log_reference,
    }
    return _audit_defaults(item)


def _audit_defaults(item: Mapping[str, Any]) -> dict[str, Any]:
    result = str(item.get("result") or "FAILED")
    return {
        "operation_id": str(item.get("operation_id") or ""),
        "result": result,
        "device_id": str(item.get("device_id") or ""),
        "reason": str(item.get("reason") or ""),
        "requested_by": str(item.get("requested_by") or ""),
        "approved_by": str(item.get("approved_by") or ""),
        "requested_at": str(item.get("requested_at") or ""),
        "before_status": item.get("before_status"),
        "before_trust_score": _optional_int(item.get("before_trust_score")),
        "after_status": item.get("after_status"),
        "after_trust_score": _optional_int(item.get("after_trust_score")),
        "firewall_release_status": str(item.get("firewall_release_status") or "UNKNOWN"),
        "backup_reference": item.get("backup_reference"),
        "backup_sha256": item.get("backup_sha256"),
        "failure_code": item.get("failure_code"),
        "failure_reason": item.get("failure_reason"),
        "log_reference": item.get("log_reference"),
    }


def _firewall_release_status(preflight: Mapping[str, Any] | None) -> str:
    if not preflight:
        return "NOT_VERIFIED"
    db_passed = bool(preflight.get("firewall_db_state", {}).get("passed"))
    request_passed = bool(
        preflight.get("firewall_release_request_state", {}).get("passed", True)
    )
    runtime_passed = bool(
        preflight.get("firewall_runtime_verification", {}).get("passed")
    )
    if db_passed and request_passed and runtime_passed:
        return "VERIFIED_RELEASED"
    if db_passed and request_passed:
        return "DB_RELEASED_RUNTIME_UNVERIFIED"
    return "ACTIVE_OR_UNRELEASED"


def _try_acquire_device_lock(device_id: str) -> bool:
    with _DEVICE_LOCK_GUARD:
        if device_id in _IN_FLIGHT_DEVICES:
            return False
        _IN_FLIGHT_DEVICES.add(device_id)
        return True


def _release_device_lock(device_id: str) -> None:
    with _DEVICE_LOCK_GUARD:
        _IN_FLIGHT_DEVICES.discard(device_id)


def _artifact_dir(value: str | Path | None) -> Path:
    return Path(value or settings.recovery_artifact_dir).expanduser().resolve()


def _sqlite_database_path(db: Session) -> Path:
    bind = db.get_bind()
    database = getattr(bind.url, "database", None)
    if not database or database == ":memory:":
        raise RecoveryCommandError("Recovery requires a file-backed SQLite database")
    return Path(database).expanduser().resolve()


def _device_snapshot(db: Session, device_id: str) -> dict[str, Any]:
    row = db.execute(
        text(
            """
            SELECT status, trust_score
            FROM devices
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).mappings().one_or_none()
    if row is None:
        return {"status": None, "trust_score": None}
    return {"status": row["status"], "trust_score": int(row["trust_score"])}


def _backup_artifact_metadata(artifacts: Path, operation_id: str) -> dict[str, str | None]:
    backup_path = artifacts / f"baseline-recovery-{operation_id}.db"
    if not backup_path.is_file():
        return {"backup_reference": None, "backup_sha256": None}
    return {
        "backup_reference": backup_path.name,
        "backup_sha256": _file_sha256(backup_path),
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomically(path: Path, payload: Mapping[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _new_operation_id() -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:12]}"


def _now_utc() -> str:
    return format_utc_iso(datetime.now(timezone.utc))


def _require_non_empty(value: str, field_name: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"{field_name} must be non-empty")
    return normalized


def _require_score(value: int) -> None:
    if not 0 <= int(value) <= 100:
        raise ValueError("expected_trust_score must be between 0 and 100")


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _basename(value: Any) -> str | None:
    if value is None:
        return None
    return Path(str(value)).name


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return None


def _operation_time(operation_id: str) -> str:
    timestamp, _, _ = operation_id.partition("-")
    try:
        return format_utc_iso(datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc))
    except ValueError:
        return ""
