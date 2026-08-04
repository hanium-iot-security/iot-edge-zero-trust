"""Operator-approved, evidence-preserving Trust Score compensation."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
from typing import Any
from uuid import uuid4

from edge.trust.trust_policy import apply_score_delta, status_for_trust_score
from edge.trust.trust_score_v2 import WINDOW_DELTA_CAP


CONFIRMATION = "APPLY-TRUST-COMPENSATION"
SUPPORTED_HISTORY_POLICY = "trust-score-v2"
APPLIED_PROCESSING_REASON = "APPLIED_TO_TRUST"
COMPENSATION_TABLE = "trust_score_compensations"
COMPENSATION_MIGRATION_VERSION = 4
COMPENSATION_MIGRATION_NAME = "trust_score_compensation"


class TrustCompensationError(RuntimeError):
    """Raised when a Trust Score compensation violates a safety contract."""


class TrustCompensationCommittedArtifactError(TrustCompensationError):
    """Raised when DB commit succeeded but the JSON artifact failed."""

    def __init__(
        self,
        message: str,
        *,
        operation_id: str,
        backup_path: Path,
    ) -> None:
        super().__init__(message)
        self.operation_id = operation_id
        self.backup_path = backup_path
        self.database_committed = True


def inspect_trust_compensation(
    *,
    db_path: str | Path,
    device_id: str,
    source_event_id: int,
    expected_status: str,
    expected_trust_score: int,
    reason: str,
    approved_by: str,
    artifact_dir: str | Path,
) -> dict[str, object]:
    """Inspect one proposed compensation without changing DB or artifacts."""

    inputs = _validate_inputs(
        device_id=device_id,
        source_event_id=source_event_id,
        expected_status=expected_status,
        expected_trust_score=expected_trust_score,
        reason=reason,
        approved_by=approved_by,
    )
    database = Path(db_path).expanduser().resolve()
    artifacts = Path(artifact_dir).expanduser().resolve()
    if not database.is_file():
        raise TrustCompensationError(f"Database가 존재하지 않습니다: {database}")

    try:
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            inspection = _inspect_connection(
                connection,
                device_id=inputs["device_id"],
                source_event_id=inputs["source_event_id"],
                expected_status=inputs["expected_status"],
                expected_trust_score=inputs["expected_trust_score"],
            )
    except sqlite3.DatabaseError as exc:
        raise TrustCompensationError(f"Database 사전 검증 실패: {exc}") from exc

    return _inspection_report(
        mode="dry-run",
        database=database,
        artifacts=artifacts,
        inputs=inputs,
        inspection=inspection,
    )


def execute_trust_compensation(
    *,
    db_path: str | Path,
    device_id: str,
    source_event_id: int,
    expected_status: str,
    expected_trust_score: int,
    reason: str,
    approved_by: str,
    artifact_dir: str | Path,
    confirm: str,
) -> dict[str, object]:
    """Apply one exact compensation after locked revalidation and backup."""

    if confirm != CONFIRMATION:
        raise TrustCompensationError(
            f'--confirm에 정확히 "{CONFIRMATION}"을 입력해야 합니다'
        )
    inputs = _validate_inputs(
        device_id=device_id,
        source_event_id=source_event_id,
        expected_status=expected_status,
        expected_trust_score=expected_trust_score,
        reason=reason,
        approved_by=approved_by,
    )
    database = Path(db_path).expanduser().resolve()
    artifacts = Path(artifact_dir).expanduser().resolve()
    if not database.is_file():
        raise TrustCompensationError(f"Database가 존재하지 않습니다: {database}")

    operation_id = _new_operation_id()
    backup_path = artifacts / f"trust-compensation-{operation_id}.db"
    log_path = artifacts / f"trust-compensation-{operation_id}.json"
    backup_sha256: str | None = None
    backup_integrity = "missing"
    backup_foreign_keys: list[tuple[object, ...]] = []
    inspection: dict[str, Any] | None = None

    connection = sqlite3.connect(database, isolation_level=None, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    try:
        connection.execute("BEGIN IMMEDIATE")
        inspection = _inspect_connection(
            connection,
            device_id=inputs["device_id"],
            source_event_id=inputs["source_event_id"],
            expected_status=inputs["expected_status"],
            expected_trust_score=inputs["expected_trust_score"],
        )
        if inspection["errors"]:
            raise TrustCompensationError(
                "Trust Compensation 사전 검증 실패: "
                + "; ".join(inspection["errors"])
            )
        if inspection["history"] is None or inspection["compensation"] is None:
            raise TrustCompensationError("Source Trust History 계산 결과가 없습니다")

        artifacts.mkdir(parents=True, exist_ok=True)
        if backup_path.exists() or log_path.exists():
            raise TrustCompensationError(
                f"Trust Compensation Artifact가 이미 존재합니다: {operation_id}"
            )
        try:
            _create_backup(database, backup_path)
        except Exception as exc:
            raise TrustCompensationError(f"Backup 생성 실패: {exc}") from exc
        backup_sha256 = _file_sha256(backup_path)
        backup_integrity, backup_foreign_keys = _verify_database_path(backup_path)
        if backup_integrity != "ok" or backup_foreign_keys:
            raise TrustCompensationError(
                "Backup 검증 실패: "
                f"integrity_check={backup_integrity}, "
                f"foreign_key_violations={backup_foreign_keys}"
            )

        compensation = inspection["compensation"]
        history = inspection["history"]
        proposed_score = int(compensation["proposed_score"])
        compensation_delta = int(compensation["compensation_delta"])
        update_result = connection.execute(
            """
            UPDATE devices
            SET trust_score = :new_score
            WHERE device_id = :device_id
              AND status = :expected_status
              AND trust_score = :expected_trust_score
            """,
            {
                "new_score": proposed_score,
                "device_id": inputs["device_id"],
                "expected_status": inputs["expected_status"],
                "expected_trust_score": inputs["expected_trust_score"],
            },
        )
        if update_result.rowcount != 1:
            raise TrustCompensationError(
                "조건부 Update 대상이 예상 상태와 다릅니다: "
                f"device_id={inputs['device_id']}, rowcount={update_result.rowcount}"
            )

        audit_result = connection.execute(
            """
            INSERT INTO trust_score_compensations (
                operation_id, device_id, source_event_id,
                source_trust_history_id, previous_score,
                compensation_delta, new_score, reason, approved_by,
                backup_path, backup_sha256
            )
            VALUES (
                :operation_id, :device_id, :source_event_id,
                :source_trust_history_id, :previous_score,
                :compensation_delta, :new_score, :reason, :approved_by,
                :backup_path, :backup_sha256
            )
            """,
            {
                "operation_id": operation_id,
                "device_id": inputs["device_id"],
                "source_event_id": inputs["source_event_id"],
                "source_trust_history_id": int(history["id"]),
                "previous_score": inputs["expected_trust_score"],
                "compensation_delta": compensation_delta,
                "new_score": proposed_score,
                "reason": inputs["reason"],
                "approved_by": inputs["approved_by"],
                "backup_path": str(backup_path),
                "backup_sha256": backup_sha256,
            },
        )
        audit_id = int(audit_result.lastrowid)
        _require_committed_state(
            connection,
            operation_id=operation_id,
            device_id=inputs["device_id"],
            expected_status=inputs["expected_status"],
            expected_score=proposed_score,
            expected_audit_id=audit_id,
        )
        integrity_check, foreign_key_violations = _verify_database_connection(
            connection
        )
        if integrity_check != "ok" or foreign_key_violations:
            raise TrustCompensationError(
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
            error=str(exc),
        )
        if isinstance(exc, TrustCompensationError):
            raise
        if isinstance(exc, sqlite3.DatabaseError):
            raise TrustCompensationError(
                f"Trust Compensation Transaction 실패: {exc}"
            ) from exc
        raise TrustCompensationError(
            f"Trust Compensation 실행 실패: {exc}"
        ) from exc
    finally:
        connection.close()

    assert inspection is not None
    assert inspection["history"] is not None
    assert inspection["compensation"] is not None
    history = inspection["history"]
    compensation = inspection["compensation"]
    proposed_score = int(compensation["proposed_score"])
    try:
        post_integrity, post_foreign_keys = _verify_database_path(database)
        with sqlite3.connect(database) as verification:
            verification.row_factory = sqlite3.Row
            _require_committed_state(
                verification,
                operation_id=operation_id,
                device_id=inputs["device_id"],
                expected_status=inputs["expected_status"],
                expected_score=proposed_score,
            )
        if post_integrity != "ok" or post_foreign_keys:
            raise TrustCompensationError(
                "Commit 후 Database 검증 실패: "
                f"integrity_check={post_integrity}, "
                f"foreign_key_violations={post_foreign_keys}"
            )
    except Exception as exc:
        raise TrustCompensationCommittedArtifactError(
            "Database 변경은 Commit됐지만 Commit 후 검증에 실패했습니다. "
            f"운영 절차를 HOLD해야 합니다: backup_path={backup_path}, error={exc}",
            operation_id=operation_id,
            backup_path=backup_path,
        ) from exc

    report: dict[str, object] = {
        "mode": "execute",
        "result": "SUCCESS",
        "operation_id": operation_id,
        "database_path": str(database),
        "device_id": inputs["device_id"],
        "source_event_id": inputs["source_event_id"],
        "source_trust_history_id": int(history["id"]),
        "previous_score": inputs["expected_trust_score"],
        "compensation_delta": int(compensation["compensation_delta"]),
        "new_score": proposed_score,
        "status": inputs["expected_status"],
        "backup_path": str(backup_path),
        "backup_sha256": backup_sha256,
        "backup_integrity_check": backup_integrity,
        "backup_foreign_key_violations": [
            list(row) for row in backup_foreign_keys
        ],
        "integrity_check": post_integrity,
        "foreign_key_violations": [list(row) for row in post_foreign_keys],
        "log_path": str(log_path),
    }
    try:
        _write_json_log(log_path, report)
    except OSError as exc:
        raise TrustCompensationCommittedArtifactError(
            "Database 변경과 감사 Row는 Commit됐지만 JSON Artifact 저장에 "
            "실패했습니다. Backup을 보존하고 운영 절차를 HOLD해야 합니다: "
            f"backup_path={backup_path}, error={exc}",
            operation_id=operation_id,
            backup_path=backup_path,
        ) from exc
    return report


def _new_operation_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{uuid4().hex[:12]}"


def _create_backup(database: Path, backup_path: Path) -> None:
    with sqlite3.connect(database) as source:
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_database_connection(
    connection: sqlite3.Connection,
) -> tuple[str, list[tuple[object, ...]]]:
    integrity_row = connection.execute("PRAGMA integrity_check").fetchone()
    integrity_check = str(integrity_row[0]) if integrity_row is not None else "missing"
    foreign_key_violations = [
        tuple(row) for row in connection.execute("PRAGMA foreign_key_check").fetchall()
    ]
    return integrity_check, foreign_key_violations


def _verify_database_path(
    database: Path,
) -> tuple[str, list[tuple[object, ...]]]:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        return _verify_database_connection(connection)


def _require_committed_state(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    device_id: str,
    expected_status: str,
    expected_score: int,
    expected_audit_id: int | None = None,
) -> None:
    device = connection.execute(
        "SELECT status, trust_score FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if device is None or (str(device[0]), int(device[1])) != (
        expected_status,
        expected_score,
    ):
        raise TrustCompensationError(
            "Trust Compensation 실행 후 Device 상태 검증에 실패했습니다: "
            f"device_id={device_id}, expected_status={expected_status}, "
            f"expected_score={expected_score}"
        )

    audit = connection.execute(
        "SELECT id FROM trust_score_compensations WHERE operation_id = ?",
        (operation_id,),
    ).fetchone()
    if audit is None:
        raise TrustCompensationError(
            "Trust Compensation 실행 후 감사 Row를 찾을 수 없습니다: "
            f"operation_id={operation_id}"
        )
    if expected_audit_id is not None and int(audit[0]) != expected_audit_id:
        raise TrustCompensationError(
            "Trust Compensation 감사 Row ID가 예상값과 다릅니다: "
            f"expected={expected_audit_id}, actual={audit[0]}"
        )


def _write_json_log(path: Path, payload: Mapping[str, object]) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _write_failure_log_if_possible(
    *,
    log_path: Path,
    operation_id: str,
    database: Path,
    backup_path: Path | None,
    backup_sha256: str | None,
    error: str,
) -> None:
    if not log_path.parent.is_dir():
        return
    payload: dict[str, object] = {
        "mode": "execute",
        "result": "FAILED",
        "database_committed": False,
        "operation_id": operation_id,
        "database_path": str(database),
        "backup_path": str(backup_path) if backup_path is not None else None,
        "backup_sha256": backup_sha256,
        "error": error,
        "log_path": str(log_path),
    }
    try:
        _write_json_log(log_path, payload)
    except OSError:
        return


def _validate_inputs(
    *,
    device_id: str,
    source_event_id: int,
    expected_status: str,
    expected_trust_score: int,
    reason: str,
    approved_by: str,
) -> dict[str, Any]:
    normalized_device = str(device_id).strip()
    normalized_status = str(expected_status).strip()
    normalized_reason = str(reason).strip()
    normalized_approver = str(approved_by).strip()
    if not normalized_device:
        raise TrustCompensationError("--device는 비어 있을 수 없습니다")
    if type(source_event_id) is not int or source_event_id <= 0:
        raise TrustCompensationError("--source-event-id는 1 이상의 정수여야 합니다")
    if not normalized_status:
        raise TrustCompensationError("--expected-status는 비어 있을 수 없습니다")
    if type(expected_trust_score) is not int or not 0 <= expected_trust_score <= 100:
        raise TrustCompensationError("--expected-trust-score는 0~100 정수여야 합니다")
    if not normalized_reason:
        raise TrustCompensationError("--reason은 비어 있거나 공백일 수 없습니다")
    if not normalized_approver:
        raise TrustCompensationError("--approved-by는 비어 있거나 공백일 수 없습니다")
    return {
        "device_id": normalized_device,
        "source_event_id": source_event_id,
        "expected_status": normalized_status,
        "expected_trust_score": expected_trust_score,
        "reason": normalized_reason,
        "approved_by": normalized_approver,
    }


def _inspect_connection(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    source_event_id: int,
    expected_status: str,
    expected_trust_score: int,
) -> dict[str, Any]:
    errors: list[str] = []
    migration_errors = _compensation_migration_errors(connection)
    if migration_errors:
        errors.extend(migration_errors)
        return {
            "errors": errors,
            "device": None,
            "event": None,
            "history": None,
            "compensation": None,
            "active_rules": [],
            "pending_events": [],
            "existing_compensations": [],
        }

    device = connection.execute(
        """
        SELECT device_id, ip_address, status, trust_score
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if device is None:
        errors.append(f"Device가 존재하지 않습니다: device_id={device_id}")
    else:
        current_status = str(device["status"])
        current_score = int(device["trust_score"])
        if current_status != expected_status:
            errors.append(
                "예상 status와 실제 값이 다릅니다: "
                f"expected={expected_status}, actual={current_status}"
            )
        if current_score != expected_trust_score:
            errors.append(
                "예상 Trust Score와 실제 값이 다릅니다: "
                f"expected={expected_trust_score}, actual={current_score}"
            )
        policy_status = status_for_trust_score(current_score)
        if current_status != policy_status:
            errors.append(
                "현재 상태가 Trust Score 정책과 일치하지 않습니다: "
                f"status={current_status}, policy_status={policy_status}, "
                f"trust_score={current_score}"
            )

    event = connection.execute(
        """
        SELECT id, device_id, detector_type, event_type, score_delta,
               applied_to_score, processed_at, processing_reason,
               analysis_window_start, analysis_window_end, detected_at
        FROM detection_events
        WHERE id = ?
        """,
        (source_event_id,),
    ).fetchone()
    if event is None:
        errors.append(f"Source Event가 존재하지 않습니다: event_id={source_event_id}")
    else:
        if event["device_id"] != device_id:
            errors.append(
                "Source Event의 Device가 대상과 다릅니다: "
                f"event_device={event['device_id']}, target_device={device_id}"
            )
        if int(event["applied_to_score"]) != 1:
            errors.append("Source Event의 applied_to_score가 1이 아닙니다")
        if event["processed_at"] is None:
            errors.append("Source Event가 Trust Score v2에서 처리되지 않았습니다")
        if event["processing_reason"] != APPLIED_PROCESSING_REASON:
            errors.append(
                "Source Event의 processing_reason이 APPLIED_TO_TRUST가 아닙니다: "
                f"actual={event['processing_reason']}"
            )
        if int(event["score_delta"]) >= 0:
            errors.append(
                "Source Event의 score_delta는 음수여야 합니다: "
                f"actual={event['score_delta']}"
            )

    history_rows = connection.execute(
        """
        SELECT id, device_id, analysis_window_start, analysis_window_end,
               previous_score, calculated_delta, capped_delta, actual_delta,
               new_score, representative_event_ids_json, policy_version,
               created_at
        FROM trust_score_history
        WHERE device_id = ?
        ORDER BY id
        """,
        (device_id,),
    ).fetchall()
    matching_histories: list[sqlite3.Row] = []
    for row in history_rows:
        parsed = _parse_representative_event_ids(
            row["representative_event_ids_json"],
            history_id=int(row["id"]),
            errors=errors,
        )
        if parsed is None or source_event_id not in parsed:
            continue
        if parsed == [source_event_id]:
            matching_histories.append(row)
        else:
            errors.append(
                "Source Event가 여러 Event와 연결된 Trust History에 포함되어 "
                "v1에서 보상할 수 없습니다: "
                f"history_id={row['id']}, event_ids={parsed}"
            )

    history: sqlite3.Row | None = None
    if not matching_histories:
        errors.append(
            "Source Event와 정확히 연결된 Trust History가 없습니다: "
            f"event_id={source_event_id}"
        )
    elif len(matching_histories) > 1:
        errors.append(
            "Source Event가 여러 Trust History에 연결되어 있습니다: "
            f"history_ids={[int(row['id']) for row in matching_histories]}"
        )
    else:
        history = matching_histories[0]
        if history["policy_version"] != SUPPORTED_HISTORY_POLICY:
            errors.append(
                "Source Trust History policy_version이 지원 대상이 아닙니다: "
                f"actual={history['policy_version']}"
            )
        actual_delta = int(history["actual_delta"])
        calculated_delta = int(history["calculated_delta"])
        capped_delta = int(history["capped_delta"])
        expected_capped_delta = max(calculated_delta, WINDOW_DELTA_CAP)
        if actual_delta >= 0:
            errors.append(
                "Source Trust History actual_delta는 음수여야 합니다: "
                f"actual={actual_delta}"
            )
        history_previous = int(history["previous_score"])
        history_new = int(history["new_score"])
        if capped_delta != expected_capped_delta:
            errors.append(
                "Source Trust History capped_delta가 Trust Score v2 정책과 "
                "일치하지 않습니다: "
                f"calculated_delta={calculated_delta}, "
                f"expected_capped_delta={expected_capped_delta}, "
                f"actual_capped_delta={capped_delta}"
            )
        expected_new_score = apply_score_delta(history_previous, capped_delta)
        if history_new != expected_new_score:
            errors.append(
                "Source Trust History new_score가 Trust Score v2 정책과 "
                "일치하지 않습니다: "
                f"previous={history_previous}, capped_delta={capped_delta}, "
                f"expected_new={expected_new_score}, actual_new={history_new}"
            )
        if history_new - history_previous != actual_delta:
            errors.append(
                "Source Trust History 산술이 일치하지 않습니다: "
                f"previous={history_previous}, actual_delta={actual_delta}, "
                f"new={history_new}"
            )
        if event is not None and calculated_delta != int(event["score_delta"]):
            errors.append(
                "Source History calculated_delta와 Event score_delta가 다릅니다: "
                f"calculated_delta={history['calculated_delta']}, "
                f"score_delta={event['score_delta']}"
            )

    history_id = int(history["id"]) if history is not None else None
    if history_id is None:
        existing_compensations = connection.execute(
            """
            SELECT id, operation_id, source_event_id, source_trust_history_id
            FROM trust_score_compensations
            WHERE source_event_id = ?
            ORDER BY id
            """,
            (source_event_id,),
        ).fetchall()
    else:
        existing_compensations = connection.execute(
            """
            SELECT id, operation_id, source_event_id, source_trust_history_id
            FROM trust_score_compensations
            WHERE source_event_id = ? OR source_trust_history_id = ?
            ORDER BY id
            """,
            (source_event_id, history_id),
        ).fetchall()
    if existing_compensations:
        errors.append(
            "Source Event 또는 Trust History가 이미 보상되었습니다: "
            f"compensation_ids={[int(row['id']) for row in existing_compensations]}"
        )

    pending_events = connection.execute(
        """
        SELECT id, event_type, detector_type, detected_at
        FROM detection_events
        WHERE device_id = ? AND processed_at IS NULL
        ORDER BY id
        """,
        (device_id,),
    ).fetchall()
    if pending_events:
        errors.append(
            "대상 Device에 미처리 Detection Event가 있습니다: "
            f"event_ids={[int(row['id']) for row in pending_events]}"
        )

    source_ip = device["ip_address"] if device is not None else None
    active_rules = _fetch_active_firewall_rules(
        connection,
        device_id=device_id,
        source_ip=source_ip,
    )
    if active_rules:
        errors.append(
            "대상 Device 또는 IP에 활성 Firewall Rule이 있습니다: "
            f"rule_ids={[int(row['id']) for row in active_rules]}"
        )

    compensation: dict[str, Any] | None = None
    if device is not None and history is not None:
        compensation_delta = -int(history["actual_delta"])
        proposed_score = int(device["trust_score"]) + compensation_delta
        proposed_status = (
            status_for_trust_score(proposed_score)
            if 0 <= proposed_score <= 100
            else None
        )
        compensation = {
            "compensation_delta": compensation_delta,
            "proposed_score": proposed_score,
            "proposed_status": proposed_status,
        }
        if compensation_delta <= 0:
            errors.append(
                "계산된 compensation_delta는 양수여야 합니다: "
                f"actual={compensation_delta}"
            )
        if proposed_score > 100:
            errors.append(
                "보상 후 Trust Score가 100을 초과하므로 cap 없이 거부합니다: "
                f"proposed_score={proposed_score}"
            )
        elif proposed_score < 0:
            errors.append(
                "보상 후 Trust Score가 0보다 작습니다: "
                f"proposed_score={proposed_score}"
            )
        elif proposed_status != str(device["status"]):
            errors.append(
                "보상에 Device 상태 변경이 필요하므로 v1에서 거부합니다: "
                f"current_status={device['status']}, proposed_status={proposed_status}"
            )

    return {
        "errors": errors,
        "device": device,
        "event": event,
        "history": history,
        "compensation": compensation,
        "active_rules": active_rules,
        "pending_events": pending_events,
        "existing_compensations": existing_compensations,
    }


def _parse_representative_event_ids(
    raw_value: object,
    *,
    history_id: int,
    errors: list[str],
) -> list[int] | None:
    try:
        parsed = json.loads(str(raw_value))
    except (TypeError, ValueError, json.JSONDecodeError):
        errors.append(
            "Source Trust History representative_event_ids_json JSON이 손상됐습니다: "
            f"history_id={history_id}"
        )
        return None
    if not isinstance(parsed, list):
        errors.append(
            "representative_event_ids_json은 배열이어야 합니다: "
            f"history_id={history_id}"
        )
        return None
    if any(type(value) is not int for value in parsed):
        errors.append(
            "representative_event_ids_json은 정수 ID 배열이어야 합니다: "
            f"history_id={history_id}"
        )
        return None
    return parsed


def _compensation_migration_errors(
    connection: sqlite3.Connection,
) -> list[str]:
    errors: list[str] = []
    migration_row: sqlite3.Row | tuple[object, ...] | None = None
    if _table_exists(connection, "schema_migrations"):
        migration_row = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = ?",
            (COMPENSATION_MIGRATION_VERSION,),
        ).fetchone()
    if migration_row is None or str(migration_row[0]) != COMPENSATION_MIGRATION_NAME:
        actual_name = None if migration_row is None else str(migration_row[0])
        errors.append(
            "Trust Score Compensation Migration metadata가 없거나 일치하지 않습니다: "
            f"expected_version={COMPENSATION_MIGRATION_VERSION}, "
            f"expected_name={COMPENSATION_MIGRATION_NAME}, actual_name={actual_name}"
        )
    if not _table_exists(connection, COMPENSATION_TABLE):
        errors.append(
            "Trust Score Compensation Migration 테이블이 존재하지 않습니다: "
            f"missing_table={COMPENSATION_TABLE}"
        )
    return errors


def _fetch_active_firewall_rules(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    source_ip: object,
) -> list[sqlite3.Row]:
    if source_ip:
        return connection.execute(
            """
            SELECT id, device_id, source_ip, status
            FROM firewall_rules
            WHERE status IN ('PENDING', 'APPLIED')
              AND (device_id = ? OR source_ip = ?)
            ORDER BY id
            """,
            (device_id, str(source_ip)),
        ).fetchall()
    return connection.execute(
        """
        SELECT id, device_id, source_ip, status
        FROM firewall_rules
        WHERE status IN ('PENDING', 'APPLIED')
          AND device_id = ?
        ORDER BY id
        """,
        (device_id,),
    ).fetchall()


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone() is not None


def _inspection_report(
    *,
    mode: str,
    database: Path,
    artifacts: Path,
    inputs: Mapping[str, Any],
    inspection: Mapping[str, Any],
) -> dict[str, object]:
    device = inspection["device"]
    event = inspection["event"]
    history = inspection["history"]
    errors = list(inspection["errors"])
    return {
        "mode": mode,
        "database_path": str(database),
        "artifact_dir": str(artifacts),
        "database_changed": False,
        "can_execute": not errors,
        "preflight_errors": errors,
        "device": _device_report(device, inputs),
        "source_event": _row_report(event),
        "source_trust_history": _row_report(history),
        "compensation": inspection["compensation"],
        "active_firewall_rule_check": {
            "passed": not inspection["active_rules"],
            "count": len(inspection["active_rules"]),
            "rule_ids": [int(row["id"]) for row in inspection["active_rules"]],
        },
        "pending_trust_event_check": {
            "passed": not inspection["pending_events"],
            "count": len(inspection["pending_events"]),
            "event_ids": [int(row["id"]) for row in inspection["pending_events"]],
        },
        "existing_compensation_check": {
            "passed": not inspection["existing_compensations"],
            "count": len(inspection["existing_compensations"]),
        },
        "execute_command": _build_execute_command(
            database=database,
            artifacts=artifacts,
            inputs=inputs,
        ),
    }


def _device_report(
    device: sqlite3.Row | None,
    inputs: Mapping[str, Any],
) -> dict[str, object] | None:
    if device is None:
        return None
    return {
        "device_id": str(device["device_id"]),
        "ip_address": device["ip_address"],
        "current_status": str(device["status"]),
        "current_trust_score": int(device["trust_score"]),
        "expected_status": str(inputs["expected_status"]),
        "expected_trust_score": int(inputs["expected_trust_score"]),
    }


def _row_report(row: sqlite3.Row | None) -> dict[str, object] | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _build_execute_command(
    *,
    database: Path,
    artifacts: Path,
    inputs: Mapping[str, Any],
) -> str:
    return shlex.join(
        [
            "python",
            "-m",
            "edge.trust.run_trust_compensation",
            "execute",
            "--db-path",
            str(database),
            "--device",
            str(inputs["device_id"]),
            "--source-event-id",
            str(inputs["source_event_id"]),
            "--expected-status",
            str(inputs["expected_status"]),
            "--expected-trust-score",
            str(inputs["expected_trust_score"]),
            "--reason",
            str(inputs["reason"]),
            "--approved-by",
            str(inputs["approved_by"]),
            "--artifact-dir",
            str(artifacts),
            "--confirm",
            CONFIRMATION,
        ]
    )
