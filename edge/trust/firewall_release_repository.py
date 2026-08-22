"""Repository for administrator-approved firewall release requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from edge.detection.phase4_time import format_db_utc, require_utc_whole_second


PENDING = "PENDING"
SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
STATUSES = {PENDING, SUCCEEDED, FAILED}


class DuplicatePendingReleaseRequest(ValueError):
    """Raised when the DB partial unique index rejects a duplicate request."""


def create_release_request(
    db: Session,
    *,
    firewall_rule_id: int,
    requested_by: str,
    reason: str,
    requested_at: datetime,
) -> int:
    requested_utc = require_utc_whole_second(requested_at, "requested_at")
    try:
        result = db.execute(
            text(
                """
                INSERT INTO firewall_release_requests (
                    firewall_rule_id,
                    status,
                    requested_by,
                    reason,
                    requested_at,
                    updated_at
                )
                SELECT
                    id,
                    'PENDING',
                    :requested_by,
                    :reason,
                    :requested_at,
                    :requested_at
                FROM firewall_rules
                WHERE id = :firewall_rule_id
                  AND status = 'APPLIED'
                """
            ),
            {
                "firewall_rule_id": firewall_rule_id,
                "requested_by": _require_non_empty(requested_by, "requested_by"),
                "reason": _require_non_empty(reason, "reason"),
                "requested_at": format_db_utc(requested_utc),
            },
        )
    except IntegrityError as exc:
        raise DuplicatePendingReleaseRequest(
            f"pending firewall release request already exists: {firewall_rule_id}"
        ) from exc
    if result.rowcount != 1:
        raise ValueError(f"firewall rule is not APPLIED: {firewall_rule_id}")
    return int(result.lastrowid)


def get_release_request(db: Session, request_id: int) -> dict[str, Any] | None:
    row = db.execute(
        text(
            """
            SELECT *
            FROM firewall_release_requests
            WHERE id = :id
            """
        ),
        {"id": request_id},
    ).mappings().first()
    return dict(row) if row is not None else None


def find_active_pending_for_rule(
    db: Session,
    *,
    firewall_rule_id: int,
) -> dict[str, Any] | None:
    row = db.execute(
        text(
            """
            SELECT *
            FROM firewall_release_requests
            WHERE firewall_rule_id = :firewall_rule_id
              AND status = 'PENDING'
            ORDER BY id ASC
            LIMIT 1
            """
        ),
        {"firewall_rule_id": firewall_rule_id},
    ).mappings().first()
    return dict(row) if row is not None else None


def list_pending_release_requests(
    db: Session,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT
                request.id AS id,
                request.firewall_rule_id AS firewall_rule_id,
                request.status AS status,
                request.requested_by AS requested_by,
                request.reason AS reason,
                request.requested_at AS requested_at,
                request.processed_at AS processed_at,
                request.last_error AS last_error,
                request.created_at AS created_at,
                request.updated_at AS updated_at,
                rule.device_id AS rule_device_id,
                rule.source_ip AS rule_source_ip,
                rule.protocol AS rule_protocol,
                rule.dest_port AS rule_dest_port,
                rule.action AS rule_action,
                rule.status AS rule_status
            FROM firewall_release_requests AS request
            JOIN firewall_rules AS rule
              ON rule.id = request.firewall_rule_id
            WHERE request.status = 'PENDING'
            ORDER BY request.id ASC
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).mappings()
    return [dict(row) for row in rows]


def pending_release_rule_ids(db: Session) -> set[int]:
    rows = db.execute(
        text(
            """
            SELECT firewall_rule_id
            FROM firewall_release_requests
            WHERE status = 'PENDING'
            """
        )
    ).all()
    return {int(row[0]) for row in rows}


def mark_succeeded(
    db: Session,
    *,
    request_id: int,
    processed_at: datetime,
) -> None:
    processed_utc = require_utc_whole_second(processed_at, "processed_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_release_requests
            SET status = 'SUCCEEDED',
                processed_at = :processed_at,
                last_error = NULL,
                updated_at = :processed_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {"id": request_id, "processed_at": format_db_utc(processed_utc)},
    )
    _ensure_one_row_changed(result, f"firewall release request is not PENDING: {request_id}")


def mark_failed(
    db: Session,
    *,
    request_id: int,
    processed_at: datetime,
    error: str,
) -> None:
    processed_utc = require_utc_whole_second(processed_at, "processed_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_release_requests
            SET status = 'FAILED',
                processed_at = :processed_at,
                last_error = :last_error,
                updated_at = :processed_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {
            "id": request_id,
            "processed_at": format_db_utc(processed_utc),
            "last_error": _summarize_error(error),
        },
    )
    _ensure_one_row_changed(result, f"firewall release request is not PENDING: {request_id}")


def _ensure_one_row_changed(result, message: str) -> None:
    if result.rowcount != 1:
        raise ValueError(message)


def _require_non_empty(value: str, field_name: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"{field_name} must be non-empty")
    return normalized


def _summarize_error(error: str, *, limit: int = 300) -> str:
    collapsed = " ".join(str(error).split())
    if not collapsed:
        return "unknown firewall release failure"
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."
