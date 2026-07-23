"""Database repository for firewall rule state."""

from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import format_db_utc, require_utc_whole_second


PENDING = "PENDING"
APPLIED = "APPLIED"
FAILED = "FAILED"
REMOVED = "REMOVED"
ACTIVE_STATUSES = {PENDING, APPLIED}
MAX_TRANSIENT_RETRIES = 3


def create_pending_rule_for_device(
    db: Session,
    *,
    device_id: str,
    source_ip: str,
    reason: str,
    trigger_event_id: int,
) -> int:
    _validate_ip(source_ip)
    existing = db.execute(
        text(
            """
            SELECT id
            FROM firewall_rules
            WHERE source_ip = :source_ip
              AND protocol = 'tcp'
              AND dest_port = 1883
              AND status IN ('PENDING', 'APPLIED')
            ORDER BY id ASC
            LIMIT 1
            """
        ),
        {"source_ip": source_ip},
    ).first()
    if existing is not None:
        return int(existing[0])

    result = db.execute(
        text(
            """
            INSERT INTO firewall_rules (
                device_id,
                source_ip,
                protocol,
                dest_port,
                action,
                status,
                reason,
                trigger_event_id
            )
            VALUES (
                :device_id,
                :source_ip,
                'tcp',
                1883,
                'DROP',
                'PENDING',
                :reason,
                :trigger_event_id
            )
            """
        ),
        {
            "device_id": device_id,
            "source_ip": source_ip,
            "reason": reason,
            "trigger_event_id": trigger_event_id,
        },
    )
    return int(result.lastrowid)


def list_pending_rules(
    db: Session,
    *,
    now: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    now_utc = require_utc_whole_second(now, "now")
    rows = db.execute(
        text(
            """
            SELECT *
            FROM firewall_rules
            WHERE status = 'PENDING'
              AND (
                  next_retry_at IS NULL
                  OR unixepoch(next_retry_at) <= unixepoch(:now)
              )
            ORDER BY id ASC
            LIMIT :limit
            """
        ),
        {"now": format_db_utc(now_utc), "limit": limit},
    ).mappings()
    return [dict(row) for row in rows]


def mark_applied(db: Session, *, rule_id: int, applied_at: datetime) -> None:
    applied_utc = require_utc_whole_second(applied_at, "applied_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'APPLIED',
                applied_at = :applied_at,
                last_attempted_at = :applied_at,
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = :applied_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {"id": rule_id, "applied_at": format_db_utc(applied_utc)},
    )
    _ensure_one_row_changed(result, f"firewall rule is not PENDING: {rule_id}")


def record_transient_failure(
    db: Session,
    *,
    rule_id: int,
    attempted_at: datetime,
    error: str,
    retry_delay_seconds: int = 30,
) -> None:
    attempted_utc = require_utc_whole_second(attempted_at, "attempted_at")
    current_retry = _current_retry_count(db, rule_id, required_status=PENDING)
    retry_count = current_retry + 1
    status = FAILED if retry_count >= MAX_TRANSIENT_RETRIES else PENDING
    next_retry_at = (
        None
        if status == FAILED
        else attempted_utc + timedelta(seconds=retry_delay_seconds)
    )
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = :status,
                retry_count = :retry_count,
                last_attempted_at = :last_attempted_at,
                next_retry_at = :next_retry_at,
                last_error = :last_error,
                updated_at = :last_attempted_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {
            "id": rule_id,
            "status": status,
            "retry_count": retry_count,
            "last_attempted_at": format_db_utc(attempted_utc),
            "next_retry_at": format_db_utc(next_retry_at) if next_retry_at else None,
            "last_error": error,
        },
    )
    _ensure_one_row_changed(result, f"firewall rule is not PENDING: {rule_id}")


def record_validation_failure(
    db: Session,
    *,
    rule_id: int,
    attempted_at: datetime,
    error: str,
) -> None:
    attempted_utc = require_utc_whole_second(attempted_at, "attempted_at")
    retry_count = _current_retry_count(db, rule_id, required_status=PENDING) + 1
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'FAILED',
                retry_count = :retry_count,
                last_attempted_at = :last_attempted_at,
                next_retry_at = NULL,
                last_error = :last_error,
                updated_at = :last_attempted_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {
            "id": rule_id,
            "retry_count": retry_count,
            "last_attempted_at": format_db_utc(attempted_utc),
            "last_error": error,
        },
    )
    _ensure_one_row_changed(result, f"firewall rule is not PENDING: {rule_id}")


def mark_removed(db: Session, *, rule_id: int, released_at: datetime) -> None:
    released_utc = require_utc_whole_second(released_at, "released_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'REMOVED',
                released_at = :released_at,
                next_retry_at = NULL,
                updated_at = :released_at
            WHERE id = :id
              AND status = 'APPLIED'
            """
        ),
        {"id": rule_id, "released_at": format_db_utc(released_utc)},
    )
    _ensure_one_row_changed(result, f"firewall rule is not APPLIED: {rule_id}")


def reset_failed_to_pending(
    db: Session,
    *,
    rule_id: int,
    requested_at: datetime,
    reset_retry_count: bool = True,
) -> None:
    requested_utc = require_utc_whole_second(requested_at, "requested_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'PENDING',
                retry_count = CASE WHEN :reset_retry_count THEN 0 ELSE retry_count END,
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = :requested_at
            WHERE id = :id
              AND status = 'FAILED'
            """
        ),
        {
            "id": rule_id,
            "reset_retry_count": 1 if reset_retry_count else 0,
            "requested_at": format_db_utc(requested_utc),
        },
    )
    _ensure_one_row_changed(result, f"firewall rule is not FAILED: {rule_id}")


def _current_retry_count(
    db: Session,
    rule_id: int,
    *,
    required_status: str | None = None,
) -> int:
    row = db.execute(
        text("SELECT retry_count, status FROM firewall_rules WHERE id = :id"),
        {"id": rule_id},
    ).mappings().first()
    if row is None:
        raise ValueError(f"firewall rule not found: {rule_id}")
    if required_status is not None and row["status"] != required_status:
        raise ValueError(f"firewall rule is not {required_status}: {rule_id}")
    return int(row["retry_count"])


def _ensure_one_row_changed(result, message: str) -> None:
    if result.rowcount != 1:
        raise ValueError(message)


def _validate_ip(source_ip: str) -> None:
    try:
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError(f"invalid source_ip: {source_ip!r}") from exc
