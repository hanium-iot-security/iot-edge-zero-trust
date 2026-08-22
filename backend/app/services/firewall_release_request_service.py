"""Service layer for administrator-approved firewall release requests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.security import RecoveryAdminContext
from edge.packet.pcap_naming import format_utc_iso
from edge.trust import firewall_release_repository
from edge.trust.firewall_release_repository import DuplicatePendingReleaseRequest


class FirewallReleaseRequestError(RuntimeError):
    def __init__(self, status_code: int, detail: dict[str, Any]) -> None:
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


class FirewallReleaseRequestDataError(RuntimeError):
    """Raised when stored release request rows violate the API contract."""


def release_confirmation_for_rule(rule_id: int) -> str:
    return f"RELEASE-FIREWALL-RULE-{rule_id}"


def create_firewall_release_request(
    db: Session,
    *,
    rule_id: int,
    reason: str,
    confirm: str,
    admin: RecoveryAdminContext,
) -> dict[str, Any]:
    expected = release_confirmation_for_rule(rule_id)
    if confirm != expected:
        raise FirewallReleaseRequestError(
            409,
            {
                "result": "DENIED",
                "failure_code": "RELEASE_CONFIRMATION_MISMATCH",
                "failure_reason": f"confirm must be {expected}",
            },
        )

    try:
        request_id = firewall_release_repository.create_release_request(
            db,
            firewall_rule_id=rule_id,
            requested_by=admin.principal,
            reason=reason,
            requested_at=_now_utc(),
        )
        db.commit()
    except DuplicatePendingReleaseRequest as exc:
        db.rollback()
        raise FirewallReleaseRequestError(
            409,
            {
                "result": "DENIED",
                "failure_code": "DUPLICATE_PENDING_RELEASE_REQUEST",
                "failure_reason": "pending release request already exists for this rule",
            },
        ) from exc
    except ValueError as exc:
        db.rollback()
        raise _rule_state_error(db, rule_id, str(exc)) from exc
    except Exception:
        db.rollback()
        raise

    row = firewall_release_repository.get_release_request(db, request_id)
    if row is None:
        raise FirewallReleaseRequestDataError("created firewall release request is missing")
    return {"item": _release_request_item(row)}


def get_firewall_release_request(db: Session, *, request_id: int) -> dict[str, Any]:
    row = firewall_release_repository.get_release_request(db, request_id)
    if row is None:
        raise FirewallReleaseRequestError(
            404,
            {
                "result": "NOT_FOUND",
                "failure_code": "FIREWALL_RELEASE_REQUEST_NOT_FOUND",
                "failure_reason": f"firewall release request not found: {request_id}",
            },
        )
    return {"item": _release_request_item(row)}


def _rule_state_error(
    db: Session,
    rule_id: int,
    fallback_reason: str,
) -> FirewallReleaseRequestError:
    row = db.execute(
        text("SELECT status FROM firewall_rules WHERE id = :id"),
        {"id": rule_id},
    ).first()
    if row is None:
        return FirewallReleaseRequestError(
            404,
            {
                "result": "NOT_FOUND",
                "failure_code": "FIREWALL_RULE_NOT_FOUND",
                "failure_reason": f"firewall rule not found: {rule_id}",
            },
        )
    return FirewallReleaseRequestError(
        409,
        {
            "result": "DENIED",
            "failure_code": "FIREWALL_RULE_NOT_APPLIED",
            "failure_reason": fallback_reason,
            "current_status": row[0],
        },
    )


def _release_request_item(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    for field_name in ("requested_at", "processed_at", "created_at", "updated_at"):
        item[field_name] = _format_optional_timestamp(item.get(field_name), field_name)
    return item


def _format_optional_timestamp(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text_value = str(value)
        text_value = text_value[:-1] + "+00:00" if text_value.endswith("Z") else text_value
        text_value = text_value.replace(" ", "T")
        try:
            parsed = datetime.fromisoformat(text_value)
        except ValueError as exc:
            raise FirewallReleaseRequestDataError(
                f"{field_name} must be a valid timestamp"
            ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
