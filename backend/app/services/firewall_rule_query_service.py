"""Firewall rule query helpers used by FastAPI routers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso
from edge.trust.firewall_repository import has_scope_schema
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883


VALID_FIREWALL_STATUSES = {"PENDING", "APPLIED", "FAILED", "REMOVED"}


class FirewallRuleDataError(RuntimeError):
    """Raised when stored firewall rule rows violate the API contract."""


def list_firewall_rules(
    db: Session,
    *,
    status: str | None = None,
    device_id: str | None = None,
    source_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    if status is not None and status not in VALID_FIREWALL_STATUSES:
        raise ValueError("invalid firewall status")
    params = {
        "status": status,
        "device_id": device_id,
        "source_ip": source_ip,
        "limit": limit,
        "offset": offset,
    }
    where_sql = """
        WHERE (:status IS NULL OR status = :status)
          AND (:device_id IS NULL OR device_id = :device_id)
          AND (:source_ip IS NULL OR source_ip = :source_ip)
    """
    total = db.execute(
        text(
            f"""
            SELECT COUNT(*)
            FROM firewall_rules
            {where_sql}
            """
        ),
        params,
    ).scalar_one()
    scope_projection = ("scope, source_rule_id, approved_policy_revision, requested_by, request_id" if has_scope_schema(db) else
                        "'" + MQTT_IPV4_TCP_1883 + "' AS scope, NULL AS source_rule_id, "
                        "NULL AS approved_policy_revision, NULL AS requested_by, NULL AS request_id")
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                device_id,
                source_ip,
                protocol,
                dest_port,
                action,
                status,
                reason,
                trigger_event_id,
                retry_count,
                last_error,
                last_attempted_at,
                next_retry_at,
                applied_at,
                released_at,
                created_at,
                updated_at,
                {scope_projection}
            FROM firewall_rules
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()
    return {"items": [_firewall_item(dict(row)) for row in rows], "total": int(total)}


def _firewall_item(row: dict[str, Any]) -> dict[str, Any]:
    for field_name in (
        "last_attempted_at",
        "next_retry_at",
        "applied_at",
        "released_at",
        "created_at",
        "updated_at",
    ):
        row[field_name] = _format_optional_timestamp(row[field_name], field_name)
    return row


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
            raise FirewallRuleDataError(
                f"{field_name} must be a valid timestamp"
            ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)
