"""Gateway metrics read helpers used by FastAPI routers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlalchemy.orm import Session

from edge.gateway.gateway_metrics_repository import (
    count_gateway_metrics,
    list_gateway_metrics,
)
from edge.packet.pcap_naming import format_utc_iso


class GatewayMetricsDataError(RuntimeError):
    """Raised when stored gateway metrics do not match the API contract."""


def list_gateway_metric_rows(
    db: Session,
    *,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    from_utc = _normalize_optional_utc(from_at, "from")
    to_utc = _normalize_optional_utc(to_at, "to")
    _validate_time_range(from_utc, to_utc)

    rows = list_gateway_metrics(
        db,
        from_at=from_utc,
        to_at=to_utc,
        limit=limit,
        offset=offset,
    )
    total = count_gateway_metrics(db, from_at=from_utc, to_at=to_utc)

    return {
        "items": [_gateway_metric_item(row) for row in rows],
        "total": total,
    }


def _gateway_metric_item(row: dict[str, Any]) -> dict[str, Any]:
    try:
        interface_metrics = json.loads(row["interface_metrics_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise GatewayMetricsDataError("Invalid interface_metrics_json") from exc

    return {
        "id": row["id"],
        "collected_at": _format_api_timestamp(row["collected_at"], "collected_at"),
        "sample_interval_seconds": row["sample_interval_seconds"],
        "cpu_percent": row["cpu_percent"],
        "memory_percent": row["memory_percent"],
        "disk_percent": row["disk_percent"],
        "disk_used_mb": row["disk_used_mb"],
        "temperature_c": row["temperature_c"],
        "interface_metrics": interface_metrics,
    }


def _normalize_optional_utc(value: datetime | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone")
    return value.astimezone(timezone.utc)


def _validate_time_range(
    from_at: datetime | None,
    to_at: datetime | None,
) -> None:
    if from_at is not None and to_at is not None and from_at > to_at:
        raise ValueError("from must be earlier than or equal to to")


def _format_api_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=timezone.utc)
        return format_utc_iso(value)

    text = str(value)
    if text.endswith("Z"):
        parse_target = text[:-1] + "+00:00"
    else:
        parse_target = text.replace(" ", "T")

    try:
        parsed = datetime.fromisoformat(parse_target)
    except ValueError as exc:
        raise GatewayMetricsDataError(
            f"{field_name} must be a valid timestamp"
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)
