"""Packet feature read helpers used by FastAPI routers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from edge.features.packet_feature_repository import (
    count_packet_feature_logs,
    list_packet_feature_logs,
)
from edge.packet.pcap_naming import format_utc_iso


PACKET_WINDOW_SECONDS = 10.0


class PacketFeatureDataError(RuntimeError):
    """Raised when stored packet feature rows do not match the API contract."""


def list_packet_features(
    db: Session,
    *,
    session_id: str | None = None,
    device_id: str | None = None,
    peer_ip: str | None = None,
    direction: str | None = None,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    from_utc = _normalize_optional_utc(from_at, "from")
    to_utc = _normalize_optional_utc(to_at, "to")
    _validate_time_range(from_utc, to_utc)

    rows = list_packet_feature_logs(
        db,
        session_id=session_id,
        device_id=device_id,
        peer_ip=peer_ip,
        direction=direction,
        from_at=from_utc,
        to_at=to_utc,
        limit=limit,
        offset=offset,
    )
    total = count_packet_feature_logs(
        db,
        session_id=session_id,
        device_id=device_id,
        peer_ip=peer_ip,
        direction=direction,
        from_at=from_utc,
        to_at=to_utc,
    )

    return {
        "items": [_packet_feature_item(row) for row in rows],
        "total": total,
    }


def _packet_feature_item(row: dict[str, Any]) -> dict[str, Any]:
    packet_count = int(row["packet_count"])
    total_bytes = int(row["total_bytes"])
    return {
        "id": row["id"],
        "capture_segment_id": row["capture_segment_id"],
        "session_id": row["session_id"],
        "device_id": row["device_id"],
        "peer_ip": row["peer_ip"],
        "direction": row["direction"],
        "window_start": _format_api_timestamp(row["window_start"], "window_start"),
        "window_end": _format_api_timestamp(row["window_end"], "window_end"),
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_packet_size": row["avg_packet_size"],
        "max_packet_size": row["max_packet_size"],
        "mean_inter_arrival_time": row["mean_inter_arrival_time"],
        "distinct_dest_port_count": row["distinct_dest_port_count"],
        "tcp_syn_count": row["tcp_syn_count"],
        "mqtt_related_packet_count": row["mqtt_related_packet_count"],
        "non_mqtt_tcp_udp_packet_count": row["non_mqtt_tcp_udp_packet_count"],
        "packets_per_second": packet_count / PACKET_WINDOW_SECONDS,
        "bytes_per_second": total_bytes / PACKET_WINDOW_SECONDS,
        "capture_scope": row["capture_scope"],
        "created_at": _format_api_timestamp(row["created_at"], "created_at"),
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
        raise PacketFeatureDataError(
            f"{field_name} must be a valid timestamp"
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)
