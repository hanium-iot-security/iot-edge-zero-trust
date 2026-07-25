"""Detection event query helpers used by FastAPI routers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso


class DetectionEventDataError(RuntimeError):
    """Raised when stored detection event rows violate the API contract."""


def _rows_to_items(rows) -> list[dict[str, Any]]:
    return [_event_item(dict(row)) for row in rows]


def list_detection_events(
    db: Session,
    device_id: str | None = None,
    event_type: str | None = None,
    detector_type: str | None = None,
    severity: str | None = None,
    applied_to_score: int | None = None,
    incident_family: str | None = None,
    subject_ip: str | None = None,
    processing_reason: str | None = None,
    window_start_from: datetime | None = None,
    window_end_to: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    window_start_from_utc = _normalize_optional_utc(
        window_start_from,
        "window_start_from",
    )
    window_end_to_utc = _normalize_optional_utc(window_end_to, "window_end_to")
    columns = _column_names(db, "detection_events")
    _validate_filter_columns(
        columns,
        incident_family=incident_family,
        subject_ip=subject_ip,
        processing_reason=processing_reason,
        window_start_from=window_start_from_utc,
        window_end_to=window_end_to_utc,
    )
    params: dict[str, Any] = {
        "device_id": device_id,
        "event_type": event_type,
        "detector_type": detector_type,
        "severity": severity,
        "applied_to_score": applied_to_score,
        "incident_family": incident_family,
        "subject_ip": subject_ip,
        "processing_reason": processing_reason,
        "window_start_from": (
            format_utc_iso(window_start_from_utc)
            if window_start_from_utc is not None
            else None
        ),
        "window_end_to": (
            format_utc_iso(window_end_to_utc)
            if window_end_to_utc is not None
            else None
        ),
        "limit": limit,
        "offset": offset,
    }
    where_sql = _where_sql(columns)

    total = db.execute(
        text(
            f"""
            SELECT COUNT(*)
            FROM detection_events
            {where_sql}
            """
        ),
        params,
    ).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                device_id,
                feature_log_id,
                mqtt_log_id,
                {_select_column(columns, "packet_feature_log_id")},
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at,
                {_select_column(columns, "analysis_window_start")},
                {_select_column(columns, "analysis_window_end")},
                {_select_column(columns, "incident_family")},
                {_select_column(columns, "subject_ip")},
                {_select_column(columns, "evidence_json")},
                {_select_column(columns, "evidence_schema_version")},
                {_select_column(columns, "processing_reason")},
                {_select_column(columns, "processed_at")},
                {_select_column(columns, "policy_version")}
            FROM detection_events
            {where_sql}
            ORDER BY detected_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_items(rows), "total": int(total)}


def _event_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "feature_log_id": row["feature_log_id"],
        "mqtt_log_id": row["mqtt_log_id"],
        "packet_feature_log_id": row["packet_feature_log_id"],
        "detector_type": row["detector_type"],
        "event_type": row["event_type"],
        "severity": row["severity"],
        "score_delta": row["score_delta"],
        "applied_to_score": row["applied_to_score"],
        "description": row["description"],
        "detected_at": _format_optional_timestamp(row["detected_at"], "detected_at"),
        "analysis_window_start": _format_optional_timestamp(
            row["analysis_window_start"],
            "analysis_window_start",
        ),
        "analysis_window_end": _format_optional_timestamp(
            row["analysis_window_end"],
            "analysis_window_end",
        ),
        "incident_family": row["incident_family"],
        "subject_ip": row["subject_ip"],
        "evidence": _parse_optional_json(row["evidence_json"], "evidence_json"),
        "evidence_schema_version": row["evidence_schema_version"],
        "processing_reason": row["processing_reason"],
        "processed_at": _format_optional_timestamp(row["processed_at"], "processed_at"),
        "policy_version": row["policy_version"],
    }


def _normalize_optional_utc(value: datetime | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone")
    return value.astimezone(timezone.utc)


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
            raise DetectionEventDataError(
                f"{field_name} must be a valid timestamp"
            ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)


def _parse_optional_json(value: Any, field_name: str) -> Any:
    if value is None:
        return None
    try:
        return json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise DetectionEventDataError(f"{field_name} must be valid JSON") from exc


def _column_names(db: Session, table_name: str) -> set[str]:
    rows = db.execute(text(f"PRAGMA table_info({table_name})")).mappings().all()
    return {str(row["name"]) for row in rows}


def _select_column(columns: set[str], column_name: str) -> str:
    if column_name in columns:
        return column_name
    return f"NULL AS {column_name}"


def _where_sql(columns: set[str]) -> str:
    filters = [
        "(:device_id IS NULL OR device_id = :device_id)",
        "(:event_type IS NULL OR event_type = :event_type)",
        "(:detector_type IS NULL OR detector_type = :detector_type)",
        "(:severity IS NULL OR severity = :severity)",
        "(:applied_to_score IS NULL OR applied_to_score = :applied_to_score)",
    ]
    if "incident_family" in columns:
        filters.append("(:incident_family IS NULL OR incident_family = :incident_family)")
    if "subject_ip" in columns:
        filters.append("(:subject_ip IS NULL OR subject_ip = :subject_ip)")
    if "processing_reason" in columns:
        filters.append("(:processing_reason IS NULL OR processing_reason = :processing_reason)")
    if "analysis_window_start" in columns:
        filters.append(
            "(:window_start_from IS NULL OR unixepoch(analysis_window_start) >= unixepoch(:window_start_from))"
        )
    if "analysis_window_end" in columns:
        filters.append(
            "(:window_end_to IS NULL OR unixepoch(analysis_window_end) <= unixepoch(:window_end_to))"
        )
    return "WHERE " + "\n          AND ".join(filters)


def _validate_filter_columns(
    columns: set[str],
    *,
    incident_family: str | None,
    subject_ip: str | None,
    processing_reason: str | None,
    window_start_from: datetime | None,
    window_end_to: datetime | None,
) -> None:
    requested = {
        "incident_family": incident_family,
        "subject_ip": subject_ip,
        "processing_reason": processing_reason,
        "analysis_window_start": window_start_from,
        "analysis_window_end": window_end_to,
    }
    missing = [
        field_name
        for field_name, value in requested.items()
        if value is not None and field_name not in columns
    ]
    if missing:
        raise ValueError(f"filter requires Phase 4 schema columns: {', '.join(missing)}")
