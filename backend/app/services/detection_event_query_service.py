"""Detection event query helpers used by FastAPI routers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlalchemy import bindparam, text
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

    items = _rows_to_items(rows)
    _add_score_effects(db, items)
    return {"items": items, "total": int(total)}


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


# Only completed, known non-application decisions prove a zero effect. In
# particular, legacy migration markers and an unapplied flag alone do not.
NON_APPLIED_REASONS = frozenset({
    "NOT_REPRESENTATIVE", "ALREADY_ISOLATED", "UNMAPPED_DEVICE",
    "UNMAPPED_EVENT_TYPE", "LATE_EVENT", "INVALID_INCIDENT_FAMILY",
    "NO_SCORE_EVENT", "AI_OBSERVATION_ONLY", "AI_OFF_AT_WINDOW",
    "INVALID_AI_POLICY_EVIDENCE", "PENDING_AT_WINDOW", "DISABLED_AT_WINDOW",
    "DISABLE_REQUESTED_OR_DISABLED", "UNREGISTERED_AT_WINDOW",
    "POLICY_UNAVAILABLE", "INVALID_POLICY_REVISION", "INVALID_REGISTRATION_REVISION",
})


def _add_score_effects(db: Session, items: list[dict[str, Any]]) -> None:
    histories = _linked_histories(db, [item["id"] for item in items])
    for item in items:
        item.update(policy_score_delta=item["score_delta"], actual_score_delta=None,
                    score_effect_reason="UNKNOWN", trust_score_history_id=None,
                    window_actual_delta=None)
        evidence = item.get("evidence")
        decision = evidence.get("trust_decision") if isinstance(evidence, dict) else None
        if (isinstance(decision, dict) and decision.get("ai_mode") == "observe"
                and decision.get("policy_version") == "trust-ai-observation-v1"
                and type(decision.get("policy_score_delta")) is int):
            # Older observe writers zeroed the raw field but retained this fact.
            item["policy_score_delta"] = decision["policy_score_delta"]
        linked = histories.get(item["id"], [])
        if not item["processed_at"]:
            item["score_effect_reason"] = "PENDING" if not item["applied_to_score"] else "UNKNOWN"
        elif (not linked and item["applied_to_score"] == 0
              and item["processing_reason"] in NON_APPLIED_REASONS):
            item.update(actual_score_delta=0, score_effect_reason="NOT_APPLIED")
        elif (len(linked) == 1 and item["applied_to_score"] == 1
              and item["processing_reason"] == "APPLIED_TO_TRUST"):
            history = linked[0]
            if not _history_matches_event(history, item):
                continue
            members = json.loads(history["representative_event_ids_json"])
            item.update(trust_score_history_id=history["id"],
                        window_actual_delta=history["actual_delta"])
            if len(members) == 1:
                item.update(actual_score_delta=history["actual_delta"], score_effect_reason="EVENT_HISTORY")
            else:
                # The window cap / floor has no recorded allocation among events.
                item["score_effect_reason"] = "GROUP_HISTORY"


def _linked_histories(db: Session, event_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
    required = {"id", "device_id", "analysis_window_start", "analysis_window_end",
                "previous_score", "new_score", "actual_delta", "representative_event_ids_json"}
    if not event_ids or not required.issubset(_column_names(db, "trust_score_history")):
        return {}
    # Read only audit rows referencing this page, with malformed JSON kept out
    # of json_each. Exact device/window and arithmetic checks follow below.
    rows = db.execute(text("""
        SELECT DISTINCT history.* FROM trust_score_history AS history
        JOIN json_each(CASE WHEN json_valid(history.representative_event_ids_json)
            THEN history.representative_event_ids_json ELSE '[]' END) AS member
        WHERE member.type = 'integer' AND member.value IN :event_ids
    """).bindparams(bindparam("event_ids", expanding=True)), {"event_ids": event_ids}).mappings()
    result: dict[int, list[dict[str, Any]]] = {}
    requested = set(event_ids)
    for row in rows:
        history = dict(row)
        members = json.loads(history["representative_event_ids_json"])
        # Invalid arrays are still linked, so they cannot prove a zero effect.
        if isinstance(members, dict):
            ids = list(members.values())
        elif isinstance(members, list):
            ids = members
        else:
            ids = [members]
        for member in {value for value in ids if type(value) is int} & requested:
            result.setdefault(member, []).append(history)
    return result


def _history_matches_event(history: dict[str, Any], item: dict[str, Any]) -> bool:
    members = json.loads(history["representative_event_ids_json"])
    if (not isinstance(members, list) or not members
            or any(type(value) is not int or value < 1 for value in members)
            or len(set(members)) != len(members) or item["id"] not in members
            or history["device_id"] != item["device_id"]):
        return False
    if (any(type(history[key]) is not int for key in ("previous_score", "new_score", "actual_delta"))
            or not 0 <= history["previous_score"] <= 100 or not 0 <= history["new_score"] <= 100
            or history["new_score"] - history["previous_score"] != history["actual_delta"]):
        return False
    try:
        return all(item[key] is not None and
                   _format_optional_timestamp(history[key], key) == item[key]
                   for key in ("analysis_window_start", "analysis_window_end"))
    except DetectionEventDataError:
        return False


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
