"""Bounded raw MQTT reads. Graph ranges use [from, to), in exact UTC instants."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.schemas.mqtt_log_schema import MqttLogPage
from backend.app.services.feature_read_snapshot import feature_read_snapshot
from backend.app.services.mqtt_log_time import datetime_microseconds, mqtt_received_microseconds, optional_utc

MAX_MQTT_OFFSET = 100_000
_COLUMNS = "id, device_id, topic, payload, payload_size, received_at, is_json_valid, is_topic_valid, error_message"


def list_mqtt_logs(
    db: Session,
    limit: int = 100,
    offset: int = 0,
    device_id: str | None = None,
    valid_only: bool = False,
    *,
    is_json_valid: bool | None = None,
    is_topic_valid: bool | None = None,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    snapshot_max_id: int | None = None,
) -> MqttLogPage:
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("limit must be an integer between 1 and 500")
    if type(offset) is not int or not 0 <= offset <= MAX_MQTT_OFFSET:
        raise ValueError(f"offset must be an integer between 0 and {MAX_MQTT_OFFSET}")
    for name, value in (("is_json_valid", is_json_valid), ("is_topic_valid", is_topic_valid)):
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be a boolean or omitted")
    start = optional_utc(from_at, "from")
    end = optional_utc(to_at, "to")
    if start is not None and end is not None and start > end:
        raise ValueError("from must be before or equal to to")
    ranged = start is not None or end is not None

    with feature_read_snapshot(db, "mqtt_logs", snapshot_max_id) as maximum:
        filters = ["id <= :snapshot_max_id"]
        params: dict[str, Any] = {"limit": limit, "offset": offset, "snapshot_max_id": maximum}
        if device_id:
            filters.append("device_id = :device_id")
            params["device_id"] = device_id
        source_where = " AND ".join(filters)
        if valid_only:
            filters.extend(["is_json_valid = 1", "is_topic_valid = 1"])
        for column, value in (("is_json_valid", is_json_valid), ("is_topic_valid", is_topic_valid)):
            if value is not None:
                filters.append(f"{column} = :{column}")
                params[column] = int(value)
        where = " AND ".join(filters)
        unavailable = None
        source_span = None
        if not ranged:
            # Preserve ingestion order for Dashboard/Logs and avoid parsing history
            # when a legacy consumer asks only for the latest raw messages.
            total = db.execute(text(f"SELECT COUNT(*) FROM mqtt_logs WHERE {where}"), params).scalar_one()
            rows = db.execute(text(f"SELECT {_COLUMNS} FROM mqtt_logs WHERE {where} ORDER BY id DESC LIMIT :limit OFFSET :offset"), params).mappings().all()
            items = [dict(row) for row in rows]
        else:
            # No mqtt device/time index exists in the current migrations. Materialize
            # only IDs/times, once per request; never copy all payloads or raw BLOBs.
            # Python parsing retains microseconds and rejects ambiguous legacy times.
            db.connection().connection.driver_connection.create_function(
                "mqtt_received_us", 1, mqtt_received_microseconds, deterministic=True
            )
            range_filters = ["received_us IS NOT NULL"]
            if start is not None:
                range_filters.append("received_us >= :from_us")
                params["from_us"] = datetime_microseconds(start)
            if end is not None:
                range_filters.append("received_us < :to_us")
                params["to_us"] = datetime_microseconds(end)
            # Only offset=0 audits unknown timestamps across the whole device
            # snapshot. Later pages retain that first-page audit in the client and
            # use native coarse bounds before exact parsing. A full second of
            # padding safely covers SQLite julianday rounding of microseconds.
            # A NULL native parse must still reach the exact parser: explicit
            # offsets accepted by Python can exceed SQLite's timezone range.
            scoped_where = where
            if offset:
                if start is not None:
                    scoped_where += " AND (julianday(received_at) IS NULL OR julianday(received_at) >= julianday(:coarse_from) - 1.0 / 86400)"
                    params["coarse_from"] = start.isoformat()
                if end is not None:
                    scoped_where += " AND (julianday(received_at) IS NULL OR julianday(received_at) < julianday(:coarse_to) + 1.0 / 86400)"
                    params["coarse_to"] = end.isoformat()
            unavailable_sql = "(SELECT COUNT(*) FROM scoped WHERE received_us IS NULL)" if offset == 0 else "NULL"
            # All source rows between selected IDs must be accounted for, even
            # when their timestamp/payload prevents inclusion in this graph.
            source_span_sql = f"""(SELECT COUNT(*) FROM mqtt_logs WHERE {source_where}
                AND id BETWEEN (SELECT MIN(id) FROM matching) AND (SELECT MAX(id) FROM matching))""" if offset == 0 else "NULL"
            selected = ", ".join(f"logs.{column.strip()}" for column in _COLUMNS.split(","))
            result = db.execute(text(f"""
                WITH scoped AS MATERIALIZED (
                    SELECT id, mqtt_received_us(received_at) AS received_us
                    FROM mqtt_logs WHERE {scoped_where}
                ), matching AS MATERIALIZED (
                    SELECT id, received_us FROM scoped WHERE {' AND '.join(range_filters)}
                ), page AS (
                    SELECT id, received_us FROM matching
                    ORDER BY received_us DESC, id DESC LIMIT :limit OFFSET :offset
                ), stats AS (
                    SELECT (SELECT COUNT(*) FROM matching) AS matched_total,
                           {unavailable_sql} AS unavailable_total,
                           {source_span_sql} AS source_span_total
                )
                SELECT stats.matched_total, stats.unavailable_total, stats.source_span_total, {selected}
                FROM stats LEFT JOIN page ON 1 = 1 LEFT JOIN mqtt_logs AS logs ON logs.id = page.id
                ORDER BY page.received_us DESC, page.id DESC
            """), params).mappings().all()
            total = int(result[0]["matched_total"])
            unavailable = int(result[0]["unavailable_total"]) if offset == 0 else None
            source_span = int(result[0]["source_span_total"]) if offset == 0 else None
            items = [{key: value for key, value in row.items() if key not in ("matched_total", "unavailable_total", "source_span_total")}
                     for row in result if row["id"] is not None]
        return {
            "items": items, "total": total, "snapshot_max_id": maximum,
            "offset": offset, "limit": limit, "has_more": offset + len(items) < total,
            "applied_validity_filters": {
                "is_json_valid": is_json_valid, "is_topic_valid": is_topic_valid,
                "valid_only": valid_only,
            },
            "source_span_count": source_span,
            "source_span_count_scope": "selected_source_ids_first_page" if ranged else "not_evaluated",
            "timestamp_unavailable_count": unavailable,
            "timestamp_unavailable_count_scope": "device_snapshot_first_page" if ranged else "not_evaluated",
            # No outside-range predecessor is fetched or manufactured. The first
            # chronological row has no interval, even when more history exists.
            "interval_predecessor_policy": "within_range_only",
        }