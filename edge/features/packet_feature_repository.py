"""Repository helpers for packet feature extraction and queries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def load_ip_device_map(db: Session) -> dict[str, str]:
    rows = db.execute(
        text(
            """
            SELECT device_id, ip_address
            FROM devices
            WHERE ip_address IS NOT NULL
              AND ip_address != ''
            """
        )
    ).mappings()
    return {
        str(row["ip_address"]): str(row["device_id"])
        for row in rows
        if row["ip_address"]
    }


def fetch_ready_segments(
    db: Session,
    *,
    limit: int,
    session_id: str | None = None,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT
                pcsg.id,
                pcsg.file_name,
                pcsg.window_start,
                pcsg.window_end,
                pcs.session_id
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs
                ON pcs.id = pcsg.capture_session_id
            WHERE pcsg.status = 'READY'
              AND (:session_id IS NULL OR pcs.session_id = :session_id)
            ORDER BY pcsg.window_start ASC, pcsg.id ASC
            LIMIT :limit
            """
        ),
        {"limit": limit, "session_id": session_id},
    ).mappings()
    return [dict(row) for row in rows]


def get_segment_status_by_file_name(
    db: Session,
    *,
    file_name: str,
    session_id: str | None = None,
) -> str | None:
    row = db.execute(
        text(
            """
            SELECT pcsg.status
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs
                ON pcs.id = pcsg.capture_session_id
            WHERE pcsg.file_name = :file_name
              AND (:session_id IS NULL OR pcs.session_id = :session_id)
            """
        ),
        {"file_name": file_name, "session_id": session_id},
    ).first()
    return str(row[0]) if row is not None else None


def update_capture_segment_status(
    db: Session,
    *,
    segment_id: int,
    status: str,
    packet_count: int | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    now = datetime.utcnow().strftime(DATETIME_FORMAT)
    db.execute(
        text(
            """
            UPDATE packet_capture_segments
            SET status        = :status,
                packet_count  = :packet_count,
                processed_at  = :processed_at,
                error_code    = :error_code,
                error_message = :error_message,
                updated_at    = :updated_at
            WHERE id = :id
            """
        ),
        {
            "status": status,
            "packet_count": packet_count,
            "processed_at": now if status in ("PROCESSED", "EMPTY") else None,
            "error_code": error_code,
            "error_message": error_message,
            "updated_at": now,
            "id": segment_id,
        },
    )


def insert_packet_feature_rows(
    db: Session,
    *,
    capture_segment_id: int,
    feature_rows: list[dict[str, Any]],
    ip_device_map: dict[str, str],
    capture_scope: str,
) -> int:
    inserted_count = 0
    for row in feature_rows:
        device_id = ip_device_map.get(row["peer_ip"])
        # ON CONFLICT DO NOTHING only ignores duplicate feature keys.
        # NOT NULL/CHECK failures still propagate so the caller can rollback.
        result = db.execute(
            text(
                """
                INSERT INTO packet_feature_logs (
                    capture_segment_id,
                    device_id,
                    peer_ip,
                    direction,
                    window_start,
                    window_end,
                    packet_count,
                    total_bytes,
                    avg_packet_size,
                    max_packet_size,
                    mean_inter_arrival_time,
                    distinct_dest_port_count,
                    tcp_syn_count,
                    mqtt_related_packet_count,
                    non_mqtt_tcp_udp_packet_count,
                    capture_scope
                )
                VALUES (
                    :capture_segment_id,
                    :device_id,
                    :peer_ip,
                    :direction,
                    :window_start,
                    :window_end,
                    :packet_count,
                    :total_bytes,
                    :avg_packet_size,
                    :max_packet_size,
                    :mean_inter_arrival_time,
                    :distinct_dest_port_count,
                    :tcp_syn_count,
                    :mqtt_related_packet_count,
                    :non_mqtt_tcp_udp_packet_count,
                    :capture_scope
                )
                ON CONFLICT(capture_segment_id, peer_ip, direction) DO NOTHING
                """
            ),
            {
                "capture_segment_id": capture_segment_id,
                "device_id": device_id,
                "peer_ip": row["peer_ip"],
                "direction": row["direction"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "packet_count": row["packet_count"],
                "total_bytes": row["total_bytes"],
                "avg_packet_size": row["avg_packet_size"],
                "max_packet_size": row["max_packet_size"],
                "mean_inter_arrival_time": row["mean_inter_arrival_time"],
                "distinct_dest_port_count": row["distinct_dest_port_count"],
                "tcp_syn_count": row["tcp_syn_count"],
                "mqtt_related_packet_count": row["mqtt_related_packet_count"],
                "non_mqtt_tcp_udp_packet_count": row["non_mqtt_tcp_udp_packet_count"],
                "capture_scope": capture_scope,
            },
        )
        inserted_count += max(result.rowcount or 0, 0)
    return inserted_count


def list_packet_feature_logs(
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
) -> list[dict[str, Any]]:
    where_clause, params = _packet_feature_filters(
        session_id=session_id,
        device_id=device_id,
        peer_ip=peer_ip,
        direction=direction,
        from_at=from_at,
        to_at=to_at,
    )
    params.update({"limit": limit, "offset": offset})
    rows = db.execute(
        text(
            f"""
            SELECT
                pfl.id,
                pfl.capture_segment_id,
                pcs.session_id AS session_id,
                pfl.device_id,
                pfl.peer_ip,
                pfl.direction,
                pfl.window_start,
                pfl.window_end,
                pfl.packet_count,
                pfl.total_bytes,
                pfl.avg_packet_size,
                pfl.max_packet_size,
                pfl.mean_inter_arrival_time,
                pfl.distinct_dest_port_count,
                pfl.tcp_syn_count,
                pfl.mqtt_related_packet_count,
                pfl.non_mqtt_tcp_udp_packet_count,
                pfl.capture_scope,
                pfl.created_at,
                pcsg.captured_duration_seconds
            FROM packet_feature_logs pfl
            JOIN packet_capture_segments pcsg
                ON pfl.capture_segment_id = pcsg.id
            JOIN packet_capture_sessions pcs
                ON pcsg.capture_session_id = pcs.id
            {where_clause}
            ORDER BY pfl.window_start DESC, pfl.id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings()
    return [dict(row) for row in rows]


def count_packet_feature_logs(
    db: Session,
    *,
    session_id: str | None = None,
    device_id: str | None = None,
    peer_ip: str | None = None,
    direction: str | None = None,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
) -> int:
    where_clause, params = _packet_feature_filters(
        session_id=session_id,
        device_id=device_id,
        peer_ip=peer_ip,
        direction=direction,
        from_at=from_at,
        to_at=to_at,
    )
    row = db.execute(
        text(
            f"""
            SELECT COUNT(*) AS count
            FROM packet_feature_logs pfl
            JOIN packet_capture_segments pcsg
                ON pfl.capture_segment_id = pcsg.id
            JOIN packet_capture_sessions pcs
                ON pcsg.capture_session_id = pcs.id
            {where_clause}
            """
        ),
        params,
    ).mappings().one()
    return int(row["count"])


def _packet_feature_filters(
    *,
    session_id: str | None,
    device_id: str | None,
    peer_ip: str | None,
    direction: str | None,
    from_at: datetime | None,
    to_at: datetime | None,
) -> tuple[str, dict[str, Any]]:
    filters: list[str] = []
    params: dict[str, Any] = {}
    if session_id is not None:
        filters.append("pcs.session_id = :session_id")
        params["session_id"] = session_id
    if device_id is not None:
        filters.append("pfl.device_id = :device_id")
        params["device_id"] = device_id
    if peer_ip is not None:
        filters.append("pfl.peer_ip = :peer_ip")
        params["peer_ip"] = peer_ip
    if direction is not None:
        filters.append("pfl.direction = :direction")
        params["direction"] = direction
    if from_at is not None:
        filters.append("pfl.window_start >= :from_at")
        params["from_at"] = format_utc_iso(from_at)
    if to_at is not None:
        filters.append("pfl.window_start <= :to_at")
        params["to_at"] = format_utc_iso(to_at)

    return ("WHERE " + " AND ".join(filters), params) if filters else ("", params)
