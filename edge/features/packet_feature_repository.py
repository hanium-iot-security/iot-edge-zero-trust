"""Repository helpers for packet feature extraction and queries."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import parse_db_utc
from edge.packet.pcap_naming import format_utc_iso
from edge.policy.repository import load_policy_resolver

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
RECONCILIATION_STATUS_BATCH_SIZE = 500

BROKER_TARGET_COLUMNS = ("broker_target_ip", "broker_target_port", "broker_target_syn_count")


def _has_broker_target_schema(db: Session) -> bool:
    columns = {row[1] for row in db.execute(text("PRAGMA table_info(packet_feature_logs)"))}
    present = set(BROKER_TARGET_COLUMNS) & columns
    if present and present != set(BROKER_TARGET_COLUMNS):
        raise ValueError("Packet Broker target schema is incomplete")
    return bool(present)


def require_broker_target_schema(db: Session) -> None:
    if not _has_broker_target_schema(db):
        raise ValueError("Packet Broker target evidence requires Migration 013")


def _broker_target_values(row: dict[str, Any]) -> dict[str, Any]:
    values = {name: row.get(name) for name in BROKER_TARGET_COLUMNS}
    if all(value is None for value in values.values()):
        return values
    ip, port, count = (values[name] for name in BROKER_TARGET_COLUMNS)
    if (not isinstance(ip, str) or type(port) is not int or port != 1883
            or type(count) is not int or count < 0):
        raise ValueError("Packet Broker evidence requires IPv4, port 1883 and a nonnegative integer count")
    try:
        if str(IPv4Address(ip)) != ip:
            raise ValueError
    except ValueError as exc:
        raise ValueError("Packet Broker target must be a canonical IPv4 address") from exc
    return values


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


def get_reconcilable_segment_statuses_by_file_names(
    db: Session,
    *,
    file_names: list[str],
    session_id: str | None = None,
    batch_size: int = RECONCILIATION_STATUS_BATCH_SIZE,
) -> dict[str, str]:
    """ready/ 파일 중 terminal DB 상태만 batch 조회합니다.

    READY 또는 DB에 없는 파일은 Reconciliation 이동 대상이 아니므로 결과에서
    제외합니다. SQLite host parameter 수를 안정적으로 제한하기 위해 file_names를
    고정 크기 batch로 나눕니다.
    """
    if not file_names:
        return {}
    if batch_size < 1:
        raise ValueError(f"batch_size는 1 이상이어야 합니다: {batch_size}")

    statement = text(
        """
        SELECT pcsg.file_name, pcsg.status
        FROM packet_capture_segments pcsg
        JOIN packet_capture_sessions pcs
            ON pcs.id = pcsg.capture_session_id
        WHERE pcsg.file_name IN :file_names
          AND pcsg.status IN ('PROCESSED', 'EMPTY', 'FAILED')
          AND (:session_id IS NULL OR pcs.session_id = :session_id)
        """
    ).bindparams(bindparam("file_names", expanding=True))

    statuses: dict[str, str] = {}
    for start in range(0, len(file_names), batch_size):
        chunk = file_names[start : start + batch_size]
        rows = db.execute(
            statement,
            {"file_names": chunk, "session_id": session_id},
        ).mappings()
        for row in rows:
            statuses[str(row["file_name"])] = str(row["status"])
    return statuses


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
    has_broker_target = _has_broker_target_schema(db)
    # Validate the whole batch before any feature insert, including legacy schemas.
    broker_values = [_broker_target_values(row) for row in feature_rows]
    if not has_broker_target and any(
        value is not None for values in broker_values for value in values.values()
    ):
        raise ValueError("Packet Broker target evidence requires Migration 013")
    extra_columns = ", " + ", ".join(BROKER_TARGET_COLUMNS) if has_broker_target else ""
    extra_values = ", " + ", ".join(":" + name for name in BROKER_TARGET_COLUMNS) if has_broker_target else ""
    resolver = load_policy_resolver(db)
    for row, broker in zip(feature_rows, broker_values):
        device_id = (
            resolver.device_id_for_ip(
                str(row["peer_ip"]),
                parse_db_utc(row["window_start"], "window_start"),
            )
            if resolver is not None else ip_device_map.get(row["peer_ip"])
        )
        # ON CONFLICT DO NOTHING only ignores duplicate feature keys.
        # NOT NULL/CHECK failures still propagate so the caller can rollback.
        result = db.execute(
            text(
                f"""
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
                    capture_scope{extra_columns}
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
                    :capture_scope{extra_values}
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
                **(broker if has_broker_target else {}),
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
    has_broker_target = _has_broker_target_schema(db)
    broker_projection = ", ".join(
        f"pfl.{name}" if has_broker_target else f"NULL AS {name}"
        for name in BROKER_TARGET_COLUMNS
    )
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
                {broker_projection},
                pfl.capture_scope,
                pfl.created_at,
                pcsg.status AS segment_status,
                pcsg.error_code AS segment_error_code,
                pcsg.start_delay_seconds,
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
