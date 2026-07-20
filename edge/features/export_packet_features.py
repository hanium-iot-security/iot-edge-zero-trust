"""packet_feature_logs를 DB에서 읽어 CSV로 내보냅니다."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text

from backend.app.database import SessionLocal
from edge.features.packet_feature_utils import export_packet_features_csv

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT = Path("data/exports/packet_features.csv")


def _fetch_feature_rows(
    session_id: str | None,
    window_start_from: str | None,
    window_start_to: str | None,
) -> list[dict[str, Any]]:
    filters: list[str] = []
    params: dict[str, Any] = {}

    if session_id:
        filters.append("pcs.session_id = :session_id")
        params["session_id"] = session_id

    if window_start_from:
        filters.append("pfl.window_start >= :window_start_from")
        params["window_start_from"] = window_start_from

    if window_start_to:
        filters.append("pfl.window_start <= :window_start_to")
        params["window_start_to"] = window_start_to

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    query = text(
        f"""
        SELECT
            pcs.session_id   AS session_id,
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
            pfl.non_mqtt_tcp_udp_packet_count
        FROM packet_feature_logs pfl
        JOIN packet_capture_segments pcsg
            ON pfl.capture_segment_id = pcsg.id
        JOIN packet_capture_sessions pcs
            ON pcsg.capture_session_id = pcs.id
        {where_clause}
        ORDER BY pfl.window_start, pfl.peer_ip, pfl.direction
        """
    )

    with SessionLocal() as db:
        rows = db.execute(query, params).mappings()
        return [dict(row) for row in rows]


def export_features(
    output_path: Path = DEFAULT_OUTPUT,
    session_id: str | None = None,
    window_start_from: str | None = None,
    window_start_to: str | None = None,
) -> int:
    rows = _fetch_feature_rows(session_id, window_start_from, window_start_to)
    count = export_packet_features_csv(rows, output_path)
    logger.info("CSV 내보내기 완료: %s (%d rows)", output_path, count)
    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="packet_feature_logs를 CSV로 내보냅니다."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--session-id", type=str, default=None)
    parser.add_argument("--from", dest="window_start_from", type=str, default=None,
                        help="window_start 시작 필터 (ISO 8601, e.g. 2026-07-16T10:00:00Z)")
    parser.add_argument("--to", dest="window_start_to", type=str, default=None,
                        help="window_start 종료 필터 (ISO 8601)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    count = export_features(
        output_path=args.output,
        session_id=args.session_id,
        window_start_from=args.window_start_from,
        window_start_to=args.window_start_to,
    )
    print(f"내보낸 행 수: {count}")
    print(f"출력 파일: {args.output}")


if __name__ == "__main__":
    main()
