"""mqtt_logs를 10초 feature window로 집계합니다."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from pathlib import Path
import sys
import time
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import SessionLocal
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import (
    WINDOW_SECONDS,
    format_db_utc,
    floor_window_start as phase4_floor_window_start,
    parse_db_utc,
    require_utc_window_boundary,
)


DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
MQTT_FEATURE_BUILDER = "mqtt_feature_builder"
MQTT_LOGS_SOURCE = "mqtt_logs"
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProducerRunResult:
    source_table: str
    cutoff: datetime
    selected_count: int
    created_feature_count: int
    late_source_count: int
    last_processed_id_before: int | None
    last_processed_id_after: int | None
    completed_window_end_before: datetime | None
    completed_window_end_after: datetime


def parse_db_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.replace(microsecond=0)
    # Python 3.10 이하에서는 fromisoformat()이 'Z' 접미사를 처리하지 못함
    normalized = value[:-1] + "+00:00" if isinstance(value, str) and value.endswith("Z") else value
    return datetime.fromisoformat(normalized).replace(microsecond=0)


def format_db_datetime(value: datetime) -> str:
    return value.replace(microsecond=0).strftime(DATETIME_FORMAT)


def floor_window_start(value: datetime, window_seconds: int) -> datetime:
    return value.replace(second=(value.second // window_seconds) * window_seconds, microsecond=0)


def registered_feature_devices(db: Session) -> set[str]:
    rows = db.execute(
        text(
            """
            SELECT device_id
            FROM devices
            WHERE status != 'isolated'
            """
        )
    ).scalars()
    return {str(device_id) for device_id in rows}


def _intervals_seconds(rows: list[dict[str, Any]]) -> list[float]:
    received_times = sorted(parse_db_datetime(row["received_at"]) for row in rows)
    return [
        (received_times[index] - received_times[index - 1]).total_seconds()
        for index in range(1, len(received_times))
    ]


def build_feature_row(
    device_id: str,
    window_start: datetime,
    window_end: datetime,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    payload_sizes = [int(row["payload_size"] or 0) for row in rows]
    intervals = _intervals_seconds(rows)
    if not intervals:
        intervals = [5.0]

    return {
        "device_id": device_id,
        "window_start": format_db_datetime(window_start),
        "window_end": format_db_datetime(window_end),
        "publish_count": len(rows),
        "avg_payload_size": sum(payload_sizes) / len(payload_sizes),
        "max_payload_size": max(payload_sizes),
        "avg_message_interval": sum(intervals) / len(intervals),
        "min_message_interval": min(intervals),
        "topic_count": len({row["topic"] for row in rows}),
        "abnormal_topic_count": sum(1 for row in rows if int(row["is_topic_valid"]) == 0),
        "malformed_payload_count": sum(1 for row in rows if int(row["is_json_valid"]) == 0),
    }


def _feature_window_exists(db: Session, row: dict[str, Any]) -> bool:
    exists = db.execute(
        text(
            """
            SELECT 1
            FROM feature_logs
            WHERE device_id = :device_id
              AND window_start = :window_start
              AND window_end = :window_end
            LIMIT 1
            """
        ),
        row,
    ).first()
    return exists is not None


def _insert_feature_row(db: Session, row: dict[str, Any]) -> bool:
    if _feature_window_exists(db, row):
        return False

    db.execute(
        text(
            """
            INSERT INTO feature_logs (
                device_id,
                window_start,
                window_end,
                publish_count,
                avg_payload_size,
                max_payload_size,
                avg_message_interval,
                min_message_interval,
                topic_count,
                abnormal_topic_count,
                malformed_payload_count
            )
            VALUES (
                :device_id,
                :window_start,
                :window_end,
                :publish_count,
                :avg_payload_size,
                :max_payload_size,
                :avg_message_interval,
                :min_message_interval,
                :topic_count,
                :abnormal_topic_count,
                :malformed_payload_count
            )
            """
        ),
        row,
    )
    return True


def collect_feature_windows(
    db: Session,
    now: datetime | None = None,
    window_seconds: int | None = None,
) -> int:
    now = (now or datetime.now()).replace(microsecond=0)
    window_seconds = window_seconds or settings.feature_window_seconds
    registered_devices = registered_feature_devices(db)
    if not registered_devices:
        return 0

    rows = db.execute(
        text(
            """
            SELECT
                id,
                device_id,
                topic,
                payload_size,
                received_at,
                is_json_valid,
                is_topic_valid
            FROM mqtt_logs
            WHERE device_id IS NOT NULL
              AND received_at <= :now
            ORDER BY received_at ASC, id ASC
            """
        ),
        {"now": format_db_datetime(now)},
    ).mappings()

    grouped: dict[tuple[str, datetime, datetime], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        device_id = str(row["device_id"])
        if device_id not in registered_devices:
            continue

        received_at = parse_db_datetime(row["received_at"])
        window_start = floor_window_start(received_at, window_seconds)
        window_end = window_start + timedelta(seconds=window_seconds)
        if window_end > now:
            continue

        grouped[(device_id, window_start, window_end)].append(dict(row))

    inserted_count = 0
    for (device_id, window_start, window_end), window_rows in grouped.items():
        feature_row = build_feature_row(device_id, window_start, window_end, window_rows)
        if _insert_feature_row(db, feature_row):
            inserted_count += 1

    db.commit()
    return inserted_count


def produce_mqtt_features_until(
    db: Session,
    *,
    producer_cutoff: datetime,
) -> ProducerRunResult:
    """Build mqtt feature windows and checkpoint them in the caller transaction."""
    cutoff = require_utc_window_boundary(producer_cutoff, "producer_cutoff")
    checkpoint = checkpoints.get_detector_checkpoint(
        db,
        detector_name=MQTT_FEATURE_BUILDER,
        source_table=MQTT_LOGS_SOURCE,
    )
    last_processed_before = (
        int(checkpoint["last_processed_id"])
        if checkpoint is not None and checkpoint["last_processed_id"] is not None
        else None
    )
    completed_before = (
        parse_db_utc(
            checkpoint["last_completed_window_end"],
            "last_completed_window_end",
        )
        if checkpoint is not None and checkpoint["last_completed_window_end"] is not None
        else None
    )
    if completed_before is not None and completed_before > cutoff:
        raise ValueError("existing MQTT feature checkpoint exceeds producer_cutoff")

    registered_devices = registered_feature_devices(db)
    source_rows = _fetch_mqtt_sources_after_checkpoint(
        db,
        last_processed_id=last_processed_before,
        cutoff=cutoff,
    )

    grouped: dict[tuple[str, datetime, datetime], list[dict[str, Any]]] = defaultdict(list)
    late_source_count = 0
    last_processed_after = last_processed_before

    for row in source_rows:
        source = dict(row)
        source_id = int(source["id"])
        last_processed_after = (
            source_id
            if last_processed_after is None
            else max(last_processed_after, source_id)
        )
        received_at = parse_db_utc(source["received_at"], "received_at")
        window_start = phase4_floor_window_start(received_at)
        window_end = window_start + timedelta(seconds=WINDOW_SECONDS)

        if completed_before is not None and window_end <= completed_before:
            late_source_count += 1
            logger.info(
                "event=LATE_SOURCE source_table=mqtt_logs source_id=%s "
                "received_at=%s last_completed_window_end=%s",
                source_id,
                format_db_utc(received_at),
                format_db_utc(completed_before),
            )
            continue
        if window_end > cutoff:
            continue
        device_id = str(source["device_id"]) if source["device_id"] is not None else ""
        if device_id not in registered_devices:
            continue
        grouped[(device_id, window_start, window_end)].append(source)

    inserted_count = 0
    for (device_id, window_start, window_end), window_rows in grouped.items():
        feature_row = build_feature_row(device_id, window_start, window_end, window_rows)
        if _insert_feature_row(db, feature_row):
            inserted_count += 1

    checkpoints.upsert_detector_checkpoint(
        db,
        detector_name=MQTT_FEATURE_BUILDER,
        source_table=MQTT_LOGS_SOURCE,
        last_processed_id=last_processed_after,
        last_completed_window_end=cutoff,
        updated_at=cutoff,
    )

    return ProducerRunResult(
        source_table=MQTT_LOGS_SOURCE,
        cutoff=cutoff,
        selected_count=len(source_rows),
        created_feature_count=inserted_count,
        late_source_count=late_source_count,
        last_processed_id_before=last_processed_before,
        last_processed_id_after=last_processed_after,
        completed_window_end_before=completed_before,
        completed_window_end_after=cutoff,
    )


def _fetch_mqtt_sources_after_checkpoint(
    db: Session,
    *,
    last_processed_id: int | None,
    cutoff: datetime,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT
                id,
                device_id,
                topic,
                payload_size,
                received_at,
                is_json_valid,
                is_topic_valid
            FROM mqtt_logs
            WHERE (:last_processed_id IS NULL OR id > :last_processed_id)
              AND unixepoch(received_at) < unixepoch(:cutoff)
            ORDER BY id ASC
            """
        ),
        {
            "last_processed_id": last_processed_id,
            "cutoff": format_db_utc(cutoff),
        },
    ).mappings()
    return [dict(row) for row in rows]


def main() -> None:
    parser = argparse.ArgumentParser(description="mqtt_logs를 10초 feature window로 집계합니다.")
    parser.add_argument("--loop", action="store_true", help="반복 실행합니다.")
    parser.add_argument("--interval", type=float, default=5.0, help="loop 모드 실행 간격, 초 단위")
    args = parser.parse_args()

    while True:
        with SessionLocal() as db:
            inserted_count = collect_feature_windows(db)
        print(f"feature_logs 생성: {inserted_count} rows")
        if not args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
