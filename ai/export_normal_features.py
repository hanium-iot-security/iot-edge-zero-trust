"""Isolation Forest 학습용 정상 feature log를 CSV로 export합니다."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import SessionLocal

EXPORT_COLUMNS = [
    "device_id",
    "window_start",
    "window_end",
    "publish_count",
    "avg_payload_size",
    "max_payload_size",
    "avg_message_interval",
    "min_message_interval",
]


def export_normal_features(
    db: Session,
    output: str | Path,
    device_id: str | None = None,
    limit: int | None = None,
) -> int:
    filters = [
        "fl.publish_count BETWEEN 1 AND 3",
        "fl.avg_payload_size BETWEEN 20 AND 100",
        "fl.abnormal_topic_count = 0",
        "fl.malformed_payload_count = 0",
        "fl.topic_count = 1",
        "fl.max_payload_size <= 100",
        "fl.avg_message_interval BETWEEN 4 AND 6",
        "fl.min_message_interval BETWEEN 4 AND 6",
        "d.status != 'isolated'",
    ]
    params: dict[str, Any] = {}
    if device_id:
        filters.append("fl.device_id = :device_id")
        params["device_id"] = device_id

    limit_clause = ""
    if limit is not None:
        limit_clause = "LIMIT :limit"
        params["limit"] = limit

    rows = db.execute(
        text(
            f"""
            SELECT
                fl.device_id,
                fl.window_start,
                fl.window_end,
                fl.publish_count,
                fl.avg_payload_size,
                fl.max_payload_size,
                fl.avg_message_interval,
                fl.min_message_interval
            FROM feature_logs fl
            JOIN devices d ON d.device_id = fl.device_id
            WHERE {' AND '.join(filters)}
            ORDER BY fl.window_start ASC, fl.id ASC
            {limit_clause}
            """
        ),
        params,
    ).mappings()

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=EXPORT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row[column] for column in EXPORT_COLUMNS})
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="정상 feature log를 Isolation Forest 학습용 CSV로 export합니다.")
    parser.add_argument("--device-id", default=None, help="특정 device_id만 export합니다.")
    parser.add_argument("--limit", type=int, default=None, help="export할 최대 row 수")
    parser.add_argument("--output", default="data/exports/normal_features.csv", help="출력 CSV 경로")
    args = parser.parse_args()

    with SessionLocal() as db:
        count = export_normal_features(db, output=args.output, device_id=args.device_id, limit=args.limit)
    print(f"정상 feature CSV export 완료: {args.output} ({count} rows)")


if __name__ == "__main__":
    main()
