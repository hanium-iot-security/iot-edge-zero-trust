import csv

from sqlalchemy import text

from ai.export_normal_features import export_normal_features
from tests.conftest import cleanup_device


def test_export_normal_features_filters_training_rows(db_session, tmp_path) -> None:
    device_id = "test_export_normal"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.95', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.execute(
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
            VALUES
                (:device_id, '2026-05-26 14:30:00', '2026-05-26 14:30:10', 2, 29.0, 29, 5.0, 5.0, 1, 0, 0),
                (:device_id, '2026-05-26 14:30:10', '2026-05-26 14:30:20', 4, 29.0, 29, 2.5, 2.5, 1, 0, 0),
                (:device_id, '2026-05-26 14:30:20', '2026-05-26 14:30:30', 2, 120.0, 120, 5.0, 5.0, 1, 0, 0),
                (:device_id, '2026-05-26 14:30:30', '2026-05-26 14:30:40', 2, 29.0, 29, 5.0, 5.0, 1, 1, 0),
                (:device_id, '2026-05-26 14:30:40', '2026-05-26 14:30:50', 2, 29.0, 29, 5.0, 5.0, 1, 0, 1)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    output = tmp_path / "train_normal_final.csv"
    count = export_normal_features(db_session, output, device_id=device_id)

    assert count == 1
    rows = list(csv.DictReader(output.open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["device_id"] == device_id
    assert rows[0]["publish_count"] == "2"
    assert rows[0]["avg_message_interval"] == "5.0"
    cleanup_device(db_session, device_id)
