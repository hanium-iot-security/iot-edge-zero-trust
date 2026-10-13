"""Broker target storage contract: unknown historical evidence is never zero."""
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import MIGRATIONS_DIR, MigrationError, apply_migrations
from edge.features.packet_feature_repository import (
    BROKER_TARGET_COLUMNS, insert_packet_feature_rows, list_packet_feature_logs,
    require_broker_target_schema,
)
from backend.app.services.packet_feature_query_service import list_packet_features


def _database(tmp_path, *, migrated=True):
    path = tmp_path / "broker.db"
    previous = tmp_path / "previous"
    previous.mkdir()
    for source in MIGRATIONS_DIR.glob("*.sql"):
        if int(source.name.split("_", 1)[0]) <= 12:
            (previous / source.name).write_bytes(source.read_bytes())
    apply_migrations(path, MIGRATIONS_DIR if migrated else previous)
    with sqlite3.connect(path) as db:
        db.execute("""INSERT INTO packet_capture_sessions
            (id,session_id,capture_interface,started_at,first_window_start)
            VALUES(1,'11111111-1111-4111-8111-111111111111','eth0',
                '2026-07-16T10:00:00Z','2026-07-16T10:00:00Z')""")
        db.execute("""INSERT INTO packet_capture_segments
            (id,capture_session_id,file_name,capture_interface,window_start,window_end,status,
             start_delay_seconds,captured_duration_seconds)
            VALUES(1,1,'a.pcap','eth0','2026-07-16T10:00:00Z','2026-07-16T10:00:10Z',
                'PROCESSED',0,10)""")
    return path, previous


def _feature(**extra):
    return dict(peer_ip="192.168.0.10", direction="INBOUND",
                window_start="2026-07-16T10:00:00Z", window_end="2026-07-16T10:00:10Z",
                packet_count=5, total_bytes=300, avg_packet_size=60, max_packet_size=60,
                mean_inter_arrival_time=1.0, distinct_dest_port_count=2, tcp_syn_count=3,
                mqtt_related_packet_count=4, non_mqtt_tcp_udp_packet_count=1, **extra)


def _target(count=2):
    return dict(broker_target_ip="192.168.0.20", broker_target_port=1883,
                broker_target_syn_count=count)


def _insert(db, rows):
    return insert_packet_feature_rows(db, capture_segment_id=1, feature_rows=rows,
                                      ip_device_map={}, capture_scope="PI1_INTERNAL_LAN")


def test_migration_preserves_history_and_leaves_three_nulls(tmp_path):
    path, _ = _database(tmp_path, migrated=False)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db, db.begin():
            assert _insert(db, [_feature()]) == 1
        with sqlite3.connect(path) as db:
            before = db.execute("SELECT * FROM packet_feature_logs").fetchone()
            indexes = db.execute("SELECT name,sql FROM sqlite_master WHERE type='index' "
                                 "AND tbl_name='packet_feature_logs' ORDER BY name").fetchall()
        assert apply_migrations(path, MIGRATIONS_DIR).applied_versions == [13]
        with sqlite3.connect(path) as db:
            row = db.execute("SELECT * FROM packet_feature_logs").fetchone()
            assert row[:-3] == before
            assert row[-3:] == (None, None, None)
            assert db.execute("SELECT name,sql FROM sqlite_master WHERE type='index' "
                              "AND tbl_name='packet_feature_logs' ORDER BY name").fetchall() == indexes
            assert db.execute("PRAGMA foreign_key_check").fetchall() == []
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert apply_migrations(path, MIGRATIONS_DIR).applied_versions == []
    finally:
        engine.dispose()


def test_migration_failure_rolls_back_all_added_columns(tmp_path):
    path, previous = _database(tmp_path, migrated=False)
    migration = MIGRATIONS_DIR / "013_packet_broker_target.sql"
    (previous / migration.name).write_text(
        migration.read_text(encoding="utf-8") + "\nSELECT * FROM nonexistent_broker_table;\n",
        encoding="utf-8",
    )
    with pytest.raises(MigrationError):
        apply_migrations(path, previous)
    with sqlite3.connect(path) as db:
        assert not set(BROKER_TARGET_COLUMNS) & {
            row[1] for row in db.execute("PRAGMA table_info(packet_feature_logs)")
        }
        assert db.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (12,)
        assert db.execute("SELECT COUNT(*) FROM packet_capture_segments").fetchone() == (1,)


@pytest.mark.parametrize("target", [
    (None, 1883, 0), ("192.168.0.20", None, 0), ("192.168.0.20", 1883, None),
    (None, None, 0), ("192.168.0.20", 9001, 0), ("192.168.0.20", 1883, -1),
    ("192.168.0.20", 1883, 1.5), ("192.168.0.20", 1883, "bad"),
    (" ", 1883, 0),
])
def test_sql_rejects_partial_tuple_or_invalid_integer(tmp_path, target):
    path, _ = _database(tmp_path)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db, db.begin():
            _insert(db, [_feature()])
        with sqlite3.connect(path) as db:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute("""UPDATE packet_feature_logs SET
                    broker_target_ip=?,broker_target_port=?,broker_target_syn_count=?""", target)
            assert db.execute("SELECT broker_target_syn_count FROM packet_feature_logs").fetchone() == (None,)
    finally:
        engine.dispose()


@pytest.mark.parametrize("update", [
    {"broker_target_ip": None}, {"broker_target_ip": "::1"},
    {"broker_target_ip": "192.168.00.20"}, {"broker_target_port": True},
    {"broker_target_port": 9001}, {"broker_target_syn_count": True},
    {"broker_target_syn_count": 1.0}, {"broker_target_syn_count": "1"},
    {"broker_target_syn_count": -1},
])
def test_repository_rejects_bad_evidence_before_batch_writes(tmp_path, update):
    path, _ = _database(tmp_path)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db:
            bad = _target()
            bad.update(update)
            with pytest.raises(ValueError):
                _insert(db, [_feature(), _feature(**bad)])
            assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs")).scalar_one() == 0
    finally:
        engine.dispose()


def test_count_zero_and_unknown_are_distinct_and_duplicate_is_immutable(tmp_path):
    path, _ = _database(tmp_path)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db, db.begin():
            require_broker_target_schema(db)
            inbound = _feature(**_target())
            outbound = _feature(**_target(0))
            outbound["direction"] = "OUTBOUND"
            assert _insert(db, [inbound, outbound]) == 2
            assert _insert(db, [_feature(**_target(99))]) == 0
            rows = list_packet_feature_logs(db)
            by_direction = {row["direction"]: row for row in rows}
            assert by_direction["INBOUND"]["broker_target_syn_count"] == 2
            assert by_direction["OUTBOUND"]["broker_target_syn_count"] == 0
            assert all(row["broker_target_ip"] == "192.168.0.20" for row in rows)
            assert all(row["packet_count"] == 5 and row["tcp_syn_count"] == 3 for row in rows)
    finally:
        engine.dispose()


def test_legacy_schema_accepts_unconfigured_rows_but_rejects_broker_evidence(tmp_path):
    path, _ = _database(tmp_path, migrated=False)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db, db.begin():
            with pytest.raises(ValueError, match="Migration 013"):
                require_broker_target_schema(db)
            assert _insert(db, [_feature()]) == 1
            with pytest.raises(ValueError, match="Migration 013"):
                _insert(db, [_feature(**_target(0))])
            rows = list_packet_features(db)
            assert rows["total"] == 1
            assert all(rows["items"][0][name] is None for name in BROKER_TARGET_COLUMNS)
            assert rows["items"][0]["packets_per_second"] == 0.5
    finally:
        engine.dispose()


def test_partial_schema_fails_before_insert_or_query(tmp_path):
    path, _ = _database(tmp_path, migrated=False)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE packet_feature_logs ADD COLUMN broker_target_syn_count INTEGER")
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db:
            for operation in (
                lambda: require_broker_target_schema(db),
                lambda: _insert(db, [_feature()]),
                lambda: list_packet_feature_logs(db),
            ):
                with pytest.raises(ValueError, match="incomplete"):
                    operation()
            assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs")).scalar_one() == 0
    finally:
        engine.dispose()


def test_broker_feature_rollback_uses_callers_transaction(tmp_path):
    path, _ = _database(tmp_path)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db:
            with pytest.raises(RuntimeError):
                with db.begin():
                    _insert(db, [_feature(**_target())])
                    raise RuntimeError("later extractor failure")
            assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs")).scalar_one() == 0
    finally:
        engine.dispose()
