"""export_packet_features DB JOIN, 필터, CSV 출력 integration 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations

SESSION_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SESSION_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ESP_IP = "192.168.0.10"
PI_IP = "192.168.0.20"

WINDOW_START_A1 = "2026-07-16T10:00:00Z"
WINDOW_END_A1   = "2026-07-16T10:00:10Z"
WINDOW_START_A2 = "2026-07-16T10:00:10Z"
WINDOW_END_A2   = "2026-07-16T10:00:20Z"
WINDOW_START_B1 = "2026-07-16T10:00:20Z"
WINDOW_END_B1   = "2026-07-16T10:00:30Z"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "test.db"
    apply_migrations(path, MIGRATIONS_DIR)
    return path


@pytest.fixture
def db_session(db_path: Path):
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with Session() as session:
        session.execute(text("PRAGMA foreign_keys = ON"))
        yield session
    engine.dispose()


def _insert_session(db, session_uuid: str) -> int:
    db.execute(
        text(
            "INSERT INTO packet_capture_sessions "
            "(session_id, capture_interface, started_at) "
            "VALUES (:sid, 'eth0', '2026-07-16 10:00:00')"
        ),
        {"sid": session_uuid},
    )
    db.commit()
    row = db.execute(
        text("SELECT id FROM packet_capture_sessions WHERE session_id = :sid"),
        {"sid": session_uuid},
    ).fetchone()
    return row[0]


def _insert_segment(
    db,
    capture_session_id: int,
    file_name: str,
    window_start: str,
    window_end: str,
) -> int:
    db.execute(
        text(
            "INSERT INTO packet_capture_segments "
            "(capture_session_id, file_name, capture_interface, window_start, window_end, status) "
            "VALUES (:csid, :fname, 'eth0', :ws, :we, 'PROCESSED')"
        ),
        {
            "csid": capture_session_id,
            "fname": file_name,
            "ws": window_start,
            "we": window_end,
        },
    )
    db.commit()
    row = db.execute(
        text("SELECT id FROM packet_capture_segments WHERE file_name = :fname"),
        {"fname": file_name},
    ).fetchone()
    return row[0]


def _insert_feature(
    db,
    capture_segment_id: int,
    peer_ip: str,
    direction: str,
    window_start: str,
    window_end: str,
    packet_count: int = 5,
) -> int:
    db.execute(
        text(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id, device_id, peer_ip, direction,
                window_start, window_end,
                packet_count, total_bytes, avg_packet_size, max_packet_size,
                mean_inter_arrival_time, distinct_dest_port_count,
                tcp_syn_count, mqtt_related_packet_count,
                non_mqtt_tcp_udp_packet_count
            ) VALUES (
                :csid, NULL, :peer_ip, :direction,
                :ws, :we,
                :pc, 1000, 200.0, 300,
                0.5, 2, 1, 3, 1
            )
            """
        ),
        {
            "csid": capture_segment_id,
            "peer_ip": peer_ip,
            "direction": direction,
            "ws": window_start,
            "we": window_end,
            "pc": packet_count,
        },
    )
    db.commit()
    row = db.execute(
        text(
            "SELECT id FROM packet_feature_logs "
            "WHERE capture_segment_id = :csid AND peer_ip = :peer_ip AND direction = :dir"
        ),
        {"csid": capture_segment_id, "peer_ip": peer_ip, "dir": direction},
    ).fetchone()
    return row[0]


@pytest.fixture
def populated_db(db_session):
    """Session A → 2 segments × 1 feature / Session B → 1 segment × 1 feature."""
    sid_a = _insert_session(db_session, SESSION_A)
    seg_a1 = _insert_segment(db_session, sid_a, "a1.pcap", WINDOW_START_A1, WINDOW_END_A1)
    seg_a2 = _insert_segment(db_session, sid_a, "a2.pcap", WINDOW_START_A2, WINDOW_END_A2)
    _insert_feature(db_session, seg_a1, ESP_IP, "INBOUND", WINDOW_START_A1, WINDOW_END_A1, packet_count=3)
    _insert_feature(db_session, seg_a2, ESP_IP, "INBOUND", WINDOW_START_A2, WINDOW_END_A2, packet_count=7)

    sid_b = _insert_session(db_session, SESSION_B)
    seg_b1 = _insert_segment(db_session, sid_b, "b1.pcap", WINDOW_START_B1, WINDOW_END_B1)
    _insert_feature(db_session, seg_b1, ESP_IP, "OUTBOUND", WINDOW_START_B1, WINDOW_END_B1, packet_count=2)

    return db_session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _run_export(db_path: Path, monkeypatch, **kwargs) -> list[dict]:
    """export_features를 monkeypatched SessionLocal로 실행하고 CSV를 파싱해 반환."""
    import edge.features.export_packet_features as mod
    from sqlalchemy.orm import sessionmaker as sm

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    TestSession = sm(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    output = kwargs.pop("output_path")
    mod.export_features(output_path=output, **kwargs)
    engine.dispose()

    import csv
    with open(output) as f:
        return list(csv.DictReader(f))


def test_export_all_rows_returned(populated_db, db_path: Path, tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "out.csv"
    rows = _run_export(db_path, monkeypatch, output_path=output)
    assert len(rows) == 3


def test_export_csv_has_correct_columns(populated_db, db_path: Path, tmp_path: Path, monkeypatch) -> None:
    from edge.features.packet_feature_utils import CSV_FIELDS

    output = tmp_path / "out.csv"
    rows = _run_export(db_path, monkeypatch, output_path=output)
    assert set(rows[0].keys()) == set(CSV_FIELDS)


def test_export_filter_by_session_id_returns_only_that_session(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "out.csv"
    rows = _run_export(db_path, monkeypatch, output_path=output, session_id=SESSION_A)
    assert len(rows) == 2
    assert all(r["session_id"] == SESSION_A for r in rows)


def test_export_filter_by_session_id_other_session(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "out.csv"
    rows = _run_export(db_path, monkeypatch, output_path=output, session_id=SESSION_B)
    assert len(rows) == 1
    assert rows[0]["session_id"] == SESSION_B


def test_export_filter_window_start_from(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """window_start >= A2 이상만 반환 → A2 + B1 = 2행."""
    output = tmp_path / "out.csv"
    rows = _run_export(
        db_path, monkeypatch,
        output_path=output,
        window_start_from=WINDOW_START_A2,
    )
    assert len(rows) == 2
    starts = {r["window_start"] for r in rows}
    assert WINDOW_START_A1 not in starts


def test_export_filter_window_start_to(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """window_start <= A1 이하만 반환 → A1 = 1행."""
    output = tmp_path / "out.csv"
    rows = _run_export(
        db_path, monkeypatch,
        output_path=output,
        window_start_to=WINDOW_START_A1,
    )
    assert len(rows) == 1
    assert rows[0]["window_start"] == WINDOW_START_A1


def test_export_filter_combined_session_and_range(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "out.csv"
    rows = _run_export(
        db_path, monkeypatch,
        output_path=output,
        session_id=SESSION_A,
        window_start_from=WINDOW_START_A2,
    )
    assert len(rows) == 1
    assert rows[0]["window_start"] == WINDOW_START_A2


def test_export_creates_csv_file(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "subdir" / "packet_features.csv"
    _run_export(db_path, monkeypatch, output_path=output)
    assert output.exists()


def test_export_returns_correct_row_count(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    import edge.features.export_packet_features as mod
    from sqlalchemy.orm import sessionmaker as sm

    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    TestSession = sm(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    output = tmp_path / "out.csv"
    count = mod.export_features(output_path=output)
    engine.dispose()

    assert count == 3


def test_export_ordered_by_window_start(
    populated_db, db_path: Path, tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "out.csv"
    rows = _run_export(db_path, monkeypatch, output_path=output)
    starts = [r["window_start"] for r in rows]
    assert starts == sorted(starts)
