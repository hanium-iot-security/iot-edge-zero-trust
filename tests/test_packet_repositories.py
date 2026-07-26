from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.features import packet_feature_repository as feature_repo
from edge.packet import capture_session_repository as capture_repo

SESSION_A = "11111111-1111-4111-8111-111111111111"
SESSION_B = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def db_session(tmp_path: Path):
    db_path = tmp_path / "packet-repositories.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with SessionLocal() as session:
        session.execute(text("PRAGMA foreign_keys = ON"))
        yield session
    engine.dispose()


def _utc(hour: int, minute: int, second: int) -> datetime:
    return datetime(2026, 7, 16, hour, minute, second, tzinfo=timezone.utc)


def _create_session(
    db: Session,
    *,
    session_id: str = SESSION_A,
    capture_interface: str = "eth0",
    first_window_start: datetime | None = _utc(10, 0, 0),
) -> int:
    session_pk = capture_repo.create_session(
        db,
        session_id=session_id,
        capture_interface=capture_interface,
        started_at=_utc(9, 59, 50),
    )
    if first_window_start is not None:
        capture_repo.set_first_window_start(db, session_pk, first_window_start)
    return session_pk


def _insert_segment(
    db: Session,
    *,
    session_pk: int,
    file_name: str,
    start: datetime,
    capture_interface: str = "eth0",
    status: str = "READY",
    packet_count: int | None = None,
) -> int:
    segment_id = capture_repo.insert_ready_segment(
        db,
        capture_session_pk=session_pk,
        file_name=file_name,
        capture_interface=capture_interface,
        window_start=start,
        window_end=start + timedelta(seconds=10),
    )
    if status != "READY" or packet_count is not None:
        feature_repo.update_capture_segment_status(
            db,
            segment_id=segment_id,
            status=status,
            packet_count=packet_count,
            error_code="TEST_ERROR" if status == "FAILED" else None,
            error_message="failed" if status == "FAILED" else None,
        )
    return segment_id


def _feature_row(
    *,
    peer_ip: str = "10.0.0.8",
    direction: str = "INBOUND",
    window_start: str = "2026-07-16T10:00:00Z",
    window_end: str = "2026-07-16T10:00:10Z",
    packet_count: int = 2,
) -> dict:
    return {
        "peer_ip": peer_ip,
        "direction": direction,
        "window_start": window_start,
        "window_end": window_end,
        "packet_count": packet_count,
        "total_bytes": 200,
        "avg_packet_size": 100.0,
        "max_packet_size": 120,
        "mean_inter_arrival_time": 0.5,
        "distinct_dest_port_count": 1,
        "tcp_syn_count": 1,
        "mqtt_related_packet_count": 1,
        "non_mqtt_tcp_udp_packet_count": 0,
    }


def test_capture_repository_does_not_commit_on_create(db_session: Session) -> None:
    capture_repo.create_session(
        db_session,
        session_id=SESSION_A,
        capture_interface="eth0",
        started_at=_utc(10, 0, 0),
    )
    db_session.rollback()

    assert capture_repo.find_session_pk_by_session_id(db_session, SESSION_A) is None


def test_get_packet_capture_ready_through_missing_and_empty_states(
    db_session: Session,
) -> None:
    assert capture_repo.get_packet_capture_ready_through(
        db_session,
        session_id="99999999-9999-4999-8999-999999999999",
    ) is None

    _create_session(db_session, first_window_start=None)
    db_session.commit()
    readiness = capture_repo.get_packet_capture_ready_through(
        db_session,
        session_id=SESSION_A,
    )
    assert readiness is not None
    assert readiness.packet_capture_ready_through is None


def test_get_packet_capture_ready_through_contiguous_ready_processed_empty(
    db_session: Session,
) -> None:
    session_pk = _create_session(db_session)
    _insert_segment(db_session, session_pk=session_pk, file_name="ready.pcap", start=_utc(10, 0, 0), status="READY")
    _insert_segment(db_session, session_pk=session_pk, file_name="processed.pcap", start=_utc(10, 0, 10), status="PROCESSED")
    _insert_segment(db_session, session_pk=session_pk, file_name="empty.pcap", start=_utc(10, 0, 20), status="EMPTY")
    db_session.commit()

    readiness = capture_repo.get_packet_capture_ready_through(
        db_session,
        session_id=SESSION_A,
    )

    assert readiness is not None
    assert readiness.session_id == SESSION_A
    assert readiness.packet_capture_ready_through == _utc(10, 0, 30)


def test_get_packet_capture_ready_through_stops_at_gap_or_failed(
    db_session: Session,
) -> None:
    gap_session_pk = _create_session(db_session, session_id=SESSION_A)
    _insert_segment(db_session, session_pk=gap_session_pk, file_name="gap-1.pcap", start=_utc(10, 0, 0), status="PROCESSED")
    _insert_segment(db_session, session_pk=gap_session_pk, file_name="gap-3.pcap", start=_utc(10, 0, 20), status="PROCESSED")

    failed_session_pk = _create_session(db_session, session_id=SESSION_B, capture_interface="eth1")
    _insert_segment(db_session, session_pk=failed_session_pk, file_name="failed-1.pcap", start=_utc(10, 0, 0), capture_interface="eth1", status="PROCESSED")
    _insert_segment(db_session, session_pk=failed_session_pk, file_name="failed-2.pcap", start=_utc(10, 0, 10), capture_interface="eth1", status="FAILED")
    _insert_segment(db_session, session_pk=failed_session_pk, file_name="failed-3.pcap", start=_utc(10, 0, 20), capture_interface="eth1", status="PROCESSED")
    db_session.commit()

    gap_readiness = capture_repo.get_packet_capture_ready_through(
        db_session,
        session_id=SESSION_A,
    )
    failed_readiness = capture_repo.get_packet_capture_ready_through(
        db_session,
        session_id=SESSION_B,
    )

    assert gap_readiness is not None
    assert gap_readiness.packet_capture_ready_through == _utc(10, 0, 10)
    assert failed_readiness is not None
    assert failed_readiness.packet_capture_ready_through == _utc(10, 0, 10)


def test_get_packet_capture_ready_through_ignores_other_sessions_and_before_first_window(
    db_session: Session,
) -> None:
    session_a_pk = _create_session(db_session, session_id=SESSION_A)
    session_b_pk = _create_session(db_session, session_id=SESSION_B, capture_interface="eth1")
    _insert_segment(db_session, session_pk=session_a_pk, file_name="before.pcap", start=_utc(9, 59, 50), status="PROCESSED")
    _insert_segment(db_session, session_pk=session_a_pk, file_name="session-a.pcap", start=_utc(10, 0, 0), status="PROCESSED")
    _insert_segment(db_session, session_pk=session_b_pk, file_name="session-b.pcap", start=_utc(10, 0, 10), capture_interface="eth1", status="PROCESSED")
    db_session.commit()

    readiness = capture_repo.get_packet_capture_ready_through(
        db_session,
        session_id=SESSION_A,
    )

    assert readiness is not None
    assert readiness.packet_capture_ready_through == _utc(10, 0, 10)
    assert readiness.packet_capture_ready_through.tzinfo is timezone.utc


def test_get_packet_feature_ready_through_requires_extractor_terminal_prefix(
    db_session: Session,
) -> None:
    session_pk = _create_session(db_session)
    first_segment = _insert_segment(
        db_session,
        session_pk=session_pk,
        file_name="feature-ready.pcap",
        start=_utc(10, 0, 0),
    )
    _insert_segment(
        db_session,
        session_pk=session_pk,
        file_name="still-ready.pcap",
        start=_utc(10, 0, 10),
    )
    feature_repo.insert_packet_feature_rows(
        db_session,
        capture_segment_id=first_segment,
        feature_rows=[_feature_row()],
        ip_device_map={},
        capture_scope="scope-a",
    )
    feature_repo.update_capture_segment_status(
        db_session,
        segment_id=first_segment,
        status="PROCESSED",
        packet_count=2,
    )
    db_session.commit()

    readiness = capture_repo.get_packet_feature_ready_through(
        db_session,
        session_id=SESSION_A,
    )

    assert readiness is not None
    assert readiness.first_window_start == _utc(10, 0, 0)
    assert readiness.packet_feature_ready_through == _utc(10, 0, 10)


def test_get_packet_feature_ready_through_rejects_inconsistent_terminal_rows(
    db_session: Session,
) -> None:
    session_pk = _create_session(db_session)
    _insert_segment(
        db_session,
        session_pk=session_pk,
        file_name="processed-without-feature.pcap",
        start=_utc(10, 0, 0),
        status="PROCESSED",
    )
    db_session.commit()

    readiness = capture_repo.get_packet_feature_ready_through(
        db_session,
        session_id=SESSION_A,
    )

    assert readiness is not None
    assert readiness.packet_feature_ready_through is None


def test_packet_feature_repository_write_contracts(db_session: Session) -> None:
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '10.0.0.8', 'isolated', 0)
            """
        )
    )
    session_pk = _create_session(db_session)
    segment_id = _insert_segment(
        db_session,
        session_pk=session_pk,
        file_name="feature.pcap",
        start=_utc(10, 0, 0),
    )
    db_session.commit()

    ip_device_map = feature_repo.load_ip_device_map(db_session)
    inserted = feature_repo.insert_packet_feature_rows(
        db_session,
        capture_segment_id=segment_id,
        feature_rows=[
            _feature_row(peer_ip="10.0.0.8", direction="INBOUND"),
            _feature_row(peer_ip="10.0.0.9", direction="OUTBOUND"),
        ],
        ip_device_map=ip_device_map,
        capture_scope="PI1_INTERNAL_LAN",
    )
    feature_repo.update_capture_segment_status(
        db_session,
        segment_id=segment_id,
        status="PROCESSED",
        packet_count=2,
    )
    db_session.commit()

    rows = feature_repo.list_packet_feature_logs(db_session, session_id=SESSION_A)
    assert inserted == 2
    assert len(rows) == 2
    assert feature_repo.count_packet_feature_logs(db_session, session_id=SESSION_A) == 2
    assert rows[0]["session_id"] == SESSION_A
    assert {row["device_id"] for row in rows} == {"esp32_01", None}
    assert {row["direction"] for row in rows} == {"INBOUND", "OUTBOUND"}
    assert feature_repo.get_segment_status_by_file_name(
        db_session,
        file_name="feature.pcap",
    ) == "PROCESSED"

    duplicate_inserted = feature_repo.insert_packet_feature_rows(
        db_session,
        capture_segment_id=segment_id,
        feature_rows=[_feature_row(peer_ip="10.0.0.8", direction="INBOUND")],
        ip_device_map=ip_device_map,
        capture_scope="PI1_INTERNAL_LAN",
    )
    db_session.commit()
    assert duplicate_inserted == 0
    assert feature_repo.count_packet_feature_logs(db_session, session_id=SESSION_A) == 2


def test_packet_feature_ready_segments_and_query_filters(db_session: Session) -> None:
    session_a_pk = _create_session(db_session, session_id=SESSION_A)
    session_b_pk = _create_session(db_session, session_id=SESSION_B, capture_interface="eth1")
    segment_a1 = _insert_segment(db_session, session_pk=session_a_pk, file_name="a1.pcap", start=_utc(10, 0, 0))
    segment_a2 = _insert_segment(db_session, session_pk=session_a_pk, file_name="a2.pcap", start=_utc(10, 0, 10))
    segment_b1 = _insert_segment(db_session, session_pk=session_b_pk, file_name="b1.pcap", start=_utc(10, 0, 20), capture_interface="eth1")
    db_session.commit()

    ready_segments = feature_repo.fetch_ready_segments(db_session, limit=2)
    assert [segment["id"] for segment in ready_segments] == [segment_a1, segment_a2]

    feature_repo.insert_packet_feature_rows(
        db_session,
        capture_segment_id=segment_a1,
        feature_rows=[_feature_row(peer_ip="10.0.0.8", direction="INBOUND")],
        ip_device_map={},
        capture_scope="scope-a",
    )
    feature_repo.insert_packet_feature_rows(
        db_session,
        capture_segment_id=segment_a2,
        feature_rows=[_feature_row(
            peer_ip="10.0.0.9",
            direction="OUTBOUND",
            window_start="2026-07-16T10:00:10Z",
            window_end="2026-07-16T10:00:20Z",
        )],
        ip_device_map={},
        capture_scope="scope-a",
    )
    feature_repo.insert_packet_feature_rows(
        db_session,
        capture_segment_id=segment_b1,
        feature_rows=[_feature_row(
            peer_ip="10.0.0.8",
            direction="INBOUND",
            window_start="2026-07-16T10:00:20Z",
            window_end="2026-07-16T10:00:30Z",
        )],
        ip_device_map={},
        capture_scope="scope-b",
    )
    db_session.commit()

    assert feature_repo.count_packet_feature_logs(db_session, session_id=SESSION_A) == 2
    assert feature_repo.count_packet_feature_logs(db_session, peer_ip="10.0.0.8") == 2
    assert feature_repo.count_packet_feature_logs(db_session, direction="OUTBOUND") == 1
    assert feature_repo.count_packet_feature_logs(
        db_session,
        from_at=_utc(10, 0, 10),
        to_at=_utc(10, 0, 20),
    ) == 2

    rows = feature_repo.list_packet_feature_logs(db_session, session_id=SESSION_A, limit=1, offset=1)
    assert len(rows) == 1
    assert rows[0]["peer_ip"] == "10.0.0.8"
    assert "packets_per_second" not in rows[0]
    assert "bytes_per_second" not in rows[0]


def test_packet_feature_repository_rollback_is_caller_controlled(
    db_session: Session,
) -> None:
    session_pk = _create_session(db_session)
    segment_id = _insert_segment(
        db_session,
        session_pk=session_pk,
        file_name="rollback.pcap",
        start=_utc(10, 0, 0),
    )
    db_session.commit()

    with pytest.raises(IntegrityError):
        feature_repo.insert_packet_feature_rows(
            db_session,
            capture_segment_id=segment_id,
            feature_rows=[
                _feature_row(peer_ip="10.0.0.8"),
                _feature_row(peer_ip="10.0.0.9", packet_count=-1),
            ],
            ip_device_map={},
            capture_scope="PI1_INTERNAL_LAN",
        )
        feature_repo.update_capture_segment_status(
            db_session,
            segment_id=segment_id,
            status="PROCESSED",
            packet_count=2,
        )
        db_session.commit()
    db_session.rollback()

    assert feature_repo.count_packet_feature_logs(db_session, session_id=SESSION_A) == 0
    assert feature_repo.get_segment_status_by_file_name(
        db_session,
        file_name="rollback.pcap",
    ) == "READY"
