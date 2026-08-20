from __future__ import annotations

import calendar
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dpkt
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import format_db_utc
from edge.features.run_mqtt_feature_builder import (
    bootstrap_producer_checkpoint,
    run_producer_cycle,
)
from edge.orchestration.run_detection_orchestrator import (
    CYCLE_SKIPPED_PACKET_NOT_READY,
    run_orchestration_cycle,
)
from edge.orchestration.stage_registry import PACKET_RULE, build_stage_registry
from edge.trust.trust_score_v2 import TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE


PI_IP = "192.168.0.20"
ESP_IP = "192.168.0.5"
BASE = datetime(2026, 8, 20, 0, 0, 0, tzinfo=timezone.utc)
FAILED_SESSION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _make_test_session_factory(db_path: Path):
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    return sessionmaker(autocommit=False, autoflush=False, bind=engine), engine


def _write_pcap(path: Path, timestamp: float) -> None:
    tcp = dpkt.tcp.TCP(sport=50000, dport=1883, flags=0x02, data=b"x")
    ip = dpkt.ip.IP(
        src=socket.inet_aton(ESP_IP),
        dst=socket.inet_aton(PI_IP),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    eth = dpkt.ethernet.Ethernet(
        dst=b"\xff\xff\xff\xff\xff\xff",
        src=b"\x00\x00\x00\x00\x00\x01",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        writer.writepkt(bytes(eth), ts=timestamp)


def _insert_capture_session(db, *, status: str = "COMPLETED") -> int:
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at,
                first_window_start, ended_at, status
            )
            VALUES (
                :session_id, 'eth0', :started_at,
                :first_window_start, :ended_at, :status
            )
            """
        ),
        {
            "session_id": FAILED_SESSION_ID,
            "started_at": format_db_utc(BASE),
            "first_window_start": format_db_utc(BASE),
            "ended_at": format_db_utc(BASE + timedelta(seconds=30)),
            "status": status,
        },
    )
    return int(result.lastrowid)


def _insert_segment(
    db,
    *,
    session_pk: int,
    file_name: str,
    window_start: datetime,
    status: str,
    error_code: str | None = None,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, error_code
            )
            VALUES (
                :session_pk, :file_name, 'eth0',
                :window_start, :window_end, :status, :error_code
            )
            """
        ),
        {
            "session_pk": session_pk,
            "file_name": file_name,
            "window_start": format_db_utc(window_start),
            "window_end": format_db_utc(window_start + timedelta(seconds=10)),
            "status": status,
            "error_code": error_code,
        },
    )
    return int(result.lastrowid)


def test_reconciliation_uses_one_batched_segment_status_query(tmp_path: Path) -> None:
    """소량 ready 파일은 파일마다 SELECT하지 않고 한 번에 상태를 조회한다."""
    from edge.features.run_packet_feature_extractor import reconcile_orphaned_files

    db_path = tmp_path / "reconcile.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    SessionLocal, engine = _make_test_session_factory(db_path)

    with SessionLocal() as db:
        session_pk = _insert_capture_session(db)
        _insert_segment(
            db,
            session_pk=session_pk,
            file_name="processed.pcap",
            window_start=BASE,
            status="PROCESSED",
        )
        _insert_segment(
            db,
            session_pk=session_pk,
            file_name="failed.pcap",
            window_start=BASE + timedelta(seconds=10),
            status="FAILED",
            error_code="PCAP_PARSE_ERROR",
        )
        _insert_segment(
            db,
            session_pk=session_pk,
            file_name="ready.pcap",
            window_start=BASE + timedelta(seconds=20),
            status="READY",
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    for name in ("processed.pcap", "failed.pcap", "ready.pcap"):
        (ready_dir / name).write_bytes(name.encode())

    segment_selects = 0

    def count_segment_selects(
        _conn, _cursor, statement, _parameters, _context, _executemany
    ) -> None:
        nonlocal segment_selects
        normalized = statement.upper()
        if "SELECT" in normalized and "PACKET_CAPTURE_SEGMENTS" in normalized:
            segment_selects += 1

    event.listen(engine, "before_cursor_execute", count_segment_selects)
    try:
        with SessionLocal() as db:
            moved = reconcile_orphaned_files(
                db,
                ready_dir,
                tmp_path / "processed",
                tmp_path / "failed",
            )
    finally:
        event.remove(engine, "before_cursor_execute", count_segment_selects)
        engine.dispose()

    assert moved == 2
    assert segment_selects == 1
    assert (tmp_path / "processed" / "processed.pcap").exists()
    assert (tmp_path / "failed" / "failed.pcap").exists()
    assert (ready_dir / "ready.pcap").exists()


def test_global_mode_processes_ready_child_of_failed_parent_without_skipping_failed_sibling(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """현재 Global 계약: FAILED 부모의 READY도 처리하지만 FAILED sibling은 보존한다."""
    import edge.features.run_packet_feature_extractor as extractor

    db_path = tmp_path / "failed-parent.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    SessionLocal, engine = _make_test_session_factory(db_path)

    with SessionLocal() as db:
        session_pk = _insert_capture_session(db, status="FAILED")
        ready_id = _insert_segment(
            db,
            session_pk=session_pk,
            file_name="ready-child.pcap",
            window_start=BASE,
            status="READY",
        )
        failed_id = _insert_segment(
            db,
            session_pk=session_pk,
            file_name="failed-sibling.pcap",
            window_start=BASE + timedelta(seconds=10),
            status="FAILED",
            error_code="LATE_CAPTURE",
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    _write_pcap(
        ready_dir / "ready-child.pcap",
        float(calendar.timegm(BASE.utctimetuple())),
    )
    monkeypatch.setattr(extractor.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(extractor, "SessionLocal", SessionLocal)

    count = extractor.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=tmp_path / "processed",
        failed_dir=tmp_path / "failed",
        limit=20,
        lock_path=tmp_path / ".lock",
    )

    with SessionLocal() as db:
        ready_status = db.execute(
            text("SELECT status FROM packet_capture_segments WHERE id=:id"),
            {"id": ready_id},
        ).scalar_one()
        failed_row = db.execute(
            text(
                "SELECT status, error_code FROM packet_capture_segments WHERE id=:id"
            ),
            {"id": failed_id},
        ).one()

    engine.dispose()
    assert count == 1
    assert ready_status == "PROCESSED"
    assert tuple(failed_row) == ("FAILED", "LATE_CAPTURE")


def test_failed_parent_segment_blocks_packet_and_trust_checkpoints(tmp_path: Path) -> None:
    """FAILED Capture Session의 실패 Window를 Packet/Trust가 건너뛰지 않는다."""
    db_path = tmp_path / "failed-parent-gate.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    SessionLocal, engine = _make_test_session_factory(db_path)

    with SessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, trust_score, status)
                VALUES ('esp32_02', :ip, 100, 'normal')
                """
            ),
            {"ip": ESP_IP},
        )
        bootstrap_producer_checkpoint(db, now=BASE)
        for message_index in range(20):
            db.execute(
                text(
                    """
                    INSERT INTO mqtt_logs (
                        device_id, topic, payload, payload_size,
                        received_at, is_json_valid, is_topic_valid
                    )
                    VALUES (
                        'esp32_02', 'iot/esp32_02/sensor',
                        '{"device_id":"esp32_02"}', 26,
                        :received_at, 1, 1
                    )
                    """
                ),
                {
                    "received_at": format_db_utc(
                        BASE + timedelta(seconds=message_index % 10)
                    )
                },
            )
        session_pk = _insert_capture_session(db, status="FAILED")
        _insert_segment(
            db,
            session_pk=session_pk,
            file_name="failed-window.pcap",
            window_start=BASE,
            status="FAILED",
            error_code="LATE_CAPTURE",
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=registry,
    )

    assert outcome.status == CYCLE_SKIPPED_PACKET_NOT_READY
    with SessionLocal() as db:
        assert checkpoints.get_completed_window_end(
            db,
            detector_name=PACKET_RULE,
            source_table="packet_feature_logs",
        ) is None
        assert checkpoints.get_completed_window_end(
            db,
            detector_name=TRUST_DETECTOR_NAME,
            source_table=TRUST_SOURCE_TABLE,
        ) is None

    engine.dispose()
