"""packet_feature_extractor DB 연동 integration 테스트."""

from __future__ import annotations

import calendar
import multiprocessing
import socket
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import dpkt
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.features.run_packet_feature_extractor import (
    CAPTURE_SCOPE_DEFAULT,
    _acquire_lock,
    _insert_feature_rows,
    _load_ip_device_map,
    _move_pcap,
    process_segment,
    reconcile_orphaned_files,
)

PI_IP = "192.168.0.20"
ESP_IP = "192.168.0.10"
EXTERNAL_IP = "10.0.0.5"
SESSION_UUID = "11111111-1111-4111-8111-111111111111"
WINDOW_START_STR = "2026-07-16T10:00:00Z"
WINDOW_END_STR = "2026-07-16T10:00:10Z"
WINDOW_START_DT = datetime(2026, 7, 16, 10, 0, 0)
WINDOW_TS = float(calendar.timegm(WINDOW_START_DT.timetuple()))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_eth_bytes(
    src_ip: str,
    dst_ip: str,
    src_port: int = 50000,
    dst_port: int = 1883,
    payload_size: int = 60,
) -> bytes:
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, flags=0x02, data=b"\x00" * payload_size)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    eth = dpkt.ethernet.Ethernet(
        dst=b"\xff\xff\xff\xff\xff\xff",
        src=b"\x00\x00\x00\x00\x00\x01",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _write_pcap(path: Path, entries: list[tuple[float, str, str]]) -> None:
    """entries: [(timestamp, src_ip, dst_ip)]"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for ts, src, dst in entries:
            writer.writepkt(_make_eth_bytes(src, dst), ts=ts)


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


@pytest.fixture
def ready_dir(tmp_path: Path) -> Path:
    d = tmp_path / "pcap" / "ready"
    d.mkdir(parents=True)
    return d


def _insert_capture_session(db_session, session_uuid: str = SESSION_UUID) -> int:
    db_session.execute(
        text(
            """
            INSERT INTO packet_capture_sessions
                (session_id, capture_interface, started_at)
            VALUES (:sid, 'eth0', '2026-07-16 10:00:00')
            """
        ),
        {"sid": session_uuid},
    )
    db_session.commit()
    row = db_session.execute(
        text("SELECT id FROM packet_capture_sessions WHERE session_id = :sid"),
        {"sid": session_uuid},
    ).fetchone()
    return row[0]


def _insert_segment(
    db_session,
    capture_session_id: int,
    file_name: str = "test.pcap",
    window_start: str = WINDOW_START_STR,
    window_end: str = WINDOW_END_STR,
) -> dict:
    db_session.execute(
        text(
            """
            INSERT INTO packet_capture_segments
                (capture_session_id, file_name, capture_interface,
                 window_start, window_end, status)
            VALUES (:csid, :fname, 'eth0', :ws, :we, 'READY')
            """
        ),
        {
            "csid": capture_session_id,
            "fname": file_name,
            "ws": window_start,
            "we": window_end,
        },
    )
    db_session.commit()
    row = db_session.execute(
        text(
            "SELECT id, file_name, window_start, window_end "
            "FROM packet_capture_segments WHERE file_name = :fname"
        ),
        {"fname": file_name},
    ).fetchone()
    return {"id": row[0], "file_name": row[1], "window_start": row[2], "window_end": row[3]}


def _segment_status(db_session, segment_id: int) -> dict:
    row = db_session.execute(
        text(
            "SELECT status, packet_count, error_code, error_message, processed_at "
            "FROM packet_capture_segments WHERE id = :id"
        ),
        {"id": segment_id},
    ).fetchone()
    return {
        "status": row[0],
        "packet_count": row[1],
        "error_code": row[2],
        "error_message": row[3],
        "processed_at": row[4],
    }


def _feature_rows(db_session, segment_id: int) -> list[dict]:
    rows = db_session.execute(
        text(
            "SELECT device_id, peer_ip, direction, packet_count, capture_scope "
            "FROM packet_feature_logs WHERE capture_segment_id = :sid"
        ),
        {"sid": segment_id},
    ).fetchall()
    return [
        {
            "device_id": r[0],
            "peer_ip": r[1],
            "direction": r[2],
            "packet_count": r[3],
            "capture_scope": r[4],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_processed_when_normal_pcap_has_matching_packets(
    db_session, ready_dir: Path
) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    _write_pcap(
        ready_dir / "test.pcap",
        [(WINDOW_TS + 0.0, ESP_IP, PI_IP), (WINDOW_TS + 1.0, ESP_IP, PI_IP)],
    )

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "PROCESSED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "PROCESSED"
    assert seg["packet_count"] == 2
    assert seg["processed_at"] is not None
    assert seg["error_code"] is None

    features = _feature_rows(db_session, segment["id"])
    assert len(features) == 1
    assert features[0]["direction"] == "INBOUND"
    assert features[0]["peer_ip"] == ESP_IP
    assert features[0]["capture_scope"] == CAPTURE_SCOPE_DEFAULT


def test_empty_when_no_pi_related_packets(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    _write_pcap(
        ready_dir / "test.pcap",
        [(WINDOW_TS + 0.0, ESP_IP, EXTERNAL_IP)],  # Pi 무관 패킷
    )

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "EMPTY"
    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "EMPTY"
    assert seg["packet_count"] == 1  # parsed packet 수
    assert seg["processed_at"] is not None

    assert _feature_rows(db_session, segment["id"]) == []


def test_failed_when_pcap_file_missing(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    # pcap 파일을 만들지 않음

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "FAILED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "FAILED"
    assert seg["error_code"] == "PCAP_FILE_MISSING"
    assert seg["error_message"] is not None
    assert seg["processed_at"] is None


def test_failed_when_pcap_is_corrupted(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    corrupt = ready_dir / "test.pcap"
    corrupt.write_bytes(b"\x00\x01\x02\x03")  # 잘못된 magic bytes

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "FAILED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "FAILED"
    assert seg["error_code"] == "PCAP_PARSE_ERROR"


def test_device_id_resolved_when_ip_matches(db_session, ready_dir: Path) -> None:
    db_session.execute(
        text(
            "INSERT INTO devices (device_id, ip_address, status, trust_score) "
            "VALUES ('esp32_01', :ip, 'normal', 100)"
        ),
        {"ip": ESP_IP},
    )
    db_session.commit()

    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    ip_device_map = _load_ip_device_map(db_session)
    process_segment(db_session, segment, ready_dir, PI_IP, ip_device_map)

    features = _feature_rows(db_session, segment["id"])
    assert features[0]["device_id"] == "esp32_01"


def test_device_id_null_when_ip_not_registered(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, EXTERNAL_IP, PI_IP)])

    process_segment(db_session, segment, ready_dir, PI_IP, {})

    features = _feature_rows(db_session, segment["id"])
    assert features[0]["device_id"] is None


def test_no_duplicate_on_reprocess(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    process_segment(db_session, segment, ready_dir, PI_IP, {})

    # PROCESSED 상태에서 같은 segment 재처리 시뮬레이션
    # (segment dict는 처음 조회한 READY 기준이라 가정)
    process_segment(db_session, segment, ready_dir, PI_IP, {})

    features = _feature_rows(db_session, segment["id"])
    assert len(features) == 1  # ON CONFLICT DO NOTHING으로 중복 없음


def test_inbound_and_outbound_create_separate_rows(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(
        ready_dir / "test.pcap",
        [
            (WINDOW_TS + 0.0, ESP_IP, PI_IP),   # INBOUND
            (WINDOW_TS + 1.0, PI_IP, ESP_IP),   # OUTBOUND
        ],
    )

    process_segment(db_session, segment, ready_dir, PI_IP, {})

    features = _feature_rows(db_session, segment["id"])
    assert len(features) == 2
    directions = {f["direction"] for f in features}
    assert directions == {"INBOUND", "OUTBOUND"}


def test_packet_count_is_total_parsed_not_filtered(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(
        ready_dir / "test.pcap",
        [
            (WINDOW_TS + 0.0, ESP_IP, PI_IP),         # INBOUND (Pi 관련)
            (WINDOW_TS + 1.0, ESP_IP, EXTERNAL_IP),   # Pi 무관
        ],
    )

    process_segment(db_session, segment, ready_dir, PI_IP, {})

    seg = _segment_status(db_session, segment["id"])
    assert seg["packet_count"] == 2  # 전체 IP packet 수
    assert seg["status"] == "PROCESSED"


def test_out_of_window_packets_excluded_from_features(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(
        ready_dir / "test.pcap",
        [
            (WINDOW_TS - 1.0, ESP_IP, PI_IP),   # window 이전
            (WINDOW_TS + 0.0, ESP_IP, PI_IP),   # window 내
            (WINDOW_TS + 10.0, ESP_IP, PI_IP),  # window 이후 (== window_end, 제외)
        ],
    )

    process_segment(db_session, segment, ready_dir, PI_IP, {})

    seg = _segment_status(db_session, segment["id"])
    assert seg["packet_count"] == 3  # 전체 parsed
    features = _feature_rows(db_session, segment["id"])
    assert features[0]["packet_count"] == 1  # window 내 1개만


# ---------------------------------------------------------------------------
# WINDOW_MISMATCH
# ---------------------------------------------------------------------------


def test_failed_window_mismatch_when_all_packets_before_window(
    db_session, ready_dir: Path
) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(
        ready_dir / "test.pcap",
        [
            (WINDOW_TS - 100.0, ESP_IP, PI_IP),
            (WINDOW_TS - 50.0, ESP_IP, PI_IP),
        ],
    )

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "FAILED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "FAILED"
    assert seg["error_code"] == "WINDOW_MISMATCH"
    assert seg["error_message"] is not None
    assert _feature_rows(db_session, segment["id"]) == []


def test_empty_not_mismatch_when_pi_unrelated_but_in_window(
    db_session, ready_dir: Path
) -> None:
    """window 안에 패킷이 있지만 Pi 무관 → EMPTY (WINDOW_MISMATCH 아님)."""
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(
        ready_dir / "test.pcap",
        [(WINDOW_TS + 0.0, ESP_IP, EXTERNAL_IP)],  # window 내, Pi 무관
    )

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "EMPTY"
    seg = _segment_status(db_session, segment["id"])
    assert seg["error_code"] is None


# ---------------------------------------------------------------------------
# DB 오류 rollback
# ---------------------------------------------------------------------------


def test_db_error_leaves_segment_ready(db_session, ready_dir: Path) -> None:
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    with patch(
        "edge.features.run_packet_feature_extractor._insert_feature_rows",
        side_effect=Exception("DB connection lost"),
    ):
        with pytest.raises(Exception, match="DB connection lost"):
            process_segment(db_session, segment, ready_dir, PI_IP, {})

    db_session.rollback()

    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "READY"
    assert _feature_rows(db_session, segment["id"]) == []


# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------


def test_lock_releases_after_context_exit(tmp_path: Path) -> None:
    lock_path = tmp_path / ".test.lock"
    with _acquire_lock(lock_path):
        pass  # acquired and released
    with _acquire_lock(lock_path):
        pass  # 재획득 가능


def _worker_try_lock(lock_path_str: str, result_queue: multiprocessing.Queue) -> None:
    """별도 프로세스에서 lock 획득을 시도하는 헬퍼."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from edge.features.run_packet_feature_extractor import _acquire_lock

    try:
        with _acquire_lock(Path(lock_path_str)):
            result_queue.put("acquired")
    except RuntimeError:
        result_queue.put("blocked")


def test_lock_blocks_concurrent_process(tmp_path: Path) -> None:
    lock_path = tmp_path / ".test.lock"
    q: multiprocessing.Queue = multiprocessing.Queue()

    with _acquire_lock(lock_path):
        p = multiprocessing.Process(target=_worker_try_lock, args=(str(lock_path), q))
        p.start()
        p.join(timeout=5)

    result = q.get_nowait()
    assert result == "blocked"


# ---------------------------------------------------------------------------
# 파일 이동 (_move_pcap 단위 테스트)
# ---------------------------------------------------------------------------


def test_move_pcap_moves_file_to_dst(tmp_path: Path) -> None:
    src = tmp_path / "ready" / "seg.pcap"
    src.parent.mkdir()
    src.write_bytes(b"\xd4\xc3\xb2\xa1data")

    dst_dir = tmp_path / "processed"
    _move_pcap(src, dst_dir)

    assert not src.exists()
    assert (dst_dir / "seg.pcap").read_bytes() == b"\xd4\xc3\xb2\xa1data"


def test_move_pcap_overwrites_existing_dst(tmp_path: Path) -> None:
    src = tmp_path / "ready" / "seg.pcap"
    src.parent.mkdir()
    src.write_bytes(b"new_content")

    dst_dir = tmp_path / "processed"
    dst_dir.mkdir()
    (dst_dir / "seg.pcap").write_bytes(b"old_content")

    _move_pcap(src, dst_dir)

    assert (dst_dir / "seg.pcap").read_bytes() == b"new_content"


def test_move_pcap_creates_dst_dir_if_missing(tmp_path: Path) -> None:
    src = tmp_path / "ready" / "seg.pcap"
    src.parent.mkdir()
    src.write_bytes(b"data")

    dst_dir = tmp_path / "nonexistent" / "subdir"
    _move_pcap(src, dst_dir)

    assert (dst_dir / "seg.pcap").exists()


# ---------------------------------------------------------------------------
# 파일 이동 통합 (extract_packet_features 경유)
# ---------------------------------------------------------------------------


def _make_test_session_factory(db_path: Path):
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    return sessionmaker(autocommit=False, autoflush=False, bind=engine), engine


def test_processed_file_moved_to_processed_dir(tmp_path: Path, monkeypatch) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        csid = _insert_capture_session(db)
        _insert_segment(db, csid)

    ready_dir = tmp_path / "ready"
    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=processed_dir,
        failed_dir=failed_dir,
        lock_path=tmp_path / ".lock",
    )

    assert count == 1
    assert not (ready_dir / "test.pcap").exists()
    assert (processed_dir / "test.pcap").exists()
    engine.dispose()


def test_empty_file_moved_to_processed_dir(tmp_path: Path, monkeypatch) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        csid = _insert_capture_session(db)
        _insert_segment(db, csid)

    ready_dir = tmp_path / "ready"
    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, EXTERNAL_IP)])

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=processed_dir,
        failed_dir=failed_dir,
        lock_path=tmp_path / ".lock",
    )

    assert not (ready_dir / "test.pcap").exists()
    assert (processed_dir / "test.pcap").exists()
    engine.dispose()


def test_failed_file_moved_to_failed_dir(tmp_path: Path, monkeypatch) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        csid = _insert_capture_session(db)
        _insert_segment(db, csid)

    ready_dir = tmp_path / "ready"
    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    ready_dir.mkdir()
    corrupt = ready_dir / "test.pcap"
    corrupt.write_bytes(b"\x00\x01\x02\x03")  # 잘못된 magic

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=processed_dir,
        failed_dir=failed_dir,
        lock_path=tmp_path / ".lock",
    )

    assert not (ready_dir / "test.pcap").exists()
    assert (failed_dir / "test.pcap").exists()
    engine.dispose()


def test_missing_pcap_file_not_moved(tmp_path: Path, monkeypatch) -> None:
    """PCAP_FILE_MISSING: 파일이 없으므로 이동 없음, 오류 없음."""
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        csid = _insert_capture_session(db)
        _insert_segment(db, csid)

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    # pcap 파일을 만들지 않음

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=tmp_path / "processed",
        failed_dir=tmp_path / "failed",
        lock_path=tmp_path / ".lock",
    )

    assert count == 1  # FAILED로 정상 처리됨
    engine.dispose()


# ---------------------------------------------------------------------------
# CAPTURE_INTERFACE_IP 유효성 검사
# ---------------------------------------------------------------------------


def test_extract_raises_when_capture_ip_not_set(tmp_path: Path, monkeypatch) -> None:
    import edge.features.run_packet_feature_extractor as mod

    monkeypatch.setattr(mod.settings, "capture_interface_ip", "")

    with pytest.raises(ValueError, match="CAPTURE_INTERFACE_IP가 설정되지 않았습니다"):
        mod.extract_packet_features(lock_path=tmp_path / ".lock")


def test_extract_raises_when_capture_ip_invalid_format(
    tmp_path: Path, monkeypatch
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    monkeypatch.setattr(mod.settings, "capture_interface_ip", "not_an_ip")

    with pytest.raises(ValueError, match="올바른 IPv4 형식이 아닙니다"):
        mod.extract_packet_features(lock_path=tmp_path / ".lock")


def test_extract_raises_when_capture_ip_is_ipv6(
    tmp_path: Path, monkeypatch
) -> None:
    """IPv6 주소는 dpkt.ip.IP(IPv4 전용) parser와 맞지 않으므로 거부한다."""
    import edge.features.run_packet_feature_extractor as mod

    monkeypatch.setattr(mod.settings, "capture_interface_ip", "::1")

    with pytest.raises(ValueError, match="올바른 IPv4 형식이 아닙니다"):
        mod.extract_packet_features(lock_path=tmp_path / ".lock")


# ---------------------------------------------------------------------------
# reconcile_orphaned_files
# ---------------------------------------------------------------------------


def test_reconcile_moves_processed_orphan_to_processed_dir(
    db_session, ready_dir: Path, tmp_path: Path
) -> None:
    csid = _insert_capture_session(db_session)
    _insert_segment(db_session, csid)
    pcap = ready_dir / "test.pcap"
    pcap.write_bytes(b"data")

    # DB를 수동으로 PROCESSED로 업데이트 (이전 실행에서 커밋됐지만 이동 실패 시나리오)
    db_session.execute(
        text("UPDATE packet_capture_segments SET status = 'PROCESSED' WHERE file_name = 'test.pcap'")
    )
    db_session.commit()

    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    moved = reconcile_orphaned_files(db_session, ready_dir, processed_dir, failed_dir)

    assert moved == 1
    assert not pcap.exists()
    assert (processed_dir / "test.pcap").exists()


def test_reconcile_moves_failed_orphan_to_failed_dir(
    db_session, ready_dir: Path, tmp_path: Path
) -> None:
    csid = _insert_capture_session(db_session)
    _insert_segment(db_session, csid)
    pcap = ready_dir / "test.pcap"
    pcap.write_bytes(b"corrupt")

    db_session.execute(
        text(
            "UPDATE packet_capture_segments SET status = 'FAILED', "
            "error_code = 'PCAP_PARSE_ERROR' WHERE file_name = 'test.pcap'"
        )
    )
    db_session.commit()

    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    moved = reconcile_orphaned_files(db_session, ready_dir, processed_dir, failed_dir)

    assert moved == 1
    assert not pcap.exists()
    assert (failed_dir / "test.pcap").exists()


def test_reconcile_skips_ready_status_file(
    db_session, ready_dir: Path, tmp_path: Path
) -> None:
    csid = _insert_capture_session(db_session)
    _insert_segment(db_session, csid)
    pcap = ready_dir / "test.pcap"
    pcap.write_bytes(b"data")
    # status = READY (기본값): 이동하면 안 됨

    moved = reconcile_orphaned_files(
        db_session, ready_dir, tmp_path / "processed", tmp_path / "failed"
    )

    assert moved == 0
    assert pcap.exists()


def test_reconcile_skips_file_not_in_db(
    db_session, ready_dir: Path, tmp_path: Path
) -> None:
    unknown = ready_dir / "unknown.pcap"
    unknown.write_bytes(b"data")

    moved = reconcile_orphaned_files(
        db_session, ready_dir, tmp_path / "processed", tmp_path / "failed"
    )

    assert moved == 0
    assert unknown.exists()


def test_reconcile_returns_zero_when_ready_dir_missing(
    db_session, tmp_path: Path
) -> None:
    missing_dir = tmp_path / "nonexistent"
    moved = reconcile_orphaned_files(
        db_session, missing_dir, tmp_path / "processed", tmp_path / "failed"
    )
    assert moved == 0


# ---------------------------------------------------------------------------
# 파일 이동 실패 시 DB 오류로 오해하지 않음
# ---------------------------------------------------------------------------


def test_move_failure_does_not_mask_as_db_error(
    tmp_path: Path, monkeypatch
) -> None:
    """DB 커밋 성공 후 파일 이동 실패 → count는 1, READY 유지 로그 없음."""
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        csid = _insert_capture_session(db)
        _insert_segment(db, csid)

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    # _move_pcap을 실패하도록 패치
    monkeypatch.setattr(
        mod, "_move_pcap", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full"))
    )

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=tmp_path / "processed",
        failed_dir=tmp_path / "failed",
        lock_path=tmp_path / ".lock",
    )

    # 이동은 실패했지만 처리 자체는 완료됨
    assert count == 1
    # 파일은 ready에 남음
    assert (ready_dir / "test.pcap").exists()
    # DB 상태는 PROCESSED
    with TestSession() as db:
        row = db.execute(
            text("SELECT status FROM packet_capture_segments WHERE file_name = 'test.pcap'")
        ).fetchone()
    assert row[0] == "PROCESSED"
    engine.dispose()


def test_extract_reconciles_orphan_on_next_run(
    tmp_path: Path, monkeypatch
) -> None:
    """이전 실행에서 커밋 후 이동 실패한 파일이 다음 실행 시작 시 reconcile로 복구된다."""
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    # DB에는 이미 PROCESSED 상태, 파일은 ready에 남아 있는 상황 시뮬레이션
    with TestSession() as db:
        csid = _insert_capture_session(db)
        seg = _insert_segment(db, csid)
        db.execute(
            text(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' "
                "WHERE id = :id"
            ),
            {"id": seg["id"]},
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    (ready_dir / "test.pcap").write_bytes(b"orphan")

    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=processed_dir,
        failed_dir=failed_dir,
        lock_path=tmp_path / ".lock",
    )

    assert not (ready_dir / "test.pcap").exists()
    assert (processed_dir / "test.pcap").exists()
    engine.dispose()


# ---------------------------------------------------------------------------
# ON CONFLICT DO NOTHING: 중복만 무시, CHECK 위반은 예외
# ---------------------------------------------------------------------------


def test_duplicate_feature_row_is_silently_ignored(
    db_session, ready_dir: Path
) -> None:
    """(capture_segment_id, peer_ip, direction) 중복 삽입은 예외 없이 무시된다."""
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    process_segment(db_session, segment, ready_dir, PI_IP, {})
    # 같은 segment 재처리: 중복 → 무시, 예외 없음
    process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert len(_feature_rows(db_session, segment["id"])) == 1


def test_check_constraint_violation_raises_not_silently_ignored(
    db_session,
) -> None:
    """packet_count < 0 같은 CHECK 위반은 ON CONFLICT DO NOTHING으로도 예외가 발생한다."""
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    bad_rows = [
        {
            "peer_ip": ESP_IP,
            "direction": "INBOUND",
            "window_start": WINDOW_START_STR,
            "window_end": WINDOW_END_STR,
            "packet_count": -1,  # CHECK(packet_count >= 0) 위반
            "total_bytes": 100,
            "avg_packet_size": 50.0,
            "max_packet_size": 100,
            "mean_inter_arrival_time": 0.5,
            "distinct_dest_port_count": 1,
            "tcp_syn_count": 0,
            "mqtt_related_packet_count": 0,
            "non_mqtt_tcp_udp_packet_count": 0,
        }
    ]

    with pytest.raises(Exception):
        _insert_feature_rows(db_session, segment["id"], bad_rows, {}, CAPTURE_SCOPE_DEFAULT)
