"""packet_feature_extractor DB 연동 integration 테스트."""

from __future__ import annotations

import calendar
import multiprocessing
import socket
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import dpkt
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from sqlalchemy.exc import OperationalError

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.features.collect_feature_logs import parse_db_datetime
from edge.features.packet_feature_utils import PartialPcapError
from edge.features.run_packet_feature_extractor import (
    CAPTURE_SCOPE_DEFAULT,
    _HAS_FCNTL,
    _acquire_lock,
    _file_sha256,
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
OTHER_SESSION_UUID = "22222222-2222-4222-8222-222222222222"
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


def _insert_capture_session(
    db_session,
    session_uuid: str = SESSION_UUID,
    *,
    capture_interface: str = "eth0",
    status: str = "RUNNING",
) -> int:
    db_session.execute(
        text(
            """
            INSERT INTO packet_capture_sessions
                (session_id, capture_interface, started_at, ended_at, status)
            VALUES (
                :sid,
                :capture_interface,
                '2026-07-16T10:00:00Z',
                :ended_at,
                :status
            )
            """
        ),
        {
            "sid": session_uuid,
            "capture_interface": capture_interface,
            "ended_at": "2026-07-16T10:10:00Z" if status != "RUNNING" else None,
            "status": status,
        },
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
    capture_interface: str = "eth0",
) -> dict:
    db_session.execute(
        text(
            """
            INSERT INTO packet_capture_segments
                (capture_session_id, file_name, capture_interface,
                 window_start, window_end, status)
            VALUES (:csid, :fname, :capture_interface, :ws, :we, 'READY')
            """
        ),
        {
            "csid": capture_session_id,
            "fname": file_name,
            "capture_interface": capture_interface,
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


@pytest.mark.skipif(not _HAS_FCNTL, reason="fcntl 미지원 환경 (Windows 등)")
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


@pytest.mark.skipif(not _HAS_FCNTL, reason="fcntl 미지원 환경 (Windows 등)")
def test_lock_blocks_concurrent_process(tmp_path: Path) -> None:
    lock_path = tmp_path / ".test.lock"
    q: multiprocessing.Queue = multiprocessing.Queue()

    with _acquire_lock(lock_path):
        p = multiprocessing.Process(target=_worker_try_lock, args=(str(lock_path), q))
        p.start()
        p.join(timeout=5)

    result = q.get_nowait()
    assert result == "blocked"


def test_lock_no_fcntl_executes_without_lock(tmp_path: Path) -> None:
    """_HAS_FCNTL=False 환경에서는 lock 없이 정상 실행된다."""
    import edge.features.run_packet_feature_extractor as mod

    executed = []
    with patch.object(mod, "_HAS_FCNTL", False):
        with mod._acquire_lock(tmp_path / ".lock"):
            executed.append(True)

    assert executed == [True]


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


def test_move_pcap_same_hash_removes_src(tmp_path: Path) -> None:
    """dst에 같은 내용의 파일이 있으면 src만 삭제한다."""
    src = tmp_path / "ready" / "seg.pcap"
    src.parent.mkdir()
    src.write_bytes(b"same_content")

    dst_dir = tmp_path / "processed"
    dst_dir.mkdir()
    (dst_dir / "seg.pcap").write_bytes(b"same_content")

    _move_pcap(src, dst_dir)

    assert not src.exists()
    assert (dst_dir / "seg.pcap").read_bytes() == b"same_content"


def test_move_pcap_different_hash_raises_file_exists_error(tmp_path: Path) -> None:
    """dst에 다른 내용의 동명 파일이 있으면 FileExistsError를 발생시킨다."""
    src = tmp_path / "ready" / "seg.pcap"
    src.parent.mkdir()
    src.write_bytes(b"new_content")

    dst_dir = tmp_path / "processed"
    dst_dir.mkdir()
    (dst_dir / "seg.pcap").write_bytes(b"old_content")

    with pytest.raises(FileExistsError):
        _move_pcap(src, dst_dir)

    # 기존 파일은 보존되어야 함
    assert src.exists()
    assert (dst_dir / "seg.pcap").read_bytes() == b"old_content"


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


def _configure_test_extractor(monkeypatch, module, session_factory) -> None:
    monkeypatch.setattr(module.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(module, "SessionLocal", session_factory)


def test_session_mode_processes_only_selected_completed_session_with_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        session_a = _insert_capture_session(db, status="COMPLETED")
        session_b = _insert_capture_session(
            db,
            OTHER_SESSION_UUID,
            capture_interface="eth1",
            status="COMPLETED",
        )
        segment_a_first = _insert_segment(db, session_a, file_name="a-first.pcap")
        segment_a_second = _insert_segment(
            db,
            session_a,
            file_name="a-second.pcap",
            window_start="2026-07-16T10:00:10Z",
            window_end="2026-07-16T10:00:20Z",
        )
        segment_b = _insert_segment(
            db,
            session_b,
            file_name="b-first.pcap",
            capture_interface="eth1",
        )

    ready_dir = tmp_path / "ready"
    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "a-first.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _write_pcap(
        ready_dir / "a-second.pcap",
        [(WINDOW_TS + 10.0, ESP_IP, PI_IP)],
    )
    _write_pcap(ready_dir / "b-first.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _configure_test_extractor(monkeypatch, mod, TestSession)

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=processed_dir,
        failed_dir=failed_dir,
        limit=1,
        lock_path=tmp_path / ".lock",
        session_id=SESSION_UUID,
    )

    with TestSession() as db:
        assert _segment_status(db, segment_a_first["id"])["status"] == "PROCESSED"
        assert _segment_status(db, segment_a_second["id"])["status"] == "READY"
        assert _segment_status(db, segment_b["id"])["status"] == "READY"
    assert count == 1
    assert (processed_dir / "a-first.pcap").exists()
    assert (ready_dir / "a-second.pcap").exists()
    assert (ready_dir / "b-first.pcap").exists()
    engine.dispose()


def test_session_mode_reconciles_only_selected_session(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    with TestSession() as db:
        session_a = _insert_capture_session(db, status="COMPLETED")
        session_b = _insert_capture_session(
            db,
            OTHER_SESSION_UUID,
            capture_interface="eth1",
            status="COMPLETED",
        )
        segment_a = _insert_segment(db, session_a, file_name="a-orphan.pcap")
        segment_b = _insert_segment(
            db,
            session_b,
            file_name="b-orphan.pcap",
            capture_interface="eth1",
        )
        db.execute(
            text(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' "
                "WHERE id = :id"
            ),
            {"id": segment_a["id"]},
        )
        db.execute(
            text(
                "UPDATE packet_capture_segments SET status = 'FAILED', "
                "error_code = 'PCAP_PARSE_ERROR' WHERE id = :id"
            ),
            {"id": segment_b["id"]},
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    processed_dir = tmp_path / "processed"
    failed_dir = tmp_path / "failed"
    ready_dir.mkdir()
    (ready_dir / "a-orphan.pcap").write_bytes(b"session-a")
    (ready_dir / "b-orphan.pcap").write_bytes(b"session-b")
    _configure_test_extractor(monkeypatch, mod, TestSession)

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=processed_dir,
        failed_dir=failed_dir,
        lock_path=tmp_path / ".lock",
        session_id=SESSION_UUID,
    )

    assert count == 0
    assert (processed_dir / "a-orphan.pcap").exists()
    assert (ready_dir / "b-orphan.pcap").exists()
    assert not (failed_dir / "b-orphan.pcap").exists()
    engine.dispose()


@pytest.mark.parametrize(
    ("requested_session_id", "message"),
    [
        ("not-a-uuid", "UUIDv4"),
        ("33333333-3333-4333-8333-333333333333", "존재하지"),
    ],
)
def test_invalid_or_missing_session_is_rejected_before_reconciliation(
    tmp_path: Path,
    monkeypatch,
    requested_session_id: str,
    message: str,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)
    with TestSession() as db:
        session_pk = _insert_capture_session(
            db,
            OTHER_SESSION_UUID,
            status="COMPLETED",
        )
        segment = _insert_segment(db, session_pk, file_name="sentinel.pcap")
        db.execute(
            text(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' "
                "WHERE id = :id"
            ),
            {"id": segment["id"]},
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    sentinel = ready_dir / "sentinel.pcap"
    sentinel.write_bytes(b"unchanged")
    _configure_test_extractor(monkeypatch, mod, TestSession)

    with pytest.raises(ValueError, match=message):
        mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            lock_path=tmp_path / ".lock",
            session_id=requested_session_id,
        )

    with TestSession() as db:
        assert _segment_status(db, segment["id"])["status"] == "PROCESSED"
    assert sentinel.read_bytes() == b"unchanged"
    assert not (tmp_path / "processed" / "sentinel.pcap").exists()
    engine.dispose()


@pytest.mark.parametrize("status", ["RUNNING", "FAILED"])
def test_ineligible_session_is_rejected_before_reconciliation(
    tmp_path: Path,
    monkeypatch,
    status: str,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)
    with TestSession() as db:
        session_pk = _insert_capture_session(db, status=status)
        segment = _insert_segment(db, session_pk, file_name="target-orphan.pcap")
        db.execute(
            text(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' "
                "WHERE id = :id"
            ),
            {"id": segment["id"]},
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    target = ready_dir / "target-orphan.pcap"
    target.write_bytes(b"unchanged")
    _configure_test_extractor(monkeypatch, mod, TestSession)

    with pytest.raises(ValueError, match="COMPLETED"):
        mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            lock_path=tmp_path / ".lock",
            session_id=SESSION_UUID,
        )

    with TestSession() as db:
        assert _segment_status(db, segment["id"])["status"] == "PROCESSED"
    assert target.read_bytes() == b"unchanged"
    assert not (tmp_path / "processed" / "target-orphan.pcap").exists()
    engine.dispose()


@pytest.mark.parametrize("limit", [0, -1])
def test_limit_below_one_is_rejected_before_reconciliation(
    tmp_path: Path,
    monkeypatch,
    limit: int,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)
    with TestSession() as db:
        session_pk = _insert_capture_session(db, status="COMPLETED")
        segment = _insert_segment(db, session_pk, file_name="limit-orphan.pcap")
        db.execute(
            text(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' "
                "WHERE id = :id"
            ),
            {"id": segment["id"]},
        )
        db.commit()

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    orphan = ready_dir / "limit-orphan.pcap"
    orphan.write_bytes(b"unchanged")
    _configure_test_extractor(monkeypatch, mod, TestSession)

    with pytest.raises(ValueError, match="limit.*1"):
        mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            limit=limit,
            lock_path=tmp_path / ".lock",
            session_id=SESSION_UUID,
        )

    assert orphan.read_bytes() == b"unchanged"
    assert not (tmp_path / "processed" / "limit-orphan.pcap").exists()
    engine.dispose()


def test_session_mode_missing_file_marks_only_selected_session_failed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)
    with TestSession() as db:
        session_a = _insert_capture_session(db, status="COMPLETED")
        session_b = _insert_capture_session(
            db,
            OTHER_SESSION_UUID,
            capture_interface="eth1",
            status="COMPLETED",
        )
        target = _insert_segment(db, session_a, file_name="missing.pcap")
        other = _insert_segment(
            db,
            session_b,
            file_name="other.pcap",
            capture_interface="eth1",
        )

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "other.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _configure_test_extractor(monkeypatch, mod, TestSession)

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=tmp_path / "processed",
        failed_dir=tmp_path / "failed",
        lock_path=tmp_path / ".lock",
        session_id=SESSION_UUID,
    )

    with TestSession() as db:
        assert _segment_status(db, target["id"])["status"] == "FAILED"
        assert _segment_status(db, other["id"])["status"] == "READY"
    assert count == 1
    assert (ready_dir / "other.pcap").exists()
    engine.dispose()


def test_session_mode_rerun_does_not_reprocess_completed_segment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)
    with TestSession() as db:
        session_pk = _insert_capture_session(db, status="COMPLETED")
        segment = _insert_segment(db, session_pk, file_name="once.pcap")

    ready_dir = tmp_path / "ready"
    processed_dir = tmp_path / "processed"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "once.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _configure_test_extractor(monkeypatch, mod, TestSession)
    kwargs = {
        "ready_dir": ready_dir,
        "processed_dir": processed_dir,
        "failed_dir": tmp_path / "failed",
        "lock_path": tmp_path / ".lock",
        "session_id": SESSION_UUID,
    }

    first_count = mod.extract_packet_features(**kwargs)
    second_count = mod.extract_packet_features(**kwargs)

    with TestSession() as db:
        feature_count = db.execute(
            text(
                "SELECT COUNT(*) FROM packet_feature_logs "
                "WHERE capture_segment_id = :segment_id"
            ),
            {"segment_id": segment["id"]},
        ).scalar_one()
    assert first_count == 1
    assert second_count == 0
    assert feature_count == 1
    assert (processed_dir / "once.pcap").exists()
    engine.dispose()


def test_session_id_omitted_preserves_global_mode_with_warning(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)
    with TestSession() as db:
        session_a = _insert_capture_session(db, status="COMPLETED")
        session_b = _insert_capture_session(
            db,
            OTHER_SESSION_UUID,
            capture_interface="eth1",
            status="COMPLETED",
        )
        _insert_segment(db, session_a, file_name="global-a.pcap")
        _insert_segment(
            db,
            session_b,
            file_name="global-b.pcap",
            capture_interface="eth1",
        )

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "global-a.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _write_pcap(ready_dir / "global-b.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _configure_test_extractor(monkeypatch, mod, TestSession)

    with caplog.at_level("WARNING"):
        count = mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            limit=2,
            lock_path=tmp_path / ".lock",
        )

    assert count == 2
    assert any("전체 READY" in record.message for record in caplog.records)
    engine.dispose()


def test_cli_invalid_session_exits_nonzero_with_clear_message(
    monkeypatch,
    capsys,
) -> None:
    import edge.features.run_packet_feature_extractor as mod

    monkeypatch.setattr(
        sys,
        "argv",
        ["run_packet_feature_extractor", "--session-id", "not-a-uuid"],
    )

    with pytest.raises(SystemExit) as exc_info:
        mod.main()

    assert exc_info.value.code != 0
    assert "UUIDv4" in capsys.readouterr().err


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


# ---------------------------------------------------------------------------
# SHA-256 파일 해시
# ---------------------------------------------------------------------------


def test_file_sha256_same_content_same_hash(tmp_path: Path) -> None:
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"hello world")
    b.write_bytes(b"hello world")
    assert _file_sha256(a) == _file_sha256(b)


def test_file_sha256_different_content_different_hash(tmp_path: Path) -> None:
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"hello")
    b.write_bytes(b"world")
    assert _file_sha256(a) != _file_sha256(b)


# ---------------------------------------------------------------------------
# 예상하지 못한 예외 전파 (Issue 5)
# ---------------------------------------------------------------------------


def test_unexpected_exception_propagates_from_extract(
    tmp_path: Path, monkeypatch
) -> None:
    """SQLAlchemyError가 아닌 예외는 루프를 중단하고 상위로 전파된다."""
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
    monkeypatch.setattr(
        mod, "process_segment",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("unexpected!")),
    )

    with pytest.raises(RuntimeError, match="unexpected!"):
        mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            lock_path=tmp_path / ".lock",
        )
    engine.dispose()


# ---------------------------------------------------------------------------
# UNSUPPORTED_FORMAT (Issue 6)
# ---------------------------------------------------------------------------


def test_failed_unsupported_format_when_non_ethernet_pcap(
    db_session, ready_dir: Path
) -> None:
    """비-Ethernet Datalink pcap은 UNSUPPORTED_FORMAT으로 FAILED 처리된다."""
    import dpkt

    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    DLT_NULL = 0  # loopback (Ethernet 아님)
    pcap_path = ready_dir / "test.pcap"
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=DLT_NULL)
        writer.writepkt(b"\x00" * 20)

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "FAILED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["status"] == "FAILED"
    assert seg["error_code"] == "UNSUPPORTED_FORMAT"
    assert seg["error_message"] is not None


# ---------------------------------------------------------------------------
# Python 3.10 Z 파싱 (parse_db_datetime)
# ---------------------------------------------------------------------------


def test_parse_db_datetime_z_suffix() -> None:
    """'Z' 접미사가 있는 ISO 8601 문자열을 Python 3.10 이하에서도 파싱한다."""
    from datetime import timezone

    dt = parse_db_datetime("2026-07-16T10:00:00Z")
    assert dt.year == 2026
    assert dt.month == 7
    assert dt.day == 16
    assert dt.hour == 10
    assert dt.minute == 0
    assert dt.second == 0
    assert dt.microsecond == 0


def test_parse_db_datetime_z_matches_utc_offset() -> None:
    """+00:00 형식과 Z 형식이 동일한 datetime을 반환한다."""
    dt_z = parse_db_datetime("2026-07-16T10:00:00Z")
    dt_plus = parse_db_datetime("2026-07-16T10:00:00+00:00")
    assert dt_z == dt_plus


def test_segment_with_z_window_start_processes_correctly(
    db_session, ready_dir: Path
) -> None:
    """DB에서 'Z' 형식으로 저장된 window_start를 가진 segment를 정상 처리한다."""
    csid = _insert_capture_session(db_session)
    # WINDOW_START_STR = "2026-07-16T10:00:00Z" (Migration 실제 포맷)
    segment = _insert_segment(db_session, csid, window_start=WINDOW_START_STR)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "PROCESSED"


# ---------------------------------------------------------------------------
# OperationalError 처리 (일시적 DB 잠금)
# ---------------------------------------------------------------------------


def test_operational_error_continues_to_next_segment(
    tmp_path: Path, monkeypatch
) -> None:
    """OperationalError(SQLite locked 등)는 READY 유지 후 다음 segment로 넘어간다."""
    import edge.features.run_packet_feature_extractor as mod

    db_path = tmp_path / "test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    TestSession, engine = _make_test_session_factory(db_path)

    WINDOW_START_2 = "2026-07-16T10:00:10Z"
    WINDOW_END_2 = "2026-07-16T10:00:20Z"
    WINDOW_TS_2 = WINDOW_TS + 10.0

    with TestSession() as db:
        csid = _insert_capture_session(db)
        _insert_segment(db, csid, file_name="seg1.pcap")
        _insert_segment(
            db, csid,
            file_name="seg2.pcap",
            window_start=WINDOW_START_2,
            window_end=WINDOW_END_2,
        )

    ready_dir = tmp_path / "ready"
    ready_dir.mkdir()
    _write_pcap(ready_dir / "seg1.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])
    _write_pcap(ready_dir / "seg2.pcap", [(WINDOW_TS_2, ESP_IP, PI_IP)])

    monkeypatch.setattr(mod.settings, "capture_interface_ip", PI_IP)
    monkeypatch.setattr(mod, "SessionLocal", TestSession)

    call_count = {"n": 0}
    original_process = mod.process_segment

    def _side_effect(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OperationalError("(sqlite3.OperationalError) database is locked", None, None)
        return original_process(*args, **kwargs)

    monkeypatch.setattr(mod, "process_segment", _side_effect)

    count = mod.extract_packet_features(
        ready_dir=ready_dir,
        processed_dir=tmp_path / "processed",
        failed_dir=tmp_path / "failed",
        lock_path=tmp_path / ".lock",
    )

    # seg1은 OperationalError로 건너뜀(count 미증가), seg2는 정상 완료
    assert count == 1

    # seg2가 실제로 PROCESSED 됐는지 확인
    with TestSession() as db:
        row = db.execute(
            text("SELECT status FROM packet_capture_segments WHERE file_name = 'seg2.pcap'")
        ).fetchone()
    assert row[0] == "PROCESSED"
    engine.dispose()


def test_non_operational_sqlalchemy_error_propagates(
    tmp_path: Path, monkeypatch
) -> None:
    """IntegrityError 등 구조적 DB 오류는 상위로 전파된다."""
    from sqlalchemy.exc import IntegrityError

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
    monkeypatch.setattr(
        mod, "process_segment",
        lambda *a, **kw: (_ for _ in ()).throw(
            IntegrityError("constraint failed", None, None)
        ),
    )

    with pytest.raises(IntegrityError):
        mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            lock_path=tmp_path / ".lock",
        )
    engine.dispose()


# ---------------------------------------------------------------------------
# 부분 손상 pcap (Issue 6 확장)
# ---------------------------------------------------------------------------


def test_failed_partial_capture_when_some_packets_corrupted(
    db_session, ready_dir: Path
) -> None:
    """정상 1개 + 손상 1개: 일부 손상 pcap은 PARTIAL_CAPTURE로 FAILED 처리된다."""
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    pcap_path = ready_dir / "test.pcap"
    _write_pcap(pcap_path, [(WINDOW_TS, ESP_IP, PI_IP), (WINDOW_TS + 1.0, ESP_IP, PI_IP)])

    call_count = [0]
    original_eth = dpkt.ethernet.Ethernet

    def _sometimes_fail(buf):
        call_count[0] += 1
        if call_count[0] == 2:
            raise Exception("forced failure on 2nd packet")
        return original_eth(buf)

    with patch(
        "edge.features.packet_feature_utils.dpkt.ethernet.Ethernet",
        side_effect=_sometimes_fail,
    ):
        status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "FAILED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["error_code"] == "PARTIAL_CAPTURE"


def test_failed_pcap_parse_error_when_all_packets_corrupted(
    db_session, ready_dir: Path
) -> None:
    """모든 패킷 파싱 실패 pcap은 PCAP_PARSE_ERROR로 FAILED 처리된다."""
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    pcap_path = ready_dir / "test.pcap"
    _write_pcap(pcap_path, [(WINDOW_TS, ESP_IP, PI_IP)])  # 패킷 1개 전부 실패

    with patch(
        "edge.features.packet_feature_utils.dpkt.ethernet.Ethernet",
        side_effect=Exception("forced parse failure"),
    ):
        status = process_segment(db_session, segment, ready_dir, PI_IP, {})

    assert status == "FAILED"
    seg = _segment_status(db_session, segment["id"])
    assert seg["error_code"] == "PCAP_PARSE_ERROR"


# ---------------------------------------------------------------------------
# OperationalError: locked만 continue, 그 외 전파
# ---------------------------------------------------------------------------


def test_non_locked_operational_error_propagates(
    tmp_path: Path, monkeypatch
) -> None:
    """'locked'/'busy'가 아닌 OperationalError(테이블 누락 등)는 상위로 전파된다."""
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
    monkeypatch.setattr(
        mod, "process_segment",
        lambda *a, **kw: (_ for _ in ()).throw(
            OperationalError("no such table: packet_feature_logs", None, None)
        ),
    )

    with pytest.raises(OperationalError):
        mod.extract_packet_features(
            ready_dir=ready_dir,
            processed_dir=tmp_path / "processed",
            failed_dir=tmp_path / "failed",
            lock_path=tmp_path / ".lock",
        )
    engine.dispose()


# ---------------------------------------------------------------------------
# isolated 상태 기기 Packet Feature 생성 (통합)
# ---------------------------------------------------------------------------


def test_isolated_device_packet_feature_created(db_session, ready_dir: Path) -> None:
    """isolated 상태의 기기로부터 오는 패킷도 Packet Feature에 기록된다."""
    db_session.execute(
        text(
            "INSERT INTO devices (device_id, ip_address, status, trust_score) "
            "VALUES ('esp32_isolated', :ip, 'isolated', 0)"
        ),
        {"ip": ESP_IP},
    )
    db_session.commit()

    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)
    _write_pcap(ready_dir / "test.pcap", [(WINDOW_TS, ESP_IP, PI_IP)])

    ip_device_map = _load_ip_device_map(db_session)
    status = process_segment(db_session, segment, ready_dir, PI_IP, ip_device_map)

    assert status == "PROCESSED"
    features = _feature_rows(db_session, segment["id"])
    assert len(features) == 1
    assert features[0]["device_id"] == "esp32_isolated"


# ---------------------------------------------------------------------------
# 부분 삽입 후 실패 → 전체 rollback (통합)
# ---------------------------------------------------------------------------


def test_partial_feature_insert_failure_rolls_back_all(
    db_session, ready_dir: Path
) -> None:
    """첫 번째 Feature 삽입 성공 후 두 번째 삽입 실패 시 전체 Feature와 Segment가 rollback된다."""
    csid = _insert_capture_session(db_session)
    segment = _insert_segment(db_session, csid)

    # 두 peer_ip → feature_rows 2개
    _write_pcap(
        ready_dir / "test.pcap",
        [
            (WINDOW_TS + 0.0, ESP_IP, PI_IP),
            (WINDOW_TS + 1.0, EXTERNAL_IP, PI_IP),
        ],
    )

    import edge.features.run_packet_feature_extractor as _mod
    _real_insert = _mod._insert_feature_rows  # patch 전에 원본 참조 저장

    def _insert_first_then_fail(db, seg_id, feature_rows, ip_device_map, capture_scope):
        # 첫 번째 row만 삽입 후 예외 발생 → 트랜잭션 전체 rollback 검증
        _real_insert(db, seg_id, feature_rows[:1], ip_device_map, capture_scope)
        raise Exception("second insert failed")

    with patch(
        "edge.features.run_packet_feature_extractor._insert_feature_rows",
        side_effect=_insert_first_then_fail,
    ):
        with pytest.raises(Exception, match="second insert failed"):
            process_segment(db_session, segment, ready_dir, PI_IP, {})

    db_session.rollback()

    assert _feature_rows(db_session, segment["id"]) == []
    assert _segment_status(db_session, segment["id"])["status"] == "READY"
