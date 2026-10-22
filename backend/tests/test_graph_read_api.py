"""Stable insertion watermarks and honest capture gaps through the actual APIs."""

from datetime import datetime, timedelta, timezone
import sqlite3

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.main import app
from backend.app.services.feature_log_query_service import list_feature_logs
from backend.app.services.packet_feature_query_service import list_packet_features
from db.migration_runner import MIGRATIONS_DIR, apply_migrations


SESSION_ID = "11111111-1111-4111-8111-111111111111"
START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _stamp(slot):
    return (START + timedelta(seconds=slot * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def graph_api(tmp_path):
    path = tmp_path / "graph.db"
    apply_migrations(path, MIGRATIONS_DIR)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executemany("INSERT INTO devices(device_id) VALUES (?)", [("a",), ("b",)])
        connection.execute("""INSERT INTO packet_capture_sessions
            (id,session_id,capture_interface,started_at,first_window_start,ended_at,status)
            VALUES(1,?,'eth0',?,?,?,'COMPLETED')""", (SESSION_ID, _stamp(0), _stamp(0), _stamp(6)))
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def read_only(connection, _):
        connection.execute("PRAGMA query_only=ON")

    def get_test_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = get_test_db
    try:
        yield TestClient(app), path, engine
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def _segment(connection, slot, status="PROCESSED"):
    connection.execute("""INSERT OR IGNORE INTO packet_capture_segments
        (id,capture_session_id,file_name,capture_interface,window_start,window_end,
         status,packet_count,error_code,start_delay_seconds,captured_duration_seconds)
        VALUES(?,1,?,'eth0',?,?,?, ?,?,0,10)""",
        (slot + 1, f"capture-{slot}.pcap", _stamp(slot), _stamp(slot + 1), status,
         0 if status == "EMPTY" else 2,
         "PCAP_PARSE_ERROR" if status == "FAILED" else None))


def _append(path, kind, *, device="a", slot=0):
    with sqlite3.connect(path) as connection:
        if kind == "feature-logs":
            connection.execute("""INSERT INTO feature_logs
                (device_id,window_start,window_end,publish_count) VALUES(?,?,?,2)""",
                (device, _stamp(slot), _stamp(slot + 1)))
        else:
            _segment(connection, slot)
            connection.execute("""INSERT INTO packet_feature_logs
                (capture_segment_id,device_id,peer_ip,direction,window_start,window_end,
                 packet_count,total_bytes,avg_packet_size,max_packet_size,mean_inter_arrival_time,
                 distinct_dest_port_count,tcp_syn_count,mqtt_related_packet_count,
                 non_mqtt_tcp_udp_packet_count)
                VALUES(?,?,?,'INBOUND',?,?,2,100,50,50,1,1,0,2,0)""",
                (slot + 1, device, "192.168.0.20" if device == "a" else "192.168.0.21",
                 _stamp(slot), _stamp(slot + 1)))


@pytest.mark.parametrize("kind", ["feature-logs", "packet-feature-logs"])
def test_pages_keep_initial_ids_and_total_while_new_rows_arrive(graph_api, kind):
    client, path, _ = graph_api
    for device, slot in [("a", 0), ("b", 0), ("a", 1)]:
        _append(path, kind, device=device, slot=slot)
    first = client.get(f"/api/{kind}", params={"limit": 1}).json()
    assert first["snapshot_max_id"] == first["total"] == 3
    assert first["items"][0]["id"] == 3
    _append(path, kind, slot=2)
    second = client.get(f"/api/{kind}", params={"limit": 1, "offset": 1, "snapshot_max_id": 3}).json()
    third = client.get(f"/api/{kind}", params={"limit": 1, "offset": 2, "snapshot_max_id": 3}).json()
    assert second["total"] == third["total"] == 3
    assert [second["items"][0]["id"], third["items"][0]["id"]] == [2, 1]
    current = client.get(f"/api/{kind}").json()
    assert current["snapshot_max_id"] == current["total"] == 4
    filtered = client.get(f"/api/{kind}", params={"device_id": "b", "snapshot_max_id": 4}).json()
    assert filtered["snapshot_max_id"] == 4 and filtered["total"] == 1


@pytest.mark.parametrize("kind", ["feature-logs", "packet-feature-logs"])
def test_empty_watermark_stays_empty_and_future_tokens_are_rejected(graph_api, kind):
    client, path, _ = graph_api
    assert client.get(f"/api/{kind}").json() == {"items": [], "total": 0, "snapshot_max_id": 0}
    _append(path, kind)
    assert client.get(f"/api/{kind}", params={"snapshot_max_id": 0}).json() == {
        "items": [], "total": 0, "snapshot_max_id": 0}
    for token in (-1, 2, 2**63, "invalid"):
        assert client.get(f"/api/{kind}", params={"snapshot_max_id": token}).status_code == 422


@pytest.mark.parametrize("kind,table,count_column", [
    ("feature-logs", "feature_logs", "publish_count"),
    ("packet-feature-logs", "packet_feature_logs", "packet_count"),
])
def test_maximum_total_and_items_share_a_physical_read_snapshot(graph_api, kind, table, count_column):
    client, path, engine = graph_api
    _append(path, kind)
    changed = []

    def concurrent_update(_conn, _cursor, statement, _params, _context, _many):
        if "SELECT COALESCE(MAX(id), 0)" in statement and not changed:
            changed.append(True)
            with sqlite3.connect(path) as writer:
                writer.execute(f"UPDATE {table} SET {count_column}=99,device_id='b' WHERE id=1")

    event.listen(engine, "after_cursor_execute", concurrent_update)
    try:
        body = client.get(f"/api/{kind}", params={"device_id": "a"}).json()
    finally:
        event.remove(engine, "after_cursor_execute", concurrent_update)
    assert changed == [True]
    assert body["snapshot_max_id"] == body["total"] == 1
    assert body["items"][0][count_column] == 2
    # The watermark is not an immutable data snapshot across separate requests.
    assert client.get(f"/api/{kind}", params={"device_id": "a", "snapshot_max_id": 1}).json()["total"] == 0


@pytest.mark.parametrize("service", [list_feature_logs, list_packet_features])
def test_read_service_releases_only_its_own_transaction(graph_api, service):
    _, _, engine = graph_api
    with Session(engine) as db:
        body = service(db)
        assert body["items"] == []
        assert not db.in_transaction()
        with pytest.raises(ValueError, match="global maximum"):
            service(db, snapshot_max_id=1)
        assert not db.in_transaction()
        with db.begin() as caller_transaction:
            assert service(db)["snapshot_max_id"] == 0
            assert db.get_transaction() is caller_transaction
            assert db.connection().connection.driver_connection.in_transaction


def _capture(client, **overrides):
    params = {"session_id": SESSION_ID, "from": _stamp(0), "to": _stamp(6), **overrides}
    return client.get("/api/packet-capture-windows", params=params)


def test_capture_metadata_distinguishes_missing_empty_failed_and_pending_without_features(graph_api):
    client, path, _ = graph_api
    with sqlite3.connect(path) as connection:
        for slot, status in enumerate(("PROCESSED", "EMPTY", "FAILED", "READY")):
            _segment(connection, slot, status)
    _append(path, "packet-feature-logs", slot=0)
    response = _capture(client)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 6
    assert [item["observation"] for item in body["items"]] == [
        "PROCESSED", "EMPTY", "FAILED", "PENDING", "MISSING", "MISSING"]
    assert [item["feature_row_count"] for item in body["items"]] == [1, 0, 0, 0, None, None]
    assert body["items"][1]["packet_count"] == 0
    assert body["items"][2]["capture_eligible"] is False
    assert body["items"][3]["segment_status"] == "READY"
    for item in body["items"][4:]:
        assert item["packet_count"] is item["capture_eligible"] is item["segment_status"] is None
    assert all("file_name" not in item and "error_message" not in item for item in body["items"])
    assert client.get("/api/packet-feature-logs").json()["total"] == 1


def test_capture_range_is_fully_contained_bounded_and_timezone_normalized(graph_api):
    client, _, _ = graph_api
    body = _capture(client, **{"from": "2026-10-01T09:00:00+09:00", "to": _stamp(1)}).json()
    assert body["total"] == 1 and body["items"][0]["window_end"] == _stamp(1)
    assert _capture(client, **{"to": _stamp(0)}).json()["total"] == 0
    assert _capture(client, **{"to": _stamp(360)}).json()["total"] == 360
    # Missing before/after session bounds means no DB record, never FAILED/zero.
    future = _capture(client, **{"from": _stamp(360), "to": _stamp(361)}).json()
    assert future["items"][0]["observation"] == "MISSING"


@pytest.mark.parametrize("overrides", [
    {"from": "invalid"}, {"from": "2026-10-01T00:00:00"},
    {"from": "2026-10-01T00:00:00.000001Z"}, {"from": "2026-10-01T00:00:01Z"},
    {"to": _stamp(361)}, {"from": _stamp(7)}, {"session_id": "invalid"},
    {"from": "0001-01-01T00:00:00+09:00"}, {"to": "9999-12-31T23:59:59-09:00"},
])
def test_capture_invalid_queries_return_422(graph_api, overrides):
    assert _capture(graph_api[0], **overrides).status_code == 422


def test_capture_requires_explicit_bounds_and_reports_missing_session_and_schema(graph_api):
    client, path, _ = graph_api
    assert client.get("/api/packet-capture-windows", params={"session_id": SESSION_ID}).status_code == 422
    assert _capture(client, session_id="22222222-2222-4222-8222-222222222222").status_code == 404
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE packet_capture_segments")
    response = _capture(client)
    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "PACKET_CAPTURE_DATA_UNAVAILABLE"}


@pytest.mark.parametrize("bad_start,bad_end", [
    (_stamp(0), _stamp(1)),
    ("2026-10-01T00:00:01Z", "2026-10-01T00:00:11Z"),
])
def test_capture_rejects_duplicate_or_unaligned_stored_windows(graph_api, bad_start, bad_end):
    client, path, _ = graph_api
    with sqlite3.connect(path) as connection:
        _segment(connection, 0)
        connection.execute("""INSERT INTO packet_capture_segments
            (capture_session_id,file_name,capture_interface,window_start,window_end,status)
            VALUES (1,'bad.pcap','eth1',?,?,'READY')""", (bad_start, bad_end))
    response = _capture(client)
    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "PACKET_CAPTURE_DATA_UNAVAILABLE"}


def test_packet_existing_to_start_boundary_and_utc_overflow_contract(graph_api):
    client, path, _ = graph_api
    _append(path, "packet-feature-logs", slot=0)
    body = client.get("/api/packet-feature-logs", params={"to": _stamp(0)}).json()
    assert body["total"] == 1  # Existing Packet filter compares window_start.
    for bounds in ({"from": "0001-01-01T00:00:00+09:00"}, {"to": "9999-12-31T23:59:59-09:00"}):
        assert client.get("/api/packet-feature-logs", params=bounds).status_code == 422
