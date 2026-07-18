from __future__ import annotations

from pathlib import Path
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.database import get_db
from backend.app.main import app
from db.migration_runner import MIGRATIONS_DIR, apply_migrations


SESSION_A = "11111111-1111-4111-8111-111111111111"
SESSION_B = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def api_client(tmp_path: Path):
    db_path = tmp_path / "packet-gateway-api.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        db.execute(text("PRAGMA foreign_keys = ON"))
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), db_path
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def seed_packet_gateway_rows(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        session_a_pk = _insert_capture_session(connection, SESSION_A, "eth0")
        session_b_pk = _insert_capture_session(connection, SESSION_B, "eth1")
        segment_a1 = _insert_segment(
            connection,
            session_pk=session_a_pk,
            file_name="a1.pcap",
            capture_interface="eth0",
            window_start="2026-07-16T10:00:00Z",
            window_end="2026-07-16T10:00:10Z",
        )
        segment_a2 = _insert_segment(
            connection,
            session_pk=session_a_pk,
            file_name="a2.pcap",
            capture_interface="eth0",
            window_start="2026-07-16T10:00:10Z",
            window_end="2026-07-16T10:00:20Z",
        )
        segment_b1 = _insert_segment(
            connection,
            session_pk=session_b_pk,
            file_name="b1.pcap",
            capture_interface="eth1",
            window_start="2026-07-16T10:00:20Z",
            window_end="2026-07-16T10:00:30Z",
        )
        _insert_feature(
            connection,
            segment_id=segment_a1,
            device_id="esp32_01",
            peer_ip="10.0.0.8",
            direction="INBOUND",
            window_start="2026-07-16T10:00:00Z",
            window_end="2026-07-16T10:00:10Z",
            packet_count=42,
            total_bytes=8192,
            created_at="2026-07-16 10:00:21",
        )
        _insert_feature(
            connection,
            segment_id=segment_a2,
            device_id="esp32_02",
            peer_ip="10.0.0.9",
            direction="OUTBOUND",
            window_start="2026-07-16T10:00:10Z",
            window_end="2026-07-16T10:00:20Z",
            packet_count=12,
            total_bytes=1200,
            created_at="2026-07-16T10:00:22Z",
        )
        _insert_feature(
            connection,
            segment_id=segment_b1,
            device_id=None,
            peer_ip="10.0.0.10",
            direction="INBOUND",
            window_start="2026-07-16T10:00:20Z",
            window_end="2026-07-16T10:00:30Z",
            packet_count=30,
            total_bytes=3000,
            capture_scope="PI1_USB_LAN",
            created_at="2026-07-16 10:00:23",
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:00Z",
            sample_interval_seconds=None,
            cpu_percent=None,
            temperature_c=None,
            internal_rate=None,
            usb_exists=False,
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:10Z",
            sample_interval_seconds=10.5,
            cpu_percent=75.0,
            temperature_c=48.5,
            internal_rate=100.0,
            usb_exists=True,
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:20Z",
            sample_interval_seconds=10.0,
            cpu_percent=50.0,
            temperature_c=None,
            internal_rate=200.0,
            usb_exists=False,
        )


def _insert_capture_session(
    connection: sqlite3.Connection,
    session_id: str,
    capture_interface: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_sessions (
            session_id,
            capture_interface,
            started_at,
            first_window_start
        )
        VALUES (?, ?, ?, ?)
        """,
        (session_id, capture_interface, "2026-07-16T09:59:50Z", "2026-07-16T10:00:00Z"),
    )
    return int(cursor.lastrowid)


def _insert_segment(
    connection: sqlite3.Connection,
    *,
    session_pk: int,
    file_name: str,
    capture_interface: str,
    window_start: str,
    window_end: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_segments (
            capture_session_id,
            file_name,
            capture_interface,
            window_start,
            window_end
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (session_pk, file_name, capture_interface, window_start, window_end),
    )
    return int(cursor.lastrowid)


def _insert_feature(
    connection: sqlite3.Connection,
    *,
    segment_id: int,
    device_id: str | None,
    peer_ip: str,
    direction: str,
    window_start: str,
    window_end: str,
    packet_count: int,
    total_bytes: int,
    capture_scope: str = "PI1_INTERNAL_LAN",
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO packet_feature_logs (
            capture_segment_id,
            device_id,
            peer_ip,
            direction,
            window_start,
            window_end,
            packet_count,
            total_bytes,
            avg_packet_size,
            max_packet_size,
            mean_inter_arrival_time,
            distinct_dest_port_count,
            tcp_syn_count,
            mqtt_related_packet_count,
            non_mqtt_tcp_udp_packet_count,
            capture_scope,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            segment_id,
            device_id,
            peer_ip,
            direction,
            window_start,
            window_end,
            packet_count,
            total_bytes,
            total_bytes / max(packet_count, 1),
            512,
            0.5,
            2,
            3,
            4,
            5,
            capture_scope,
            created_at,
        ),
    )


def _insert_gateway_metric(
    connection: sqlite3.Connection,
    *,
    collected_at: str,
    sample_interval_seconds: float | None,
    cpu_percent: float | None,
    temperature_c: float | None,
    internal_rate: float | None,
    usb_exists: bool,
) -> None:
    interface_metrics = {
        "internal_lan": {
            "interface_name": "eth0",
            "exists": True,
            "is_up": True,
            "ip_address": "192.168.0.20",
            "rx_bytes": 124000000,
            "tx_bytes": 36000000,
            "rx_bytes_per_sec": internal_rate,
            "tx_bytes_per_sec": internal_rate,
        },
        "usb_lan": {
            "interface_name": "eth1",
            "exists": usb_exists,
            "is_up": False,
            "ip_address": None,
            "rx_bytes": None,
            "tx_bytes": None,
            "rx_bytes_per_sec": None,
            "tx_bytes_per_sec": None,
        },
    }
    connection.execute(
        """
        INSERT INTO gateway_metrics (
            collected_at,
            sample_interval_seconds,
            cpu_percent,
            memory_percent,
            disk_percent,
            disk_used_mb,
            network_rx_bytes,
            network_tx_bytes,
            temperature_c,
            interface_metrics_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            collected_at,
            sample_interval_seconds,
            cpu_percent,
            40.0,
            30.0,
            512.0,
            123456,
            654321,
            temperature_c,
            json.dumps(interface_metrics),
        ),
    )


def test_packet_feature_logs_return_sorted_rows_and_derived_fields(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    response = client.get("/api/packet-feature-logs")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert [item["window_start"] for item in body["items"]] == [
        "2026-07-16T10:00:20Z",
        "2026-07-16T10:00:10Z",
        "2026-07-16T10:00:00Z",
    ]
    latest = body["items"][0]
    assert latest["session_id"] == SESSION_B
    assert latest["device_id"] is None
    assert latest["packets_per_second"] == 3.0
    assert latest["bytes_per_second"] == 300.0
    assert latest["created_at"] == "2026-07-16T10:00:23Z"


def test_packet_feature_logs_support_filters_and_pagination(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    response = client.get(
        "/api/packet-feature-logs",
        params={
            "session_id": SESSION_A,
            "direction": "OUTBOUND",
            "from": "2026-07-16T19:00:00+09:00",
            "to": "2026-07-16T10:00:20Z",
            "limit": 1,
            "offset": 0,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["peer_ip"] == "10.0.0.9"
    assert body["items"][0]["session_id"] == SESSION_A


def test_packet_feature_logs_return_empty_result(api_client) -> None:
    client, _ = api_client

    response = client.get("/api/packet-feature-logs")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


def test_packet_feature_logs_reject_invalid_queries(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    assert client.get("/api/packet-feature-logs", params={"limit": 0}).status_code == 422
    assert client.get("/api/packet-feature-logs", params={"offset": -1}).status_code == 422
    assert client.get(
        "/api/packet-feature-logs",
        params={"from": "2026-07-16T10:00:00"},
    ).status_code == 422
    assert client.get(
        "/api/packet-feature-logs",
        params={
            "from": "2026-07-16T10:00:20Z",
            "to": "2026-07-16T10:00:00Z",
        },
    ).status_code == 422


def test_packet_feature_logs_return_500_for_stored_timestamp_error(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE packet_feature_logs
            SET created_at = 'not-a-timestamp'
            WHERE peer_ip = '10.0.0.10'
            """
        )

    response = client.get("/api/packet-feature-logs")

    assert response.status_code == 500
    assert response.json()["detail"] == "created_at must be a valid timestamp"


def test_gateway_metrics_return_latest_rows_and_parse_json(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    response = client.get("/api/gateway-metrics", params={"limit": 1})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert len(body["items"]) == 1
    latest = body["items"][0]
    assert latest["collected_at"] == "2026-07-16T10:00:20Z"
    assert latest["sample_interval_seconds"] == 10.0
    assert latest["cpu_percent"] == 50.0
    assert latest["interface_metrics"]["internal_lan"]["rx_bytes_per_sec"] == 200.0
    assert latest["interface_metrics"]["usb_lan"]["exists"] is False
    assert "interface_metrics_json" not in latest
    assert "network_rx_bytes" not in latest
    assert "network_tx_bytes" not in latest
    assert "created_at" not in latest
    assert "disk_total_mb" not in latest
    assert "gateway_status" not in latest


def test_gateway_metrics_preserve_nullable_first_sample(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    response = client.get(
        "/api/gateway-metrics",
        params={
            "from": "2026-07-16T10:00:00Z",
            "to": "2026-07-16T10:00:00Z",
        },
    )

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["sample_interval_seconds"] is None
    assert item["cpu_percent"] is None
    assert item["temperature_c"] is None
    assert item["interface_metrics"]["internal_lan"]["rx_bytes_per_sec"] is None
    assert item["interface_metrics"]["usb_lan"]["exists"] is False
    assert item["interface_metrics"]["usb_lan"]["is_up"] is False


def test_gateway_metrics_support_time_filters_and_pagination(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    response = client.get(
        "/api/gateway-metrics",
        params={
            "from": "2026-07-16T19:00:00+09:00",
            "to": "2026-07-16T10:00:20Z",
            "limit": 1,
            "offset": 1,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert len(body["items"]) == 1
    assert body["items"][0]["collected_at"] == "2026-07-16T10:00:10Z"


def test_gateway_metrics_return_empty_result(api_client) -> None:
    client, _ = api_client

    response = client.get("/api/gateway-metrics")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


def test_gateway_metrics_reject_invalid_queries(api_client) -> None:
    client, db_path = api_client
    seed_packet_gateway_rows(db_path)

    assert client.get("/api/gateway-metrics", params={"limit": 501}).status_code == 422
    assert client.get("/api/gateway-metrics", params={"offset": -1}).status_code == 422
    assert client.get(
        "/api/gateway-metrics",
        params={"from": "2026-07-16T10:00:00"},
    ).status_code == 422
    assert client.get(
        "/api/gateway-metrics",
        params={
            "from": "2026-07-16T10:00:20Z",
            "to": "2026-07-16T10:00:00Z",
        },
    ).status_code == 422


def test_query_services_call_repository_functions(monkeypatch) -> None:
    from backend.app.services import gateway_metrics_query_service
    from backend.app.services import packet_feature_query_service

    packet_calls: list[str] = []
    gateway_calls: list[str] = []

    def fake_packet_list(*args, **kwargs):
        packet_calls.append("list")
        return [
            {
                "id": 1,
                "capture_segment_id": 10,
                "session_id": SESSION_A,
                "device_id": None,
                "peer_ip": "10.0.0.8",
                "direction": "INBOUND",
                "window_start": "2026-07-16T10:00:00Z",
                "window_end": "2026-07-16T10:00:10Z",
                "packet_count": 10,
                "total_bytes": 1000,
                "avg_packet_size": 100.0,
                "max_packet_size": 120,
                "mean_inter_arrival_time": 0.5,
                "distinct_dest_port_count": 1,
                "tcp_syn_count": 1,
                "mqtt_related_packet_count": 1,
                "non_mqtt_tcp_udp_packet_count": 0,
                "capture_scope": "PI1_INTERNAL_LAN",
                "created_at": "2026-07-16 10:00:11",
            }
        ]

    def fake_packet_count(*args, **kwargs):
        packet_calls.append("count")
        return 1

    def fake_gateway_list(*args, **kwargs):
        gateway_calls.append("list")
        return [
            {
                "id": 1,
                "collected_at": "2026-07-16T10:00:00Z",
                "sample_interval_seconds": None,
                "cpu_percent": None,
                "memory_percent": 40.0,
                "disk_percent": 30.0,
                "disk_used_mb": 512.0,
                "network_rx_bytes": None,
                "network_tx_bytes": None,
                "temperature_c": None,
                "interface_metrics_json": json.dumps({
                    "internal_lan": {
                        "interface_name": "eth0",
                        "exists": True,
                        "is_up": True,
                        "ip_address": "192.168.0.20",
                        "rx_bytes": 1,
                        "tx_bytes": 2,
                        "rx_bytes_per_sec": None,
                        "tx_bytes_per_sec": None,
                    },
                    "usb_lan": {
                        "interface_name": "eth1",
                        "exists": False,
                        "is_up": False,
                        "ip_address": None,
                        "rx_bytes": None,
                        "tx_bytes": None,
                        "rx_bytes_per_sec": None,
                        "tx_bytes_per_sec": None,
                    },
                }),
                "created_at": "2026-07-16 10:00:01",
            }
        ]

    def fake_gateway_count(*args, **kwargs):
        gateway_calls.append("count")
        return 1

    monkeypatch.setattr(packet_feature_query_service, "list_packet_feature_logs", fake_packet_list)
    monkeypatch.setattr(packet_feature_query_service, "count_packet_feature_logs", fake_packet_count)
    monkeypatch.setattr(gateway_metrics_query_service, "list_gateway_metrics", fake_gateway_list)
    monkeypatch.setattr(gateway_metrics_query_service, "count_gateway_metrics", fake_gateway_count)

    packet_result = packet_feature_query_service.list_packet_features(db=object())
    gateway_result = gateway_metrics_query_service.list_gateway_metric_rows(db=object())

    assert packet_calls == ["list", "count"]
    assert gateway_calls == ["list", "count"]
    assert packet_result["items"][0]["packets_per_second"] == 1.0
    assert gateway_result["items"][0]["interface_metrics"]["usb_lan"]["exists"] is False
