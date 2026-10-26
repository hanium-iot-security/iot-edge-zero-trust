"""Raw graph reads preserve measured bytes and exact explicit-zone timestamps."""
from datetime import datetime

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import text

from backend.app.main import app
from backend.app.services.mqtt_log_query_service import list_mqtt_logs


def insert(db, received_at, *, device="raw_a", size=2, valid=1):
    result = db.execute(text("""INSERT INTO mqtt_logs
        (device_id, topic, payload, payload_size, received_at, is_json_valid, is_topic_valid)
        VALUES (:device, 'iot/raw/sensor', 'invalid raw text', :size, :at, :valid, 1)"""),
        {"device": device, "size": size, "at": received_at, "valid": valid})
    db.commit()
    return int(result.lastrowid)


def get(**params):
    return TestClient(app).get("/api/mqtt-logs", params=params)


def test_raw_range_is_half_open_exact_utc_and_excludes_unverifiable_times(db_session):
    before = insert(db_session, "2026-10-01T00:00:00.000001Z")
    first = insert(db_session, "2026-10-01T09:00:00.000002+09:00", size=0, valid=0)
    same = insert(db_session, "2026-10-01T00:00:00.000002Z", size=None)
    insert(db_session, "2026-10-01T00:00:00.000003Z")
    insert(db_session, "2026-10-01 00:00:00")
    insert(db_session, "bad-time")
    insert(db_session, "2026-10-01T00:00:00.000002Z", device="raw_b")
    response = get(device_id="raw_a", **{"from": "2026-10-01T00:00:00.000002Z", "to": "2026-10-01T00:00:00.000003Z"})
    assert response.status_code == 200
    body = response.json()
    assert [row["id"] for row in body["items"]] == [same, first]
    assert before not in [row["id"] for row in body["items"]]
    assert [row["payload_size"] for row in body["items"]] == [None, 0]
    assert body["total"] == 2
    assert body["timestamp_unavailable_count"] == 2
    assert body["interval_predecessor_policy"] == "within_range_only"
    assert body["offset"] == 0 and body["limit"] == 100 and body["has_more"] is False


def test_raw_watermark_keeps_live_arrivals_from_shifting_offsets(db_session):
    ids = [insert(db_session, f"2026-10-01T00:00:0{n}Z") for n in range(3)]
    bounds = {"device_id": "raw_a", "from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:10Z", "limit": 1}
    first = get(**bounds).json()
    insert(db_session, "2026-10-01T00:00:01.500000Z")
    second = get(**bounds, offset=1, snapshot_max_id=first["snapshot_max_id"]).json()
    assert first["items"][0]["id"] == ids[2]
    assert second["items"][0]["id"] == ids[1]
    assert second["total"] == first["total"] == 3
    assert second["snapshot_max_id"] == first["snapshot_max_id"]
    assert first["has_more"] is True


def test_legacy_log_order_and_invalid_payload_visibility_stay_compatible(db_session):
    older_id = insert(db_session, "2026-10-01T00:00:09Z", size=7)
    latest_id = insert(db_session, "2026-10-01 00:00:01", size=0, valid=0)
    body = get(device_id="raw_a").json()
    assert [row["id"] for row in body["items"]] == [latest_id, older_id]
    assert body["items"][0]["payload_size"] == 0
    assert get(device_id="raw_a", valid_only=True).json()["total"] == 1


@pytest.mark.parametrize("params", [
    {"from": "2026-10-01T00:00:00"}, {"to": "bad"},
    {"from": "2026-10-01T00:00:02Z", "to": "2026-10-01T00:00:01Z"},
    {"limit": 501}, {"offset": -1}, {"offset": 100001},
    {"snapshot_max_id": -1}, {"snapshot_max_id": 9223372036854775808},
])
def test_raw_invalid_bounds_are_422(db_session, params):
    assert get(**params).status_code == 422


def test_service_bounds_are_safe_for_non_http_consumers(db_session):
    with pytest.raises(ValueError, match="limit"):
        list_mqtt_logs(db_session, limit=501)
    with pytest.raises(ValueError, match="timezone"):
        list_mqtt_logs(db_session, from_at=datetime(2026, 10, 1))


def test_empty_range_and_future_snapshot_are_explicit(db_session):
    insert(db_session, "2026-10-01T00:00:00Z")
    body = get(device_id="missing", **{"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:00Z"}).json()
    assert body["items"] == [] and body["total"] == 0
    assert body["timestamp_unavailable_count"] == 0
    assert get(snapshot_max_id=100).status_code == 422

def test_later_coarse_pages_preserve_offset_and_microsecond_edges(db_session):
    times = ["2026-10-01T00:00:00.999998Z", "2026-10-01T09:00:00.999999+09:00",
             "2026-10-01T00:00:01.000000Z", "2026-10-01T00:00:01.000001Z"]
    ids = [insert(db_session, at) for at in times]
    bounds = {"device_id": "raw_a", "from": "2026-10-01T00:00:00.999999Z", "to": "2026-10-01T00:00:01.000001Z", "limit": 1}
    first = get(**bounds).json()
    second = get(**bounds, offset=1, snapshot_max_id=first["snapshot_max_id"]).json()
    assert [first["items"][0]["id"], second["items"][0]["id"]] == [ids[2], ids[1]]
    assert first["total"] == second["total"] == 2
    assert second["timestamp_unavailable_count"] is None
    assert second["timestamp_unavailable_count_scope"] == "device_snapshot_first_page"


def test_exact_supported_offsets_do_not_disappear_on_coarse_later_pages(db_session):
    ids = [insert(db_session, "2026-01-01T20:00:00+20:00"),
           insert(db_session, "2026-01-01T00:00:01Z")]
    bounds = {"device_id": "raw_a", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T00:00:02Z", "limit": 1}
    first = get(**bounds).json()
    second = get(**bounds, offset=1, snapshot_max_id=first["snapshot_max_id"]).json()
    assert first["total"] == second["total"] == 2
    assert [first["items"][0]["id"], second["items"][0]["id"]] == [ids[1], ids[0]]


def test_malformed_raw_offset_is_unverifiable_not_normalized():
    from backend.app.services.mqtt_log_time import mqtt_received_microseconds
    assert mqtt_received_microseconds("2026-01-01T00:00:00+09:60") is None


def test_older_unknown_time_does_not_break_proven_selected_source_continuity(db_session):
    insert(db_session, "2026-07-01 00:00:00")
    ids = [insert(db_session, "2026-10-01T00:00:00Z"), insert(db_session, "2026-10-01T00:00:05Z")]
    bounds = {"device_id": "raw_a", "from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:10Z", "limit": 1}
    first = get(**bounds).json()
    second = get(**bounds, offset=1, snapshot_max_id=first["snapshot_max_id"]).json()
    assert first["timestamp_unavailable_count"] == 1
    assert first["source_span_count"] == first["total"] == 2
    assert first["source_span_count_scope"] == "selected_source_ids_first_page"
    assert second["source_span_count"] is None
    assert [first["items"][0]["id"], second["items"][0]["id"]] == list(reversed(ids))


@pytest.mark.parametrize("middle", ["bad-time", "2026-09-01T00:00:00Z"])
def test_hidden_intervening_raw_message_invalidates_selected_source_continuity(db_session, middle):
    insert(db_session, "2026-10-01T00:00:00Z")
    insert(db_session, middle)
    insert(db_session, "2026-10-01T00:00:05Z")
    body = get(device_id="raw_a", **{"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:10Z"}).json()
    assert body["total"] == 2 and body["source_span_count"] == 3


def test_valid_only_does_not_hide_intervening_invalid_payload_from_continuity(db_session):
    insert(db_session, "2026-10-01T00:00:00Z")
    insert(db_session, "2026-10-01T00:00:03Z", valid=0)
    insert(db_session, "2026-10-01T00:00:05Z")
    body = get(device_id="raw_a", valid_only=True, **{"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:10Z"}).json()
    assert body["total"] == 2 and body["source_span_count"] == 3


def test_source_continuity_is_device_scoped_and_empty_ranges_have_zero_span(db_session):
    insert(db_session, "2026-10-01T00:00:00Z")
    insert(db_session, "bad-time", device="raw_b")
    insert(db_session, "2026-10-01T00:00:05Z")
    body = get(device_id="raw_a", **{"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:10Z"}).json()
    assert body["total"] == body["source_span_count"] == 2
    empty = get(device_id="raw_a", **{"from": "2026-10-02T00:00:00Z", "to": "2026-10-02T00:00:10Z"}).json()
    assert empty["total"] == empty["source_span_count"] == 0
    legacy = get(device_id="raw_a").json()
    assert legacy["source_span_count"] is None
    assert legacy["source_span_count_scope"] == "not_evaluated"
