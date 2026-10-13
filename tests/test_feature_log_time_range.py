"""Time-range reads use complete MQTT feature windows without changing output timestamps."""
from datetime import datetime

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import text

from backend.app.main import app
from backend.app.services.feature_log_query_service import list_feature_logs


@pytest.fixture
def feature_rows(db_session):
    rows = [
        ("device_a", "2026-10-01 00:00:00", "2026-10-01 00:00:10"),
        ("device_a", "2026-10-01T00:00:10Z", "2026-10-01T00:00:20Z"),
        ("device_a", "2026-10-01T09:00:20+09:00", "2026-10-01T09:00:30+09:00"),
        ("device_b", "2026-10-01T00:00:10+00:00", "2026-10-01T00:00:20+00:00"),
        ("device_a", "2026-10-01T00:00:30", "2026-10-01T00:00:40"),
    ]
    saved = {}
    for device_id, start, end in rows:
        result = db_session.execute(text("""INSERT INTO feature_logs
            (device_id, window_start, window_end, publish_count)
            VALUES (:device, :start, :end, 2)"""), {"device": device_id, "start": start, "end": end})
        saved[int(result.lastrowid)] = (device_id, start, end)
    db_session.commit()
    return saved


def _get(**params):
    return TestClient(app).get("/api/feature-logs", params=params)


@pytest.mark.parametrize("start,end", [
    ("2026-10-01T00:00:00Z", "2026-10-01T00:00:30Z"),
    ("2026-10-01T09:00:00+09:00", "2026-10-01T09:00:30+09:00"),
])
def test_range_compares_equivalent_utc_instants_and_preserves_stored_text(feature_rows, start, end):
    response = _get(device_id="device_a", **{"from": start, "to": end})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert {item["id"] for item in body["items"]} == {1, 2, 3}
    for item in body["items"]:
        assert (item["device_id"], item["window_start"], item["window_end"]) == feature_rows[item["id"]]


def test_range_requires_whole_window_containment_not_overlap(feature_rows):
    response = _get(**{"from": "2026-10-01T00:00:05Z", "to": "2026-10-01T00:00:25Z"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {item["id"] for item in body["items"]} == {2, 4}


@pytest.mark.parametrize("bounds,ids", [
    ({"from": "2026-10-01T00:00:00.000001Z", "to": "2026-10-01T00:00:30Z"}, {2, 3}),
    ({"from": "2026-10-01T00:00:09.999999Z", "to": "2026-10-01T00:00:30Z"}, {2, 3}),
    ({"from": "2026-10-01T00:00:10.000001Z", "to": "2026-10-01T00:00:30Z"}, {3}),
    ({"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:29.999999Z"}, {1, 2}),
    ({"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:30.000001Z"}, {1, 2, 3}),
])
def test_microsecond_query_boundaries_are_not_rounded_by_sqlite(feature_rows, bounds, ids):
    response = _get(device_id="device_a", **bounds)
    assert response.status_code == 200
    assert response.json()["total"] == len(ids)
    assert {item["id"] for item in response.json()["items"]} == ids


@pytest.mark.parametrize("bounds,ids", [
    ({"from": "2026-10-01T00:00:20Z"}, {3, 5}),
    ({"to": "2026-10-01T00:00:20Z"}, {1, 2}),
    ({"from": "2026-10-01T00:00:10Z", "to": "2026-10-01T00:00:10Z"}, set()),
])
def test_optional_and_equal_boundaries(feature_rows, bounds, ids):
    response = _get(device_id="device_a", **bounds)
    assert response.status_code == 200
    assert response.json()["total"] == len(ids)
    assert {item["id"] for item in response.json()["items"]} == ids


def test_filtered_total_pagination_and_original_sort_order_are_preserved(db_session, feature_rows):
    bounds = {"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:40Z"}
    expected = db_session.execute(text("SELECT id FROM feature_logs WHERE device_id='device_a' "
                                       "ORDER BY window_start DESC, id DESC")).scalars().all()
    body = _get(device_id="device_a", limit=1, offset=1, **bounds).json()
    assert set(body) == {"items", "total", "snapshot_max_id"} and body["total"] == 4
    assert [row["id"] for row in body["items"]] == expected[1:2]
    assert _get(device_id="device_a", offset=100, **bounds).json() == {"items": [], "total": 4, "snapshot_max_id": 5}
    unbounded = _get(device_id="device_a").json()
    assert [row["id"] for row in unbounded["items"]] == expected


@pytest.mark.parametrize("bounds", [
    {"from": "not-a-time"}, {"to": "not-a-time"},
    {"from": "2026-10-01T00:00:00"}, {"to": "2026-10-01 00:00:20"},
    {"from": "2026-10-01T00:00:20Z", "to": "2026-10-01T00:00:10Z"},
    {"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T08:59:59+09:00"},
    {"from": "0001-01-01T00:00:00+09:00"},
    {"to": "9999-12-31T23:59:59-09:00"},
])
def test_invalid_naive_and_reversed_ranges_return_422(feature_rows, bounds):
    assert _get(**bounds).status_code == 422


def test_service_rejects_naive_bounds_before_query(db_session):
    with pytest.raises(ValueError, match="timezone"):
        list_feature_logs(db_session, from_at=datetime(2026, 10, 1))


def test_microsecond_bounds_before_epoch_use_floor_and_ceiling(db_session):
    db_session.execute(text("""INSERT INTO feature_logs
        (device_id, window_start, window_end) VALUES
        ('old', '1969-12-31T23:59:50Z', '1970-01-01T00:00:00Z'),
        ('old', '1970-01-01T00:00:00Z', '1970-01-01T00:00:10Z')"""))
    db_session.commit()
    body = _get(device_id="old", **{"from": "1969-12-31T23:59:50.000001Z"}).json()
    assert body["total"] == 1 and body["items"][0]["id"] == 2
    body = _get(device_id="old", **{"to": "1969-12-31T23:59:59.999999Z"}).json()
    assert body == {"items": [], "total": 0, "snapshot_max_id": 2}
