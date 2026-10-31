"""Dashboard validity filters must affect raw-log rows and server totals."""
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import text

from backend.app.main import app
from backend.app.services.mqtt_log_query_service import list_mqtt_logs


def insert(db, json_valid, topic_valid, at="2026-10-01T00:00:00Z", device="filter_a"):
    result = db.execute(text("""INSERT INTO mqtt_logs
        (device_id, topic, payload, payload_size, received_at, is_json_valid, is_topic_valid)
        VALUES (:device, 'iot/filter_a/sensor', '{}', 2, :at, :json, :topic)"""),
        {"device": device, "at": at, "json": json_valid, "topic": topic_valid})
    db.commit()
    return int(result.lastrowid)


def get(**params):
    return TestClient(app).get("/api/mqtt-logs", params=params)


def applied(json_valid=None, topic_valid=None, valid_only=False):
    return {"is_json_valid": json_valid, "is_topic_valid": topic_valid, "valid_only": valid_only}


@pytest.mark.parametrize("json_valid,topic_valid", [
    (None, None), (False, None), (True, None), (None, False), (None, True),
    (False, False), (False, True), (True, False), (True, True),
])
def test_individual_validity_filters_apply_to_rows_and_total(db_session, json_valid, topic_valid):
    ids = {(j, t): insert(db_session, j, t) for j, t in [(1, 1), (1, 0), (0, 1), (0, 0)]}
    insert(db_session, 0, 0, device="filter_b")
    params = {"device_id": "filter_a"}
    if json_valid is not None:
        params["is_json_valid"] = json_valid
    if topic_valid is not None:
        params["is_topic_valid"] = topic_valid
    response = get(**params)
    assert response.status_code == 200
    body = response.json()
    expected = sorted((value for (j, t), value in ids.items()
        if (json_valid is None or bool(j) == json_valid)
        and (topic_valid is None or bool(t) == topic_valid)), reverse=True)
    assert [row["id"] for row in body["items"]] == expected
    assert body["total"] == len(expected)
    assert body["applied_validity_filters"] == applied(json_valid, topic_valid)


@pytest.mark.parametrize("extra,expected", [
    ({}, 1), ({"is_json_valid": True}, 1), ({"is_topic_valid": True}, 1),
    ({"is_json_valid": False}, 0), ({"is_topic_valid": False}, 0),
])
def test_legacy_valid_only_is_conjunctive_with_explicit_filters(db_session, extra, expected):
    for j, t in [(0, 0), (0, 1), (1, 0), (1, 1)]:
        insert(db_session, j, t)
    response = get(device_id="filter_a", valid_only=True, **extra)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == expected and len(body["items"]) == expected
    assert body["applied_validity_filters"] == applied(
        extra.get("is_json_valid"), extra.get("is_topic_valid"), True)


def test_filtered_legacy_pagination_keeps_snapshot_and_ingestion_order(db_session):
    oldest = insert(db_session, 0, 1, "2026-10-01T00:00:09Z")
    insert(db_session, 1, 1)
    newest = insert(db_session, 0, 0, "2026-10-01 00:00:01")
    first = get(device_id="filter_a", is_json_valid=False, limit=1).json()
    assert [row["id"] for row in first["items"]] == [newest]
    assert first["total"] == 2 and first["has_more"] is True
    insert(db_session, 0, 1, "2026-10-01T00:00:08Z")
    second = get(device_id="filter_a", is_json_valid=False, limit=1, offset=1,
                 snapshot_max_id=first["snapshot_max_id"]).json()
    assert [row["id"] for row in second["items"]] == [oldest]
    assert second["total"] == 2 and second["has_more"] is False
    assert second["snapshot_max_id"] == first["snapshot_max_id"]
    assert second["applied_validity_filters"] == applied(False)
    beyond = get(device_id="filter_a", is_json_valid=False, limit=1, offset=2,
                 snapshot_max_id=first["snapshot_max_id"]).json()
    assert beyond["total"] == 2 and beyond["items"] == []
    assert beyond["applied_validity_filters"] == applied(False)


@pytest.mark.parametrize("flag", ["is_json_valid", "is_topic_valid"])
def test_ranged_false_filter_preserves_excluded_source_ids_and_unknown_times(db_session, flag):
    matching = {"is_json_valid": (0, 1), "is_topic_valid": (1, 0)}[flag]
    first_id = insert(db_session, *matching, "2026-10-01T00:00:00Z")
    insert(db_session, 1, 1, "bad-time")  # Excluded by validity, still breaks source continuity.
    last_id = insert(db_session, *matching, "2026-10-01T00:00:05Z")
    insert(db_session, *matching, "2026-10-01T00:00:10Z")  # Half-open end.
    insert(db_session, *matching, "bad-time")
    insert(db_session, 1, 1, "bad-time")
    insert(db_session, *matching, "bad-time", device="filter_b")
    bounds = {"device_id": "filter_a", flag: False, "from": "2026-10-01T00:00:00Z",
              "to": "2026-10-01T00:00:10Z", "limit": 1}
    response = get(**bounds)
    assert response.status_code == 200
    first = response.json()
    assert first["total"] == 2 and first["items"][0]["id"] == last_id
    assert first["source_span_count"] == 3
    assert first["timestamp_unavailable_count"] == 1
    assert first["applied_validity_filters"][flag] is False
    second = get(**bounds, offset=1, snapshot_max_id=first["snapshot_max_id"]).json()
    assert second["total"] == 2 and second["items"][0]["id"] == first_id
    assert second["source_span_count"] is None
    assert second["timestamp_unavailable_count"] is None
    assert second["applied_validity_filters"] == first["applied_validity_filters"]
    empty = get(device_id="filter_a", **{flag: False, "from": "2026-10-02T00:00:00Z",
                                       "to": "2026-10-02T00:00:10Z"}).json()
    assert empty["items"] == [] and empty["total"] == empty["source_span_count"] == 0
    assert empty["applied_validity_filters"][flag] is False


@pytest.mark.parametrize("flag", ["is_json_valid", "is_topic_valid"])
def test_malformed_validity_queries_are_rejected(db_session, flag):
    assert get(**{flag: "not-a-boolean"}).status_code == 422
    with pytest.raises(ValueError, match=flag):
        list_mqtt_logs(db_session, **{flag: "false"})