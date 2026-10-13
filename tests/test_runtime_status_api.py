"""Public runtime/warning reads use recorded evidence, never configuration as proof."""
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.main import app
from backend.app.services import ai_runtime_query_service as service
from db.migration_runner import apply_migrations
from edge.detection.ai_run_evidence import AICompletionRecord
from edge.detection.ai_runtime_repository import save_runtime_snapshot, store_ai_completions
from edge.detection.ai_warning_aggregation import WarningPolicy

NOW = datetime(2026, 10, 14, 0, 5, tzinfo=timezone.utc)
BOOT = "11111111-1111-4111-8111-111111111111"
RUN = "22222222-2222-4222-8222-222222222222"
POLICY = WarningPolicy("fixture-warnings-v1", 60, 2, 120)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


@pytest.fixture
def api(tmp_path, monkeypatch):
    path = tmp_path / "runtime-api.db"
    apply_migrations(path)
    engine = create_engine(f"sqlite:///{path.as_posix()}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def read_only(connection, _):
        connection.execute("PRAGMA query_only = ON")

    sessions = sessionmaker(bind=engine)

    def get_test_db():
        with sessions() as db:
            yield db

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = get_test_db
    monkeypatch.setattr(service, "utc_now", lambda: NOW)
    monkeypatch.setattr(service, "current_boot_id", lambda: BOOT)
    monkeypatch.setattr(settings, "recovery_admin_api_key", "")
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            yield {"client": client, "path": path}
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


def write(api, callback):
    with closing(sqlite3.connect(api["path"])) as db:
        callback(db)
        db.commit()


def dump(api):
    with closing(sqlite3.connect(api["path"])) as db:
        return list(db.iterdump())


def snapshot(api, *, observed_at=None, boot_id=BOOT, run_id=RUN, policy=POLICY, status="RUNNING"):
    value = {
        "run_id": run_id, "boot_id": boot_id, "started_at": NOW - timedelta(minutes=1),
        "observed_at": observed_at or NOW - timedelta(seconds=5), "status": status,
        "error_code": "STAGE_FAILED" if status == "FAILED" else None,
        "warning_policy": asdict(policy) if policy else None,
        "stages": [{"name": "mqtt_if", "enabled": True, "required": False,
                    "status": "FAILED" if status == "FAILED" else "COMPLETED",
                    "observed_at": observed_at or NOW - timedelta(seconds=5),
                    "trust_ai_mode": "observe", "model_version": "mqtt-fixture-v1",
                    "bundle_sha256": "a" * 64, "last_completed_window_end": NOW - timedelta(seconds=10),
                    "last_processed_id": 20, "error_code": None,
                    "private_path": "DO_NOT_EXPOSE_STAGE_PATH"}],
        "private_path": "DO_NOT_EXPOSE_SNAPSHOT_PATH",
    }
    write(api, lambda db: save_runtime_snapshot(db, value))


def completion(api, *, device="ESP32_01", detector="mqtt_if", start=None, run_id=RUN,
               boot_id=BOOT, observed_at=None, mode="OBSERVE", kind="normal"):
    start = start or NOW - timedelta(seconds=20)
    excluded = {"AI_OFF_AT_WINDOW": 1} if kind == "excluded" else {}
    record = AICompletionRecord(
        detector, device, None if kind == "empty" else start,
        start + timedelta(seconds=10), 0 if kind == "empty" else 1,
        int(kind in ("normal", "anomaly")), int(kind == "normal"), int(kind == "anomaly"), excluded,
        "mqtt-fixture-v1" if kind in ("normal", "anomaly") else None,
        "a" * 64 if kind in ("normal", "anomaly") else None,
        1 if device is not None else None, mode if device is not None else None,
    )
    write(api, lambda db: store_ai_completions(db, [record], run_id=run_id, boot_id=boot_id,
                                             observed_at=observed_at or NOW - timedelta(seconds=5)))


def warning(api, *, device="ESP32_01", start=None, count=2, policy=POLICY):
    start = start or NOW - timedelta(minutes=2)

    def seed(db):
        for index in range(count):
            window = start + timedelta(seconds=index * 10)
            evidence = {"detector_name": "mqtt_if", "device_ai_mode": "OBSERVE", "device_ai_revision": 1,
                        "model_version": "mqtt-fixture-v1", "bundle_sha256": "a" * 64}
            db.execute("""INSERT INTO detection_events
                (device_id,detector_type,event_type,analysis_window_start,analysis_window_end,evidence_json)
                VALUES (?, 'AI', 'AI_ANOMALY', ?, ?, ?)""",
                (device, stamp(window), stamp(window + timedelta(seconds=10)), json.dumps(evidence)))
            record = AICompletionRecord("mqtt_if", device, window, window + timedelta(seconds=10),
                                        1, 1, 0, 1, {}, "mqtt-fixture-v1", "a" * 64, 1, "OBSERVE")
            store_ai_completions(db, [record], run_id=RUN, boot_id=BOOT,
                                 observed_at=NOW - timedelta(seconds=5), warning_policy=policy)
    write(api, seed)


def get(api, route="runtime-status", **params):
    response = api["client"].get("/api/" + route, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_real_mqtt_stage_to_runtime_and_warning_api_preserves_evidence(api, tmp_path, monkeypatch):
    from edge.detection.mqtt_adapters import MqttIsolationForestStage
    from edge.detection.orchestrator import run_detection_cycle
    from edge.orchestration import runtime_evidence
    from edge.policy.ai_window_decision import AIRevision, decide_ai_window
    from test_mqtt_if_artifact import _fixture, _write_contract
    from test_mqtt_if_runtime import _feature, _settings
    from test_phase8_trust_gates import _seed

    directory = tmp_path / "stage-api-bundle"
    metadata = _fixture(directory)
    metadata["threshold"] = 1.0
    _write_contract(directory, metadata)
    configured = _settings(directory)
    start = NOW - timedelta(seconds=30)
    observed = NOW - timedelta(microseconds=123456)
    stage = MqttIsolationForestStage.from_settings(
        app_settings=configured,
        ai_window_selector=lambda resolution: decide_ai_window(
            resolution, [AIRevision("esp32_01", 1, "OBSERVE", start)],
            stage_activation_from=start),
    )
    # The selector/activation above is a synthetic test input, never a runtime default.
    writer = create_engine(f"sqlite:///{api['path'].as_posix()}")
    sessions = sessionmaker(bind=writer)
    monkeypatch.setattr(runtime_evidence, "current_boot_id", lambda: BOOT)
    try:
        with sessions.begin() as db:
            _seed(db, status="ACTIVE")
            _feature(db, start=start)
            _feature(db, start=start + timedelta(seconds=10))
        publisher = runtime_evidence.RuntimeEvidence(sessions, configured, clock=lambda: observed)
        publisher.warning_policy = POLICY
        publisher.trust_ai_mode = "observe"
        publisher.publish("STARTING")
        publisher.register_stage("mqtt_if", stage)
        run_detection_cycle(
            session_factory=sessions, stages=(stage,), cycle_range_start=start,
            cycle_cutoff=start + timedelta(seconds=20),
            stage_completion_sink=publisher.stage_completed,
        )
        with sessions() as db:
            events = db.execute(text("SELECT id, analysis_window_start, analysis_window_end "
                                     "FROM detection_events ORDER BY id")).mappings().all()
        assert [row["analysis_window_start"] for row in events] == [
            stamp(start), stamp(start + timedelta(seconds=10))]
        result = get(api, device_id="esp32_01")
        assert (result["status"], result["freshness"]) == ("RUNNING", "FRESH")
        actual_stage = next(item for item in result["stages"] if item["name"] == "mqtt_if")
        assert (actual_stage["status"], actual_stage["selected_count"],
                actual_stage["created_event_count"], actual_stage["trust_ai_mode"]) == (
                    "COMPLETED", 2, 2, "observe")
        (completed,) = result["completions"]
        assert completed["window_start"] == events[-1]["analysis_window_start"]
        assert completed["completed_window_end"] == events[-1]["analysis_window_end"]
        assert completed["observed_at"] == actual_stage["observed_at"] == stamp(observed)
        assert completed["run_id"] == result["run_id"] == publisher.run_id
        assert completed["evidence_status"] == "CURRENT"
        assert (completed["input_count"], completed["inference_count"],
                completed["normal_count"], completed["anomaly_count"]) == (1, 1, 0, 1)
        assert (completed["ai_mode"], completed["ai_revision"]) == ("OBSERVE", 1)
        assert completed["model_version"] == actual_stage["model_version"] == metadata["model_version"]
        assert completed["bundle_sha256"] == actual_stage["bundle_sha256"] == stage.artifact.inspection.bundle_sha256
        warnings = get(api, "ai-warnings", device_id="esp32_01")
        assert warnings["source_status"] == "AVAILABLE" and warnings["total"] == 1
        (warning_item,) = warnings["items"]
        assert warning_item["count"] == 2
        assert warning_item["event_ids"] == [row["id"] for row in events]
        assert warning_item["analysis_windows"] == [row["analysis_window_start"] for row in events]
    finally:
        writer.dispose()


def test_missing_observation_is_unknown_not_configured_or_checkpoint_evidence(api, monkeypatch):
    monkeypatch.setattr(settings, "orchestrator_enabled_stages", "mqtt_if,packet_if")
    monkeypatch.setattr(settings, "trust_ai_mode", "observe")
    monkeypatch.setattr(settings, "mqtt_if_expected_model_version", "configured-but-not-running")
    write(api, lambda db: db.execute("""INSERT INTO detector_checkpoints
        (detector_name,source_table,last_processed_id,last_completed_window_end)
        VALUES ('mqtt_if','feature_logs',999,'2026-10-14T00:05:00Z')"""))
    body = get(api)
    assert body["status"] == "UNKNOWN" and body["freshness"] == "MISSING"
    assert body["observed_at"] is body["run_id"] is body["boot_id"] is None
    assert body["last_observation_status"] is None and body["age_seconds"] is None
    assert body["stages"] == body["completions"] == []
    assert "configured-but-not-running" not in json.dumps(body)


@pytest.mark.parametrize("status", ["STARTING", "RUNNING", "FAILED", "STOPPED"])
def test_fresh_stored_lifecycle_is_preserved_without_runtime_promotion(api, status):
    snapshot(api, status=status)
    body = get(api)
    assert body["status"] == body["last_observation_status"] == status
    assert body["freshness"] == "FRESH" and body["age_seconds"] == 5
    assert body["max_age_seconds"] == 45
    assert body["run_id"] == RUN and body["boot_id"] == BOOT
    assert body["stages"][0]["model_version"] == "mqtt-fixture-v1"
    assert body["completions"] == []
    assert "DO_NOT_EXPOSE" not in json.dumps(body)


@pytest.mark.parametrize("delta,boot,expected", [
    (-45, BOOT, "FRESH"), (-45.000001, BOOT, "STALE"),
    (0.000001, BOOT, "FUTURE"), (-5, "different-boot", "BOOT_MISMATCH"),
    (-5, None, "BOOT_UNAVAILABLE"),
])
def test_runtime_freshness_boundaries_keep_historical_snapshot(api, delta, boot, expected):
    snapshot(api, observed_at=NOW + timedelta(seconds=delta), boot_id=boot)
    body = get(api)
    assert body["freshness"] == expected
    assert body["status"] == ("RUNNING" if expected == "FRESH" else "UNKNOWN")
    assert body["last_observation_status"] == "RUNNING"
    assert body["stages"][0]["last_processed_id"] == 20


def test_unavailable_current_boot_cannot_certify_snapshot(api, monkeypatch):
    snapshot(api)
    monkeypatch.setattr(service, "current_boot_id", lambda: None)
    body = get(api)
    assert body["status"] == "UNKNOWN" and body["freshness"] == "BOOT_UNAVAILABLE"


def test_completion_filter_keeps_each_devices_actual_counts_and_model(api):
    snapshot(api)
    completion(api)
    completion(api, device="pico_01", mode="OFF", kind="excluded")
    body = get(api, device_id="ESP32_01")
    assert len(body["completions"]) == 1
    row = body["completions"][0]
    assert row["device_id"] == "ESP32_01" and row["evidence_status"] == "CURRENT"
    assert (row["input_count"], row["inference_count"], row["normal_count"], row["anomaly_count"]) == (1, 1, 1, 0)
    assert row["model_version"] == "mqtt-fixture-v1" and row["bundle_sha256"] == "a" * 64
    excluded = get(api, device_id="pico_01")["completions"][0]
    assert excluded["normal_count"] == excluded["inference_count"] == 0
    assert excluded["exclusion_counts"] == {"AI_OFF_AT_WINDOW": 1}
    assert excluded["model_version"] is None
    assert get(api, device_id="absent")["completions"] == []


@pytest.mark.parametrize("changes", [
    {"run_id": "older-run"}, {"boot_id": "older-boot"},
    {"observed_at": NOW - timedelta(seconds=46)}, {"observed_at": NOW + timedelta(microseconds=1)},
])
def test_old_or_unverifiable_completion_is_retained_as_historical(api, changes):
    snapshot(api)
    completion(api, **changes)
    row = get(api)["completions"][0]
    assert row["evidence_status"] == "HISTORICAL"
    assert row["normal_count"] == 1


def test_no_input_stage_does_not_create_device_normal_inference(api):
    snapshot(api)
    completion(api, device=None, kind="empty")
    row = get(api)["completions"][0]
    assert row["device_id"] is row["window_start"] is row["model_version"] is None
    assert row["input_count"] == row["inference_count"] == row["normal_count"] == 0
    assert get(api, device_id="ESP32_01")["completions"] == []


@pytest.mark.parametrize("route,code", [
    ("runtime-status", "RUNTIME_EVIDENCE_UNAVAILABLE"),
    ("ai-warnings", "AI_WARNING_DATA_UNAVAILABLE"),
])
@pytest.mark.parametrize("damage", ["missing", "columns", "snapshot"])
def test_missing_or_corrupt_evidence_fails_closed_without_details(api, route, code, damage):
    if damage == "snapshot":
        write(api, lambda db: db.execute("INSERT INTO ai_runtime_snapshot VALUES(1,'{}')"))
    else:
        def corrupt(db):
            db.execute("DROP TABLE ai_runtime_snapshot")
            if damage == "columns":
                db.execute("CREATE TABLE ai_runtime_snapshot(id INTEGER PRIMARY KEY,wrong TEXT)")
        write(api, corrupt)
    response = api["client"].get("/api/" + route)
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == code
    assert "SELECT" not in response.text and str(api["path"]) not in response.text


def test_corrupt_completion_does_not_turn_into_unknown_zero_counts(api):
    snapshot(api)
    write(api, lambda db: db.execute("""INSERT INTO ai_device_completions
        VALUES('mqtt_if','ESP32_01','2026-10-14T00:04:50Z','{}')"""))
    response = api["client"].get("/api/runtime-status")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "RUNTIME_EVIDENCE_UNAVAILABLE"


def test_warning_policy_absence_is_not_a_claim_of_zero_anomalies(api):
    assert get(api, "ai-warnings")["source_status"] == "UNKNOWN"
    snapshot(api, policy=None)
    body = get(api, "ai-warnings")
    assert body["source_status"] == "POLICY_UNCONFIGURED"
    assert body["items"] == [] and body["total"] == 0


def test_warning_filters_total_pagination_and_source_references(api):
    snapshot(api)
    warning(api)
    warning(api, start=NOW - timedelta(minutes=1))
    warning(api, device="pico_01")
    all_rows = get(api, "ai-warnings")
    assert all_rows["source_status"] == "AVAILABLE" and all_rows["total"] == 3
    filtered = get(api, "ai-warnings", device_id="ESP32_01", limit=1, offset=1)
    assert filtered["total"] == 2 and len(filtered["items"]) == 1
    row = filtered["items"][0]
    assert row["bucket_start"] == stamp(NOW - timedelta(minutes=2))
    assert row["count"] == len(row["event_ids"]) == len(row["analysis_windows"]) == 2
    assert row["model_version"] == "mqtt-fixture-v1"
    assert row["warning_policy_version"] == POLICY.version
    assert row["last_decision"] == "NOTIFY" and row["notified_at"] is not None
    assert get(api, "ai-warnings", device_id="ESP32_01", offset=999)["items"] == []
    assert get(api, "ai-warnings", limit=500)["total"] == 3


def test_below_threshold_bucket_is_not_an_api_warning(api):
    snapshot(api)
    warning(api, count=1)
    body = get(api, "ai-warnings")
    assert body["source_status"] == "AVAILABLE"
    assert body["items"] == [] and body["total"] == 0


@pytest.mark.parametrize("bounds,expected", [
    ({"from": "2026-10-14T00:03:00Z", "to": "2026-10-14T00:04:00Z"}, 1),
    ({"from": "2026-10-14T09:03:00+09:00", "to": "2026-10-14T09:04:00+09:00"}, 1),
    ({"from": "2026-10-14T00:03:00.000001Z"}, 0),
    ({"to": "2026-10-14T00:03:59.999999Z"}, 0),
    ({"to": "2026-10-14T00:04:00Z"}, 1),
    ({"from": "2026-10-14T00:03:00Z"}, 1),
    ({"from": "2026-10-14T00:03:10Z", "to": "2026-10-14T00:03:50Z"}, 0),
    ({"from": "2026-10-14T00:03:00Z", "to": "2026-10-14T00:03:00Z"}, 0),
])
def test_warning_time_range_contains_complete_buckets(api, bounds, expected):
    snapshot(api)
    warning(api)
    body = get(api, "ai-warnings", **bounds)
    assert body["total"] == len(body["items"]) == expected


@pytest.mark.parametrize("params", [
    {"from": "bad"}, {"from": "2026-10-14T00:00:00"},
    {"from": "2026-10-14T00:05:00Z", "to": "2026-10-14T00:04:00Z"},
    {"from": "0001-01-01T00:00:00+09:00"}, {"to": "9999-12-31T23:59:59-09:00"},
    {"from": "9999-12-31T23:59:59.999999Z"},
    {"limit": 0}, {"limit": 501}, {"offset": -1}, {"device_id": "bad id"},
])
def test_warning_invalid_queries_return_422(api, params):
    assert api["client"].get("/api/ai-warnings", params=params).status_code == 422


@pytest.mark.parametrize("route", ["runtime-status", "ai-warnings"])
def test_read_routes_reject_invalid_device_identifier(api, route):
    assert api["client"].get("/api/" + route, params={"device_id": "bad id"}).status_code == 422


@pytest.mark.parametrize("state", ["missing", "stale", "policy_unconfigured"])
def test_historical_warnings_remain_visible_when_current_source_is_unknown(api, state):
    warning(api)
    if state == "stale":
        snapshot(api, observed_at=NOW - timedelta(seconds=46))
    elif state == "policy_unconfigured":
        snapshot(api, policy=None)
    body = get(api, "ai-warnings")
    assert body["source_status"] == ("POLICY_UNCONFIGURED" if state == "policy_unconfigured" else "UNKNOWN")
    assert body["total"] == 1 and len(body["items"]) == 1


def test_both_apis_work_on_query_only_connection_without_modifying_database(api):
    snapshot(api)
    warning(api)
    before = dump(api)
    get(api)
    get(api, "ai-warnings")
    assert dump(api) == before


@pytest.mark.parametrize("status", ["STARTING", "FAILED", "STOPPED"])
def test_fresh_non_running_source_does_not_claim_warning_collection_available(api, status):
    snapshot(api, status=status)
    warning(api)
    body = get(api, "ai-warnings")
    assert body["source_status"] == "UNKNOWN" and body["total"] == 1
    assert body["reason_code"] == "RUNTIME_" + status


@pytest.mark.parametrize("route,code", [("runtime-status", "RUNTIME_EVIDENCE_UNAVAILABLE"),
                                       ("ai-warnings", "AI_WARNING_DATA_UNAVAILABLE")])
def test_database_read_failure_is_unavailable_without_sql_details(api, monkeypatch, route, code):
    def fail(_db):
        raise sqlite3.OperationalError("SELECT private_sql FROM /private/database/path")
    monkeypatch.setattr(service, "read_runtime_snapshot", fail)
    response = api["client"].get("/api/" + route)
    assert response.status_code == 503
    assert response.json() == {"detail": {"code": code}}


@pytest.mark.parametrize("damage", ["counts", "policy"])
def test_corrupt_warning_state_is_not_returned_as_zero_warnings(api, damage):
    snapshot(api)
    warning(api)
    query = ("UPDATE ai_warning_aggregates SET count=3" if damage == "counts" else
             "UPDATE ai_warning_keys SET policy_json='{}'")
    def corrupt(db):
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute(query)
        db.execute("PRAGMA ignore_check_constraints=OFF")
    write(api, corrupt)
    response = api["client"].get("/api/ai-warnings")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "AI_WARNING_DATA_UNAVAILABLE"
