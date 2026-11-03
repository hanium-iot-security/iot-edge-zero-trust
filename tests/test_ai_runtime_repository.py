from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import apply_migrations
from edge.detection.ai_run_evidence import AICompletionRecord
from edge.detection.ai_runtime_repository import (
    RuntimeEvidenceUnavailable, list_ai_warnings, read_ai_completions,
    read_runtime_snapshot, save_runtime_snapshot, store_ai_completions,
)
from edge.detection.ai_warning_aggregation import WarningPolicy

START = datetime(2026, 10, 10, tzinfo=timezone.utc)
MIGRATIONS = Path(__file__).resolve().parents[1] / "db" / "migrations"
POLICY = WarningPolicy("warning-v1", 60, 2, 120)


@pytest.fixture
def engine(tmp_path):
    path = tmp_path / "runtime.db"
    apply_migrations(path, MIGRATIONS)
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    yield engine
    engine.dispose()


def stamp(seconds=0):
    return (START + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def record(seconds=0, *, device="sensor1", detector="mqtt_if", anomaly=False, **changes):
    row = AICompletionRecord(detector, device, START + timedelta(seconds=seconds),
        START + timedelta(seconds=seconds + 10), 1, 1, int(not anomaly), int(anomaly),
        {}, "model-v1", "a" * 64, 1, "OBSERVE")
    return replace(row, **changes)


def store(db, rows, seconds=20, policy=None, run_id="run-1"):
    store_ai_completions(db, rows, run_id=run_id, boot_id="boot-1",
                         observed_at=START + timedelta(seconds=seconds), warning_policy=policy)


def event(db, seconds=0, *, device="sensor1", detector="mqtt_if", **changes):
    evidence = dict(detector_name=detector, device_ai_mode="OBSERVE", device_ai_revision=1,
                    model_version="model-v1", bundle_sha256="a" * 64)
    evidence.update(changes)
    if detector == "packet_if":
        evidence = {"detector_name": detector,
                    "model": {key: value for key, value in evidence.items() if key != "detector_name"}}
    result = db.execute(text("""INSERT INTO detection_events
        (device_id,detector_type,event_type,analysis_window_start,analysis_window_end,evidence_json)
        VALUES(:device,'AI',:event,:start,:end,:evidence)"""),
        dict(device=device, event="AI_ANOMALY" if detector == "mqtt_if" else "AI_PACKET_ANOMALY",
             start=stamp(seconds), end=stamp(seconds + 10), evidence=json.dumps(evidence)))
    return result.lastrowid


def snapshot(**changes):
    result = dict(run_id="run-1", boot_id="boot-1", observed_at=START,
                  status="COMPLETED", stages=[{"detector_name": "mqtt_if", "observed_at": START}])
    result.update(changes)
    return result


def test_upgrade_012_preserves_data_and_second_apply_is_noop(tmp_path):
    old = tmp_path / "old"
    old.mkdir()
    for path in MIGRATIONS.glob("*.sql"):
        if int(path.name[:3]) <= 12:
            shutil.copy2(path, old / path.name)
    path = tmp_path / "upgrade.db"
    apply_migrations(path, old)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO devices(device_id) VALUES('sensor1')")
        device_columns = ", ".join(row[1] for row in db.execute("PRAGMA table_info(devices)"))
        before = db.execute(f"SELECT {device_columns} FROM devices").fetchall()
    assert apply_migrations(path, MIGRATIONS).applied_versions == list(range(13, 20))
    assert apply_migrations(path, MIGRATIONS).applied_versions == []
    with sqlite3.connect(path) as db:
        assert db.execute(f"SELECT {device_columns} FROM devices").fetchall() == before
        assert db.execute("SELECT hidden_at, registration_instance_id FROM devices").fetchall() == [(None, None)]
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert read_runtime_snapshot(db) is None
        assert read_ai_completions(db) == []


def test_success_snapshot_and_completion_share_caller_transaction(engine):
    with Session(engine) as db:
        with db.begin():
            save_runtime_snapshot(db, snapshot())
            store(db, [record()])
        saved = read_runtime_snapshot(db)
        assert saved["stages"][0]["observed_at"] == "2026-10-10T00:00:00.000000Z"
        assert read_ai_completions(db)[0]["normal_count"] == 1
        db.rollback()
        with pytest.raises(RuntimeError):
            with db.begin():
                save_runtime_snapshot(db, snapshot(run_id="run-2"))
                store(db, [record(10)], run_id="run-2")
                event(db, 10)
                db.execute(text("""INSERT INTO detector_checkpoints
                    (detector_name,source_table,last_processed_id)
                    VALUES('mqtt_if','feature_logs',10)"""))
                raise RuntimeError("stage rollback")
        assert read_runtime_snapshot(db)["run_id"] == "run-1"
        assert read_ai_completions(db)[0]["window_start"] == stamp()
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar() == 0
        assert db.execute(text("SELECT COUNT(*) FROM detector_checkpoints")).scalar() == 0


def test_latest_device_evidence_retries_do_not_add_or_renew(engine):
    with Session(engine) as db, db.begin():
        store(db, [record()], seconds=20)
        store(db, [record()], seconds=100, run_id="retry")
        actual = read_ai_completions(db, "sensor1")[0]
        assert actual["input_count"] == 1 and actual["run_id"] == "run-1"
        assert actual["observed_at"].endswith("00:00:20.000000Z")
        store(db, [record(20)], seconds=30, run_id="new")
        store(db, [record(10)], seconds=40, run_id="older")
        assert read_ai_completions(db, "sensor1")[0]["run_id"] == "new"


def test_conflicting_same_window_is_rejected(engine):
    with Session(engine) as db, db.begin():
        store(db, [record()])
        with pytest.raises(ValueError, match="conflicting"):
            store(db, [record(anomaly=True)])


def test_empty_stage_and_unknown_peer_are_not_device_normal(engine):
    empty = AICompletionRecord("mqtt_if", None, None, START + timedelta(seconds=10),
                               0, 0, 0, 0, {}, None, None, None, None)
    unknown = record(device=None, detector="packet_if", inference_count=0, normal_count=0,
                     exclusion_counts={"AI_REGISTRATION_UNAVAILABLE": 1})
    with Session(engine) as db, db.begin():
        store(db, [empty, unknown])
        assert read_ai_completions(db, "sensor1") == []
        assert len(read_ai_completions(db)) == 1
        assert read_ai_completions(db)[0]["device_id"] is None


@pytest.mark.parametrize("changes", [
    {"input_count": -1}, {"normal_count": True}, {"inference_count": 2},
    {"anomaly_count": 1}, {"exclusion_counts": {"OFF": 1}},
    {"exclusion_counts": {"OFF": -1}}, {"ai_revision": True},
    {"ai_mode": "ENFORCE"}, {"completed_window_end": START + timedelta(seconds=20)},
])
def test_invalid_completion_counters_and_metadata_rejected(engine, changes):
    with Session(engine) as db, db.begin():
        with pytest.raises(ValueError):
            store(db, [record(**changes)])
        assert read_ai_completions(db) == []


def test_missing_schema_and_corrupt_json_state_are_unavailable(engine):
    with sqlite3.connect(":memory:") as db:
        with pytest.raises(RuntimeEvidenceUnavailable, match="014"):
            read_runtime_snapshot(db)
    with Session(engine) as db, db.begin():
        save_runtime_snapshot(db, snapshot())
        store(db, [record()])
        db.execute(text("UPDATE ai_runtime_snapshot SET snapshot_json='{}'"))
        with pytest.raises(RuntimeEvidenceUnavailable, match="corrupt"):
            read_runtime_snapshot(db)
        db.execute(text("UPDATE ai_device_completions SET record_json='{}'"))
        with pytest.raises(RuntimeEvidenceUnavailable, match="corrupt"):
            read_ai_completions(db)


def test_warning_restart_dedup_cooldown_and_late_history(engine):
    with Session(engine) as db, db.begin():
        first = event(db)
        store(db, [record(anomaly=True)], policy=POLICY)
        assert list_ai_warnings(db)["total"] == 0
        second = event(db, 10)
        store(db, [record(10, anomaly=True)], policy=POLICY)
        assert list_ai_warnings(db)["items"][0]["last_decision"] == "NOTIFY"
    with Session(engine) as db, db.begin():
        store(db, [record(10, anomaly=True)], seconds=200, policy=POLICY, run_id="retry")
        duplicate_window = event(db, 10)
        store(db, [record(10, anomaly=True)], seconds=200, policy=POLICY, run_id="retry2")
        warning = list_ai_warnings(db)["items"][0]
        assert warning["count"] == 2
        assert warning["event_ids"] == [first, second, duplicate_window]
        assert warning["last_decision"] == "NOTIFY" and warning["suppressed_count"] == 0
        for seconds in (60, 70):
            event(db, seconds)
            store(db, [record(seconds, anomaly=True)], seconds=80, policy=POLICY)
        assert list_ai_warnings(db)["items"][0]["last_decision"] == "COOLDOWN_SUPPRESSED"
    with Session(engine) as db, db.begin():
        event(db, 20)
        store(db, [record(20, anomaly=True)], seconds=200, policy=POLICY)
        warnings = list_ai_warnings(db)["items"]
        assert warnings[1]["closed"] and warnings[1]["last_decision"] == "LATE_ATTACHED"
        event(db, 80)
        store(db, [record(80, anomaly=True)], seconds=200, policy=POLICY)
        assert list_ai_warnings(db)["items"][0]["last_decision"] == "NOTIFY"


def test_warning_sink_rollback_preserves_event_cp_and_warning_state(engine):
    with Session(engine) as db:
        with pytest.raises(RuntimeError):
            with db.begin():
                event(db)
                store(db, [record(anomaly=True)], policy=WarningPolicy("w", 60, 1, 0))
                assert list_ai_warnings(db)["total"] == 1
                raise RuntimeError("rollback")
        assert list_ai_warnings(db)["total"] == 0
        assert read_ai_completions(db) == []
        assert db.execute(text("SELECT COUNT(*) FROM ai_warning_keys")).scalar() == 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar() == 0


@pytest.mark.parametrize("changes", [
    {"device_ai_mode": "OFF"}, {"device_ai_revision": True},
    {"device_ai_revision": None}, {"model_version": "different"},
    {"bundle_sha256": "b" * 64}, {"detector_name": "packet_if"},
    {"model": {"device_ai_mode": "OBSERVE"}},
])
def test_warning_requires_matching_saved_observe_evidence(engine, changes):
    with Session(engine) as db, db.begin():
        event(db, **changes)
        store(db, [record(anomaly=True)], policy=WarningPolicy("w", 60, 1, 0))
        assert list_ai_warnings(db)["total"] == 0


def test_packet_nested_evidence_and_policy_model_keys(engine):
    policy = WarningPolicy("w", 60, 1, 0)
    with Session(engine) as db, db.begin():
        event(db, detector="packet_if")
        store(db, [record(detector="packet_if", anomaly=True)], policy=policy)
        event(db)
        store(db, [record(anomaly=True)], policy=policy)
        store(db, [record(anomaly=True)], policy=WarningPolicy("w2", 60, 1, 0))
        assert list_ai_warnings(db)["total"] == 3
        with pytest.raises(ValueError, match="W/N/C"):
            store(db, [record(anomaly=True)], policy=WarningPolicy("w", 120, 1, 0))


def test_no_policy_and_normal_or_off_do_not_generate_warning(engine):
    with Session(engine) as db, db.begin():
        event(db)
        store(db, [record(anomaly=True)])
        store(db, [record(10)], policy=POLICY)
        store(db, [record(20, ai_mode="OFF", inference_count=0, normal_count=0,
                          exclusion_counts={"AI_OFF_AT_WINDOW": 1})], policy=POLICY)
        assert list_ai_warnings(db)["total"] == 0


def test_warning_filters_are_whole_bucket_microsecond_exact_and_read_only(engine):
    with Session(engine) as db, db.begin():
        for device in ("sensor1", "sensor2"):
            for seconds in (0, 60, 120):
                event(db, seconds, device=device)
                store(db, [record(seconds, device=device, anomaly=True)],
                      policy=WarningPolicy("w", 60, 1, 0))
        before = db.connection().connection.driver_connection.total_changes
        selected = list_ai_warnings(db, device_id="sensor1", from_at=START,
                                    to_at=START + timedelta(seconds=120), limit=1, offset=1)
        assert selected["total"] == 2 and selected["items"][0]["bucket_start"] == stamp()
        assert list_ai_warnings(db, from_at=START + timedelta(microseconds=1),
                                to_at=START + timedelta(seconds=60))["total"] == 0
        assert list_ai_warnings(db, from_at=START,
                                to_at=START + timedelta(seconds=60, microseconds=-1))["total"] == 0
        assert list_ai_warnings(db, from_at=START, to_at=START, limit=500)["total"] == 0
        assert db.connection().connection.driver_connection.total_changes == before


def test_corrupt_warning_references_are_detected(engine):
    with Session(engine) as db, db.begin():
        event(db)
        store(db, [record(anomaly=True)], policy=WarningPolicy("w", 60, 1, 0))
        db.execute(text("UPDATE ai_warning_aggregates SET count=10"))
        with pytest.raises(RuntimeEvidenceUnavailable, match="corrupt"):
            list_ai_warnings(db)


@pytest.mark.parametrize("exclusion", ["AI_OFF_AT_WINDOW", "INVALID_CAPTURE"])
def test_excluded_window_closes_bucket_and_return_does_not_join_pre_gap(engine, exclusion):
    with Session(engine) as db, db.begin():
        event(db)
        store(db, [record(anomaly=True)], policy=POLICY)
        excluded = record(10, inference_count=0, normal_count=0,
                          ai_mode="OFF" if exclusion == "AI_OFF_AT_WINDOW" else "OBSERVE",
                          exclusion_counts={exclusion: 1})
        store(db, [excluded], seconds=20, policy=POLICY)
        row = db.execute(text("SELECT closed,last_decision FROM ai_warning_aggregates")).one()
        assert row == (1, "INPUT_INTERRUPTED")
    with Session(engine) as db, db.begin():
        event(db, 20)
        store(db, [record(20, anomaly=True)], seconds=30, policy=POLICY)
        assert list_ai_warnings(db)["items"] == []
        warning = db.execute(text("SELECT closed,last_decision,notified_at,count FROM ai_warning_aggregates")).one()
        assert warning == (1, "LATE_ATTACHED", None, 2)


def test_no_input_closes_only_its_detector_and_normal_keeps_counting(engine):
    with Session(engine) as db, db.begin():
        for detector in ("mqtt_if", "packet_if"):
            event(db, detector=detector)
            store(db, [record(detector=detector, anomaly=True)], policy=POLICY)
        store(db, [record(10)], seconds=20, policy=POLICY)
        assert db.execute(text("SELECT SUM(closed) FROM ai_warning_aggregates")).scalar() == 0
        empty = AICompletionRecord("mqtt_if", None, None, START + timedelta(seconds=30),
                                   0, 0, 0, 0, {}, None, None, None, None)
        store(db, [empty], seconds=30, policy=POLICY)
        rows = db.execute(text("SELECT detector_name,closed FROM ai_warning_aggregates ORDER BY detector_name")).all()
        assert rows == [("mqtt_if", 1), ("packet_if", 0)]


def test_completion_key_identity_mismatch_is_unavailable(engine):
    with Session(engine) as db, db.begin():
        store(db, [record()])
        payload = read_ai_completions(db)[0]
        payload["device_id"] = "other-device"
        db.execute(text("UPDATE ai_device_completions SET record_json=:payload"),
                   {"payload": json.dumps(payload)})
        with pytest.raises(RuntimeEvidenceUnavailable, match="identity"):
            read_ai_completions(db, "sensor1")


def test_corrupt_warning_policy_cannot_hide_saved_warning(engine):
    with Session(engine) as db, db.begin():
        event(db)
        store(db, [record(anomaly=True)], policy=WarningPolicy("w", 60, 1, 0))
        db.execute(text("PRAGMA ignore_check_constraints=ON"))
        db.execute(text("UPDATE ai_warning_keys SET policy_json='{}'"))
        db.execute(text("PRAGMA ignore_check_constraints=OFF"))
        with pytest.raises(RuntimeEvidenceUnavailable, match="policy"):
            list_ai_warnings(db)


def test_warning_from_ceil_overflow_is_validation_error(engine):
    with Session(engine) as db:
        with pytest.raises(ValueError, match="boundary"):
            list_ai_warnings(db, from_at="9999-12-31T23:59:59.999999Z")
