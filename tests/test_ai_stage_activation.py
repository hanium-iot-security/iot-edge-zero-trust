from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import sqlite3
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import apply_migrations
from edge.policy import ai_stage_activation as activation
from edge.detection.runtime_checkpoint_repository import upsert_detector_checkpoint

START = datetime(2026, 10, 10, tzinfo=timezone.utc)
B = START + timedelta(seconds=30)
MIGRATIONS = Path(__file__).resolve().parents[1] / "db" / "migrations"
CONFIG = dict(stage_name="mqtt_if", model_version="mqtt-v1", bundle_sha256="a" * 64,
              enabled_stages=["mqtt_feature_rule", "mqtt_if"],
              required_stages=["mqtt_feature_rule", "mqtt_if"], trust_ai_mode="observe")


def utc(seconds):
    return (START + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def checkpoint(db, name, seconds, identifier=None):
    upsert_detector_checkpoint(db, detector_name=name,
        source_table=activation.STAGE_SOURCES[name], last_processed_id=identifier,
        last_completed_window_end=START + timedelta(seconds=seconds), updated_at=START)


@pytest.fixture
def environment(tmp_path):
    path = tmp_path / "activation.db"
    apply_migrations(path, MIGRATIONS)
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    with Session(engine) as db, db.begin():
        db.execute(text("INSERT INTO devices(device_id) VALUES('sensor1')"))
        for seconds in (0, 10, 20, 30, 40):
            db.execute(text("""INSERT INTO feature_logs(device_id,window_start,window_end,publish_count)
                VALUES('sensor1',:start,:end,1)"""), {"start": utc(seconds), "end": utc(seconds + 10)})
        checkpoint(db, "mqtt_if", 0)
        checkpoint(db, "mqtt_feature_rule", 30)
        checkpoint(db, "trust_score_v2", 30)
    yield engine, path
    engine.dispose()


def prepare(db, **changes):
    args = dict(**CONFIG, boundary=B, approved_by="operator", reason="initial approved model",
                prepared_at=B + timedelta(seconds=5))
    args.update(changes)
    return activation.prepare_activation(db, **args)


def apply(db, plan, **changes):
    args = dict(**CONFIG, applied_at=B + timedelta(seconds=6))
    args.update(changes)
    return activation.apply_activation(db, plan, **args)


def test_prepare_is_read_only_and_excludes_only_target_before_boundary(environment):
    engine, path = environment
    ro_engine = create_engine(f"sqlite:///file:{path.as_posix()}?mode=ro&uri=true")
    try:
        with Session(ro_engine) as db:
            db.execute(text("BEGIN"))
            plan = prepare(db)
            assert plan["excluded_source"]["row_count"] == 3
            assert plan["excluded_source"]["range_start"] == utc(0)
            assert plan["excluded_source"]["range_end"] == utc(30)
            assert len(plan["excluded_source"]["rows_sha256"]) == 64
            assert plan["original_checkpoint"]["last_completed_window_end"] == utc(0)
            assert db.execute(text("SELECT COUNT(*) FROM ai_stage_activations")).scalar() == 0
    finally:
        ro_engine.dispose()


def test_apply_audit_and_only_target_checkpoint_are_atomic_and_idempotent(environment):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        plan = prepare(db)
        before_others = db.execute(text("SELECT * FROM detector_checkpoints WHERE detector_name!='mqtt_if' ORDER BY detector_name")).all()
        source_before = db.execute(text("SELECT * FROM feature_logs ORDER BY id")).all()
        receipt = apply(db, plan)
        assert receipt["boundary"] == utc(30)
        assert receipt["original_checkpoint"]["last_completed_window_end"] == utc(0)
        assert db.execute(text("SELECT * FROM detector_checkpoints WHERE detector_name!='mqtt_if' ORDER BY detector_name")).all() == before_others
        assert db.execute(text("SELECT * FROM feature_logs ORDER BY id")).all() == source_before
    with Session(engine) as db, db.begin():
        checkpoint(db, "mqtt_if", 40, identifier=5)
        changes = db.connection().connection.driver_connection.total_changes
        retry = apply(db, plan, applied_at=B + timedelta(seconds=100))
        assert retry == receipt
        assert db.connection().connection.driver_connection.total_changes == changes
        assert activation.get_stage_activation(db, "mqtt_if", "mqtt-v1", "a" * 64) == receipt


def test_cp_write_failure_rolls_back_receipt(environment, monkeypatch):
    engine, _ = environment
    with Session(engine) as db:
        plan = prepare(db)
        db.rollback()
        def fail(*args, **kwargs):
            raise RuntimeError("CP failed")
        monkeypatch.setattr(activation.checkpoints, "upsert_detector_checkpoint", fail)
        with pytest.raises(RuntimeError, match="CP failed"):
            with db.begin():
                apply(db, plan)
        assert db.execute(text("SELECT COUNT(*) FROM ai_stage_activations")).scalar() == 0
        assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints WHERE detector_name='mqtt_if'")).scalar() == utc(0)


@pytest.mark.parametrize("mutation", [
    "UPDATE feature_logs SET publish_count=2 WHERE window_start='2026-10-10T00:00:10Z'",
    "DELETE FROM feature_logs WHERE window_start='2026-10-10T00:00:10Z'",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-10-10T00:00:40Z' WHERE detector_name='trust_score_v2'",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-10-10T00:00:40Z' WHERE detector_name='mqtt_feature_rule'",
    "UPDATE detector_checkpoints SET updated_at='2026-10-10T00:00:01Z' WHERE detector_name='mqtt_if'",
])
def test_apply_rechecks_exact_source_and_all_checkpoint_snapshots(environment, mutation):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        plan = prepare(db)
        db.execute(text(mutation))
        with pytest.raises(activation.AiStageActivationError):
            apply(db, plan)
        assert db.execute(text("SELECT COUNT(*) FROM ai_stage_activations")).scalar() == 0


def test_future_source_changes_outside_approved_range_do_not_invalidate_plan(environment):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        plan = prepare(db)
        db.execute(text("UPDATE feature_logs SET publish_count=99 WHERE window_start>=:boundary"),
                   {"boundary": utc(30)})
        assert apply(db, plan)["excluded_source"]["row_count"] == 3


@pytest.mark.parametrize("changes", [
    {"model_version": "mqtt-v2"}, {"bundle_sha256": "b" * 64},
    {"enabled_stages": ["mqtt_if", "mqtt_feature_rule"]},
    {"required_stages": ["mqtt_if"]}, {"trust_ai_mode": "enforce"},
    {"stage_name": "packet_if"},
])
def test_apply_runtime_identity_and_config_must_match_reviewed_plan(environment, changes):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        plan = prepare(db)
        with pytest.raises(activation.AiStageActivationError):
            apply(db, plan, **changes)
        assert db.execute(text("SELECT COUNT(*) FROM ai_stage_activations")).scalar() == 0


@pytest.mark.parametrize("mutation", [
    "DELETE FROM detector_checkpoints WHERE detector_name='trust_score_v2'",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-10-10T00:00:20Z' WHERE detector_name='trust_score_v2'",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-10-10T00:00:20Z' WHERE detector_name='mqtt_feature_rule'",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-10-10T00:00:40Z' WHERE detector_name='mqtt_if'",
])
def test_prepare_rejects_unsafe_boundary_or_required_progress(environment, mutation):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        db.execute(text(mutation))
        with pytest.raises(activation.AiStageActivationError):
            prepare(db)


def test_plan_tampering_and_repeat_activation_are_rejected(environment):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        plan = prepare(db)
        changed = deepcopy(plan)
        changed["reason"] = "different"
        with pytest.raises(activation.AiStageActivationError, match="hash"):
            apply(db, changed)
        apply(db, plan)
        with pytest.raises(activation.AiStageActivationError, match="already"):
            prepare(db)
        with pytest.raises(activation.AiStageActivationError) as error:
            activation.get_stage_activation(db, "mqtt_if", "different-model", "a" * 64)
        assert error.value.code == "AI_STAGE_ACTIVATION_MISMATCH"
        changed = deepcopy(plan)
        changed["activation_id"] = str(uuid4())
        changed["plan_sha256"] = activation._hash(changed)
        with pytest.raises(activation.AiStageActivationError, match="different"):
            apply(db, changed)


def test_missing_activation_and_missing_schema_fail_explicitly(environment, tmp_path):
    engine, _ = environment
    with Session(engine) as db:
        with pytest.raises(activation.AiStageActivationError) as error:
            activation.get_stage_activation(db, "mqtt_if", "mqtt-v1", "a" * 64)
        assert error.value.code == "AI_STAGE_ACTIVATION_MISSING"
    empty = create_engine(f"sqlite:///{(tmp_path / 'empty.db').as_posix()}")
    try:
        with Session(empty) as db:
            with pytest.raises(activation.AiStageActivationError) as error:
                prepare(db)
            assert error.value.code == "AI_STAGE_ACTIVATION_UNAVAILABLE"
    finally:
        empty.dispose()


def test_new_target_checkpoint_can_be_created_but_existing_id_is_preserved(environment):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        db.execute(text("DELETE FROM detector_checkpoints WHERE detector_name='mqtt_if'"))
        plan = prepare(db)
        assert plan["original_checkpoint"] is None
        receipt = apply(db, plan)
        assert receipt["excluded_source"]["row_count"] == 3
    with Session(engine) as db, db.begin():
        db.execute(text("UPDATE detector_checkpoints SET last_completed_window_end=:old WHERE detector_name='mqtt_if'"), {"old": utc(0)})
        with pytest.raises(activation.AiStageActivationError, match="below"):
            apply(db, plan)


def test_activation_row_is_immutable_at_database_level(environment):
    engine, path = environment
    with Session(engine) as db, db.begin():
        apply(db, prepare(db))
    with sqlite3.connect(path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE ai_stage_activations SET model_version='other'")
        with pytest.raises(sqlite3.IntegrityError, match="deleted"):
            db.execute("DELETE FROM ai_stage_activations")


def packet_config():
    return dict(stage_name="packet_if", model_version="packet-v1", bundle_sha256="b" * 64,
                enabled_stages=["packet_if"], required_stages=["packet_if"], trust_ai_mode="observe")


def seed_packet(db, missing=False):
    checkpoint(db, "packet_if", 0)
    session_id = str(uuid4())
    db.execute(text("""INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start)
        VALUES(:session,'eth0',:start,:start)"""), {"session": session_id, "start": utc(0)})
    session_pk = db.execute(text("SELECT id FROM packet_capture_sessions WHERE session_id=:session"),
                            {"session": session_id}).scalar()
    for seconds in ((0, 20) if missing else (0, 10, 20)):
        db.execute(text("""INSERT INTO packet_capture_segments
            (capture_session_id,file_name,capture_interface,window_start,window_end,status,packet_count,
             start_delay_seconds,captured_duration_seconds)
            VALUES(:session,:name,'eth0',:start,:end,'EMPTY',0,0,10)"""),
            {"session": session_pk, "name": f"packet-{seconds}.pcap", "start": utc(seconds), "end": utc(seconds+10)})


def test_packet_activation_cannot_skip_an_old_missing_capture_window(environment):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        seed_packet(db, missing=True)
        with pytest.raises(activation.AiStageActivationError) as error:
            prepare(db, **packet_config())
        assert error.value.code == "AI_STAGE_ACTIVATION_PACKET_GAP"


def test_packet_contiguous_empty_prefix_is_valid_exclusion_evidence(environment):
    engine, _ = environment
    with Session(engine) as db, db.begin():
        seed_packet(db)
        plan = prepare(db, **packet_config())
        assert plan["excluded_source"]["row_count"] == 0
        receipt = apply(db, plan, **packet_config())
        assert receipt["source_table"] == "packet_feature_logs"


def test_upgrade_014_preserves_runtime_evidence_and_is_idempotent(tmp_path):
    old = tmp_path / "old"
    old.mkdir()
    for path in MIGRATIONS.glob("*.sql"):
        if int(path.name[:3]) <= 14:
            shutil.copy2(path, old / path.name)
    path = tmp_path / "upgrade.db"
    apply_migrations(path, old)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO ai_runtime_snapshot VALUES(1,'{}')")
        before = db.execute("SELECT * FROM ai_runtime_snapshot").fetchall()
    assert apply_migrations(path, MIGRATIONS).applied_versions == list(range(15, 20))
    assert apply_migrations(path, MIGRATIONS).applied_versions == []
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM ai_runtime_snapshot").fetchall() == before
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
