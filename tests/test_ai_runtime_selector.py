"""The stored-policy reader uses historical revisions and a real SQLite snapshot."""
from dataclasses import replace
from datetime import timedelta
import sqlite3
from types import SimpleNamespace

import pytest
from sqlalchemy import event, text

from backend.app.config import Settings
from backend.app.schemas.ai_runtime_schema import RuntimeStage
from edge.detection.ai_runtime_repository import read_runtime_snapshot
from edge.detection.detector_contract import DetectorRunResult
from edge.detection.mqtt_adapters import MqttIsolationForestStage
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.runtime_checkpoint_repository import upsert_detector_checkpoint
from edge.orchestration.runtime_evidence import RuntimeEvidence
from edge.policy.ai_runtime_selector import AIRuntimePolicyError, load_ai_runtime_selector
from edge.policy.ai_stage_activation import AiStageActivationError, apply_activation, prepare_activation
from test_phase8_trust_gates import session_factory, _seed, _revision, T0, T1, T2


IDENTITY = dict(stage_name="mqtt_if", model_version="selector-test-v1", bundle_sha256="a" * 64)
CONFIG = IDENTITY | dict(enabled_stages=["mqtt_if"], required_stages=["mqtt_if"], trust_ai_mode="observe")


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def revision(db, *, device="esp32_01", number=1, mode="OFF", effective=T0):
    db.execute(text("""INSERT INTO device_ai_policy_revisions
        (device_id,revision,mode,effective_from,created_at,created_by,reason)
        VALUES (:device,:number,:mode,:effective,:created,'test','selector fixture')"""),
        dict(device=device, number=number, mode=mode, effective=stamp(effective), created=stamp(T0)))


def cp(db, when=T0):
    upsert_detector_checkpoint(db, detector_name="mqtt_if", source_table="feature_logs",
                               last_processed_id=None, last_completed_window_end=when, updated_at=when)


@pytest.fixture
def approved(session_factory):
    with session_factory.begin() as db:
        _seed(db, status="ACTIVE")
        cp(db)
        upsert_detector_checkpoint(db, detector_name="trust_score_v2", source_table="detection_events",
                                   last_processed_id=None, last_completed_window_end=T0, updated_at=T0)
        plan = prepare_activation(db, **CONFIG, boundary=T0, approved_by="test",
                                  reason="synthetic selector approval", prepared_at=T1)
        apply_activation(db, plan, **CONFIG, applied_at=T2)
    return session_factory


def load(db, start=T0, **changes):
    return load_ai_runtime_selector(db, **(IDENTITY | changes), source_table="feature_logs",
                                    cycle_range_start=start)


def decision(selector, when=T0, device="esp32_01"):
    return selector(selector.resolver.resolve(device, when))


def test_full_prefix_resolves_off_observe_off_at_original_windows(approved):
    with approved.begin() as db:
        revision(db)
        revision(db, number=2, mode="OBSERVE", effective=T1)
        revision(db, number=3, effective=T2)
    with approved.begin() as db:
        snapshot = load(db)
        assert [(decision(snapshot, at).mode, decision(snapshot, at).ai_revision) for at in (T0,T1,T2)] == [
            ("OFF",1),("OBSERVE",2),("OFF",3)]
        assert decision(snapshot, T1).approved_start == T1


def test_missing_ai_history_is_not_off_and_unregistered_is_not_inferred(approved):
    with approved.begin() as db:
        snapshot = load(db)
        assert decision(snapshot).reason == "AI_POLICY_UNAVAILABLE"
        assert not decision(snapshot, device="unknown").infer


def test_future_corrupt_mode_does_not_change_historical_off(approved):
    with approved.begin() as db:
        revision(db)
        revision(db, number=2, mode="OBSERVE", effective=T1)
        db.execute(text("DROP TRIGGER trg_device_ai_policy_revisions_no_update"))
        db.execute(text("PRAGMA ignore_check_constraints=ON"))
        db.execute(text("UPDATE device_ai_policy_revisions SET mode='BROKEN' WHERE revision=2"))
    with approved.begin() as db:
        snapshot = load(db)
        assert decision(snapshot).reason == "AI_OFF_AT_WINDOW"
        assert decision(snapshot, T1).reason == "INVALID_AI_REVISION"


@pytest.mark.parametrize("bad_time", ["not-a-time", "2026-09-30T00:00:00", "2026-09-30T00:00:00+09:00", "2026-09-30T00:00:00.000001Z"])
def test_malformed_revision_only_excludes_its_device(approved, bad_time):
    with approved.begin() as db:
        revision(db)
        db.execute(text("INSERT INTO devices(device_id,ip_address,registration_effective_from) VALUES('other','192.0.2.2',:start)"), {"start":stamp(T0)})
        _revision(db, device_id="other")
        revision(db, device="other", mode="OBSERVE")
        db.execute(text("DROP TRIGGER trg_device_ai_policy_revisions_no_update"))
        db.execute(text("PRAGMA ignore_check_constraints=ON"))
        db.execute(text("UPDATE device_ai_policy_revisions SET effective_from=:bad WHERE device_id='esp32_01'"), {"bad":bad_time})
    with approved.begin() as db:
        snapshot = load(db)
        assert decision(snapshot, T1).reason == "INVALID_AI_REVISION"
        assert decision(snapshot, T1, "other").infer


@pytest.mark.parametrize("table", ["device_ai_policy_revisions", "device_policy_revisions"])
def test_missing_schema_fails_stage_without_changing_checkpoint(approved, table):
    with approved.begin() as db:
        db.execute(text(f"DROP TABLE {table}"))
    with approved() as db:
        before = db.execute(text("SELECT * FROM detector_checkpoints")).all()
        with pytest.raises(AIRuntimePolicyError, match="schema") as raised:
            load(db)
        assert raised.value.code == "AI_POLICY_SCHEMA_UNAVAILABLE"
        assert db.execute(text("SELECT * FROM detector_checkpoints")).all() == before


def test_model_pin_mismatch_is_hold_even_with_all_off(approved):
    with approved.begin() as db:
        revision(db)
        with pytest.raises(AiStageActivationError) as raised:
            load(db, bundle_sha256="b"*64)
        assert raised.value.code == "AI_STAGE_ACTIVATION_MISMATCH"


def test_global_range_cannot_skip_a_lagging_optional_stage(approved):
    with approved.begin() as db:
        with pytest.raises(AIRuntimePolicyError) as raised:
            load(db, start=T1)
        assert raised.value.code == "AI_STAGE_ACTIVATION_HOLD"
        assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints WHERE detector_name='mqtt_if'")).scalar_one() == stamp(T0)


def test_older_global_range_uses_own_completed_checkpoint(approved):
    with approved.begin() as db:
        cp(db, T1)
    with approved.begin() as db:
        snapshot = load(db, start=T0-timedelta(seconds=10))
        assert snapshot.activation_from == T0
        assert snapshot.checkpoint["last_completed_window_end"] == T1


def test_physical_snapshot_survives_ai_change_between_registration_and_ai_reads(approved):
    engine = approved.kw["bind"]
    path = engine.url.database
    with sqlite3.connect(path) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
    with approved.begin() as db:
        revision(db)
    changed = False

    def concurrent_write(connection, cursor, statement, parameters, context, many):
        nonlocal changed
        if changed or "registered_device_id" not in statement:
            return
        changed = True
        assert connection.connection.driver_connection.in_transaction
        with sqlite3.connect(path, timeout=3) as writer:
            writer.execute("""INSERT INTO device_ai_policy_revisions
                (device_id,revision,mode,effective_from,created_at,created_by,reason)
                VALUES ('esp32_01',2,'OBSERVE',?,?,'test','concurrent commit')""", (stamp(T1),stamp(T0)))

    event.listen(engine, "after_cursor_execute", concurrent_write)
    try:
        with approved.begin() as db:
            assert not db.connection().connection.driver_connection.in_transaction
            snapshot = load(db)
            assert changed
            assert decision(snapshot, T1).reason == "AI_OFF_AT_WINDOW"
        with approved.begin() as db:
            assert decision(load(db), T1).infer
    finally:
        event.remove(engine, "after_cursor_execute", concurrent_write)


@pytest.mark.parametrize("stage", [MqttIsolationForestStage, PacketIsolationForestStage])
def test_runtime_policy_requires_observe_and_rejects_external_selector(stage):
    with pytest.raises(ValueError, match="TRUST_AI_MODE=observe"):
        stage.from_settings(app_settings=Settings(_env_file=None, ai_device_policy_enabled=True, trust_ai_mode="enforce"))
    with pytest.raises(ValueError, match="external selector"):
        stage.from_settings(app_settings=Settings(_env_file=None, ai_device_policy_enabled=True, trust_ai_mode="observe"),
                            ai_window_selector=lambda row: None)


def test_mqtt_runtime_policy_cannot_fall_back_to_legacy_model():
    assert Settings(_env_file=None).ai_device_policy_enabled is False
    with pytest.raises(ValueError, match="pinned MQTT Bundle"):
        MqttIsolationForestStage.from_settings(app_settings=Settings(
            _env_file=None, ai_device_policy_enabled=True, trust_ai_mode="observe"))


def test_runtime_evidence_exposes_actual_flag_and_does_not_refresh_noop(approved):
    configured = Settings(_env_file=None, orchestrator_enabled_stages="mqtt_if", orchestrator_required_stages="mqtt_if")
    publisher = RuntimeEvidence(approved, configured, clock=lambda:T2)
    stage = SimpleNamespace(detector_name="mqtt_if", source_table="feature_logs", ai_device_policy_enabled=True)
    publisher.register_stage("mqtt_if", stage)
    result = DetectorRunResult("mqtt_if", "feature_logs", T0, T1, 0, 0, None, None, T0, T1)
    with approved.begin() as db:
        publisher.stage_completed(db, result)
    with approved() as db:
        before = read_runtime_snapshot(db)
    actual = next(row for row in before["stages"] if row["name"] == "mqtt_if")
    assert RuntimeStage.model_validate(actual).ai_device_policy_enabled is True
    publisher.clock = lambda:T2+timedelta(seconds=10)
    with approved.begin() as db:
        publisher.stage_completed(db, replace(result, completed_window_end_before=T1))
    with approved() as db:
        assert read_runtime_snapshot(db) == before
    assert RuntimeStage(name="legacy",enabled=True,required=True,status="COMPLETED").ai_device_policy_enabled is None
