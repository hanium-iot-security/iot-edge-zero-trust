"""Stored AI revisions and approved activation through real IF Stages and Trust."""
from contextlib import closing
from datetime import timedelta
from importlib.metadata import version
import json
import sqlite3
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.packet_if_artifact import packet_if_bundle_sha256
from ai.packet_if_dataset import file_sha256
from backend.app.config import Settings
from backend.app.database import get_db
from backend.app.main import app
from backend.app.services import ai_runtime_query_service
from db.migration_runner import apply_migrations
from edge.detection.ai_runtime_repository import read_ai_completions
from edge.detection.mqtt_adapters import MqttFeatureRuleStage
from edge.detection.orchestrator import run_detection_cycle
from edge.detection.runtime_checkpoint_repository import upsert_detector_checkpoint
from edge.orchestration.runtime_evidence import RuntimeEvidence
from edge.orchestration.stage_registry import load_stage_registry
from edge.policy.device_ai_policy_repository import append_ai_policy_revision
from edge.policy.device_policy import validate_policy
from edge.policy.device_policy_repository import create_device_locked, write_transaction
from edge.trust.trust_score_v2 import apply_trust_score_v2_until
from tests.device_policy_support import POLICY
from test_mqtt_if_artifact import _fixture, _pin, _row, _write_contract
from test_packet_ai_detector import RANGE_START as START, _insert_capture_session, _insert_packet_source
from test_predict_packet_isolation_forest import _write_artifact, _write_metadata


def at(seconds):
    return START + timedelta(seconds=seconds)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


@pytest.fixture(params=["mqtt_if", "packet_if"])
def runtime(request, tmp_path, monkeypatch):
    path = tmp_path / "stored-ai-policy.db"
    apply_migrations(path)
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    sessions = sessionmaker(bind=engine)
    kind = request.param
    directory = tmp_path / kind
    if kind == "mqtt_if":
        metadata = _fixture(directory)
        metadata["threshold"] = 1.0
        _write_contract(directory, metadata)
        pin = _pin(directory)
    else:
        metadata = _write_artifact(directory)
        metadata["threshold"] = -1.0
        report = directory / "training_report.json"
        report.write_text(json.dumps({"threshold": -1.0}), encoding="utf-8")
        metadata["training_report_sha256"] = file_sha256(report)
        metadata["library_versions"].update({key: version(package) for key, package in (
            ("numpy", "numpy"), ("pandas", "pandas"),
            ("scikit_learn", "scikit-learn"), ("joblib", "joblib"))})
        _write_metadata(directory, metadata)
        pin = packet_if_bundle_sha256(directory)
    configured = Settings(_env_file=None, ai_device_policy_enabled=True, trust_ai_mode="observe",
                          orchestrator_enabled_stages=kind, orchestrator_required_stages=kind,
                          **{f"{kind}_artifact_dir": str(directory),
                             f"{kind}_expected_model_version": metadata["model_version"],
                             f"{kind}_expected_bundle_sha256": pin})
    with closing(sqlite3.connect(path, isolation_level=None)) as db, write_transaction(db):
        create_device_locked(db, device_id="esp32_01", ip_address="192.168.0.4",
                             device_type="SENSOR", mqtt_principal="esp32_01",
                             policy=validate_policy(POLICY), reason="synthetic integration fixture",
                             created_by="test", initial_state="ACTIVE",
                             effective_from=at(-10), now=at(-20))
    monkeypatch.setattr("edge.orchestration.runtime_evidence.current_boot_id",
                        lambda: "11111111-1111-4111-8111-111111111111")
    publisher = RuntimeEvidence(sessions, configured, clock=lambda: at(60))
    publisher.trust_ai_mode = "observe"
    publisher.publish("STARTING")
    registry = load_stage_registry(configured, runtime_evidence=publisher)
    (stage,) = registry.detector_stages
    delegate = getattr(stage, "delegate", stage)
    assert delegate.ai_device_policy_enabled is True
    calls = []
    original = delegate.artifact.model.decision_function

    def score(matrix):
        calls.append(len(matrix))
        return original(matrix)

    monkeypatch.setattr(delegate.artifact.model, "decision_function", score)
    with sessions.begin() as db:
        session_id = _insert_capture_session(db) if kind == "packet_if" else None
        for detector, source in ((kind, stage.source_table), ("trust_score_v2", "detection_events")):
            upsert_detector_checkpoint(db, detector_name=detector, source_table=source,
                                       last_processed_id=None, last_completed_window_end=START,
                                       updated_at=START)
    try:
        yield SimpleNamespace(path=path, sessions=sessions, settings=configured, stage=stage,
                              publisher=publisher, kind=kind, calls=calls, capture_session=session_id,
                              model_version=metadata["model_version"], bundle_sha256=pin)
    finally:
        engine.dispose()


def activate(runtime):
    from edge.policy.ai_stage_activation import apply_activation, prepare_activation
    identity = dict(stage_name=runtime.kind, model_version=runtime.model_version,
                    bundle_sha256=runtime.bundle_sha256, enabled_stages=[runtime.kind],
                    required_stages=[runtime.kind], trust_ai_mode="observe")
    with runtime.sessions.begin() as db:
        plan = prepare_activation(db, **identity, boundary=START, approved_by="fixture-author",
                                  reason="synthetic integration test only", prepared_at=at(40))
        apply_activation(db, plan, **identity, applied_at=at(41))


def change_mode(runtime, mode, expected, requested_at):
    with closing(sqlite3.connect(runtime.path, isolation_level=None)) as db:
        return append_ai_policy_revision(db, device_id="esp32_01", mode=mode,
                                         expected_revision=expected, created_by="test",
                                         reason="synthetic integration change",
                                         clock=lambda: at(requested_at))


def mqtt_source(db, seconds, *, device="esp32_01", count=2):
    db.execute(text("""INSERT INTO feature_logs (device_id,window_start,window_end,
        publish_count,avg_payload_size,max_payload_size,avg_message_interval,min_message_interval)
        VALUES (:device,:start,:end,:publish_count,:avg_payload_size,:max_payload_size,
                :avg_message_interval,:min_message_interval)"""),
        _row(count=count) | dict(device=device, start=stamp(at(seconds)), end=stamp(at(seconds + 10))))


def source(runtime, seconds, *, device="esp32_01", peer_ip="192.168.0.4", count=2):
    with runtime.sessions.begin() as db:
        if runtime.kind == "mqtt_if":
            mqtt_source(db, seconds, device=device, count=count)
        else:
            index = seconds // 10 + 1
            _insert_packet_source(db, session_pk=runtime.capture_session, feature_id=index,
                                  segment_id=index, device_id=device, peer_ip=peer_ip,
                                  window_start=stamp(at(seconds)), window_end=stamp(at(seconds + 10)))


def run(runtime, start, end):
    result = run_detection_cycle(session_factory=runtime.sessions, stages=(runtime.stage,),
                                 cycle_range_start=at(start), cycle_cutoff=at(end),
                                 stage_completion_sink=runtime.publisher.stage_completed)
    return result.stage_results[0]


def _stage_outputs(runtime):
    with runtime.sessions() as db:
        return {
            table: db.execute(text(f"SELECT * FROM {table}")).all()
            for table in ("detector_checkpoints", "detection_events", "ai_device_completions",
                          "ai_warning_keys", "ai_warning_aggregates", "ai_warning_events",
                          "ai_runtime_snapshot")
        }


@pytest.mark.parametrize("fail_after_stage", [False, True])
def test_parallel_writer_during_inference_preserves_atomic_stage(runtime, monkeypatch, fail_after_stage):
    change_mode(runtime, "OBSERVE", 1, -5)
    activate(runtime)
    source(runtime, 0)
    with closing(sqlite3.connect(runtime.path)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    before = _stage_outputs(runtime)
    delegate = getattr(runtime.stage, "delegate", runtime.stage)
    original_score = delegate.artifact.model.decision_function
    writer_commits = []

    def score(matrix):
        # A separate collection writer commits after the policy snapshot has
        # been read. Closing it rules out an outstanding writer-lock timeout.
        assert not writer_commits
        with closing(sqlite3.connect(runtime.path, timeout=0)) as writer, writer:
            writer.execute("UPDATE devices SET last_seen_at=? WHERE device_id='esp32_01'",
                           (stamp(at(1)),))
        writer_commits.append(True)
        scores = original_score(matrix)
        # The success regression must first write a normal completion. The
        # injected failure also creates an event to verify its atomic rollback.
        return scores if fail_after_stage else scores * 0 + 2.0

    monkeypatch.setattr(delegate.artifact.model, "decision_function", score)
    completed = runtime.publisher.stage_completed

    def fail_after_writes(db, result):
        completed(db, result)
        assert read_ai_completions(db)[0]["anomaly_count"] == 1
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 1
        assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints "
                               "WHERE detector_name=:name"), {"name": runtime.kind}).scalar_one() == stamp(at(10))
        raise RuntimeError("injected failure after all Stage writes")

    if fail_after_stage:
        monkeypatch.setattr(runtime.publisher, "stage_completed", fail_after_writes)
    try:
        if fail_after_stage:
            with pytest.raises(RuntimeError, match="injected failure after all Stage writes"):
                run(runtime, 0, 10)
            assert _stage_outputs(runtime) == before
        else:
            result = run(runtime, 0, 10)
            assert result.created_event_count == 0
            with runtime.sessions() as db:
                (completion,) = read_ai_completions(db)
                assert (completion["inference_count"], completion["normal_count"],
                        completion["anomaly_count"]) == (1, 1, 0)
                assert completion["ai_revision"] == 2 and completion["ai_mode"] == "OBSERVE"
                assert completion["completed_window_end"] == stamp(at(10))
                assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints "
                                       "WHERE detector_name=:name"), {"name": runtime.kind}).scalar_one() == stamp(at(10))
                assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
    except Exception:
        # On the broken implementation, retain proof that the exact completion
        # write failure rolled back detector state before re-raising it as RED.
        assert _stage_outputs(runtime) == before
        raise
    finally:
        assert writer_commits == [True]
        with closing(sqlite3.connect(runtime.path)) as observer:
            assert observer.execute("SELECT last_seen_at FROM devices WHERE device_id='esp32_01'").fetchone()[0] == stamp(at(1))


def test_stored_off_observe_off_replay_uses_original_windows(runtime):
    change_mode(runtime, "OBSERVE", 1, 5)
    change_mode(runtime, "OFF", 2, 15)
    activate(runtime)
    for seconds in (0, 10, 20):
        # Packet ownership comes from peer IP at the window, not its candidate id.
        source(runtime, seconds, device=None if runtime.kind == "packet_if" else "esp32_01")
    result = run(runtime, 0, 30)
    assert runtime.calls == [1]
    assert result.created_event_count == 1
    assert [(record.window_start, record.ai_mode, record.ai_revision, record.inference_count)
            for record in result.ai_completion_records] == [
                (at(0), "OFF", 1, 0), (at(10), "OBSERVE", 2, 1), (at(20), "OFF", 3, 0)]
    with runtime.sessions() as db:
        event = db.execute(text("SELECT analysis_window_start,evidence_json FROM detection_events")).one()
        assert event.analysis_window_start == stamp(at(10))
        evidence = json.loads(event.evidence_json)
        model = evidence["model"] if runtime.kind == "packet_if" else evidence
        assert (model["device_ai_mode"], model["device_ai_revision"]) == ("OBSERVE", 2)
        assert (model["model_version"], model["bundle_sha256"]) == (
            runtime.model_version, runtime.bundle_sha256)
        (latest,) = read_ai_completions(db, device_id="esp32_01")
        assert (latest["ai_mode"], latest["inference_count"], latest["normal_count"]) == ("OFF", 0, 0)
        assert latest["exclusion_counts"] == {"AI_OFF_AT_WINDOW": 1}


def test_same_stage_reads_new_revision_on_next_cycle_and_off_never_scores(runtime, monkeypatch):
    activate(runtime)
    source(runtime, 0)
    run(runtime, 0, 10)
    assert runtime.calls == []
    change_mode(runtime, "OBSERVE", 1, 15)
    source(runtime, 10)
    source(runtime, 20)
    result = run(runtime, 10, 30)
    assert runtime.calls == [1] and result.created_event_count == 1
    assert [(row.window_start, row.ai_mode, row.ai_revision) for row in result.ai_completion_records] == [
        (at(10), "OFF", 1), (at(20), "OBSERVE", 2)]
    monkeypatch.setattr(ai_runtime_query_service, "utc_now", lambda: at(61))
    monkeypatch.setattr(ai_runtime_query_service, "current_boot_id", lambda: runtime.publisher.boot_id)

    def get_test_db():
        with runtime.sessions() as db:
            yield db

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = get_test_db
    try:
        with TestClient(app) as client:
            response = client.get("/api/runtime-status", params={"device_id": "esp32_01"})
        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], body["freshness"]) == ("RUNNING", "FRESH")
        stage = next(item for item in body["stages"] if item["name"] == runtime.kind)
        assert stage["ai_device_policy_enabled"] is True
        assert stage["enabled"] is True and stage["required"] is True
        assert stage["status"] == "COMPLETED" and stage["trust_ai_mode"] == "observe"
        (completed,) = body["completions"]
        assert (completed["ai_mode"], completed["ai_revision"], completed["evidence_status"]) == (
            "OBSERVE", 2, "CURRENT")
        assert completed["window_start"] == stamp(at(20))
        assert (completed["inference_count"], completed["anomaly_count"], completed["normal_count"]) == (1, 1, 0)
        assert completed["model_version"] == stage["model_version"] == runtime.model_version
        assert completed["bundle_sha256"] == stage["bundle_sha256"] == runtime.bundle_sha256
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous


def test_missing_device_ai_revision_excludes_only_that_device(runtime):
    # A migrated legacy device has registration policy but no AI revision/backfill.
    with runtime.sessions.begin() as db:
        db.execute(text("""INSERT INTO devices (device_id,ip_address,registration_effective_from)
            VALUES ('esp32_02','192.168.0.5',:start)"""), {"start": stamp(at(-10))})
        db.execute(text("""INSERT INTO device_policy_revisions
            (device_id,revision,effective_from,registration_state,policy_profile,
             expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
             packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason)
            SELECT 'esp32_02',revision,effective_from,registration_state,policy_profile,
             expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
             packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason
            FROM device_policy_revisions WHERE device_id='esp32_01'"""))
    change_mode(runtime, "OBSERVE", 1, -5)
    activate(runtime)
    source(runtime, 0, device="esp32_02", peer_ip="192.168.0.5")
    source(runtime, 10)
    result = run(runtime, 0, 20)
    assert runtime.calls == [1] and result.created_event_count == 1
    missing = next(row for row in result.ai_completion_records if row.device_id == "esp32_02")
    assert missing.ai_mode is None and missing.ai_revision is None
    assert missing.inference_count == missing.normal_count == 0
    assert missing.exclusion_counts == {"AI_POLICY_UNAVAILABLE": 1}


@pytest.mark.parametrize("with_rule", [False, True])
def test_stored_observe_event_never_penalizes_but_rule_still_scores(runtime, with_rule):
    change_mode(runtime, "OBSERVE", 1, -5)
    activate(runtime)
    source(runtime, 0, count=20 if with_rule else 2)
    run(runtime, 0, 10)
    with runtime.sessions.begin() as db:
        if with_rule:
            if runtime.kind == "packet_if":
                mqtt_source(db, 0, count=20)
            MqttFeatureRuleStage().run_until(db, cycle_range_start=at(0), cycle_cutoff=at(10))
        result = apply_trust_score_v2_until(db, cycle_range_start=at(0), cycle_cutoff=at(10),
                                          ai_mode="enforce", decision_at=at(20))
        ai = db.execute(text("SELECT score_delta,applied_to_score,processing_reason "
                             "FROM detection_events WHERE detector_type='AI'")).one()
        assert tuple(ai) == (-15, 0, "AI_OBSERVATION_ONLY")
        assert result.observed_ai_event_count == 1
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id='esp32_01'")).scalar_one() == (
            80 if with_rule else 100)
        assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one() == int(with_rule)
        for table in ("isolation_history", "firewall_rules"):
            assert db.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one() == 0


def test_missing_activation_never_infers_or_advances_checkpoint(runtime):
    from edge.policy.ai_stage_activation import AiStageActivationError
    change_mode(runtime, "OBSERVE", 1, -5)
    source(runtime, 0)
    with pytest.raises(AiStageActivationError):
        run(runtime, 0, 10)
    assert runtime.calls == []
    with runtime.sessions() as db:
        assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints "
                               "WHERE detector_name=:name"), {"name": runtime.kind}).scalar_one() == stamp(START)
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
        assert read_ai_completions(db) == []
