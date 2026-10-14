"""Confirmed loss does not hide the next real Packet event from Trust."""

import pytest
from sqlalchemy import text

from edge.orchestration import run_detection_orchestrator as orchestrator
from edge.packet import capture_session_repository as captures
from test_segment_gap_runtime import (
    runtime, _time, _segment, _registry, _checkpoint, CAPTURE_ID, DEVICE_ID,
    format_db_utc, run_producer_cycle, CYCLE_COMPLETED,
    PACKET_RULE, PACKET_IF, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE,
)

NEXT = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


def _chain(runtime, tmp_path, *, attack=False, late=False):
    factory, _, source = runtime
    with factory() as db:
        _, initial_feature = _segment(db, source, 0)
        if late:
            captures.insert_late_capture_segment(
                db, capture_session_pk=source, capture_interface="eth0",
                window_start=_time(10), window_end=_time(20),
                error_message="capture did not start", start_delay_seconds=2.5,
            )
        captures.close_session(db, source, _time(12 if late else 10),
                               "FAILED" if late else "COMPLETED")
        next_start = 20 if late else 30
        target = captures.create_session(db, session_id=NEXT, capture_interface="eth0",
                                         started_at=_time(next_start - 2))
        captures.set_first_window_start(db, target, _time(next_start))
        if not late:
            captures.record_capture_gap(db, target, _time(10), _time(next_start))
        segment, last_feature = _segment(db, target, next_start)
        # The fixture helper normally names its original capture UUID.
        db.execute(text("UPDATE packet_capture_segments SET file_name=replace(file_name,:old,:new) WHERE id=:id"),
                   {"old": CAPTURE_ID, "new": NEXT, "id": segment})
        if attack:
            db.execute(text("UPDATE packet_feature_logs SET packet_count=201, total_bytes=2010 WHERE id=:id"),
                       {"id": last_feature})
        for seconds in range(0, next_start + 10, 10):
            db.execute(text("INSERT INTO mqtt_logs (device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) "
                            "VALUES (:device,:topic,'{}',2,:at,1,1)"),
                       {"device": DEVICE_ID, "topic": f"iot/{DEVICE_ID}/sensor", "at": format_db_utc(_time(seconds + 1))})
        db.commit()
    run_producer_cycle(session_factory=factory, now=_time(next_start + 11))
    registry = _registry(tmp_path)
    first = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert first.status == CYCLE_COMPLETED and first.cutoff == _time(10)
    return registry, next_start, initial_feature, last_feature


@pytest.mark.parametrize("late", [False, True])
def test_confirmed_gap_then_real_attack_is_scored(runtime, tmp_path, monkeypatch, late):
    registry, next_start, initial_feature, last_feature = _chain(runtime, tmp_path, attack=True, late=late)
    factory, _, _ = runtime
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    catchup = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED
    assert catchup.range_start == _time(10) and catchup.cutoff == _time(next_start)
    assert all(item.detector_name not in (PACKET_RULE, PACKET_IF) for item in catchup.stage_results)
    with factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE_ID}).scalar_one() == 100
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == initial_feature
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(next_start + 10)
    with factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE_ID}).scalar_one() < 100
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE applied_to_score=1")).scalar_one() > 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == last_feature
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(next_start + 10))
        if late:
            assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments WHERE status='FAILED' AND error_code='LATE_CAPTURE'")).scalar_one() == 1


def test_policy_disabled_keeps_existing_hold(runtime, tmp_path, monkeypatch):
    registry, _, _, _ = _chain(runtime, tmp_path)
    factory, _, _ = runtime
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": False}))
    result = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert result.status != CYCLE_COMPLETED
    with factory() as db:
        assert _checkpoint(db, PACKET_RULE)["last_completed_window_end"] == format_db_utc(_time(10))


def test_committed_gap_catches_up_after_restart_with_policy_disabled(runtime, tmp_path, monkeypatch):
    from edge.packet.confirmed_gaps import advance_confirmed_packet_gap

    registry, next_start, initial_feature, last_feature = _chain(runtime, tmp_path, attack=True)
    factory, _, _ = runtime
    # Persist only the atomic Packet transition, as if the process died immediately after commit.
    with factory() as db:
        assert advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(next_start + 10))
        db.commit()
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(10))
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": False}))
    catchup = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == _time(next_start)
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(next_start + 10)
    with factory() as db:
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE_ID}).scalar_one() < 100
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE applied_to_score=1")).scalar_one() > 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == last_feature
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(next_start + 10))


def _warning_evidence(factory, registry):
    from dataclasses import replace
    from backend.app.config import Settings
    from edge.detection.ai_warning_aggregation import WarningPolicy
    from edge.orchestration.runtime_evidence import RuntimeEvidence

    evidence = RuntimeEvidence(factory, Settings(
        _env_file=None, orchestrator_enabled_stages=",".join(registry.enabled_names),
        orchestrator_required_stages=",".join(registry.required_names)), clock=lambda: _time(50))
    evidence.warning_policy = WarningPolicy("gap-regression", 60, 2, 0)
    for configured in registry.stages:
        evidence.register_stage(configured.name, configured.stage)
    return replace(registry, runtime_evidence=evidence)


def _observe_anomaly(db, evidence, seconds, *, detector=PACKET_IF):
    import json
    from edge.detection.ai_run_evidence import AICompletionRecord
    from edge.detection.ai_runtime_repository import store_ai_completions

    model = dict(model_version="test-v1", bundle_sha256="a" * 64,
                 device_ai_mode="OBSERVE", device_ai_revision=1)
    facts = dict(detector_name=detector, **({"model": model} if detector == PACKET_IF else model))
    db.execute(text("INSERT INTO detection_events "
                    "(device_id,detector_type,event_type,analysis_window_start,analysis_window_end,evidence_json) "
                    "VALUES (:device,'AI',:event,:start,:end,:evidence)"),
               dict(device=DEVICE_ID, event="AI_PACKET_ANOMALY" if detector == PACKET_IF else "AI_ANOMALY",
                    start=format_db_utc(_time(seconds)), end=format_db_utc(_time(seconds + 10)),
                    evidence=json.dumps(facts)))
    record = AICompletionRecord(detector, DEVICE_ID, _time(seconds), _time(seconds + 10),
                                1, 1, 0, 1, {}, "test-v1", "a" * 64, 1, "OBSERVE")
    store_ai_completions(db, [record], run_id=evidence.run_id, boot_id=evidence.boot_id,
                         observed_at=evidence.clock(), warning_policy=evidence.warning_policy)


def test_confirmed_gap_interrupts_packet_warning_without_fabricating_completion(runtime, tmp_path, monkeypatch):
    from edge.detection.ai_runtime_repository import read_ai_completions, list_ai_warnings

    registry, next_start, _, _ = _chain(runtime, tmp_path)
    factory, _, _ = runtime
    registry = _warning_evidence(factory, registry)
    with factory() as db, db.begin():
        _observe_anomaly(db, registry.runtime_evidence, 0)
        _observe_anomaly(db, registry.runtime_evidence, 0, detector="mqtt_if")
        before = read_ai_completions(db)
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    result = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert result.status == CYCLE_COMPLETED and result.cutoff == _time(next_start)
    with factory() as db, db.begin():
        assert read_ai_completions(db) == before
        buckets = db.execute(text("SELECT detector_name,closed,last_decision FROM ai_warning_aggregates "
                                  "ORDER BY detector_name")).all()
        _observe_anomaly(db, registry.runtime_evidence, next_start)
        assert list_ai_warnings(db)["total"] == 0
        assert buckets == [("mqtt_if", 0, "BELOW_THRESHOLD"), (PACKET_IF, 1, "INPUT_INTERRUPTED")]
        assert db.execute(text("SELECT closed,last_decision,notified_at,count FROM ai_warning_aggregates "
                               "WHERE detector_name='packet_if'")).one() == (1, "LATE_ATTACHED", None, 2)


def test_warning_interruption_failure_rolls_back_gap_audit_and_packet_boundaries(runtime, tmp_path, monkeypatch):
    from edge.detection import ai_runtime_repository as repository

    registry, _, _, _ = _chain(runtime, tmp_path)
    factory, _, _ = runtime
    registry = _warning_evidence(factory, registry)
    with factory() as db, db.begin():
        _observe_anomaly(db, registry.runtime_evidence, 0)
        before = [_checkpoint(db, detector) for detector in (PACKET_RULE, PACKET_IF)]
    original = repository.interrupt_ai_warnings

    def fail_after_interruption(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("warning persistence failed")

    monkeypatch.setattr(repository, "interrupt_ai_warnings", fail_after_interruption)
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    with pytest.raises(RuntimeError, match="warning persistence failed"):
        orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    with factory() as db:
        assert [_checkpoint(db, detector) for detector in (PACKET_RULE, PACKET_IF)] == before
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 0
        assert db.execute(text("SELECT closed,last_decision FROM ai_warning_aggregates")).one() == (0, "BELOW_THRESHOLD")


@pytest.mark.parametrize("mode", ["OFF", "OBSERVE"])
def test_activated_ai_policy_resumes_real_input_after_committed_gap(runtime, tmp_path, monkeypatch, mode):
    from dataclasses import replace
    from importlib.metadata import version
    from ai.packet_if_artifact import packet_if_bundle_sha256
    from backend.app.config import Settings
    from edge.detection.ai_runtime_repository import read_ai_completions
    from edge.detection.packet_ai_detector import PacketIsolationForestStage
    from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
    from edge.orchestration.stage_registry import ConfiguredStage
    from edge.policy.ai_stage_activation import prepare_activation, apply_activation
    from test_predict_packet_isolation_forest import _write_artifact, _write_metadata

    registry, next_start, initial_feature, last_feature = _chain(runtime, tmp_path, attack=True)
    factory, _, _ = runtime
    directory = tmp_path / "pinned-packet"
    metadata = _write_artifact(directory)
    metadata["library_versions"].update({key: version(package) for key, package in (
        ("numpy", "numpy"), ("pandas", "pandas"),
        ("scikit_learn", "scikit-learn"), ("joblib", "joblib"))})
    _write_metadata(directory, metadata)
    configured = Settings(_env_file=None, ai_device_policy_enabled=True,
                          runtime_evidence_enabled=True, packet_confirmed_gap_policy_enabled=True,
                          trust_ai_mode="observe", packet_if_artifact_dir=str(directory),
                          packet_if_expected_model_version=metadata["model_version"],
                          packet_if_expected_bundle_sha256=packet_if_bundle_sha256(directory))
    delegate = PacketIsolationForestStage.from_settings(app_settings=configured)
    registry = replace(registry, stages=tuple(
        ConfiguredStage(PACKET_IF, PacketFeatureReadyStage(delegate), True)
        if item.name == PACKET_IF else item for item in registry.stages))
    registry = _warning_evidence(factory, registry)
    identity = dict(stage_name=PACKET_IF, model_version=delegate.artifact.model_version,
                    bundle_sha256=delegate.artifact.bundle_sha256,
                    enabled_stages=list(registry.enabled_names), required_stages=list(registry.required_names),
                    trust_ai_mode="observe")
    with factory() as db, db.begin():
        db.execute(text("INSERT INTO device_ai_policy_revisions "
                        "(device_id,revision,mode,effective_from,created_at,created_by,reason) "
                        "VALUES (:device,1,:mode,:start,:start,'test','gap integration')"),
                   dict(device=DEVICE_ID, mode=mode, start=format_db_utc(_time(0))))
        plan = prepare_activation(db, **identity, boundary=_time(10), approved_by="fixture-author",
                                  reason="synthetic gap integration", prepared_at=_time(50))
        apply_activation(db, plan, **identity, applied_at=_time(50))
    calls = []
    original_score = delegate.artifact.model.decision_function

    def score(matrix):
        calls.append(len(matrix))
        return original_score(matrix)

    monkeypatch.setattr(delegate.artifact.model, "decision_function", score)
    monkeypatch.setattr(orchestrator, "settings", configured)
    monkeypatch.setattr(orchestrator, "resolve_ai_mode", lambda: "observe")
    original_cycle = orchestrator.run_detection_cycle

    def fail_after_gap(**kwargs):
        raise RuntimeError("interrupted after gap commit")

    monkeypatch.setattr(orchestrator, "run_detection_cycle", fail_after_gap)
    with pytest.raises(RuntimeError, match="interrupted after gap commit"):
        orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    with factory() as db:
        assert read_ai_completions(db) == []
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        assert _checkpoint(db, PACKET_IF)["last_processed_id"] == initial_feature
        assert _checkpoint(db, PACKET_IF)["last_completed_window_end"] == format_db_utc(_time(next_start))
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(10))
    assert calls == []
    # A fresh process catches MQTT/Trust up from the persisted audit, even after opt-out.
    monkeypatch.setattr(orchestrator, "run_detection_cycle", original_cycle)
    monkeypatch.setattr(orchestrator, "settings", configured.model_copy(
        update={"packet_confirmed_gap_policy_enabled": False}))
    delegate.completion_sink = None  # A restarted publisher installs one fresh sink.
    registry = _warning_evidence(factory, registry)
    caught_up = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert caught_up.status == CYCLE_COMPLETED and caught_up.cutoff == _time(next_start)
    resumed = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert resumed.status == CYCLE_COMPLETED and resumed.cutoff == _time(next_start + 10)
    assert calls == ([1] if mode == "OBSERVE" else [])
    with factory() as db:
        (completion,) = read_ai_completions(db, device_id=DEVICE_ID)
        assert completion["window_start"] == format_db_utc(_time(next_start))
        assert completion["ai_mode"] == mode and completion["ai_revision"] == 1
        assert completion["inference_count"] == int(mode == "OBSERVE")
        assert _checkpoint(db, PACKET_IF)["last_processed_id"] == last_feature
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(next_start + 10))
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"),
                          dict(device=DEVICE_ID)).scalar_one() < 100  # Real Rule input still applies.
