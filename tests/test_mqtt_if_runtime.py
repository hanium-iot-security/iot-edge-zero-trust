"""Synthetic MQTT Bundles through settings, Stage and real SQLite transactions."""
from datetime import timedelta
import json

import pytest
from sqlalchemy import text

from ai.mqtt_if_contract import MQTT_IF_FEATURES
from backend.app.config import Settings
from edge.detection.ai_detector import DEFAULT_MODEL_PATH, predict_bundle_feature_window
from edge.detection.mqtt_adapters import MqttIsolationForestStage
from edge.orchestration.stage_registry import StageConfigurationError, load_stage_registry
from edge.policy.ai_window_decision import AIRevision, decide_ai_window
from edge.trust.trust_score_v2 import apply_trust_score_v2_until
from test_mqtt_if_artifact import _fixture, _pin, _row, _write_contract
from test_phase8_trust_gates import session_factory, _seed, T0, T1, T2


@pytest.fixture
def bundle_dir(tmp_path):
    directory = tmp_path / "mqtt-bundle"
    metadata = _fixture(directory)
    metadata["threshold"] = 1.0  # Every synthetic input is anomalous for evidence tests.
    _write_contract(directory, metadata)
    return directory


def _settings(directory=None, **overrides):
    values = dict(mqtt_if_artifact_dir="", mqtt_if_expected_model_version="",
                  mqtt_if_expected_bundle_sha256="", trust_ai_mode="observe",
                  orchestrator_enabled_stages="mqtt_if", orchestrator_required_stages="mqtt_if")
    if directory is not None:
        values.update(mqtt_if_artifact_dir=str(directory),
                      mqtt_if_expected_model_version="mqtt-if-synthetic-test-v1",
                      mqtt_if_expected_bundle_sha256=_pin(directory))
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _feature(db, *, start=T0, count=2):
    row = _row(count=count)
    db.execute(text("""INSERT INTO feature_logs (
        device_id, window_start, window_end, publish_count, avg_payload_size,
        max_payload_size, avg_message_interval, min_message_interval
    ) VALUES ('esp32_01', :start, :end, :publish_count, :avg_payload_size,
        :max_payload_size, :avg_message_interval, :min_message_interval)"""),
        row | {"start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "end": (start + timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")})
    return row


def test_empty_bundle_settings_preserve_legacy_stage():
    stage = MqttIsolationForestStage.from_settings(app_settings=_settings(trust_ai_mode="enforce"))
    assert stage.artifact is None and stage.model_path == DEFAULT_MODEL_PATH


@pytest.mark.parametrize("missing", ["mqtt_if_artifact_dir", "mqtt_if_expected_model_version",
                                     "mqtt_if_expected_bundle_sha256"])
def test_partial_bundle_settings_refuse_legacy_fallback(bundle_dir, missing):
    with pytest.raises(ValueError, match="configured together"):
        MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir, **{missing: " "}))


@pytest.mark.parametrize("entrypoint", ["settings", "constructor"])
def test_bundle_requires_observe_trust_mode(bundle_dir, entrypoint):
    configured = _settings(bundle_dir)
    if entrypoint == "settings":
        with pytest.raises(ValueError, match="TRUST_AI_MODE=observe"):
            MqttIsolationForestStage.from_settings(
                app_settings=_settings(bundle_dir, trust_ai_mode="enforce"))
    else:
        artifact = MqttIsolationForestStage.from_settings(app_settings=configured).artifact
        with pytest.raises(ValueError, match="TRUST_AI_MODE=observe"):
            MqttIsolationForestStage(artifact=artifact, trust_ai_mode="enforce")


def test_registry_builds_pinned_bundle_stage(bundle_dir):
    registry = load_stage_registry(_settings(bundle_dir))
    (stage,) = registry.detector_stages
    assert registry.enabled_names == registry.required_names == ("mqtt_if",)
    assert isinstance(stage, MqttIsolationForestStage)
    assert stage.artifact.inspection.bundle_sha256 == _pin(bundle_dir)
    assert stage.artifact.inspection.model_version == "mqtt-if-synthetic-test-v1"


@pytest.mark.parametrize("change", [
    {"mqtt_if_expected_bundle_sha256": "0" * 64},
    {"mqtt_if_expected_model_version": "different-version"},
])
def test_registry_rejects_untrusted_bundle_identity(bundle_dir, change):
    with pytest.raises(StageConfigurationError):
        load_stage_registry(_settings(bundle_dir, **change))


@pytest.mark.parametrize("threshold_offset, expected", [(-1e-6, False), (0, False), (1e-6, True)])
def test_runtime_uses_metadata_strict_lower_threshold_without_predict(
    bundle_dir, monkeypatch, threshold_offset, expected,
):
    initial = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir))
    row = _row()
    score = predict_bundle_feature_window(row, initial.artifact)["raw_decision_score"]
    metadata = initial.artifact.inspection.metadata
    metadata["threshold"] = score + threshold_offset
    _write_contract(bundle_dir, metadata)
    stage = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir))
    monkeypatch.setattr(stage.artifact.model, "predict", lambda *_: pytest.fail("Bundle must use its threshold"))
    actual = predict_bundle_feature_window(row, stage.artifact)
    assert actual["raw_decision_score"] == score
    assert actual["threshold"] == score + threshold_offset
    assert actual["is_anomaly"] is expected
    assert actual["prediction"] == (-1 if expected else 1)
    assert actual["event_type"] == ("AI_ANOMALY" if expected else None)


def test_loaded_snapshot_stays_pinned_when_contract_files_are_replaced(bundle_dir):
    original_settings = _settings(bundle_dir)
    stage = MqttIsolationForestStage.from_settings(app_settings=original_settings)
    before = predict_bundle_feature_window(_row(), stage.artifact)
    metadata = stage.artifact.inspection.metadata
    metadata["threshold"] = -1.0
    _write_contract(bundle_dir, metadata)
    assert predict_bundle_feature_window(_row(), stage.artifact) == before
    with pytest.raises(ValueError):
        MqttIsolationForestStage.from_settings(app_settings=original_settings)
    replacement = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir))
    after = predict_bundle_feature_window(_row(), replacement.artifact)
    assert before["is_anomaly"] is True and after["is_anomaly"] is False
    assert before["threshold"] == 1.0 and after["threshold"] == -1.0
    assert before["bundle_sha256"] != after["bundle_sha256"]


@pytest.mark.parametrize("count", [1, 2])
def test_sqlite_stage_preserves_bundle_evidence_completion_and_event_deduplication(
    session_factory, bundle_dir, count,
):
    stage = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir))
    with session_factory.begin() as db:
        _seed(db, status="ACTIVE")
        feature = _feature(db, count=count)
    with session_factory.begin() as db:
        first = stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T1)
    with session_factory.begin() as db:
        retry = stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T1)
    assert first.created_event_count == 1 and retry.created_event_count == 0
    (completion,) = first.ai_completion_records
    assert (completion.input_count, completion.inference_count, completion.anomaly_count) == (1, 1, 1)
    assert completion.completed_window_end == T1
    assert completion.model_version == stage.artifact.inspection.model_version
    assert completion.bundle_sha256 == _pin(bundle_dir)
    with session_factory() as db:
        event = db.execute(text("SELECT * FROM detection_events")).mappings().one()
        evidence = json.loads(event["evidence_json"])
        assert evidence["model_version"] == completion.model_version
        assert evidence["bundle_sha256"] == completion.bundle_sha256
        assert evidence["thresholds"] == {"anomaly_score": 1.0, "operator": "<"}
        assert evidence["score_method"] == "decision_function"
        assert evidence["score_direction"] == "lower_is_more_anomalous"
        assert evidence["feature_order"] == list(MQTT_IF_FEATURES)
        assert evidence["feature_values"] == feature
        assert evidence["interval_is_fallback"] is (count == 1)
        assert evidence["raw_decision_score"] < 1.0
        assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints "
                               "WHERE detector_name='mqtt_if'")).scalar_one() == "2026-09-30T00:00:10Z"


def test_all_off_skips_feature_inference_but_keeps_completion_and_checkpoint(
    session_factory, bundle_dir, monkeypatch,
):
    stage = MqttIsolationForestStage.from_settings(
        app_settings=_settings(bundle_dir), ai_window_selector=lambda resolution: decide_ai_window(
            resolution, [AIRevision("esp32_01", 1, "OFF", T0)], stage_activation_from=T0))
    monkeypatch.setattr(stage.artifact.model, "decision_function",
                        lambda *_: pytest.fail("OFF must not infer source features"))
    with session_factory.begin() as db:
        _seed(db, status="ACTIVE")
        _feature(db)
    with session_factory.begin() as db:
        result = stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T1)
    (record,) = result.ai_completion_records
    assert result.created_event_count == 0 and result.completed_window_end_after == T1
    assert record.inference_count == 0 and record.exclusion_counts == {"AI_OFF_AT_WINDOW": 1}
    assert record.ai_mode == "OFF" and record.ai_revision == 1


@pytest.mark.parametrize("failure", ["second_inference", "completion_sink"])
def test_partial_batch_failure_rolls_back_events_completion_probe_and_checkpoint(
    session_factory, bundle_dir, monkeypatch, failure,
):
    with session_factory.begin() as db:
        _seed(db, status="ACTIVE")
        _feature(db)
        _feature(db, start=T1)
        db.execute(text("CREATE TABLE mqtt_completion_probe (inferred INTEGER)"))
    sink_calls = []
    def sink(db, records):
        sink_calls.append(records)
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 2
        db.execute(text("INSERT INTO mqtt_completion_probe VALUES (2)"))
        if failure == "completion_sink":
            raise RuntimeError("completion sink failed")
    stage = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir), completion_sink=sink)
    if failure == "second_inference":
        original = stage.artifact.model.decision_function
        calls = []
        def infer(matrix):
            calls.append(matrix.copy())
            if len(calls) == 2:
                assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 1
                raise RuntimeError("second inference failed")
            return original(matrix)
        monkeypatch.setattr(stage.artifact.model, "decision_function", infer)
    error, message = ((ValueError, "could not score") if failure == "second_inference"
                      else (RuntimeError, "completion sink failed"))
    with pytest.raises(error, match=message):
        with session_factory.begin() as db:
            stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T2)
    with session_factory() as db:
        for table in ("detection_events", "mqtt_completion_probe", "detector_checkpoints"):
            assert db.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar_one() == 2
    assert len(sink_calls) == (1 if failure == "completion_sink" else 0)


def test_bundle_anomaly_remains_observation_without_trust_or_firewall_mutation(
    session_factory, bundle_dir,
):
    stage = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir))
    with session_factory.begin() as db:
        _seed(db, status="ACTIVE")
        _feature(db)
    with session_factory.begin() as db:
        stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T1)
        result = apply_trust_score_v2_until(db, cycle_range_start=T0, cycle_cutoff=T1,
                                          ai_mode="observe", decision_at=T2)
    assert result.observed_ai_event_count == 1
    with session_factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 40
        assert db.execute(text("SELECT processing_reason FROM detection_events")).scalar_one() == "AI_OBSERVATION_ONLY"
        for table in ("trust_score_history", "isolation_history", "firewall_rules"):
            assert db.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one() == 0


def test_normal_bundle_window_has_completion_without_anomaly_event(session_factory, bundle_dir):
    metadata = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
    metadata["threshold"] = -1.0
    _write_contract(bundle_dir, metadata)
    stage = MqttIsolationForestStage.from_settings(app_settings=_settings(bundle_dir))
    with session_factory.begin() as db:
        _seed(db, status="ACTIVE")
        _feature(db)
    with session_factory.begin() as db:
        result = stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T1)
    (record,) = result.ai_completion_records
    assert (record.input_count, record.inference_count, record.normal_count, record.anomaly_count) == (1, 1, 1, 0)
    assert record.bundle_sha256 == _pin(bundle_dir) and record.completed_window_end == T1
    assert result.created_event_count == 0 and result.completed_window_end_after == T1
    with session_factory() as db:
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
