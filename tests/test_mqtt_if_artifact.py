from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
import hashlib
from importlib.metadata import version
import io
import json
import os
from pathlib import Path
import platform

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from ai import mqtt_if_artifact as bundle
from ai.mqtt_if_contract import (
    MQTT_IF_FEATURES,
    MQTT_IF_FEATURE_VERSION,
    MQTT_IF_NOMINAL_WINDOW_SECONDS,
    MQTT_IF_SCORE_DIRECTION,
    MQTT_IF_THRESHOLD_OPERATOR,
    MQTT_IF_TRANSFORM_VERSION,
    mqtt_feature_matrix,
    mqtt_feature_vector,
    mqtt_interval_semantics,
)
from edge.detection.rule_detector import ISOLATION_FOREST_FEATURES


def _row(index: int = 0, *, count: int = 2) -> dict:
    return dict(zip(MQTT_IF_FEATURES, (count, 128.0 + index, 132 + index, 5.0, 5.0), strict=True))


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _report(metadata: dict) -> dict:
    return {
        key: metadata[key] for key in (
            "model_version", "feature_order", "score_method", "score_direction",
            "threshold_operator", "threshold", "threshold_source", "interval_semantics",
        )
    } | {"diagnostic_note": "synthetic fixture only; no evaluation or data approval"}


def _write_contract(directory: Path, metadata: dict, *, update_report: bool = True) -> None:
    if update_report:
        _write_json(directory / bundle.MQTT_IF_REPORT_FILENAME, _report(metadata))
    metadata["training_report_sha256"] = hashlib.sha256(
        (directory / bundle.MQTT_IF_REPORT_FILENAME).read_bytes()
    ).hexdigest()
    _write_json(directory / bundle.MQTT_IF_METADATA_FILENAME, metadata)


def _fixture(directory: Path, *, stored_object=None, feature_count: int = 5) -> dict:
    directory.mkdir()
    if stored_object is None:
        # Deliberately synthetic, varied rows: no existing MQTT candidate data.
        matrix = mqtt_feature_matrix([_row(index, count=1 + index % 3) for index in range(24)])
        stored_object = IsolationForest(n_estimators=8, random_state=42, n_jobs=1).fit(matrix[:, :feature_count])
    buffer = io.BytesIO()
    joblib.dump(stored_object, buffer)
    model_bytes = buffer.getvalue()
    (directory / bundle.MQTT_IF_MODEL_FILENAME).write_bytes(model_bytes)
    metadata = {
        "artifact_schema_version": bundle.MQTT_IF_ARTIFACT_SCHEMA_VERSION,
        "model_type": "IsolationForest",
        "model_version": "mqtt-if-synthetic-test-v1",
        "model_filename": bundle.MQTT_IF_MODEL_FILENAME,
        "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
        "training_report_filename": bundle.MQTT_IF_REPORT_FILENAME,
        "feature_version": MQTT_IF_FEATURE_VERSION,
        "feature_order": list(MQTT_IF_FEATURES),
        "transform_version": MQTT_IF_TRANSFORM_VERSION,
        "nominal_window_seconds": MQTT_IF_NOMINAL_WINDOW_SECONDS,
        "score_method": "decision_function",
        "score_direction": MQTT_IF_SCORE_DIRECTION,
        "threshold_operator": MQTT_IF_THRESHOLD_OPERATOR,
        "threshold": 0.0,
        "threshold_source": "synthetic_fixture_only",
        "interval_semantics": mqtt_interval_semantics(),
        "library_versions": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
            "scipy": version("scipy"),
            "scikit_learn": version("scikit-learn"),
            "joblib": version("joblib"),
        },
    }
    _write_contract(directory, metadata)
    return metadata


def _pin(directory: Path) -> str:
    # Test fixture author computes this independently of inspect/load. A real
    # caller must obtain the pin through a trusted channel, not this operation.
    return bundle.mqtt_if_bundle_sha256_bytes({
        name: (directory / name).read_bytes() for name in bundle.MQTT_IF_BUNDLE_FILENAMES
    })


def _inspect(directory: Path):
    return bundle.inspect_mqtt_if_bundle(
        directory, expected_bundle_sha256=_pin(directory),
        expected_model_version="mqtt-if-synthetic-test-v1",
    )


def _never_unpickle(*args, **kwargs):
    pytest.fail("model must not be deserialized before inspection succeeds")


def test_order_identity_and_payload_above_100_bytes() -> None:
    assert MQTT_IF_FEATURES == ISOLATION_FOREST_FEATURES
    row = _row()
    row["unused_device_id"] = "synthetic-device"
    assert mqtt_feature_vector(row) == (2.0, 128.0, 132.0, 5.0, 5.0)
    assert mqtt_feature_matrix([]).shape == (0, 5)
    assert mqtt_feature_vector(_row(count=1))[-2:] == (5.0, 5.0)


def test_existing_builder_one_and_two_message_interval_semantics() -> None:
    from edge.features.collect_feature_logs import build_feature_row

    start = datetime(2026, 1, 1)
    raw = {"payload_size": 132, "topic": "synthetic/topic", "is_topic_valid": 1,
           "is_json_valid": 1, "received_at": start.isoformat()}
    one = build_feature_row("synthetic-device", start, start + timedelta(seconds=10), [raw])
    assert mqtt_feature_vector(one) == (1.0, 132.0, 132.0, 5.0, 5.0)
    for second_time, expected_interval in ((start, 0.0), (start + timedelta(seconds=4), 4.0)):
        two = build_feature_row("synthetic-device", start, start + timedelta(seconds=10),
                                [raw, raw | {"received_at": second_time.isoformat()}])
        assert mqtt_feature_vector(two)[-2:] == (expected_interval, expected_interval)


@pytest.mark.parametrize("field", ["avg_message_interval", "min_message_interval"])
def test_one_message_cannot_claim_measured_nonfallback_interval(field) -> None:
    row = _row(count=1)
    row[field] = 2.0
    with pytest.raises(ValueError, match="5.0-second fallback"):
        mqtt_feature_vector(row)


@pytest.mark.parametrize("name", MQTT_IF_FEATURES)
@pytest.mark.parametrize("value", [None, "2", True, np.bool_(False), float("nan"), float("inf"), -1])
def test_invalid_numeric_inputs(name, value) -> None:
    row = _row()
    row[name] = value
    with pytest.raises(ValueError, match=name):
        mqtt_feature_vector(row)


@pytest.mark.parametrize("name", MQTT_IF_FEATURES)
def test_missing_inputs(name) -> None:
    row = _row()
    del row[name]
    with pytest.raises(ValueError, match="missing"):
        mqtt_feature_vector(row)


@pytest.mark.parametrize("name", ["publish_count", "max_payload_size"])
@pytest.mark.parametrize("value", [2.0, 2.5])
def test_integer_fields_do_not_coerce_csv_floats(name, value) -> None:
    row = _row()
    row[name] = value
    with pytest.raises(ValueError, match="integer"):
        mqtt_feature_vector(row)


def test_numpy_numbers_zero_and_finite_float32_limit() -> None:
    row = dict(zip(MQTT_IF_FEATURES, (np.int64(0), np.float64(0), np.int64(0), 0, 0), strict=True))
    assert mqtt_feature_vector(row) == (0, 0, 0, 0, 0)
    row["avg_payload_size"] = 1e100
    with pytest.raises(ValueError, match="float32"):
        mqtt_feature_matrix([row])
    row["publish_count"] = 10 ** 400
    with pytest.raises(ValueError, match="finite"):
        mqtt_feature_vector(row)
    with pytest.raises(ValueError, match="mapping"):
        mqtt_feature_vector([1, 2, 3, 4, 5])


def test_valid_inspection_does_not_unpickle_and_claims_are_limited(tmp_path, monkeypatch) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    inspection = _inspect(directory)
    summary = inspection.summary()
    assert summary["model_deserialized"] is False
    assert summary["data_eligibility_verified"] is False
    assert summary["report_claims_verified"] is False
    assert summary["operational_activation_verified"] is False
    assert summary["threshold_operator"] == "<"
    metadata = inspection.metadata
    metadata["threshold"] = 99
    assert inspection.metadata["threshold"] == 0


def test_same_bytes_snapshot_used_even_if_all_files_replaced(tmp_path, monkeypatch) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    reads = Counter()
    original_read = bundle._read_regular_file

    def counted(path, **kwargs):
        reads[path.name] += 1
        return original_read(path, **kwargs)

    monkeypatch.setattr(bundle, "_read_regular_file", counted)
    inspection = _inspect(directory)
    for name in bundle.MQTT_IF_BUNDLE_FILENAMES:
        (directory / name).write_bytes(b"changed after inspection")
    artifact = bundle.load_inspected_mqtt_if_artifact(inspection)
    predictions = bundle.score_mqtt_feature_rows(artifact, [_row(1, count=1), _row(2)])
    assert reads == Counter({name: 1 for name in bundle.MQTT_IF_BUNDLE_FILENAMES})
    assert predictions[0].interval_is_fallback is True
    assert predictions[1].interval_is_fallback is False
    assert predictions[0].anomaly_score == predictions[0].raw_decision_score
    assert predictions[1].feature_values == mqtt_feature_vector(_row(2))
    assert bundle.score_mqtt_feature_rows(artifact, []) == ()
    with pytest.raises(ValueError, match="SHA256"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=inspection.bundle_sha256)


def test_strict_less_than_threshold_matches_mqtt_score(tmp_path) -> None:
    directory = tmp_path / "bundle"
    metadata = _fixture(directory)
    first = bundle.load_inspected_mqtt_if_artifact(_inspect(directory))
    score = first.model.decision_function(mqtt_feature_matrix([_row(3)]))[0]
    for threshold, expected in ((score, False), (np.nextafter(score, np.inf), True), (np.nextafter(score, -np.inf), False)):
        metadata["threshold"] = float(threshold)
        _write_contract(directory, metadata)
        artifact = bundle.load_inspected_mqtt_if_artifact(_inspect(directory))
        prediction = bundle.score_mqtt_feature_rows(artifact, [_row(3)])[0]
        assert prediction.raw_decision_score == score
        assert prediction.anomaly_score == score
        assert prediction.is_anomaly is expected


@pytest.mark.parametrize("key,value", [
    ("artifact_schema_version", True), ("model_type", "PacketIsolationForest"),
    ("model_filename", "../model.joblib"), ("training_report_filename", "other.json"),
    ("feature_order", list(reversed(MQTT_IF_FEATURES))), ("feature_version", "new"),
    ("transform_version", "scaled"), ("nominal_window_seconds", 9),
    ("nominal_window_seconds", True), ("score_method", "predict"),
    ("score_direction", "higher_is_more_anomalous"), ("threshold_operator", "<="),
    ("threshold", True), ("threshold", float("nan")), ("threshold", float("inf")),
    ("threshold_source", ""), ("interval_semantics", {"single_message_fallback_seconds": 5}),
    ("model_sha256", "a" * 64), ("model_sha256", "A" * 64),
])
def test_contract_mismatch_rejected_before_unpickle(tmp_path, monkeypatch, key, value) -> None:
    directory = tmp_path / "bundle"
    metadata = _fixture(directory)
    metadata[key] = value
    _write_contract(directory, metadata)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    with pytest.raises(ValueError):
        _inspect(directory)


@pytest.mark.parametrize("key", ["python", "numpy", "scipy", "scikit_learn", "joblib"])
def test_library_mismatch_rejected_before_unpickle(tmp_path, monkeypatch, key) -> None:
    directory = tmp_path / "bundle"
    metadata = _fixture(directory)
    metadata["library_versions"][key] = "0.0.0"
    _write_contract(directory, metadata)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    with pytest.raises(ValueError, match="version mismatch"):
        _inspect(directory)


@pytest.mark.parametrize("pin", [None, "", "A" * 64, "a" * 64])
def test_external_pin_is_required_before_unpickle(tmp_path, monkeypatch, pin) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    with pytest.raises(ValueError, match="SHA256"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin)


@pytest.mark.parametrize("filename", bundle.MQTT_IF_BUNDLE_FILENAMES)
def test_each_file_tamper_rejected_before_unpickle(tmp_path, monkeypatch, filename) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    original_pin = _pin(directory)
    path = directory / filename
    path.write_bytes(path.read_bytes() + b" ")
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    with pytest.raises(ValueError, match="Bundle SHA256 mismatch"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=original_pin)


def test_report_hash_and_stale_report_rejected_before_unpickle(tmp_path, monkeypatch) -> None:
    directory = tmp_path / "bundle"
    metadata = _fixture(directory)
    metadata["threshold"] = 0.2
    _write_contract(directory, metadata, update_report=False)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    with pytest.raises(ValueError, match="report contract mismatch"):
        _inspect(directory)
    metadata["training_report_sha256"] = "a" * 64
    _write_json(directory / bundle.MQTT_IF_METADATA_FILENAME, metadata)
    with pytest.raises(ValueError, match="training_report_sha256 mismatch"):
        _inspect(directory)


@pytest.mark.parametrize("filename", [bundle.MQTT_IF_METADATA_FILENAME, bundle.MQTT_IF_REPORT_FILENAME])
@pytest.mark.parametrize("content", [b"[]", b"not json", b'{"threshold":0,"threshold":1}', b'{"unused":NaN}', b"\xff"])
def test_bad_json_rejected_without_unpickle(tmp_path, monkeypatch, filename, content) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    (directory / filename).write_bytes(content)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    with pytest.raises(ValueError):
        _inspect(directory)


def test_version_mismatch_and_missing_or_nonregular_file(tmp_path) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    with pytest.raises(ValueError, match="model version mismatch"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=_pin(directory), expected_model_version="other")
    path = directory / bundle.MQTT_IF_MODEL_FILENAME
    pin = _pin(directory)
    path.unlink()
    with pytest.raises(FileNotFoundError):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin)
    path.mkdir()
    with pytest.raises(ValueError, match="regular non-symlink"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin)


def test_symlink_member_rejected(tmp_path) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    pin = _pin(directory)
    path = directory / bundle.MQTT_IF_MODEL_FILENAME
    saved = tmp_path / "saved-model.joblib"
    path.rename(saved)
    try:
        path.symlink_to(saved)
    except OSError as exc:
        pytest.skip(f"host does not permit symlink creation: {exc.errno}")
    with pytest.raises(ValueError, match="regular non-symlink"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin)


def test_member_replacement_while_opening_rejected(tmp_path, monkeypatch) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    pin = _pin(directory)
    model_path = directory / bundle.MQTT_IF_MODEL_FILENAME
    replacement = tmp_path / "replacement-model"
    replacement.write_bytes(model_path.read_bytes())
    original_open = os.open

    def raced_open(path, flags, *args, **kwargs):
        if Path(path) == model_path:
            os.replace(replacement, model_path)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(bundle.os, "open", raced_open)
    with pytest.raises(ValueError, match="changed while opening"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin)


def test_serialized_sklearn_version_mismatch_rejected(tmp_path, monkeypatch) -> None:
    directory = tmp_path / "bundle"
    original_getstate = IsolationForest.__getstate__
    with monkeypatch.context() as context:
        context.setattr(IsolationForest, "__getstate__", lambda self: original_getstate(self) | {"_sklearn_version": "0.0.0"})
        _fixture(directory)
    # Metadata claims this runtime; the serialized sklearn version disagrees.
    inspection = _inspect(directory)
    with pytest.raises(ValueError, match="deserialize"):
        bundle.load_inspected_mqtt_if_artifact(inspection)


def test_report_fallback_marker_must_be_boolean_false(tmp_path) -> None:
    directory = tmp_path / "bundle"
    metadata = _fixture(directory)
    report = _report(metadata)
    report["interval_semantics"] = dict(report["interval_semantics"])
    report["interval_semantics"]["single_message_is_observed_interval"] = 0
    _write_json(directory / bundle.MQTT_IF_REPORT_FILENAME, report)
    _write_contract(directory, metadata, update_report=False)
    with pytest.raises(ValueError, match="marked fallback"):
        _inspect(directory)


@pytest.mark.parametrize("stored_object", [{"not": "a model"}, IsolationForest()])
def test_model_type_and_fitted_state_checked(tmp_path, stored_object) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory, stored_object=stored_object)
    with pytest.raises(ValueError, match="IsolationForest|fitted"):
        bundle.load_inspected_mqtt_if_artifact(_inspect(directory))


def test_wrong_feature_count_checked(tmp_path) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory, feature_count=4)
    with pytest.raises(ValueError, match="five features"):
        bundle.load_inspected_mqtt_if_artifact(_inspect(directory))


def test_fitted_feature_name_order_checked(tmp_path) -> None:
    directory = tmp_path / "bundle"
    model = IsolationForest(n_estimators=3, random_state=42).fit(mqtt_feature_matrix([_row(i) for i in range(12)]))
    model.feature_names_in_ = np.asarray(list(reversed(MQTT_IF_FEATURES)))
    _fixture(directory, stored_object=model)
    with pytest.raises(ValueError, match="fitted model feature order"):
        bundle.load_inspected_mqtt_if_artifact(_inspect(directory))


@pytest.mark.parametrize("scores", [np.array([np.nan]), np.array([np.inf]), np.array([[0.0]])])
def test_invalid_inference_scores_fail_closed(tmp_path, monkeypatch, scores) -> None:
    directory = tmp_path / "bundle"
    _fixture(directory)
    artifact = bundle.load_inspected_mqtt_if_artifact(_inspect(directory))
    monkeypatch.setattr(artifact.model, "decision_function", lambda matrix: scores)
    with pytest.raises(ValueError, match="invalid decision scores"):
        bundle.score_mqtt_feature_rows(artifact, [_row()])


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_inspection_size_limit_rejected_before_read(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(bundle, "_read_regular_file", lambda *args, **kwargs: pytest.fail("unexpected read"))
    with pytest.raises(ValueError, match="positive integer"):
        bundle.inspect_mqtt_if_bundle(tmp_path, expected_bundle_sha256="a" * 64, maximum_file_bytes=limit)


def test_inspection_size_limit_allows_exact_boundary_and_rejects_oversize(tmp_path, monkeypatch):
    directory = tmp_path / "bundle"
    _fixture(directory, stored_object={"opaque": "no model deserialization"})
    pin = _pin(directory)
    largest = max((directory / name).stat().st_size for name in bundle.MQTT_IF_BUNDLE_FILENAMES)
    monkeypatch.setattr(bundle.joblib, "load", _never_unpickle)
    assert bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin,
                                        maximum_file_bytes=largest).bundle_sha256 == pin
    with pytest.raises(ValueError, match="size limit"):
        bundle.inspect_mqtt_if_bundle(directory, expected_bundle_sha256=pin, maximum_file_bytes=largest - 1)


def test_size_limit_bounds_actual_read_when_file_grows_after_stat(tmp_path, monkeypatch):
    path = tmp_path / "growing-model"
    path.write_bytes(b"small")
    original_fdopen = bundle.os.fdopen
    reads = []

    class GrowingStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, size=-1):
            reads.append(size)
            with path.open("ab") as writer:
                writer.write(b"larger than the read limit")
            return self.stream.read(size)

    monkeypatch.setattr(bundle.os, "fdopen", lambda *args: GrowingStream(original_fdopen(*args)))
    with pytest.raises(ValueError, match="size limit"):
        bundle._read_regular_file(path, maximum_file_bytes=8)
    assert reads == [9]
