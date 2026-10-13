from __future__ import annotations

import csv
import hashlib
import json

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from ai import train_mqtt_isolation_forest as trainer
from ai.mqtt_if_artifact import (
    MQTT_IF_BUNDLE_FILENAMES, inspect_mqtt_if_bundle,
    load_inspected_mqtt_if_artifact, score_mqtt_feature_rows,
)
from ai.mqtt_if_contract import MQTT_IF_FEATURES, mqtt_feature_matrix
from ai.mqtt_if_dataset import load_mqtt_if_dataset
from tests.test_mqtt_if_dataset import _write_dataset


def _inputs(tmp_path):
    directory = tmp_path / "inputs"
    directory.mkdir()
    manifest = _write_dataset(directory)
    for role in trainer.ROLES:
        _set_payloads(manifest, role)
    return manifest


def _set_payloads(manifest, role, *, far=False):
    data = json.loads(manifest.read_text(encoding="utf-8"))
    group = next(group for group in data["groups"] if group["role"] == role)
    reference = group["runs"][0]["mqtt_features"]
    path = manifest.parent / reference["path"]
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        rows = list(reader)
    for index, row in enumerate(rows):
        payload = (10_000 if far else 20) + index * 5
        row["avg_payload_size"] = str(payload)
        row["max_payload_size"] = str(payload)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    reference["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(data), encoding="utf-8")


def _train(manifest, output, **kwargs):
    return trainer.train_from_files(
        manifest, artifact_dir=output, model_version=output.name,
        threshold_percentile=kwargs.pop("threshold_percentile", 25),
        n_estimators=32, **kwargs,
    )


def _read_report(artifacts):
    return json.loads(artifacts.training_report_path.read_text(encoding="utf-8"))


def _tree_bytes(path):
    return {str(file.relative_to(path)): file.read_bytes()
            for file in path.rglob("*") if file.is_file()}


def test_fits_train_only_and_reloads_the_existing_bundle_contract(tmp_path, monkeypatch):
    manifest = _inputs(tmp_path)
    dataset = load_mqtt_if_dataset(manifest)
    before = _tree_bytes(manifest.parent)
    fit_inputs = []
    original_fit = IsolationForest.fit

    def capture_fit(self, matrix, *args, **kwargs):
        fit_inputs.append(matrix.copy())
        assert self.contamination == "auto"
        assert self.random_state == 42
        assert self.n_jobs == 1
        return original_fit(self, matrix, *args, **kwargs)

    monkeypatch.setattr(IsolationForest, "fit", capture_fit)
    artifacts = _train(manifest, tmp_path / "models" / "candidate-v1")
    assert len(fit_inputs) == 1
    np.testing.assert_array_equal(fit_inputs[0], mqtt_feature_matrix(dataset.rows["train"]))
    assert _tree_bytes(manifest.parent) == before
    assert {path.name for path in artifacts.artifact_dir.iterdir()} == set(MQTT_IF_BUNDLE_FILENAMES)
    inspection = inspect_mqtt_if_bundle(
        artifacts.artifact_dir, expected_bundle_sha256=artifacts.bundle_sha256,
        expected_model_version="candidate-v1",
    )
    loaded = load_inspected_mqtt_if_artifact(inspection)
    calibration_scores = loaded.model.decision_function(mqtt_feature_matrix(dataset.rows["calibration"]))
    assert artifacts.threshold == float(np.percentile(calibration_scores, 25, method="linear"))
    metadata, report = inspection.metadata, inspection.report
    assert metadata["feature_order"] == list(MQTT_IF_FEATURES)
    assert metadata["transform_version"] == "mqtt-identity-v1"
    assert metadata["library_versions"]["scipy"]
    for value in (metadata, report):
        assert value["scope"] == "offline_candidate_only"
        assert value["training_approved"] is False
        assert value["operational_activation_verified"] is False
        assert value["threshold_is_acceptance_criterion"] is False
        assert value["threshold_source"] == "normal_calibration"
        assert value["threshold_percentile"] == 25
        assert value["source_code"]["git_commit_sha"]
        assert type(value["source_code"]["dirty"]) is bool
        assert value["dataset_provenance"] == dataset.provenance
    predictions = score_mqtt_feature_rows(loaded, dataset.rows["validation"])
    expected = loaded.model.decision_function(mqtt_feature_matrix(dataset.rows["validation"]))
    np.testing.assert_array_equal([prediction.raw_decision_score for prediction in predictions], expected)
    assert [prediction.is_anomaly for prediction in predictions] == list(expected < artifacts.threshold)
    alarms = sum(prediction.is_anomaly for prediction in predictions)
    assert report["splits"]["validation"]["alarm_count"] == alarms
    assert report["splits"]["validation"]["normal_alarm_rate"] == alarms / len(predictions)
    assert set(report["validation_by_device"]) == {row["device_id"] for row in dataset.rows["validation"]}
    assert set(report["validation_by_group"]) == {row["source_capture_group_id"] for row in dataset.rows["validation"]}
    for name in ("validation_by_device", "validation_by_group"):
        assert sum(item["row_count"] for item in report[name].values()) == len(predictions)
        assert sum(item["alarm_count"] for item in report[name].values()) == alarms


@pytest.mark.parametrize("changed_role", ["validation", "calibration"])
def test_held_out_roles_do_not_change_fitted_model(tmp_path, changed_role):
    manifest = _inputs(tmp_path)
    first = _train(manifest, tmp_path / "models" / "candidate-v1")
    _set_payloads(manifest, changed_role, far=True)
    second = _train(manifest, tmp_path / "models" / "candidate-v2")
    assert first.model_sha256 == second.model_sha256
    assert first.model_path.read_bytes() == second.model_path.read_bytes()
    if changed_role == "validation":
        assert first.threshold == second.threshold
        assert _read_report(first)["splits"]["validation"] != _read_report(second)["splits"]["validation"]
    else:
        assert first.threshold != second.threshold
        assert _read_report(first)["splits"]["calibration"] != _read_report(second)["splits"]["calibration"]


def test_equal_to_threshold_is_not_an_alarm():
    rows = [{"publish_count": 1}, {"publish_count": 2}, {"publish_count": 2}]
    summary = trainer._score_summary(np.array([-0.1, 0.0, 0.1]), 0.0, rows)
    assert summary["alarm_count"] == 1
    assert summary["normal_alarm_rate"] == 1 / 3
    assert summary["single_message_fallback_count"] == 1


@pytest.mark.parametrize("percentile", [0, 100, float("nan"), True])
def test_invalid_percentile_rejected_before_loading_inputs(tmp_path, percentile):
    with pytest.raises(ValueError, match="threshold_percentile"):
        _train(tmp_path / "missing.json", tmp_path / "models" / "candidate-v1", threshold_percentile=percentile)
    assert not (tmp_path / "models").exists()


def test_cli_requires_explicit_threshold_percentile(tmp_path):
    with pytest.raises(SystemExit) as error:
        trainer.main(["--manifest", str(tmp_path / "missing.json"),
                      "--artifact-dir", str(tmp_path / "candidate-v1"),
                      "--model-version", "candidate-v1"])
    assert error.value.code == 2


def test_existing_output_and_input_tree_cannot_be_changed(tmp_path):
    manifest = _inputs(tmp_path)
    before = _tree_bytes(manifest.parent)
    # Resolve a lexical parent traversal before checking the input boundary.
    with pytest.raises(ValueError, match="outside the dataset input directory"):
        _train(manifest, manifest.parent / "unused" / ".." / "candidate-v1")
    output = tmp_path / "models" / "candidate-v1"
    output.mkdir(parents=True)
    (output / "keep.txt").write_bytes(b"existing artifact")
    with pytest.raises(FileExistsError, match="already exists"):
        _train(manifest, output)
    assert _tree_bytes(output) == {"keep.txt": b"existing artifact"}
    assert _tree_bytes(manifest.parent) == before


@pytest.mark.parametrize("failure_stage", ["metadata_write", "bundle_inspection"])
def test_failed_build_leaves_no_partial_output_or_changed_inputs(tmp_path, monkeypatch, failure_stage):
    manifest = _inputs(tmp_path)
    before = _tree_bytes(manifest.parent)
    output = tmp_path / "models" / "candidate-v1"
    if failure_stage == "metadata_write":
        original_write = trainer._write_json

        def fail_metadata(path, value):
            if path.name == "metadata.json":
                raise OSError("injected metadata write failure")
            return original_write(path, value)

        monkeypatch.setattr(trainer, "_write_json", fail_metadata)
    else:
        def fail_inspection(*args, **kwargs):
            raise OSError("injected inspection failure")

        monkeypatch.setattr(trainer, "inspect_mqtt_if_bundle", fail_inspection)
    with pytest.raises(OSError, match="injected"):
        _train(manifest, output)
    assert not output.exists()
    assert list(output.parent.iterdir()) == []
    assert _tree_bytes(manifest.parent) == before
