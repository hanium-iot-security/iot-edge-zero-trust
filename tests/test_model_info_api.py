"""Public artifact information never loads a model or claims runtime identity."""
import hashlib
import json
from pathlib import Path

import joblib
import pytest
from fastapi.testclient import TestClient

from ai.packet_if_artifact import packet_if_bundle_sha256
from ai.packet_if_contract import (
    PACKET_IF_METADATA_FILENAME, PACKET_IF_MODEL_FILENAME, PACKET_IF_TRAINING_REPORT_FILENAME,
)
from ai import predict_packet_isolation_forest as predictor
from backend.app.config import settings
from backend.app.main import app
from test_predict_packet_isolation_forest import _write_artifact


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    path = tmp_path / "packet-if-test-v1"
    metadata = _write_artifact(path, stored_object={"fixture": "not-an-inference-model"})
    (path / PACKET_IF_MODEL_FILENAME).write_bytes(b"opaque invalid pickle; API must only hash this")
    report = {"threshold": metadata["threshold"], "test_by_label": {"normal": {"anomaly_rate": 0.2},
              "attack": {"anomaly_rate": 0.9}}, "private_report_marker": "DO_NOT_EXPOSE_REPORT"}
    (path / PACKET_IF_TRAINING_REPORT_FILENAME).write_text(json.dumps(report), encoding="utf-8")
    metadata.update(model_sha256=hashlib.sha256((path / PACKET_IF_MODEL_FILENAME).read_bytes()).hexdigest(),
                    training_report_sha256=hashlib.sha256((path / PACKET_IF_TRAINING_REPORT_FILENAME).read_bytes()).hexdigest(),
                    private_metadata_marker="DO_NOT_EXPOSE_METADATA")
    metadata["capture_policy"]["private_capture_marker"] = "DO_NOT_EXPOSE_CAPTURE_POLICY"
    metadata["row_counts"]["private_count_marker"] = "DO_NOT_EXPOSE_ROW_COUNTS"
    (path / PACKET_IF_METADATA_FILENAME).write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(settings, "packet_if_artifact_dir", str(path))
    monkeypatch.setattr(settings, "packet_if_expected_model_version", metadata["model_version"])
    monkeypatch.setattr(settings, "packet_if_expected_bundle_sha256", packet_if_bundle_sha256(path))
    monkeypatch.setattr(joblib, "load", lambda *_a, **_k: pytest.fail("API deserialized model"))
    monkeypatch.setattr(predictor, "load_packet_if_artifact", lambda *_a, **_k: pytest.fail("API used inference loader"))
    return path, metadata, TestClient(app)


def packet(response):
    assert response.status_code == 200, response.text
    return next(item for item in response.json()["models"] if item["detector"] == "packet_if")


def repin(path, monkeypatch):
    monkeypatch.setattr(settings, "packet_if_expected_bundle_sha256", packet_if_bundle_sha256(path))


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def test_public_bundle_metadata_information_does_not_deserialize_or_claim_runtime(artifact):
    path, metadata, client = artifact
    response = client.get("/api/models")
    item = packet(response)
    assert item["artifact_status"] == "BUNDLE_METADATA_VERIFIED"
    assert item["configured_model_version"] == metadata["model_version"]
    assert item["configured_bundle_sha256"] == packet_if_bundle_sha256(path)
    assert item["runtime"]["status"] == "UNKNOWN"
    for name in ("bundle_sha256_verified", "metadata_contract_verified", "report_sha256_verified", "report_json_object_verified"):
        assert item["checks"][name] is True
    for name in ("report_semantics_verified", "model_deserialized", "inference_verified"):
        assert item["checks"][name] is False
    serialized = response.text
    assert "DO_NOT_EXPOSE_REPORT" not in serialized
    assert "DO_NOT_EXPOSE_METADATA" not in serialized
    assert "DO_NOT_EXPOSE_CAPTURE_POLICY" not in serialized
    assert "DO_NOT_EXPOSE_ROW_COUNTS" not in serialized
    assert "anomaly_rate" not in serialized and "test_by_label" not in serialized
    assert '"accuracy"' not in serialized and '"f1"' not in serialized.lower()
    assert not any(str(path) in value for value in strings(response.json()))


def test_model_inspection_leaves_all_bundle_bytes_unchanged(artifact):
    path, _, client = artifact
    before = {item.name: item.read_bytes() for item in path.iterdir() if item.is_file()}
    assert packet(client.get("/api/models"))["artifact_status"] == "BUNDLE_METADATA_VERIFIED"
    assert {item.name: item.read_bytes() for item in path.iterdir() if item.is_file()} == before


def test_permission_denied_wrapped_by_helper_stays_unavailable(artifact, monkeypatch):
    path, _, client = artifact
    selected = path / PACKET_IF_MODEL_FILENAME
    original = Path.open

    def open_file(member, *args, **kwargs):
        if member == selected:
            raise PermissionError("DO_NOT_EXPOSE_OPEN_DETAILS")
        return original(member, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    response = client.get("/api/models")
    item = packet(response)
    assert item["artifact_status"] == "UNAVAILABLE"
    assert item["runtime"]["status"] == "UNKNOWN"
    assert item["error_code"] == "PACKET_IF_ARTIFACT_UNAVAILABLE"
    assert "DO_NOT_EXPOSE_OPEN_DETAILS" not in response.text


def test_valid_v1_metadata_can_omit_normal_policy_version(artifact, monkeypatch):
    path, metadata, client = artifact
    metadata["dataset_version"] = "packet-if-dataset-v1"
    metadata.pop("normal_policy_version")
    (path / PACKET_IF_METADATA_FILENAME).write_text(json.dumps(metadata), encoding="utf-8")
    repin(path, monkeypatch)
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "BUNDLE_METADATA_VERIFIED"
    assert item["checks"]["metadata_contract_verified"] is True
    assert item["runtime"]["status"] == "UNKNOWN"


def test_mqtt_legacy_contract_is_explicitly_unavailable(artifact):
    _, _, client = artifact
    item = next(item for item in client.get("/api/models").json()["models"] if item["detector"] == "mqtt_if")
    assert item["artifact_status"] == "LEGACY_CONTRACT_UNAVAILABLE"
    assert item["runtime"]["status"] == "UNKNOWN"
    assert item["artifact"] is None
    assert item["checks"]["model_deserialized"] is False


@pytest.mark.parametrize("field", ["packet_if_artifact_dir", "packet_if_expected_model_version", "packet_if_expected_bundle_sha256"])
def test_incomplete_configuration_is_unconfigured_without_runtime_claim(artifact, monkeypatch, field):
    _, _, client = artifact
    monkeypatch.setattr(settings, field, "")
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "UNCONFIGURED"
    assert item["runtime"]["status"] == "UNKNOWN"
    assert item["artifact"] is None


def test_wrong_external_bundle_pin_is_invalid(artifact, monkeypatch):
    _, _, client = artifact
    monkeypatch.setattr(settings, "packet_if_expected_bundle_sha256", "0" * 64)
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "INVALID"
    assert item["checks"]["bundle_sha256_verified"] is False
    assert item["runtime"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("filename", [PACKET_IF_MODEL_FILENAME, PACKET_IF_METADATA_FILENAME, PACKET_IF_TRAINING_REPORT_FILENAME])
def test_missing_bundle_member_is_unavailable(artifact, filename):
    path, _, client = artifact
    (path / filename).unlink()
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "UNAVAILABLE"
    assert item["runtime"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("content", [b"\xff", b"{", b"[]", b"null"])
def test_pinned_report_must_be_utf8_json_object(artifact, monkeypatch, content):
    path, metadata, client = artifact
    (path / PACKET_IF_TRAINING_REPORT_FILENAME).write_bytes(content)
    metadata["training_report_sha256"] = hashlib.sha256(content).hexdigest()
    (path / PACKET_IF_METADATA_FILENAME).write_text(json.dumps(metadata), encoding="utf-8")
    repin(path, monkeypatch)
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "INVALID"
    assert item["checks"]["report_json_object_verified"] is False
    assert item["checks"]["report_semantics_verified"] is False


def test_report_internal_hash_is_checked_after_external_bundle_pin(artifact, monkeypatch):
    path, _, client = artifact
    (path / PACKET_IF_TRAINING_REPORT_FILENAME).write_text('{"threshold": 99}', encoding="utf-8")
    repin(path, monkeypatch)
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "INVALID"
    assert item["checks"]["report_sha256_verified"] is False


@pytest.mark.parametrize("mutation", ["feature_order", "threshold", "version", "metadata_json"])
def test_valid_pin_does_not_replace_metadata_contract_validation(artifact, monkeypatch, mutation):
    path, metadata, client = artifact
    if mutation == "metadata_json":
        (path / PACKET_IF_METADATA_FILENAME).write_text("[]", encoding="utf-8")
    else:
        if mutation == "feature_order":
            metadata["feature_order"] = list(reversed(metadata["feature_order"]))
        elif mutation == "threshold":
            metadata["threshold"] = True
        else:
            metadata["model_version"] = "different-version"
        (path / PACKET_IF_METADATA_FILENAME).write_text(json.dumps(metadata), encoding="utf-8")
    repin(path, monkeypatch)
    item = packet(client.get("/api/models"))
    assert item["artifact_status"] == "INVALID"
    assert item["checks"]["metadata_contract_verified"] is False
    assert item["runtime"]["status"] == "UNKNOWN"


def test_report_scores_are_not_semantically_verified_or_exposed(artifact, monkeypatch):
    path, metadata, client = artifact
    content = json.dumps({"threshold": "semantically invalid but JSON object", "accuracy": 900,
                          "test_by_label": {"normal": {"anomaly_rate": -1}}}).encode()
    (path / PACKET_IF_TRAINING_REPORT_FILENAME).write_bytes(content)
    metadata["training_report_sha256"] = hashlib.sha256(content).hexdigest()
    (path / PACKET_IF_METADATA_FILENAME).write_text(json.dumps(metadata), encoding="utf-8")
    repin(path, monkeypatch)
    response = client.get("/api/models")
    item = packet(response)
    assert item["artifact_status"] == "BUNDLE_METADATA_VERIFIED"
    assert item["checks"]["report_semantics_verified"] is False
    assert "accuracy" not in response.text and "anomaly_rate" not in response.text
