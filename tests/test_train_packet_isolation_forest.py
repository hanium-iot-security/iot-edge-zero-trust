from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from ai.packet_if_contract import PACKET_IF_FEATURES, packet_feature_matrix
from ai.packet_if_dataset import (
    PACKET_IF_DATASET_VERSION,
    file_sha256,
    load_packet_if_dataset,
    session_data_sha256s,
)
from ai.predict_packet_isolation_forest import (
    load_packet_if_artifact,
    predict_packet_feature_row,
)
from ai import train_packet_isolation_forest as trainer
from ai.train_packet_isolation_forest import (
    anomaly_scores,
    train_from_files,
    train_packet_isolation_forest,
)
from edge.packet.capture_policy import CapturePolicy


GIT_COMMIT_SHA = "a" * 40
SESSION_SPECS = (
    (
        "11111111-1111-4111-8111-111111111111",
        "train",
        "normal",
        "normal_stable",
        30,
        None,
    ),
    (
        "22222222-2222-4222-8222-222222222222",
        "validation",
        "normal",
        "normal_jitter",
        20,
        None,
    ),
    (
        "33333333-3333-4333-8333-333333333333",
        "test",
        "normal",
        "normal_test",
        20,
        None,
    ),
    (
        "44444444-4444-4444-8444-444444444444",
        "test",
        "attack",
        "packet_flood",
        20,
        "esp32_01",
    ),
)


def _write_training_bundle(
    tmp_path: Path,
    *,
    attack_multiplier: float = 1.0,
) -> tuple[Path, Path]:
    rows: list[dict[str, object]] = []
    sessions: list[dict[str, object]] = []
    feature_id = 1
    base_time = datetime(2026, 7, 23, tzinfo=timezone.utc)

    for session_index, (
        session_id,
        split,
        traffic_label,
        scenario,
        row_count,
        target_device_id,
    ) in enumerate(SESSION_SPECS):
        session_entry: dict[str, object] = {
            "session_id": session_id,
            "split": split,
            "traffic_label": traffic_label,
            "scenario": scenario,
            "status": "COMPLETED",
            "capture_interface": "eth0",
            "capture_filter": "tcp or udp",
            "source_commit_sha": GIT_COMMIT_SHA,
            "capture_gap_start": None,
            "capture_gap_end": None,
            "devices": [
                {
                    "device_id": "esp32_01",
                    "peer_ip": "10.0.0.1",
                }
            ],
        }
        if target_device_id is not None:
            session_entry["target_device_id"] = target_device_id
        sessions.append(session_entry)
        session_start = base_time + timedelta(hours=session_index)
        session_entry["started_at"] = _format_utc(session_start)
        session_entry["first_window_start"] = _format_utc(session_start)
        session_entry["ended_at"] = _format_utc(
            session_start + timedelta(seconds=row_count * 10)
        )
        for row_index in range(row_count):
            is_attack = traffic_label == "attack"
            attack_scale = attack_multiplier if is_attack else 1.0
            packet_count = (
                int((250 + row_index * 3) * attack_scale)
                if is_attack
                else 20 + row_index % 5
            )
            total_bytes = (
                int((50_000 + row_index * 500) * attack_scale)
                if is_attack
                else 2_000 + row_index * 20
            )
            window_start = session_start + timedelta(seconds=row_index * 10)
            rows.append(
                {
                    "packet_feature_log_id": feature_id,
                    "session_id": session_id,
                    "device_id": "esp32_01",
                    "direction": "INBOUND",
                    "window_start": _format_utc(window_start),
                    "window_end": _format_utc(window_start + timedelta(seconds=10)),
                    "peer_ip": "10.0.0.1",
                    "segment_window_start": _format_utc(window_start),
                    "segment_window_end": _format_utc(
                        window_start + timedelta(seconds=10)
                    ),
                    "segment_status": "PROCESSED",
                    "segment_error_code": None,
                    "start_delay_seconds": 0.2,
                    "registered_device_id": "esp32_01",
                    "registered_ip_address": "10.0.0.1",
                    "packet_count": packet_count,
                    "total_bytes": total_bytes,
                    "avg_packet_size": 100.0 + row_index % 3,
                    "max_packet_size": 140 + row_index % 5,
                    "mean_inter_arrival_time": (
                        0.01 + row_index * 0.0001
                        if is_attack
                        else 0.3 + row_index * 0.002
                    ),
                    "distinct_dest_port_count": 1,
                    "captured_duration_seconds": 9.0 if row_index % 2 else 10.0,
                }
            )
            feature_id += 1

    dataset_path = tmp_path / "packet_if_dataset.csv"
    pd.DataFrame(rows).to_csv(dataset_path, index=False)
    session_hashes = session_data_sha256s(dataset_path)
    for session in sessions:
        session["data_sha256"] = session_hashes[str(session["session_id"])]
    manifest_path = tmp_path / "packet_if_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_version": PACKET_IF_DATASET_VERSION,
                "capture_policy_version": "packet-capture-policy-v1",
                "capture_policy": {
                    "version": "packet-capture-policy-v1",
                    "nominal_window_seconds": 10.0,
                    "max_start_delay_seconds": 1.0,
                    "minimum_duration_seconds": 9.0,
                    "epsilon_seconds": 0.01,
                    "minimum_coverage_ratio": 0.9,
                },
                "dataset_sha256": file_sha256(dataset_path),
                "sessions": sessions,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return dataset_path, manifest_path


def test_train_writes_reproducible_artifact_contract(tmp_path: Path) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    artifact_dir = tmp_path / "packet-if-v1"

    artifacts = train_from_files(
        dataset_path=dataset_path,
        manifest_path=manifest_path,
        artifact_dir=artifact_dir,
        git_commit_sha=GIT_COMMIT_SHA,
    )

    assert artifacts.model_path.exists()
    assert artifacts.metadata_path.exists()
    assert artifacts.training_report_path.exists()
    assert artifacts.model_sha256 == file_sha256(artifacts.model_path)
    assert artifacts.metadata_sha256 == file_sha256(artifacts.metadata_path)
    assert artifacts.training_report_sha256 == file_sha256(
        artifacts.training_report_path
    )
    assert len(artifacts.bundle_sha256) == 64

    metadata = json.loads(artifacts.metadata_path.read_text(encoding="utf-8"))
    assert metadata["feature_order"] == list(PACKET_IF_FEATURES)
    assert metadata["threshold_operator"] == ">"
    assert metadata["threshold_source"] == "normal_validation"
    assert metadata["threshold_percentile"] == 99.0
    assert metadata["scaler_type"] is None
    assert metadata["dataset_sha256"] == file_sha256(dataset_path)
    assert metadata["manifest_sha256"] == file_sha256(manifest_path)
    assert metadata["model_sha256"] == file_sha256(artifacts.model_path)
    assert metadata["training_report_filename"] == "training_report.json"
    assert metadata["training_report_sha256"] == file_sha256(
        artifacts.training_report_path
    )
    assert metadata["git_commit_sha"] == GIT_COMMIT_SHA
    assert metadata["capture_policy"] == {
        "version": "packet-capture-policy-v1",
        "nominal_window_seconds": 10.0,
        "max_start_delay_seconds": 1.0,
        "minimum_duration_seconds": 9.0,
        "epsilon_seconds": 0.01,
        "minimum_coverage_ratio": 0.9,
    }
    assert metadata["normalization"] == {
        "version": "packet-10s-normalization-v1",
        "nominal_window_seconds": 10.0,
        "packet_count_formula": (
            "packet_count * nominal_window_seconds "
            "/ captured_duration_seconds"
        ),
        "total_bytes_formula": (
            "total_bytes * nominal_window_seconds "
            "/ captured_duration_seconds"
        ),
    }
    assert metadata["row_counts"] == {
        "train": 30,
        "validation": 20,
        "test": 40,
    }

    report = json.loads(
        artifacts.training_report_path.read_text(encoding="utf-8")
    )
    assert report["test_by_label"]["normal"]["row_count"] == 20
    assert report["test_by_label"]["attack"]["row_count"] == 20


def test_training_artifact_loads_and_predicts_with_runtime_contract(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    artifacts = train_from_files(
        dataset_path=dataset_path,
        manifest_path=manifest_path,
        artifact_dir=tmp_path / "packet-if-v1",
        git_commit_sha=GIT_COMMIT_SHA,
    )
    artifact = load_packet_if_artifact(
        artifacts.model_path.parent,
        expected_bundle_sha256=artifacts.bundle_sha256,
        expected_model_version="packet-if-v1",
    )
    row = pd.read_csv(dataset_path).iloc[0].to_dict()

    prediction = predict_packet_feature_row(artifact, row)

    assert prediction.model_version == artifact.model_version
    assert prediction.threshold == pytest.approx(artifacts.threshold)
    assert prediction.is_anomaly == (
        prediction.anomaly_score > artifacts.threshold
    )


def test_threshold_is_calculated_only_from_validation_scores(
    tmp_path: Path,
) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first_dataset_path, first_manifest_path = _write_training_bundle(
        first_dir,
        attack_multiplier=1.0,
    )
    second_dataset_path, second_manifest_path = _write_training_bundle(
        second_dir,
        attack_multiplier=100.0,
    )

    first = train_from_files(
        dataset_path=first_dataset_path,
        manifest_path=first_manifest_path,
        artifact_dir=first_dir / "packet-if-v1",
        git_commit_sha=GIT_COMMIT_SHA,
    )
    second = train_from_files(
        dataset_path=second_dataset_path,
        manifest_path=second_manifest_path,
        artifact_dir=second_dir / "packet-if-v1",
        git_commit_sha=GIT_COMMIT_SHA,
    )

    assert first.threshold == pytest.approx(second.threshold)


def test_threshold_matches_validation_percentile(tmp_path: Path) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    artifacts = train_packet_isolation_forest(
        dataset,
        artifact_dir=tmp_path / "packet-if-v1",
        threshold_percentile=95.0,
        git_commit_sha=GIT_COMMIT_SHA,
        manifest_sha256=file_sha256(manifest_path),
    )
    model = joblib.load(artifacts.model_path)
    validation_matrix = packet_feature_matrix(
        dataset.validation.to_dict(orient="records")
    )

    expected = float(np.percentile(anomaly_scores(model, validation_matrix), 95.0))
    assert artifacts.threshold == pytest.approx(expected)


def test_training_is_reproducible_with_the_same_random_state(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    common = {
        "git_commit_sha": GIT_COMMIT_SHA,
        "manifest_sha256": file_sha256(manifest_path),
        "random_state": 42,
    }
    first = train_packet_isolation_forest(
        dataset,
        artifact_dir=tmp_path / "first" / "packet-if-v1",
        **common,
    )
    second = train_packet_isolation_forest(
        dataset,
        artifact_dir=tmp_path / "second" / "packet-if-v1",
        **common,
    )
    matrix = packet_feature_matrix(dataset.test.to_dict(orient="records"))

    first_scores = anomaly_scores(joblib.load(first.model_path), matrix)
    second_scores = anomaly_scores(joblib.load(second.model_path), matrix)

    assert first.threshold == pytest.approx(second.threshold)
    assert first_scores == pytest.approx(second_scores)


@pytest.mark.parametrize(
    "percentile",
    [0.0, -1.0, 100.0, 101.0, float("nan"), True, "99"],
)
def test_train_rejects_invalid_threshold_percentile(
    tmp_path: Path,
    percentile: object,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    with pytest.raises(ValueError, match="threshold_percentile"):
        train_packet_isolation_forest(
            dataset,
            artifact_dir=tmp_path / "packet-if-v1",
            threshold_percentile=percentile,
            git_commit_sha=GIT_COMMIT_SHA,
            manifest_sha256=file_sha256(manifest_path),
        )


@pytest.mark.parametrize("n_estimators", [0, -1, True, 10.5])
def test_train_rejects_invalid_n_estimators(
    tmp_path: Path,
    n_estimators: object,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    with pytest.raises(ValueError, match="n_estimators"):
        train_packet_isolation_forest(
            dataset,
            artifact_dir=tmp_path / "packet-if-v1",
            n_estimators=n_estimators,
            git_commit_sha=GIT_COMMIT_SHA,
            manifest_sha256=file_sha256(manifest_path),
        )


@pytest.mark.parametrize("random_state", [True, 42.0, "42"])
def test_train_rejects_invalid_random_state(
    tmp_path: Path,
    random_state: object,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    with pytest.raises(ValueError, match="random_state"):
        train_packet_isolation_forest(
            dataset,
            artifact_dir=tmp_path / "packet-if-v1",
            random_state=random_state,
            git_commit_sha=GIT_COMMIT_SHA,
            manifest_sha256=file_sha256(manifest_path),
        )


def test_train_always_refuses_to_replace_existing_artifact(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    artifact_dir = tmp_path / "packet-if-v1"
    kwargs = {
        "artifact_dir": artifact_dir,
        "git_commit_sha": GIT_COMMIT_SHA,
        "manifest_sha256": file_sha256(manifest_path),
    }
    artifacts = train_packet_isolation_forest(dataset, **kwargs)
    bundle_hashes = {
        path: file_sha256(path)
        for path in (
            artifacts.model_path,
            artifacts.metadata_path,
            artifacts.training_report_path,
        )
    }

    with pytest.raises(FileExistsError, match="artifact already exists"):
        train_packet_isolation_forest(dataset, **kwargs)

    assert {
        path: file_sha256(path)
        for path in bundle_hashes
    } == bundle_hashes


def test_train_succeeds_in_new_version_directory(tmp_path: Path) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    common = {
        "git_commit_sha": GIT_COMMIT_SHA,
        "manifest_sha256": file_sha256(manifest_path),
    }
    first = train_packet_isolation_forest(
        dataset, artifact_dir=tmp_path / "packet-if-v1", **common
    )
    second = train_packet_isolation_forest(
        dataset,
        artifact_dir=tmp_path / "packet-if-v2",
        model_version="packet-if-v2",
        **common,
    )

    assert first.model_path != second.model_path
    assert first.model_sha256 == file_sha256(first.model_path)
    assert second.model_sha256 == file_sha256(second.model_path)


def test_training_failure_does_not_publish_partial_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    artifact_dir = tmp_path / "packet-if-v1"
    real_write_json = trainer._write_json

    def fail_metadata_write(path: Path, payload: dict[str, object]) -> None:
        if path.name == "metadata.json":
            raise RuntimeError("metadata write failed")
        real_write_json(path, payload)

    monkeypatch.setattr(trainer, "_write_json", fail_metadata_write)
    with pytest.raises(RuntimeError, match="metadata write failed"):
        train_packet_isolation_forest(
            dataset,
            artifact_dir=artifact_dir,
            git_commit_sha=GIT_COMMIT_SHA,
            manifest_sha256=file_sha256(manifest_path),
        )

    assert not artifact_dir.exists()
    assert not list(tmp_path.glob(".packet-if-v1.*.tmp"))
    assert not (tmp_path / ".packet-if-v1.build.lock").exists()


def test_train_rejects_artifact_directory_version_mismatch(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    with pytest.raises(ValueError, match="must match model_version"):
        train_packet_isolation_forest(
            dataset,
            artifact_dir=tmp_path / "different-directory",
            model_version="packet-if-v1",
            git_commit_sha=GIT_COMMIT_SHA,
            manifest_sha256=file_sha256(manifest_path),
        )


def test_train_rejects_dataset_row_below_capture_policy(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)
    frame = pd.read_csv(dataset_path)
    frame.loc[0, "captured_duration_seconds"] = 8.98
    frame.to_csv(dataset_path, index=False)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["dataset_sha256"] = file_sha256(dataset_path)
    session_hashes = session_data_sha256s(dataset_path)
    for session in manifest["sessions"]:
        session["data_sha256"] = session_hashes[session["session_id"]]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="captured_duration_below_policy",
    ):
        train_from_files(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=tmp_path / "packet-if-v1",
            git_commit_sha=GIT_COMMIT_SHA,
        )


def test_train_rejects_dataset_capture_policy_version_mismatch(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_training_bundle(tmp_path)

    with pytest.raises(ValueError, match="Capture Policy mismatch"):
        train_from_files(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=tmp_path / "packet-if-v1",
            git_commit_sha=GIT_COMMIT_SHA,
            capture_policy=CapturePolicy(version="packet-capture-policy-v2"),
        )


def _format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
