from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pandas as pd
import pytest

from ai import evaluate_packet_isolation_forest as evaluator
from ai.evaluate_packet_isolation_forest import (
    PACKET_IF_EVALUATION_CSV_FILENAME,
    PACKET_IF_EVALUATION_FILENAME,
    PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME,
    PACKET_IF_EVALUATION_SCHEMA_VERSION,
    PACKET_IF_PREDICTIONS_FILENAME,
    evaluate_packet_if_test_split,
    evaluate_packet_isolation_forest,
)
from ai.packet_if_contract import (
    PACKET_IF_FEATURES,
    PACKET_IF_NOMINAL_WINDOW_SECONDS,
)
from ai.packet_if_dataset import (
    ATTACK_LABEL,
    NORMAL_LABEL,
    PACKET_IF_DATASET_VERSION,
    PacketIFDataset,
    PacketIFDatasetManifest,
    PacketIFSessionSpec,
    file_sha256,
    load_packet_if_dataset,
    session_data_sha256s,
)
from ai.predict_packet_isolation_forest import (
    PacketIFArtifact,
    PacketIFPrediction,
)
from ai.train_packet_isolation_forest import (
    train_from_files,
)
from edge.packet.capture_policy import CapturePolicy


GIT_COMMIT_SHA = "c" * 40
BUNDLE_SHA256 = "a" * 64
MODEL_VERSION = "packet-if-test-v1"
THRESHOLD = 0.5
EVALUATED_AT = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)

TRAIN_SESSION_ID = "11111111-1111-4111-8111-111111111111"
VALIDATION_SESSION_ID = "22222222-2222-4222-8222-222222222222"
NORMAL_TEST_SESSION_ID = "33333333-3333-4333-8333-333333333333"
ATTACK_TEST_SESSION_ID = "44444444-4444-4444-8444-444444444444"

_SCORES_BY_FEATURE_ID = {
    30: 0.1,
    31: 0.9,
    40: 0.8,
    41: 0.2,
}


def _dataset(
    *,
    capture_policy: CapturePolicy | None = None,
) -> PacketIFDataset:
    policy = capture_policy or CapturePolicy()
    manifest = PacketIFDatasetManifest(
        dataset_version=PACKET_IF_DATASET_VERSION,
        capture_policy=policy,
        dataset_sha256="d" * 64,
        sessions=(
            _session_spec(TRAIN_SESSION_ID, "train", "normal", "normal_train"),
            _session_spec(
                VALIDATION_SESSION_ID,
                "validation",
                "normal",
                "normal_validation",
            ),
            _session_spec(
                NORMAL_TEST_SESSION_ID,
                "test",
                "normal",
                "normal_test",
            ),
            _session_spec(
                ATTACK_TEST_SESSION_ID,
                "test",
                "attack",
                "packet_flood",
                target_device_id="esp32_01",
            ),
        ),
    )
    return PacketIFDataset(
        train=pd.DataFrame(
            [
                _row(
                    10,
                    TRAIN_SESSION_ID,
                    "normal",
                    "normal_train",
                    0,
                    split="train",
                )
            ]
        ),
        validation=pd.DataFrame(
            [
                _row(
                    20,
                    VALIDATION_SESSION_ID,
                    "normal",
                    "normal_validation",
                    0,
                    split="validation",
                )
            ]
        ),
        test=pd.DataFrame(
            [
                _row(
                    41,
                    ATTACK_TEST_SESSION_ID,
                    "attack",
                    "packet_flood",
                    1,
                ),
                _row(
                    31,
                    NORMAL_TEST_SESSION_ID,
                    "normal",
                    "normal_test",
                    1,
                ),
                _row(
                    40,
                    ATTACK_TEST_SESSION_ID,
                    "attack",
                    "packet_flood",
                    0,
                ),
                _row(
                    30,
                    NORMAL_TEST_SESSION_ID,
                    "normal",
                    "normal_test",
                    0,
                ),
            ]
        ),
        manifest=manifest,
    )


def _session_spec(
    session_id: str,
    split: str,
    traffic_label: str,
    scenario: str,
    *,
    target_device_id: str | None = None,
) -> PacketIFSessionSpec:
    return PacketIFSessionSpec(
        session_id=session_id,
        split=split,
        traffic_label=traffic_label,
        scenario=scenario,
        target_device_id=target_device_id,
    )


def _row(
    feature_id: int,
    session_id: str,
    traffic_label: str,
    scenario: str,
    offset: int,
    *,
    split: str = "test",
) -> dict[str, Any]:
    window_start = datetime(2026, 7, 31, tzinfo=timezone.utc) + timedelta(
        seconds=offset * 10
    )
    return {
        "packet_feature_log_id": feature_id,
        "session_id": session_id,
        "device_id": "esp32_01",
        "direction": "INBOUND",
        "window_start": _format_utc(window_start),
        "window_end": _format_utc(window_start + timedelta(seconds=10)),
        "peer_ip": "192.168.0.4",
        "segment_window_start": _format_utc(window_start),
        "segment_window_end": _format_utc(window_start + timedelta(seconds=10)),
        "segment_status": "PROCESSED",
        "segment_error_code": None,
        "start_delay_seconds": 0.1,
        "registered_device_id": "esp32_01",
        "registered_ip_address": "192.168.0.4",
        "packet_count": 20,
        "total_bytes": 2_000,
        "avg_packet_size": 100.0,
        "max_packet_size": 120,
        "mean_inter_arrival_time": 0.3,
        "distinct_dest_port_count": 1,
        "captured_duration_seconds": 10.0,
        "split": split,
        "traffic_label": traffic_label,
        "scenario": scenario,
    }


def _artifact(
    tmp_path: Path,
    *,
    capture_policy: CapturePolicy | None = None,
    dataset_sha256: str = "e" * 64,
    manifest_sha256: str = "f" * 64,
) -> PacketIFArtifact:
    policy = capture_policy or CapturePolicy()
    return PacketIFArtifact(
        model=SimpleNamespace(),
        model_path=tmp_path / "model.joblib",
        metadata_path=tmp_path / "metadata.json",
        training_report_path=tmp_path / "training_report.json",
        model_version=MODEL_VERSION,
        threshold=THRESHOLD,
        bundle_sha256=BUNDLE_SHA256,
        capture_policy=policy,
        metadata={
            "threshold_percentile": 99.0,
            "dataset_sha256": dataset_sha256,
            "manifest_sha256": manifest_sha256,
            "git_commit_sha": "b" * 40,
            "sessions": {
                "train": [TRAIN_SESSION_ID],
                "validation": [VALIDATION_SESSION_ID],
                "test": [
                    NORMAL_TEST_SESSION_ID,
                    ATTACK_TEST_SESSION_ID,
                ],
            },
        },
    )


def _predictions_for_rows(
    _artifact_value: PacketIFArtifact,
    rows: list[dict[str, Any]],
) -> tuple[PacketIFPrediction, ...]:
    return tuple(
        _prediction(_SCORES_BY_FEATURE_ID[int(row["packet_feature_log_id"])])
        for row in rows
    )


def _prediction(
    anomaly_score: float,
    *,
    is_anomaly: bool | None = None,
) -> PacketIFPrediction:
    return PacketIFPrediction(
        model_version=MODEL_VERSION,
        raw_decision_score=-anomaly_score,
        anomaly_score=anomaly_score,
        threshold=THRESHOLD,
        is_anomaly=(anomaly_score > THRESHOLD if is_anomaly is None else is_anomaly),
        feature_values=tuple(float(index) for index in range(len(PACKET_IF_FEATURES))),
    )


def _patch_verified_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    dataset: PacketIFDataset | None = None,
    artifact: PacketIFArtifact | None = None,
) -> tuple[Path, Path, Path]:
    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text("immutable dataset\n", encoding="utf-8")
    manifest_path = tmp_path / "dataset-manifest.json"
    manifest_path.write_text('{"immutable":true}\n', encoding="utf-8")
    artifact_dir = tmp_path / "packet-if-test-v1"
    artifact_dir.mkdir()
    artifact_value = artifact or _artifact(
        tmp_path,
        dataset_sha256=file_sha256(dataset_path),
        manifest_sha256=file_sha256(manifest_path),
    )

    monkeypatch.setattr(
        evaluator,
        "load_packet_if_dataset",
        lambda path, manifest: dataset or _dataset(),
    )
    monkeypatch.setattr(
        evaluator,
        "load_packet_if_artifact",
        lambda directory, **kwargs: artifact_value,
    )
    monkeypatch.setattr(
        evaluator,
        "predict_packet_feature_rows",
        _predictions_for_rows,
    )
    monkeypatch.setattr(
        evaluator,
        "_resolve_evaluation_git_provenance",
        lambda explicit_sha: evaluator._EvaluationGitProvenance(
            commit_sha=explicit_sha or GIT_COMMIT_SHA,
            worktree_clean=True,
            verification_mode="git_worktree_verified",
        ),
    )
    return dataset_path, manifest_path, artifact_dir


def _write_real_dataset_bundle(tmp_path: Path) -> tuple[Path, Path]:
    dataset = _dataset()
    frame = pd.concat(
        [dataset.train, dataset.validation, dataset.test],
        ignore_index=True,
    )
    dataset_path = tmp_path / "packet_if_dataset-v1.csv"
    frame.to_csv(dataset_path, index=False)
    session_hashes = session_data_sha256s(dataset_path)

    sessions: list[dict[str, Any]] = []
    for spec in dataset.manifest.sessions:
        session_rows = frame.loc[frame["session_id"] == spec.session_id]
        first_window_start = str(session_rows["window_start"].min())
        ended_at = str(session_rows["window_end"].max())
        session_payload: dict[str, Any] = {
            "session_id": spec.session_id,
            "split": spec.split,
            "traffic_label": spec.traffic_label,
            "scenario": spec.scenario,
            "status": "COMPLETED",
            "capture_interface": "eth0",
            "capture_filter": "tcp or udp",
            "source_commit_sha": GIT_COMMIT_SHA,
            "started_at": first_window_start,
            "first_window_start": first_window_start,
            "ended_at": ended_at,
            "capture_gap_start": None,
            "capture_gap_end": None,
            "devices": [
                {
                    "device_id": "esp32_01",
                    "peer_ip": "192.168.0.4",
                }
            ],
            "data_sha256": session_hashes[spec.session_id],
        }
        if spec.target_device_id is not None:
            session_payload["target_device_id"] = spec.target_device_id
        sessions.append(session_payload)

    policy = dataset.manifest.capture_policy
    manifest_path = tmp_path / "packet_if_manifest-v1.json"
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_version": PACKET_IF_DATASET_VERSION,
                "capture_policy_version": policy.version,
                "capture_policy": {
                    "version": policy.version,
                    "nominal_window_seconds": (PACKET_IF_NOMINAL_WINDOW_SECONDS),
                    "max_start_delay_seconds": (policy.max_start_delay_seconds),
                    "minimum_duration_seconds": (policy.minimum_duration_seconds),
                    "epsilon_seconds": policy.epsilon_seconds,
                    "minimum_coverage_ratio": (
                        policy.minimum_duration_seconds
                        / PACKET_IF_NOMINAL_WINDOW_SECONDS
                    ),
                },
                "dataset_sha256": file_sha256(dataset_path),
                "sessions": sessions,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return dataset_path, manifest_path


def test_evaluate_uses_only_test_split_and_preserves_strict_threshold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset()
    artifact = _artifact(tmp_path)
    seen_feature_ids: list[int] = []

    def predict(
        artifact_value: PacketIFArtifact,
        rows: list[dict[str, Any]],
    ) -> tuple[PacketIFPrediction, ...]:
        assert artifact_value is artifact
        seen_feature_ids.extend(int(row["packet_feature_log_id"]) for row in rows)
        scores = {
            30: THRESHOLD,
            31: 0.9,
            40: 0.8,
            41: 0.2,
        }
        return tuple(_prediction(scores[feature_id]) for feature_id in seen_feature_ids)

    monkeypatch.setattr(evaluator, "predict_packet_feature_rows", predict)

    rows = evaluate_packet_if_test_split(dataset, artifact)

    assert seen_feature_ids == [30, 31, 40, 41]
    assert {row["packet_feature_log_id"] for row in rows} == {30, 31, 40, 41}
    equal_row = next(row for row in rows if row["packet_feature_log_id"] == 30)
    assert equal_row["anomaly_score"] == THRESHOLD
    assert equal_row["is_anomaly"] is False
    assert equal_row["classification_outcome"] == "TN"


def test_evaluate_writes_metrics_and_verified_immutable_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    output_dir = tmp_path / "packet-if-eval-v1"

    result = evaluate_packet_isolation_forest(
        dataset_path=dataset_path,
        manifest_path=manifest_path,
        artifact_dir=artifact_dir,
        output_dir=output_dir,
        expected_bundle_sha256=BUNDLE_SHA256,
        expected_model_version=MODEL_VERSION,
        evaluation_git_commit_sha=GIT_COMMIT_SHA,
        evaluated_at=EVALUATED_AT,
    )

    assert result.row_count == 4
    assert result.model_version == MODEL_VERSION
    assert result.threshold == THRESHOLD
    assert result.manifest_sha256 == file_sha256(result.manifest_path)
    assert result.manifest_sha256_path.read_text(encoding="ascii") == (
        f"{result.manifest_sha256}  evaluation-manifest.json\n"
    )

    summary = json.loads(result.evaluation_path.read_text(encoding="utf-8"))
    assert summary["evaluation_schema_version"] == (PACKET_IF_EVALUATION_SCHEMA_VERSION)
    assert summary["evaluated_at"] == "2026-07-31T12:00:00Z"
    assert summary["classification_contract"] == {
        "actual_positive": "traffic_label == 'attack'",
        "predicted_positive": "is_anomaly == true",
        "threshold_operator": ">",
        "score_direction": "higher_is_more_anomalous",
        "threshold_source": "artifact_metadata",
        "evaluated_split": "test",
        "normal_fpr_unit": "packet_feature_window",
        "attack_tpr_units": {
            "row_tpr": "packet_feature_window",
            "attack_session_tpr": "capture_session",
        },
    }
    assert summary["evaluation_source"] == {
        "git_commit_sha": GIT_COMMIT_SHA,
        "worktree_clean": True,
        "verification_mode": "git_worktree_verified",
    }
    assert summary["overall"]["tp"] == 1
    assert summary["overall"]["fp"] == 1
    assert summary["overall"]["tn"] == 1
    assert summary["overall"]["fn"] == 1
    assert summary["overall"]["precision"] == pytest.approx(0.5)
    assert summary["overall"]["recall"] == pytest.approx(0.5)
    assert summary["overall"]["f1"] == pytest.approx(0.5)
    assert summary["overall"]["normal_window_fpr"] == pytest.approx(0.5)
    assert summary["overall"]["row_tpr"] == pytest.approx(0.5)
    assert summary["overall"]["attack_session_count"] == 1
    assert summary["overall"]["detected_attack_session_count"] == 1
    assert summary["overall"]["attack_session_tpr"] == pytest.approx(1.0)
    assert summary["overall"]["undefined_metrics"] == {}
    assert summary["overall"]["score_p50"] == pytest.approx(0.5)
    assert summary["by_label"]["normal"]["recall"] is None
    assert summary["by_label"]["normal"]["undefined_metrics"] == {
        "attack_session_tpr": "no_attack_sessions",
        "recall": "no_attack_rows",
        "row_tpr": "no_attack_rows",
    }
    assert summary["by_label"]["attack"]["normal_window_fpr"] is None
    assert summary["by_label"]["attack"]["undefined_metrics"] == {
        "normal_window_fpr": "no_normal_rows",
    }
    assert [item["session_id"] for item in summary["by_session"]] == [
        NORMAL_TEST_SESSION_ID,
        ATTACK_TEST_SESSION_ID,
    ]
    assert [item["scenario"] for item in summary["by_scenario"]] == [
        "normal_test",
        "packet_flood",
    ]

    prediction_lines = result.predictions_path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["packet_feature_log_id"] for line in prediction_lines] == [
        30,
        31,
        40,
        41,
    ]

    with result.evaluation_csv_path.open(newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))
    assert [row["scope_type"] for row in csv_rows] == [
        "overall",
        "label",
        "label",
        "session",
        "session",
        "scenario",
        "scenario",
    ]
    assert csv_rows[1]["recall"] == ""
    assert json.loads(csv_rows[1]["undefined_metrics"]) == {
        "attack_session_tpr": "no_attack_sessions",
        "recall": "no_attack_rows",
        "row_tpr": "no_attack_rows",
    }

    evaluation_manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert evaluation_manifest["inputs"]["dataset"]["sha256"] == file_sha256(
        dataset_path
    )
    assert evaluation_manifest["inputs"]["artifact"]["bundle_sha256"] == (BUNDLE_SHA256)
    assert evaluation_manifest["evaluation_source"] == {
        "git_commit_sha": GIT_COMMIT_SHA,
        "worktree_clean": True,
        "verification_mode": "git_worktree_verified",
    }
    assert evaluation_manifest["manifest_sha256_sidecar"] == (
        PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME
    )
    assert {item["relative_path"] for item in evaluation_manifest["outputs"]} == {
        PACKET_IF_PREDICTIONS_FILENAME,
        PACKET_IF_EVALUATION_FILENAME,
        PACKET_IF_EVALUATION_CSV_FILENAME,
    }
    for item in evaluation_manifest["outputs"]:
        output_path = output_dir / item["relative_path"]
        assert item["size_bytes"] == output_path.stat().st_size
        assert item["sha256"] == file_sha256(output_path)


def test_evaluate_passes_pinned_artifact_contract_to_loader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    calls: list[tuple[Path, dict[str, Any]]] = []

    def load_artifact(path: Path, **kwargs: Any) -> PacketIFArtifact:
        calls.append((path, kwargs))
        return _artifact(
            tmp_path,
            dataset_sha256=file_sha256(dataset_path),
            manifest_sha256=file_sha256(manifest_path),
        )

    monkeypatch.setattr(evaluator, "load_packet_if_artifact", load_artifact)

    evaluate_packet_isolation_forest(
        dataset_path=dataset_path,
        manifest_path=manifest_path,
        artifact_dir=artifact_dir,
        output_dir=tmp_path / "packet-if-eval-v1",
        expected_bundle_sha256=BUNDLE_SHA256,
        expected_model_version=MODEL_VERSION,
        evaluation_git_commit_sha=GIT_COMMIT_SHA,
        evaluated_at=EVALUATED_AT,
    )

    assert calls == [
        (
            artifact_dir,
            {
                "expected_bundle_sha256": BUNDLE_SHA256,
                "expected_model_version": MODEL_VERSION,
            },
        )
    ]


def test_evaluate_cli_loads_real_dataset_and_publishes_bundle(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_real_dataset_bundle(tmp_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    model_version = "packet-if-integration-v1"
    artifact_dir = tmp_path / model_version
    artifacts = train_from_files(
        dataset_path=dataset_path,
        manifest_path=manifest_path,
        artifact_dir=artifact_dir,
        model_version=model_version,
        git_commit_sha=GIT_COMMIT_SHA,
    )
    output_dir = tmp_path / "packet-if-eval-integration-v1"
    repository_root = Path(__file__).resolve().parents[1]
    cli_repository = tmp_path / "cli-repository"
    shutil.copytree(
        repository_root / "ai",
        cli_repository / "ai",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copy2(repository_root / ".gitignore", cli_repository / ".gitignore")
    cli_commit_sha = _commit_git_repository(cli_repository)

    python_path = f"{cli_repository}{os.pathsep}{repository_root}"
    if os.environ.get("PYTHONPATH"):
        python_path = f"{python_path}{os.pathsep}{os.environ['PYTHONPATH']}"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai.evaluate_packet_isolation_forest",
            "--dataset",
            str(dataset_path),
            "--manifest",
            str(manifest_path),
            "--artifact-dir",
            str(artifact_dir),
            "--expected-bundle-sha256",
            artifacts.bundle_sha256,
            "--expected-model-version",
            model_version,
            "--output-dir",
            str(output_dir),
            "--git-commit-sha",
            cli_commit_sha,
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": python_path,
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Packet IF evaluation complete" in completed.stderr
    predictions = [
        json.loads(line)
        for line in (output_dir / PACKET_IF_PREDICTIONS_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(predictions) == len(dataset.test)
    assert all(item["model_version"] == model_version for item in predictions)
    summary = json.loads(
        (output_dir / PACKET_IF_EVALUATION_FILENAME).read_text(encoding="utf-8")
    )
    assert summary["dataset"]["dataset_sha256"] == file_sha256(dataset_path)
    assert summary["dataset"]["manifest_sha256"] == file_sha256(manifest_path)
    assert summary["evaluation_source"] == {
        "git_commit_sha": cli_commit_sha,
        "worktree_clean": True,
        "verification_mode": "git_worktree_verified",
    }
    sidecar_path = output_dir / PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME
    assert sidecar_path.read_text(encoding="ascii").endswith(
        "  evaluation-manifest.json\n"
    )


def test_evaluate_rejects_capture_policy_mismatch_before_prediction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(
        tmp_path,
        capture_policy=CapturePolicy(minimum_duration_seconds=8.0),
    )
    called = False

    def unexpected_predict(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        nonlocal called
        called = True
        raise AssertionError("prediction must not run for mismatched policy")

    monkeypatch.setattr(
        evaluator,
        "predict_packet_feature_rows",
        unexpected_predict,
    )

    with pytest.raises(ValueError, match="Capture Policy"):
        evaluate_packet_if_test_split(_dataset(), artifact)

    assert called is False


def test_evaluate_rejects_test_session_used_for_artifact_training(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    artifact.metadata["sessions"]["train"].append(NORMAL_TEST_SESSION_ID)
    called = False

    def unexpected_predict(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        nonlocal called
        called = True
        raise AssertionError("prediction must not run for leaked Test Session")

    monkeypatch.setattr(
        evaluator,
        "predict_packet_feature_rows",
        unexpected_predict,
    )

    with pytest.raises(ValueError, match="overlaps Artifact"):
        evaluate_packet_if_test_split(_dataset(), artifact)

    assert called is False


def test_evaluate_rejects_test_session_list_that_differs_from_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    artifact.metadata["sessions"]["test"] = [NORMAL_TEST_SESSION_ID]
    called = False

    def unexpected_predict(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        nonlocal called
        called = True
        raise AssertionError("prediction must not run for a different Test split")

    monkeypatch.setattr(
        evaluator,
        "predict_packet_feature_rows",
        unexpected_predict,
    )

    with pytest.raises(ValueError, match="Test Session list does not match"):
        evaluate_packet_if_test_split(_dataset(), artifact)

    assert called is False


@pytest.mark.parametrize(
    ("mismatched_field", "error_pattern"),
    [
        ("dataset_sha256", "Dataset SHA256 does not match Artifact"),
        (
            "manifest_sha256",
            "Dataset Manifest SHA256 does not match Artifact",
        ),
    ],
)
def test_evaluate_rejects_dataset_identity_that_differs_from_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatched_field: str,
    error_pattern: str,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    artifact = _artifact(
        tmp_path,
        dataset_sha256=file_sha256(dataset_path),
        manifest_sha256=file_sha256(manifest_path),
    )
    artifact.metadata[mismatched_field] = "0" * 64
    monkeypatch.setattr(
        evaluator,
        "load_packet_if_artifact",
        lambda directory, **kwargs: artifact,
    )

    with pytest.raises(ValueError, match=error_pattern):
        evaluate_packet_isolation_forest(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=artifact_dir,
            output_dir=tmp_path / "packet-if-eval-v1",
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=EVALUATED_AT,
        )

    assert not (tmp_path / "packet-if-eval-v1").exists()


def test_evaluate_rejects_prediction_that_violates_threshold_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evaluator,
        "predict_packet_feature_rows",
        lambda artifact, rows: tuple(
            _prediction(0.9, is_anomaly=False) for _row_value in rows
        ),
    )

    with pytest.raises(ValueError, match="threshold contract"):
        evaluate_packet_if_test_split(_dataset(), _artifact(tmp_path))


def test_evaluate_refuses_to_replace_existing_output(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "packet-if-eval-v1"
    output_dir.mkdir()
    sentinel = output_dir / "keep.txt"
    sentinel.write_text("original", encoding="utf-8")

    with pytest.raises(FileExistsError, match="new version directory"):
        evaluate_packet_isolation_forest(
            dataset_path=tmp_path / "unused.csv",
            manifest_path=tmp_path / "unused.json",
            artifact_dir=tmp_path / "unused-artifact",
            output_dir=output_dir,
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=EVALUATED_AT,
        )

    assert sentinel.read_text(encoding="utf-8") == "original"


def test_evaluate_cleans_partial_bundle_after_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    output_dir = tmp_path / "packet-if-eval-v1"

    def fail_csv(_destination: Path, _summary: dict[str, Any]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(evaluator, "_write_evaluation_csv", fail_csv)

    with pytest.raises(OSError, match="disk full"):
        evaluate_packet_isolation_forest(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=artifact_dir,
            output_dir=output_dir,
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=EVALUATED_AT,
        )

    assert not output_dir.exists()
    assert not (tmp_path / ".packet-if-eval-v1.evaluation.lock").exists()
    assert not list(tmp_path.glob(".packet-if-eval-v1.*.tmp"))


def test_evaluate_does_not_publish_when_sidecar_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    output_dir = tmp_path / "packet-if-eval-v1"

    def fail_sidecar(
        _destination: Path,
        *,
        sha256: str,
        filename: str,
    ) -> None:
        raise OSError(f"sidecar write failed: {sha256}:{filename}")

    monkeypatch.setattr(evaluator, "_write_sha256_sidecar", fail_sidecar)

    with pytest.raises(OSError, match="sidecar write failed"):
        evaluate_packet_isolation_forest(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=artifact_dir,
            output_dir=output_dir,
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=EVALUATED_AT,
        )

    assert not output_dir.exists()
    assert not (tmp_path / ".packet-if-eval-v1.evaluation.lock").exists()
    assert not list(tmp_path.glob(".packet-if-eval-v1.*.tmp"))


def test_evaluate_rejects_dataset_changed_during_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    output_dir = tmp_path / "packet-if-eval-v1"

    def mutate_dataset_then_predict(
        artifact_value: PacketIFArtifact,
        rows: list[dict[str, Any]],
    ) -> tuple[PacketIFPrediction, ...]:
        dataset_path.write_text("changed during evaluation\n", encoding="utf-8")
        return _predictions_for_rows(artifact_value, rows)

    monkeypatch.setattr(
        evaluator,
        "predict_packet_feature_rows",
        mutate_dataset_then_predict,
    )

    with pytest.raises(RuntimeError, match="Dataset changed"):
        evaluate_packet_isolation_forest(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=artifact_dir,
            output_dir=output_dir,
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=EVALUATED_AT,
        )

    assert not output_dir.exists()


@pytest.mark.parametrize(
    ("source_name", "error_pattern"),
    [
        ("dataset", "Dataset changed"),
        ("manifest", "Dataset Manifest changed"),
    ],
)
def test_evaluate_rechecks_inputs_immediately_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_name: str,
    error_pattern: str,
) -> None:
    dataset_path, manifest_path, artifact_dir = _patch_verified_inputs(
        monkeypatch,
        tmp_path,
    )
    source_path = dataset_path if source_name == "dataset" else manifest_path
    output_dir = tmp_path / "packet-if-eval-v1"
    original_write_json = evaluator._write_json

    def mutate_after_manifest_write(
        destination: Path,
        payload: dict[str, Any],
    ) -> None:
        original_write_json(destination, payload)
        if destination.name == "evaluation-manifest.json":
            source_path.write_text(
                f"{source_name} changed before publish\n",
                encoding="utf-8",
            )

    monkeypatch.setattr(evaluator, "_write_json", mutate_after_manifest_write)

    with pytest.raises(RuntimeError, match=error_pattern):
        evaluate_packet_isolation_forest(
            dataset_path=dataset_path,
            manifest_path=manifest_path,
            artifact_dir=artifact_dir,
            output_dir=output_dir,
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=EVALUATED_AT,
        )

    assert not output_dir.exists()
    assert not list(tmp_path.glob(".packet-if-eval-v1.*.tmp"))


def test_evaluate_rejects_non_utc_evaluation_time_before_loading_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = False

    def unexpected_load(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal loaded
        loaded = True
        raise AssertionError("inputs must not load for invalid evaluated_at")

    monkeypatch.setattr(evaluator, "load_packet_if_dataset", unexpected_load)

    with pytest.raises(ValueError, match="timezone-aware UTC"):
        evaluate_packet_isolation_forest(
            dataset_path=tmp_path / "unused.csv",
            manifest_path=tmp_path / "unused.json",
            artifact_dir=tmp_path / "unused-artifact",
            output_dir=tmp_path / "packet-if-eval-v1",
            expected_bundle_sha256=BUNDLE_SHA256,
            evaluation_git_commit_sha=GIT_COMMIT_SHA,
            evaluated_at=datetime(2026, 7, 31, 12, 0),
        )

    assert loaded is False


def test_metric_summary_separates_window_and_attack_session_tpr() -> None:
    rows = [
        {
            "classification_outcome": "TP",
            "anomaly_score": 0.9,
            "traffic_label": ATTACK_LABEL,
            "is_anomaly": True,
            "session_id": "attack-a",
        },
        {
            "classification_outcome": "FN",
            "anomaly_score": 0.2,
            "traffic_label": ATTACK_LABEL,
            "is_anomaly": False,
            "session_id": "attack-a",
        },
        {
            "classification_outcome": "FN",
            "anomaly_score": 0.1,
            "traffic_label": ATTACK_LABEL,
            "is_anomaly": False,
            "session_id": "attack-b",
        },
        {
            "classification_outcome": "TN",
            "anomaly_score": 0.0,
            "traffic_label": NORMAL_LABEL,
            "is_anomaly": False,
            "session_id": "normal-a",
        },
    ]

    metrics = evaluator._metric_summary(rows)

    assert metrics["row_tpr"] == pytest.approx(1 / 3)
    assert metrics["attack_session_count"] == 2
    assert metrics["detected_attack_session_count"] == 1
    assert metrics["attack_session_tpr"] == pytest.approx(0.5)


def test_csv_summary_escapes_spreadsheet_formula_prefixes() -> None:
    metrics = evaluator._metric_summary(
        [
            {
                "classification_outcome": "TN",
                "anomaly_score": 0.1,
                "traffic_label": NORMAL_LABEL,
                "is_anomaly": False,
                "session_id": "normal-a",
            }
        ]
    )

    row = evaluator._csv_summary_row(
        scope_type="scenario",
        scope_value=' =WEBSERVICE("https://example.invalid")',
        traffic_labels=("+attack",),
        scenario="@SUM(1,1)",
        metrics=metrics,
    )

    assert row["scope_value"].startswith("'")
    assert row["traffic_labels"].startswith("'")
    assert row["scenario"].startswith("'")


def _initialize_git_repository(path: Path, *, content: str) -> str:
    path.mkdir()
    tracked_file = path / "tracked.txt"
    tracked_file.write_text(content, encoding="utf-8")

    return _commit_git_repository(path)


def _commit_git_repository(path: Path) -> str:

    def run_git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
        )

    run_git("init", "--quiet")
    run_git("add", ".")
    run_git(
        "-c",
        "user.name=Packet IF Test",
        "-c",
        "user.email=packet-if-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "initial",
    )
    return run_git("rev-parse", "HEAD").stdout.strip()


def test_git_provenance_accepts_clean_worktree_and_matching_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        if command == ["git", "rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(command, 0, "true\n", "")
        if command == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, f"{GIT_COMMIT_SHA}\n", "")
        if command == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected Git command: {command}")

    monkeypatch.setattr(evaluator.subprocess, "run", fake_run)
    monkeypatch.setattr(evaluator, "_has_git_marker", lambda path: True)

    provenance = evaluator._resolve_evaluation_git_provenance(GIT_COMMIT_SHA)

    assert provenance == evaluator._EvaluationGitProvenance(
        commit_sha=GIT_COMMIT_SHA,
        worktree_clean=True,
        verification_mode="git_worktree_verified",
    )


def test_git_provenance_uses_code_repository_when_cwd_is_another_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code_repository = tmp_path / "code-repository"
    caller_repository = tmp_path / "caller-repository"
    code_head = _initialize_git_repository(code_repository, content="code\n")
    caller_head = _initialize_git_repository(caller_repository, content="caller\n")
    assert code_head != caller_head

    monkeypatch.setattr(
        evaluator,
        "_EVALUATION_REPOSITORY_ROOT",
        code_repository,
    )
    monkeypatch.chdir(caller_repository)

    provenance = evaluator._resolve_evaluation_git_provenance(code_head)

    assert provenance == evaluator._EvaluationGitProvenance(
        commit_sha=code_head,
        worktree_clean=True,
        verification_mode="git_worktree_verified",
    )


def test_git_provenance_rejects_dirty_code_repository_when_cwd_is_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code_repository = tmp_path / "code-repository"
    caller_repository = tmp_path / "caller-repository"
    code_head = _initialize_git_repository(code_repository, content="code\n")
    _initialize_git_repository(caller_repository, content="caller\n")
    (code_repository / "tracked.txt").write_text("dirty code\n", encoding="utf-8")

    monkeypatch.setattr(
        evaluator,
        "_EVALUATION_REPOSITORY_ROOT",
        code_repository,
    )
    monkeypatch.chdir(caller_repository)

    with pytest.raises(RuntimeError, match="clean Git worktree"):
        evaluator._resolve_evaluation_git_provenance(code_head)


def test_git_provenance_rejects_dirty_worktree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        if command == ["git", "rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(command, 0, "true\n", "")
        if command == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, f"{GIT_COMMIT_SHA}\n", "")
        if command == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return subprocess.CompletedProcess(command, 0, " M ai/evaluator.py\n", "")
        raise AssertionError(f"unexpected Git command: {command}")

    monkeypatch.setattr(evaluator.subprocess, "run", fake_run)
    monkeypatch.setattr(evaluator, "_has_git_marker", lambda path: True)

    with pytest.raises(RuntimeError, match="clean Git worktree"):
        evaluator._resolve_evaluation_git_provenance(GIT_COMMIT_SHA)


def test_git_provenance_rejects_explicit_sha_that_differs_from_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    different_sha = "d" * 40

    def fake_run(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        if command == ["git", "rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(command, 0, "true\n", "")
        if command == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, f"{GIT_COMMIT_SHA}\n", "")
        if command == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected Git command: {command}")

    monkeypatch.setattr(evaluator.subprocess, "run", fake_run)
    monkeypatch.setattr(evaluator, "_has_git_marker", lambda path: True)

    with pytest.raises(ValueError, match="does not match current Git HEAD"):
        evaluator._resolve_evaluation_git_provenance(different_sha)


def test_git_provenance_allows_explicit_sha_without_git_worktree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evaluator.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            128,
            "",
            "fatal: not a git repository",
        ),
    )
    monkeypatch.setattr(evaluator, "_has_git_marker", lambda path: False)

    provenance = evaluator._resolve_evaluation_git_provenance(GIT_COMMIT_SHA)

    assert provenance == evaluator._EvaluationGitProvenance(
        commit_sha=GIT_COMMIT_SHA,
        worktree_clean=None,
        verification_mode="explicit_sha_without_git_worktree",
    )
    with pytest.raises(RuntimeError, match="required outside a Git worktree"):
        evaluator._resolve_evaluation_git_provenance(None)


def _format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
