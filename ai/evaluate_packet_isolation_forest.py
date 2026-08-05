"""Evaluate a verified Packet IF artifact against the immutable test split."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from math import isfinite
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Iterator, Sequence

import numpy as np

from ai.packet_if_contract import (
    PACKET_IF_FEATURES,
    PACKET_IF_SCORE_DIRECTION,
    PACKET_IF_THRESHOLD_OPERATOR,
)
from ai.packet_if_dataset import (
    ATTACK_LABEL,
    NORMAL_LABEL,
    PacketIFDataset,
    file_sha256,
    load_packet_if_dataset,
)
from ai.predict_packet_isolation_forest import (
    PacketIFArtifact,
    PacketIFPrediction,
    load_packet_if_artifact,
    predict_packet_feature_rows,
)


logger = logging.getLogger(__name__)

_EVALUATION_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

PACKET_IF_EVALUATION_SCHEMA_VERSION = "packet-if-evaluation-v1"
PACKET_IF_PREDICTIONS_FILENAME = "packet-if-predictions.jsonl"
PACKET_IF_EVALUATION_FILENAME = "packet-if-evaluation.json"
PACKET_IF_EVALUATION_CSV_FILENAME = "packet-if-evaluation.csv"
PACKET_IF_EVALUATION_MANIFEST_FILENAME = "evaluation-manifest.json"
PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME = (
    f"{PACKET_IF_EVALUATION_MANIFEST_FILENAME}.sha256"
)

_OUTPUT_FILENAMES = (
    PACKET_IF_PREDICTIONS_FILENAME,
    PACKET_IF_EVALUATION_FILENAME,
    PACKET_IF_EVALUATION_CSV_FILENAME,
)
_METRIC_FIELDS = (
    "row_count",
    "normal_count",
    "attack_count",
    "predicted_normal_count",
    "predicted_anomaly_count",
    "tp",
    "fp",
    "tn",
    "fn",
    "precision",
    "recall",
    "f1",
    "normal_window_fpr",
    "row_tpr",
    "attack_session_count",
    "detected_attack_session_count",
    "attack_session_tpr",
    "score_min",
    "score_max",
    "score_mean",
    "score_p5",
    "score_p50",
    "score_p95",
    "score_p99",
)


@dataclass(frozen=True)
class PacketIFEvaluationResult:
    output_dir: Path
    predictions_path: Path
    evaluation_path: Path
    evaluation_csv_path: Path
    manifest_path: Path
    manifest_sha256_path: Path
    row_count: int
    model_version: str
    threshold: float
    manifest_sha256: str


@dataclass(frozen=True)
class _EvaluationGitProvenance:
    commit_sha: str
    worktree_clean: bool | None
    verification_mode: str


def evaluate_packet_isolation_forest(
    *,
    dataset_path: Path,
    manifest_path: Path,
    artifact_dir: Path,
    output_dir: Path,
    expected_bundle_sha256: str,
    expected_model_version: str | None = None,
    evaluation_git_commit_sha: str | None = None,
    evaluated_at: datetime | None = None,
) -> PacketIFEvaluationResult:
    """Verify all inputs, evaluate only Test, and publish an immutable bundle."""
    _validate_output_destination(output_dir)
    evaluated_at_text = _format_utc(evaluated_at or datetime.now(timezone.utc))
    git_provenance = _resolve_evaluation_git_provenance(evaluation_git_commit_sha)
    commit_sha = git_provenance.commit_sha
    dataset_sha256 = file_sha256(dataset_path)
    dataset_manifest_sha256 = file_sha256(manifest_path)

    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    artifact = load_packet_if_artifact(
        artifact_dir,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_model_version=expected_model_version,
    )
    if dataset.manifest.capture_policy != artifact.capture_policy:
        raise ValueError(
            "Packet IF evaluation Dataset Capture Policy does not match Artifact"
        )
    _validate_dataset_artifact_identity(
        artifact=artifact,
        dataset_sha256=dataset_sha256,
        dataset_manifest_sha256=dataset_manifest_sha256,
    )

    evaluation_rows = evaluate_packet_if_test_split(dataset, artifact)
    _require_evaluation_inputs_unchanged(
        dataset_path,
        manifest_path,
        dataset_sha256=dataset_sha256,
        dataset_manifest_sha256=dataset_manifest_sha256,
    )
    summary = _build_evaluation_summary(
        dataset=dataset,
        artifact=artifact,
        evaluation_rows=evaluation_rows,
        dataset_sha256=dataset_sha256,
        dataset_manifest_sha256=dataset_manifest_sha256,
        evaluation_git_commit_sha=commit_sha,
        evaluation_git_worktree_clean=git_provenance.worktree_clean,
        evaluation_git_verification_mode=git_provenance.verification_mode,
        evaluated_at=evaluated_at_text,
    )

    with _evaluation_staging_directory(
        output_dir,
        before_publish=lambda: _require_evaluation_inputs_unchanged(
            dataset_path,
            manifest_path,
            dataset_sha256=dataset_sha256,
            dataset_manifest_sha256=dataset_manifest_sha256,
        ),
    ) as staging_dir:
        predictions_path = staging_dir / PACKET_IF_PREDICTIONS_FILENAME
        evaluation_path = staging_dir / PACKET_IF_EVALUATION_FILENAME
        evaluation_csv_path = staging_dir / PACKET_IF_EVALUATION_CSV_FILENAME
        manifest_output_path = staging_dir / PACKET_IF_EVALUATION_MANIFEST_FILENAME
        manifest_sha256_output_path = (
            staging_dir / PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME
        )

        _write_jsonl(predictions_path, evaluation_rows)
        _write_json(evaluation_path, summary)
        _write_evaluation_csv(evaluation_csv_path, summary)

        output_files = [
            _file_record(staging_dir / filename, base_dir=staging_dir)
            for filename in _OUTPUT_FILENAMES
        ]
        evaluation_manifest = {
            "evaluation_schema_version": PACKET_IF_EVALUATION_SCHEMA_VERSION,
            "evaluated_at": evaluated_at_text,
            "evaluation_git_commit_sha": commit_sha,
            "evaluation_source": {
                "git_commit_sha": commit_sha,
                "worktree_clean": git_provenance.worktree_clean,
                "verification_mode": git_provenance.verification_mode,
            },
            "manifest_sha256_sidecar": (PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME),
            "inputs": {
                "dataset": {
                    "filename": dataset_path.name,
                    "sha256": dataset_sha256,
                },
                "dataset_manifest": {
                    "filename": manifest_path.name,
                    "sha256": dataset_manifest_sha256,
                },
                "artifact": {
                    "directory_name": artifact_dir.name,
                    "model_version": artifact.model_version,
                    "bundle_sha256": artifact.bundle_sha256,
                },
            },
            "outputs": output_files,
        }
        _write_json(manifest_output_path, evaluation_manifest)
        evaluation_manifest_sha256 = file_sha256(manifest_output_path)
        _write_sha256_sidecar(
            manifest_sha256_output_path,
            sha256=evaluation_manifest_sha256,
            filename=PACKET_IF_EVALUATION_MANIFEST_FILENAME,
        )

    published_manifest = output_dir / PACKET_IF_EVALUATION_MANIFEST_FILENAME
    published_manifest_sha256_path = (
        output_dir / PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME
    )
    return PacketIFEvaluationResult(
        output_dir=output_dir,
        predictions_path=output_dir / PACKET_IF_PREDICTIONS_FILENAME,
        evaluation_path=output_dir / PACKET_IF_EVALUATION_FILENAME,
        evaluation_csv_path=output_dir / PACKET_IF_EVALUATION_CSV_FILENAME,
        manifest_path=published_manifest,
        manifest_sha256_path=published_manifest_sha256_path,
        row_count=int(summary["overall"]["row_count"]),
        model_version=artifact.model_version,
        threshold=artifact.threshold,
        manifest_sha256=evaluation_manifest_sha256,
    )


def evaluate_packet_if_test_split(
    dataset: PacketIFDataset,
    artifact: PacketIFArtifact,
) -> tuple[dict[str, Any], ...]:
    """Evaluate the canonical Test split without recalculating the threshold."""
    if dataset.manifest.capture_policy != artifact.capture_policy:
        raise ValueError(
            "Packet IF evaluation Dataset Capture Policy does not match Artifact"
        )
    _validate_test_session_isolation(dataset, artifact)

    test_frame = dataset.test.sort_values(
        ["session_id", "window_start", "packet_feature_log_id"],
        kind="stable",
    ).reset_index(drop=True)
    source_rows = test_frame.to_dict(orient="records")
    predictions = predict_packet_feature_rows(artifact, source_rows)
    if len(predictions) != len(source_rows):
        raise RuntimeError(
            "Packet IF evaluation prediction count does not match Test rows"
        )

    evaluation_rows = tuple(
        _evaluation_row(source_row, prediction, artifact)
        for source_row, prediction in zip(
            source_rows,
            predictions,
            strict=True,
        )
    )
    if not evaluation_rows:
        raise ValueError("Packet IF evaluation Test split must not be empty")
    return evaluation_rows


def _evaluation_row(
    source_row: dict[str, Any],
    prediction: PacketIFPrediction,
    artifact: PacketIFArtifact,
) -> dict[str, Any]:
    traffic_label = str(source_row["traffic_label"])
    if traffic_label not in {NORMAL_LABEL, ATTACK_LABEL}:
        raise ValueError(
            f"invalid Packet IF evaluation traffic_label: {traffic_label!r}"
        )
    if prediction.model_version != artifact.model_version:
        raise ValueError("Packet IF evaluation prediction model version mismatch")
    if (
        not isfinite(prediction.raw_decision_score)
        or not isfinite(prediction.anomaly_score)
        or not isfinite(prediction.threshold)
    ):
        raise ValueError("Packet IF evaluation prediction contains a non-finite value")
    if prediction.threshold != artifact.threshold:
        raise ValueError("Packet IF evaluation prediction threshold mismatch")
    expected_is_anomaly = prediction.anomaly_score > artifact.threshold
    if prediction.is_anomaly is not expected_is_anomaly:
        raise ValueError("Packet IF evaluation prediction violates threshold contract")
    if len(prediction.feature_values) != len(PACKET_IF_FEATURES):
        raise ValueError("Packet IF evaluation prediction feature count mismatch")

    actual_positive = traffic_label == ATTACK_LABEL
    predicted_positive = prediction.is_anomaly
    outcome = _classification_outcome(
        actual_positive=actual_positive,
        predicted_positive=predicted_positive,
    )
    return {
        "packet_feature_log_id": int(source_row["packet_feature_log_id"]),
        "session_id": str(source_row["session_id"]),
        "scenario": str(source_row["scenario"]),
        "traffic_label": traffic_label,
        "device_id": str(source_row["device_id"]),
        "peer_ip": str(source_row["peer_ip"]),
        "window_start": str(source_row["window_start"]),
        "window_end": str(source_row["window_end"]),
        "model_version": artifact.model_version,
        "threshold": float(artifact.threshold),
        "raw_decision_score": float(prediction.raw_decision_score),
        "anomaly_score": float(prediction.anomaly_score),
        "is_anomaly": predicted_positive,
        "classification_outcome": outcome,
        "feature_values": {
            feature_name: float(feature_value)
            for feature_name, feature_value in zip(
                PACKET_IF_FEATURES,
                prediction.feature_values,
                strict=True,
            )
        },
    }


def _classification_outcome(
    *,
    actual_positive: bool,
    predicted_positive: bool,
) -> str:
    if actual_positive:
        return "TP" if predicted_positive else "FN"
    return "FP" if predicted_positive else "TN"


def _build_evaluation_summary(
    *,
    dataset: PacketIFDataset,
    artifact: PacketIFArtifact,
    evaluation_rows: tuple[dict[str, Any], ...],
    dataset_sha256: str,
    dataset_manifest_sha256: str,
    evaluation_git_commit_sha: str,
    evaluation_git_worktree_clean: bool | None,
    evaluation_git_verification_mode: str,
    evaluated_at: str,
) -> dict[str, Any]:
    by_label = {
        label: _metric_summary(
            [row for row in evaluation_rows if row["traffic_label"] == label]
        )
        for label in (NORMAL_LABEL, ATTACK_LABEL)
    }

    session_ids = sorted({str(row["session_id"]) for row in evaluation_rows})
    by_session: list[dict[str, Any]] = []
    for session_id in session_ids:
        rows = [row for row in evaluation_rows if row["session_id"] == session_id]
        traffic_labels = sorted({str(row["traffic_label"]) for row in rows})
        scenarios = sorted({str(row["scenario"]) for row in rows})
        if len(traffic_labels) != 1 or len(scenarios) != 1:
            raise ValueError(
                "Packet IF evaluation Session must have one label and scenario: "
                f"session_id={session_id}"
            )
        by_session.append(
            {
                "session_id": session_id,
                "traffic_label": traffic_labels[0],
                "scenario": scenarios[0],
                "metrics": _metric_summary(rows),
            }
        )

    scenarios = sorted({str(row["scenario"]) for row in evaluation_rows})
    by_scenario = [
        {
            "scenario": scenario,
            "traffic_labels": sorted(
                {
                    str(row["traffic_label"])
                    for row in evaluation_rows
                    if row["scenario"] == scenario
                }
            ),
            "metrics": _metric_summary(
                [row for row in evaluation_rows if row["scenario"] == scenario]
            ),
        }
        for scenario in scenarios
    ]

    return {
        "evaluation_schema_version": PACKET_IF_EVALUATION_SCHEMA_VERSION,
        "evaluated_at": evaluated_at,
        "evaluation_git_commit_sha": evaluation_git_commit_sha,
        "evaluation_source": {
            "git_commit_sha": evaluation_git_commit_sha,
            "worktree_clean": evaluation_git_worktree_clean,
            "verification_mode": evaluation_git_verification_mode,
        },
        "classification_contract": {
            "actual_positive": f"traffic_label == {ATTACK_LABEL!r}",
            "predicted_positive": "is_anomaly == true",
            "threshold_operator": PACKET_IF_THRESHOLD_OPERATOR,
            "score_direction": PACKET_IF_SCORE_DIRECTION,
            "threshold_source": "artifact_metadata",
            "evaluated_split": "test",
            "normal_fpr_unit": "packet_feature_window",
            "attack_tpr_units": {
                "row_tpr": "packet_feature_window",
                "attack_session_tpr": "capture_session",
            },
        },
        "dataset": {
            "dataset_version": dataset.manifest.dataset_version,
            "normal_policy_version": dataset.manifest.normal_policy_version,
            "dataset_sha256": dataset_sha256,
            "manifest_sha256": dataset_manifest_sha256,
            "capture_policy_version": dataset.manifest.capture_policy_version,
            "test_session_ids": list(dataset.session_ids("test")),
        },
        "artifact": {
            "model_version": artifact.model_version,
            "bundle_sha256": artifact.bundle_sha256,
            "threshold": artifact.threshold,
            "threshold_percentile": artifact.metadata["threshold_percentile"],
            "training_dataset_sha256": artifact.metadata["dataset_sha256"],
            "training_manifest_sha256": artifact.metadata["manifest_sha256"],
            "training_normal_policy_version": artifact.metadata.get(
                "normal_policy_version"
            ),
            "training_git_commit_sha": artifact.metadata["git_commit_sha"],
            "training_sessions": {
                split: list(artifact.metadata["sessions"][split])
                for split in ("train", "validation", "test")
            },
        },
        "overall": _metric_summary(evaluation_rows),
        "by_label": by_label,
        "by_session": by_session,
        "by_scenario": by_scenario,
    }


def _metric_summary(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise ValueError("Packet IF evaluation metric group must not be empty")

    outcome_counts = {
        outcome: sum(row["classification_outcome"] == outcome for row in rows)
        for outcome in ("TP", "FP", "TN", "FN")
    }
    tp = outcome_counts["TP"]
    fp = outcome_counts["FP"]
    tn = outcome_counts["TN"]
    fn = outcome_counts["FN"]
    scores = np.asarray([row["anomaly_score"] for row in rows], dtype=float)
    percentiles = np.percentile(
        scores,
        [5.0, 50.0, 95.0, 99.0],
        method="linear",
    )
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = _safe_ratio(2 * tp, 2 * tp + fp + fn)
    normal_window_fpr = _safe_ratio(fp, fp + tn)
    attack_rows = [row for row in rows if row["traffic_label"] == ATTACK_LABEL]
    attack_session_ids = {str(row["session_id"]) for row in attack_rows}
    detected_attack_session_ids = {
        str(row["session_id"]) for row in attack_rows if row["is_anomaly"]
    }
    attack_session_tpr = _safe_ratio(
        len(detected_attack_session_ids),
        len(attack_session_ids),
    )
    undefined_metrics: dict[str, str] = {}
    if precision is None:
        undefined_metrics["precision"] = "no_predicted_positive_rows"
    if recall is None:
        undefined_metrics["recall"] = "no_attack_rows"
        undefined_metrics["row_tpr"] = "no_attack_rows"
    if f1 is None:
        undefined_metrics["f1"] = "no_actual_or_predicted_positive_rows"
    if normal_window_fpr is None:
        undefined_metrics["normal_window_fpr"] = "no_normal_rows"
    if attack_session_tpr is None:
        undefined_metrics["attack_session_tpr"] = "no_attack_sessions"
    return {
        "row_count": len(rows),
        "normal_count": sum(row["traffic_label"] == NORMAL_LABEL for row in rows),
        "attack_count": sum(row["traffic_label"] == ATTACK_LABEL for row in rows),
        "predicted_normal_count": sum(not row["is_anomaly"] for row in rows),
        "predicted_anomaly_count": sum(row["is_anomaly"] for row in rows),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "normal_window_fpr": normal_window_fpr,
        "row_tpr": recall,
        "attack_session_count": len(attack_session_ids),
        "detected_attack_session_count": len(detected_attack_session_ids),
        "attack_session_tpr": attack_session_tpr,
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "score_mean": float(np.mean(scores)),
        "score_p5": float(percentiles[0]),
        "score_p50": float(percentiles[1]),
        "score_p95": float(percentiles[2]),
        "score_p99": float(percentiles[3]),
        "undefined_metrics": undefined_metrics,
    }


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return float(numerator / denominator)


def _validate_test_session_isolation(
    dataset: PacketIFDataset,
    artifact: PacketIFArtifact,
) -> None:
    raw_sessions = artifact.metadata.get("sessions")
    if not isinstance(raw_sessions, dict):
        raise ValueError("Packet IF Artifact sessions metadata must be an object")

    artifact_session_ids: dict[str, tuple[str, ...]] = {}
    training_session_ids: set[str] = set()
    for split in ("train", "validation", "test"):
        session_ids = raw_sessions.get(split)
        if (
            not isinstance(session_ids, list)
            or not session_ids
            or not all(
                isinstance(session_id, str) and session_id for session_id in session_ids
            )
        ):
            raise ValueError(
                f"Packet IF Artifact sessions.{split} must be a non-empty list"
            )
        artifact_session_ids[split] = tuple(session_ids)
        if split in {"train", "validation"}:
            training_session_ids.update(session_ids)

    dataset_test_session_ids = dataset.session_ids("test")
    if dataset_test_session_ids != artifact_session_ids["test"]:
        raise ValueError(
            "Packet IF evaluation Test Session list does not match Artifact: "
            f"dataset={list(dataset_test_session_ids)}, "
            f"artifact={list(artifact_session_ids['test'])}"
        )

    overlap = sorted(set(dataset_test_session_ids) & training_session_ids)
    if overlap:
        raise ValueError(
            "Packet IF evaluation Test Session overlaps Artifact "
            f"Train/Validation Sessions: {overlap}"
        )


def _validate_dataset_artifact_identity(
    *,
    artifact: PacketIFArtifact,
    dataset_sha256: str,
    dataset_manifest_sha256: str,
) -> None:
    expected_dataset_sha256 = artifact.metadata.get("dataset_sha256")
    if dataset_sha256 != expected_dataset_sha256:
        raise ValueError(
            "Packet IF evaluation Dataset SHA256 does not match Artifact: "
            f"expected={expected_dataset_sha256}, actual={dataset_sha256}"
        )

    expected_manifest_sha256 = artifact.metadata.get("manifest_sha256")
    if dataset_manifest_sha256 != expected_manifest_sha256:
        raise ValueError(
            "Packet IF evaluation Dataset Manifest SHA256 does not match "
            "Artifact: "
            f"expected={expected_manifest_sha256}, "
            f"actual={dataset_manifest_sha256}"
        )


def _validate_output_destination(output_dir: Path) -> None:
    if os.path.lexists(output_dir):
        raise FileExistsError(
            "Packet IF evaluation already exists; use a new version directory: "
            f"{output_dir}"
        )


@contextmanager
def _evaluation_staging_directory(
    output_dir: Path,
    *,
    before_publish: Callable[[], None] | None = None,
) -> Iterator[Path]:
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    lock_path = parent / f".{output_dir.name}.evaluation.lock"
    try:
        lock_descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise RuntimeError(
            f"another Packet IF evaluation holds the lock: {lock_path}"
        ) from exc

    staging_dir: Path | None = None
    try:
        try:
            os.write(lock_descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        finally:
            os.close(lock_descriptor)
        staging_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{output_dir.name}.",
                suffix=".tmp",
                dir=parent,
            )
        )
        yield staging_dir
        _fsync_directory(staging_dir)
        if os.path.lexists(output_dir):
            raise FileExistsError(
                "Packet IF evaluation appeared during publication; refusing "
                f"to replace it: {output_dir}"
            )
        if before_publish is not None:
            before_publish()
        os.rename(staging_dir, output_dir)
        staging_dir = None
        _fsync_directory(parent)
    finally:
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)
        lock_path.unlink(missing_ok=True)


def _write_jsonl(destination: Path, rows: Sequence[dict[str, Any]]) -> None:
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(destination: Path, payload: dict[str, Any]) -> None:
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _fsync_file(destination)


def _write_sha256_sidecar(
    destination: Path,
    *,
    sha256: str,
    filename: str,
) -> None:
    with destination.open("w", encoding="ascii", newline="\n") as handle:
        handle.write(f"{sha256}  {filename}\n")
        handle.flush()
        os.fsync(handle.fileno())


def _write_evaluation_csv(
    destination: Path,
    summary: dict[str, Any],
) -> None:
    rows = _evaluation_csv_rows(summary)
    fieldnames = (
        "scope_type",
        "scope_value",
        "traffic_labels",
        "scenario",
        "undefined_metrics",
        *_METRIC_FIELDS,
    )
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())


def _evaluation_csv_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        _csv_summary_row(
            scope_type="overall",
            scope_value="all",
            traffic_labels=(NORMAL_LABEL, ATTACK_LABEL),
            scenario="",
            metrics=summary["overall"],
        )
    ]
    for label in (NORMAL_LABEL, ATTACK_LABEL):
        rows.append(
            _csv_summary_row(
                scope_type="label",
                scope_value=label,
                traffic_labels=(label,),
                scenario="",
                metrics=summary["by_label"][label],
            )
        )
    for session in summary["by_session"]:
        rows.append(
            _csv_summary_row(
                scope_type="session",
                scope_value=session["session_id"],
                traffic_labels=(session["traffic_label"],),
                scenario=session["scenario"],
                metrics=session["metrics"],
            )
        )
    for scenario in summary["by_scenario"]:
        rows.append(
            _csv_summary_row(
                scope_type="scenario",
                scope_value=scenario["scenario"],
                traffic_labels=tuple(scenario["traffic_labels"]),
                scenario=scenario["scenario"],
                metrics=scenario["metrics"],
            )
        )
    return rows


def _csv_summary_row(
    *,
    scope_type: str,
    scope_value: str,
    traffic_labels: tuple[str, ...],
    scenario: str,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scope_type": _spreadsheet_safe_text(scope_type),
        "scope_value": _spreadsheet_safe_text(scope_value),
        "traffic_labels": _spreadsheet_safe_text("|".join(traffic_labels)),
        "scenario": _spreadsheet_safe_text(scenario),
        "undefined_metrics": (
            json.dumps(
                metrics["undefined_metrics"],
                sort_keys=True,
                separators=(",", ":"),
            )
            if metrics["undefined_metrics"]
            else ""
        ),
        **{field_name: metrics[field_name] for field_name in _METRIC_FIELDS},
    }


def _spreadsheet_safe_text(value: str) -> str:
    stripped = value.lstrip(" \t\r\n")
    if value[:1] in {"\t", "\r", "\n"} or stripped[:1] in {"=", "+", "-", "@"}:
        return f"'{value}"
    return value


def _file_record(path: Path, *, base_dir: Path) -> dict[str, Any]:
    return {
        "relative_path": path.relative_to(base_dir).as_posix(),
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def _require_unchanged_file(
    path: Path,
    *,
    expected_sha256: str,
    label: str,
) -> None:
    actual_sha256 = file_sha256(path)
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"Packet IF evaluation {label} changed during evaluation: {path}"
        )


def _require_evaluation_inputs_unchanged(
    dataset_path: Path,
    manifest_path: Path,
    *,
    dataset_sha256: str,
    dataset_manifest_sha256: str,
) -> None:
    _require_unchanged_file(
        dataset_path,
        expected_sha256=dataset_sha256,
        label="Dataset",
    )
    _require_unchanged_file(
        manifest_path,
        expected_sha256=dataset_manifest_sha256,
        label="Dataset Manifest",
    )


def _fsync_file(path: Path) -> None:
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError("evaluated_at must be timezone-aware UTC")
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_git_commit_sha(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(
            "evaluation_git_commit_sha must be a lowercase 40-character SHA1"
        )


def _resolve_evaluation_git_provenance(
    explicit_commit_sha: str | None,
) -> _EvaluationGitProvenance:
    if explicit_commit_sha is not None:
        _validate_git_commit_sha(explicit_commit_sha)

    repository_root = _EVALUATION_REPOSITORY_ROOT
    if not _has_git_marker(repository_root):
        return _explicit_non_git_provenance(explicit_commit_sha)

    try:
        worktree_probe = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            check=False,
            capture_output=True,
            text=True,
            cwd=repository_root,
        )
    except OSError as exc:
        raise RuntimeError(
            "unable to verify Packet IF evaluation Git worktree"
        ) from exc

    if worktree_probe.returncode != 0 or worktree_probe.stdout.strip() != "true":
        raise RuntimeError(
            "unable to verify Packet IF evaluation Git worktree: "
            f"{worktree_probe.stderr.strip()}"
        )

    try:
        head_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            cwd=repository_root,
        )
        status_result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
            cwd=repository_root,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "unable to verify Packet IF evaluation Git provenance"
        ) from exc

    head_commit_sha = head_result.stdout.strip()
    _validate_git_commit_sha(head_commit_sha)
    if explicit_commit_sha is not None and explicit_commit_sha != head_commit_sha:
        raise ValueError(
            "evaluation_git_commit_sha does not match current Git HEAD: "
            f"expected={head_commit_sha}, actual={explicit_commit_sha}"
        )

    dirty_entries = status_result.stdout.strip().splitlines()
    if dirty_entries:
        preview = ", ".join(dirty_entries[:5])
        if len(dirty_entries) > 5:
            preview = f"{preview}, ..."
        raise RuntimeError(
            f"Packet IF evaluation requires a clean Git worktree: {preview}"
        )

    return _EvaluationGitProvenance(
        commit_sha=head_commit_sha,
        worktree_clean=True,
        verification_mode="git_worktree_verified",
    )


def _explicit_non_git_provenance(
    explicit_commit_sha: str | None,
) -> _EvaluationGitProvenance:
    if explicit_commit_sha is None:
        raise RuntimeError("--git-commit-sha is required outside a Git worktree")
    return _EvaluationGitProvenance(
        commit_sha=explicit_commit_sha,
        worktree_clean=None,
        verification_mode="explicit_sha_without_git_worktree",
    )


def _has_git_marker(path: Path) -> bool:
    return (path.resolve() / ".git").exists()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Packet Isolation Forest Test Split evaluation"
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--expected-model-version")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--git-commit-sha")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = evaluate_packet_isolation_forest(
        dataset_path=args.dataset,
        manifest_path=args.manifest,
        artifact_dir=args.artifact_dir,
        output_dir=args.output_dir,
        expected_bundle_sha256=args.expected_bundle_sha256,
        expected_model_version=args.expected_model_version,
        evaluation_git_commit_sha=args.git_commit_sha,
    )
    logger.info(
        "Packet IF evaluation complete: rows=%d, model_version=%s, threshold=%.8f",
        result.row_count,
        result.model_version,
        result.threshold,
    )
    logger.info("Packet IF evaluation output: %s", result.output_dir)
    logger.info(
        "Packet IF evaluation manifest SHA256: %s",
        result.manifest_sha256,
    )


if __name__ == "__main__":
    main()
