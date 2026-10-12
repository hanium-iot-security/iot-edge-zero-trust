"""Evaluate a frozen Packet IF artifact on an external Holdout without relaxing any existing check.

The existing evaluator accepts only the Dataset the artifact was trained on. An external Holdout is a
separate Dataset v2 bundle whose Sessions are all `test`. It is read through the normal loader, then
must prove it shares no Session, capture group, Run, slot or Session data with the training Dataset or
any previously used Dataset. The threshold is never recalculated. Nothing is approved here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.evaluate_packet_isolation_forest import (
    PACKET_IF_EVALUATION_CSV_FILENAME,
    PACKET_IF_EVALUATION_FILENAME,
    PACKET_IF_EVALUATION_MANIFEST_FILENAME,
    PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME,
    PACKET_IF_PREDICTIONS_FILENAME,
    _OUTPUT_FILENAMES,
    _build_evaluation_summary,
    _evaluation_row,
    _evaluation_staging_directory,
    _file_record,
    _format_utc,
    _require_evaluation_inputs_unchanged,
    _resolve_evaluation_git_provenance,
    _validate_output_destination,
    _write_evaluation_csv,
    _write_json,
    _write_jsonl,
    _write_sha256_sidecar,
)
from ai.packet_if_dataset import (
    TEST_SPLIT,
    PacketIFDatasetManifest,
    file_sha256,
    load_packet_if_dataset,
    load_packet_if_manifest,
)
from ai.predict_packet_isolation_forest import load_packet_if_artifact, predict_packet_feature_rows

REQUEST_SCHEMA = "packet-external-eval-request-v1"
EXTERNAL_EVALUATION_SCHEMA = "packet-if-external-evaluation-v1"
HOLD_FILENAME = "external-evaluation-hold.json"
PURPOSES = ("DEVELOPMENT", "FINAL")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9a-f]{40}")
_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_ROLE = re.compile(r"[A-Z][A-Z0-9_]{0,39}")


class ExternalEvaluationError(ValueError):
    """A fixed diagnostic code, never an input value."""


def _require(condition, code):
    if not condition:
        raise ExternalEvaluationError(code)


def _exact(value, keys, code, optional=()):
    _require(isinstance(value, dict) and set(keys) <= set(value) <= set(keys) | set(optional), code)
    return value


def _sha256(value, code="invalid_sha256"):
    _require(type(value) is str and _SHA256.fullmatch(value) is not None, code)
    return value


def _utc(value, code="invalid_utc_time"):
    _require(type(value) is str and _UTC.fullmatch(value) is not None, code)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_request(path: Path) -> dict:
    """Read and strictly validate a request; paths resolve against the request file's directory."""
    try:
        request = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ExternalEvaluationError("invalid_request_json") from exc
    _exact(request, {"schema_version", "purpose", "artifact", "dataset", "training_manifest"},
           "request_fields", optional={"prior_manifests", "freeze"})
    _require(request["schema_version"] == REQUEST_SCHEMA, "request_schema_version")
    _require(request["purpose"] in PURPOSES, "invalid_purpose")
    artifact = _exact(request["artifact"], {"dir", "expected_bundle_sha256"}, "artifact_fields",
                      optional={"expected_model_version"})
    _sha256(artifact["expected_bundle_sha256"])
    _require(type(artifact["dir"]) is str and artifact["dir"], "invalid_artifact_dir")
    dataset = _exact(request["dataset"], {"csv", "csv_sha256", "manifest", "manifest_sha256"}, "dataset_fields")
    _sha256(dataset["csv_sha256"])
    _sha256(dataset["manifest_sha256"])
    training = _exact(request["training_manifest"], {"path", "sha256"}, "training_manifest_fields")
    _sha256(training["sha256"])
    prior = request.get("prior_manifests", [])
    _require(isinstance(prior, list), "prior_manifests_fields")
    for item in prior:
        _exact(item, {"path", "sha256", "role"}, "prior_manifest_fields")
        _sha256(item["sha256"])
        _require(type(item["role"]) is str and _ROLE.fullmatch(item["role"]) is not None, "invalid_prior_role")
    freeze = request.get("freeze")
    if request["purpose"] == "FINAL":
        _exact(freeze, {"record_sha256", "frozen_at", "code_commit_sha"}, "freeze_required_for_final")
        _sha256(freeze["record_sha256"])
        _utc(freeze["frozen_at"])
        _require(type(freeze["code_commit_sha"]) is str and _SHA1.fullmatch(freeze["code_commit_sha"]) is not None,
                 "invalid_freeze_commit")
    else:
        _require(freeze is None, "freeze_only_for_final")
    return request


def _resolve(base: Path, relative: str) -> Path:
    _require(type(relative) is str and relative and "\\" not in relative, "unsafe_path")
    return (base / relative).resolve()


def _verified(base: Path, relative: str, expected: str, code: str) -> Path:
    path = _resolve(base, relative)
    _require(path.is_file() and file_sha256(path) == expected, code)
    return path


def _identity(manifest: PacketIFDatasetManifest) -> dict[str, set]:
    sessions = manifest.sessions
    return {
        "session_id": {spec.session_id for spec in sessions},
        "source_capture_group_id": {spec.source_capture_group_id for spec in sessions if spec.source_capture_group_id},
        "run_id": {spec.run_manifest_ref.run_id for spec in sessions if spec.run_manifest_ref is not None},
        "collection_slot_id": {spec.collection_slot_id for spec in sessions if spec.collection_slot_id},
        "data_sha256": {spec.data_sha256 for spec in sessions if spec.data_sha256},
    }


def _load_any_manifest(path: Path) -> PacketIFDatasetManifest:
    """A previously used Dataset is either a training bundle or an earlier external Holdout."""
    try:
        return load_packet_if_manifest(path)
    except ValueError:
        return load_packet_if_manifest(path, external_holdout=True)


def _check(report, label, function):
    try:
        function()
    except (ExternalEvaluationError, OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        # Never echo exception text: it can contain paths or row values.
        code = str(exc) if isinstance(exc, ExternalEvaluationError) else type(exc).__name__
        report["blockers"].append(f"{label}:{code}")


def evaluate_external_holdout(request_path: Path, output_dir: Path, *, evaluated_at=None,
                              evaluation_git_commit_sha=None) -> dict:
    """Run every guard; publish an immutable evaluation bundle only when all of them pass."""
    report = {"schema_version": EXTERNAL_EVALUATION_SCHEMA, "status": "HOLD", "training_approved": False,
              "whole_capture_session_approved": False, "blockers": []}
    output_dir = Path(output_dir)
    try:
        _validate_output_destination(output_dir)
        evaluated_at_text = _format_utc(evaluated_at or datetime.now(timezone.utc))
        request = load_request(request_path)
    except (ExternalEvaluationError, OSError, ValueError) as exc:
        report["blockers"].append(
            f"preflight:{exc if isinstance(exc, ExternalEvaluationError) else type(exc).__name__}")
        return report
    base = Path(request_path).resolve().parent
    report["purpose"] = request["purpose"]
    state: dict[str, Any] = {}

    def inputs():
        dataset, training = request["dataset"], request["training_manifest"]
        state["csv"] = _verified(base, dataset["csv"], dataset["csv_sha256"], "dataset_checksum")
        state["manifest_path"] = _verified(base, dataset["manifest"], dataset["manifest_sha256"],
                                           "dataset_manifest_checksum")
        state["training_path"] = _verified(base, training["path"], training["sha256"], "training_manifest_checksum")
        state["prior_paths"] = [(_verified(base, item["path"], item["sha256"], "prior_manifest_checksum"), item)
                                for item in request.get("prior_manifests", [])]
        artifact = request["artifact"]
        state["artifact"] = load_packet_if_artifact(
            _resolve(base, artifact["dir"]), expected_bundle_sha256=artifact["expected_bundle_sha256"],
            expected_model_version=artifact.get("expected_model_version"))
        state["dataset"] = load_packet_if_dataset(state["csv"], state["manifest_path"], external_holdout=True)

    _check(report, "inputs", inputs)
    if "dataset" not in state:
        return _hold(report, output_dir)
    artifact, dataset = state["artifact"], state["dataset"]

    def contract():
        _require(dataset.manifest.capture_policy == artifact.capture_policy, "capture_policy_mismatch")
        _require(dataset.manifest.normal_policy_version == artifact.metadata.get("normal_policy_version"),
                 "normal_policy_mismatch")
        _require(all(spec.split == TEST_SPLIT for spec in dataset.manifest.sessions), "external_sessions_not_test")

    def training_evidence():
        _require(request["training_manifest"]["sha256"] == artifact.metadata.get("manifest_sha256"),
                 "training_manifest_not_the_artifact_manifest")
        training = load_packet_if_manifest(state["training_path"])
        state["training"] = training
        listed = artifact.metadata["sessions"]
        for split in ("train", "validation", "test"):
            _require(sorted(spec.session_id for spec in training.sessions if spec.split == split)
                     == sorted(listed[split]), "training_manifest_sessions_differ_from_artifact")

    def non_overlap():
        training = state.get("training")
        _require(training is not None, "training_evidence_unavailable")
        used = [("training", _identity(training))]
        for path, item in state["prior_paths"]:
            used.append((item["role"], _identity(_load_any_manifest(path))))
        external = _identity(dataset.manifest)
        summary = []
        for role, identity in used:
            for kind, values in external.items():
                shared = values & identity[kind]
                _require(not shared, f"overlap_{kind}")
            summary.append({"role": role, **{kind: len(values) for kind, values in identity.items()}})
        state["used_summary"] = summary

    def freeze():
        if request["purpose"] != "FINAL":
            return
        frozen_at = _utc(request["freeze"]["frozen_at"])
        for spec in dataset.manifest.sessions:
            _require(spec.started_at is not None and spec.started_at.astimezone(timezone.utc) > frozen_at,
                     "session_not_collected_after_freeze")

    for label, function in (("contract", contract), ("training_evidence", training_evidence),
                            ("non_overlap", non_overlap), ("freeze", freeze)):
        _check(report, label, function)
    if report["blockers"]:
        return _hold(report, output_dir)

    def publish():
        nonlocal rows
        git = _resolve_evaluation_git_provenance(evaluation_git_commit_sha)
        digests = {"dataset_sha256": request["dataset"]["csv_sha256"],
                   "dataset_manifest_sha256": request["dataset"]["manifest_sha256"]}
        frame = dataset.test.sort_values(["session_id", "window_start", "packet_feature_log_id"],
                                         kind="stable").reset_index(drop=True)
        source_rows = frame.to_dict(orient="records")
        _require(source_rows, "external_test_split_empty")
        predictions = predict_packet_feature_rows(artifact, source_rows)
        _require(len(predictions) == len(source_rows), "prediction_count_mismatch")
        rows = tuple(_evaluation_row(source, prediction, artifact)
                     for source, prediction in zip(source_rows, predictions, strict=True))
        unchanged = lambda: _require_evaluation_inputs_unchanged(  # noqa: E731
            state["csv"], state["manifest_path"], dataset_sha256=digests["dataset_sha256"],
            dataset_manifest_sha256=digests["dataset_manifest_sha256"])
        unchanged()
        summary = _build_evaluation_summary(
            dataset=dataset, artifact=artifact, evaluation_rows=rows, evaluated_at=evaluated_at_text,
            evaluation_git_commit_sha=git.commit_sha, evaluation_git_worktree_clean=git.worktree_clean,
            evaluation_git_verification_mode=git.verification_mode, **digests)
        external = {"purpose": request["purpose"], "final_evaluation": request["purpose"] == "FINAL",
                    "freeze": request.get("freeze"), "threshold_recalculated": False,
                    "non_overlap_checked_against": state["used_summary"],
                    "training_manifest_sha256": request["training_manifest"]["sha256"],
                    "prior_manifests": [{"role": item["role"], "sha256": item["sha256"]}
                                        for _, item in state["prior_paths"]]}
        summary["evaluation_schema_version"] = EXTERNAL_EVALUATION_SCHEMA
        summary["external_evaluation"] = external

        with _evaluation_staging_directory(output_dir, before_publish=unchanged) as staging:
            _write_jsonl(staging / PACKET_IF_PREDICTIONS_FILENAME, rows)
            _write_json(staging / PACKET_IF_EVALUATION_FILENAME, summary)
            _write_evaluation_csv(staging / PACKET_IF_EVALUATION_CSV_FILENAME, summary)
            manifest = {"evaluation_schema_version": EXTERNAL_EVALUATION_SCHEMA, "evaluated_at": evaluated_at_text,
                        "evaluation_git_commit_sha": git.commit_sha,
                        "manifest_sha256_sidecar": PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME,
                        "external_evaluation": external,
                        "inputs": {"dataset": {"filename": state["csv"].name, "sha256": digests["dataset_sha256"]},
                                   "dataset_manifest": {"filename": state["manifest_path"].name,
                                                        "sha256": digests["dataset_manifest_sha256"]},
                                   "artifact": {"model_version": artifact.model_version,
                                                "bundle_sha256": artifact.bundle_sha256},
                                   "request_sha256": file_sha256(Path(request_path))},
                        "outputs": [_file_record(staging / name, base_dir=staging) for name in _OUTPUT_FILENAMES]}
            _write_json(staging / PACKET_IF_EVALUATION_MANIFEST_FILENAME, manifest)
            _write_sha256_sidecar(staging / PACKET_IF_EVALUATION_MANIFEST_SHA256_FILENAME,
                                  sha256=file_sha256(staging / PACKET_IF_EVALUATION_MANIFEST_FILENAME),
                                  filename=PACKET_IF_EVALUATION_MANIFEST_FILENAME)

    rows = ()
    _check(report, "evaluation", publish)
    if report["blockers"]:
        return _hold(report, output_dir)
    report.update({"status": "PASS", "output_dir": str(output_dir), "row_count": len(rows),
                   "model_version": artifact.model_version, "threshold": artifact.threshold})
    return report


def _hold(report: dict, output_dir: Path) -> dict:
    """Record the HOLD in a new directory; no evaluation bundle is published."""
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / HOLD_FILENAME).write_text(
            json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    except OSError:
        report["blockers"].append("output:hold_report_not_written")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="New version directory")
    parser.add_argument("--evaluation-git-commit-sha", default=None)
    args = parser.parse_args(argv)
    report = evaluate_external_holdout(args.request, args.output_dir,
                                       evaluation_git_commit_sha=args.evaluation_git_commit_sha)
    print(f"External Packet IF evaluation: {report['status']}; training_approved=false")
    if report["blockers"]:
        print("Blockers: " + "; ".join(report["blockers"]))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
