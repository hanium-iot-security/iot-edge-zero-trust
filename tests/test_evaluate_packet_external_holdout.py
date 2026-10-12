"""External Packet IF Holdout: reuses the normal loader and adds Holdout independence guards."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from ai import evaluate_packet_external_holdout as holdout
from ai.evaluate_packet_external_holdout import evaluate_external_holdout, main
from ai.evaluate_packet_isolation_forest import _EvaluationGitProvenance
from ai.packet_if_dataset import (
    PacketIFDataset,
    PacketIFDatasetManifest,
    PacketIFSessionDevice,
    PacketIFSessionSpec,
    file_sha256,
)
from ai.packet_if_phase5_manifest import (
    PACKET_IF_DATASET_VERSION_V1,
    PACKET_IF_DATASET_VERSION_V2,
    PacketIFRunManifestReference,
)
from ai.predict_packet_isolation_forest import PacketIFArtifact, PacketIFPrediction
from edge.packet.capture_policy import CapturePolicy
from edge.phase5.contracts import RUN_MANIFEST_SCHEMA_VERSION

THRESHOLD = 0.5
MODEL = "packet-if-frozen-v1"
BUNDLE_SHA = "b" * 64
POLICY_VERSION = "normal-policy-v1"
FROZEN_AT = datetime(2026, 10, 14, tzinfo=timezone.utc)
COLLECTED = datetime(2026, 10, 16, tzinfo=timezone.utc)
SCORES = {1: 0.1, 2: 0.9, 3: 0.2, 4: 0.8}


def run_ref(name):
    return PacketIFRunManifestReference(name, f"{name}/run-manifest.json", RUN_MANIFEST_SCHEMA_VERSION, "a" * 64)


def spec(name, split, *, label="normal", started=COLLECTED, group=None, slot=None, data=None, target=None):
    return PacketIFSessionSpec(
        session_id=name, split=split, traffic_label=label, scenario="packet_flood" if label == "attack" else "normal_holdout",
        target_device_id=target, started_at=started, data_sha256=data or (name[0] * 64)[:64],
        collection_slot_id=slot or f"slot-{name}", source_capture_group_id=group or f"group-{name}",
        run_manifest_ref=run_ref(f"run-{name}"), normal_policy_version=POLICY_VERSION)


def manifest(sessions, policy=None, sha="d" * 64):
    return PacketIFDatasetManifest(PACKET_IF_DATASET_VERSION_V2, policy or CapturePolicy(), sha, tuple(sessions))


def row(feature_id, session, label, offset):
    start = datetime(2026, 10, 16, tzinfo=timezone.utc) + timedelta(seconds=offset * 10)
    fmt = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    return {"packet_feature_log_id": feature_id, "session_id": session, "device_id": "esp32_01",
            "direction": "INBOUND", "window_start": fmt(start), "window_end": fmt(start + timedelta(seconds=10)),
            "peer_ip": "192.168.0.4", "split": "test", "traffic_label": label,
            "scenario": "packet_flood" if label == "attack" else "normal_holdout"}


class Case:
    """Files on disk, request writer and monkeypatched loaders for one scenario."""

    def __init__(self, tmp_path, monkeypatch):
        self.dir = tmp_path / "work"
        self.dir.mkdir()
        self.out = tmp_path / "out"
        self.monkeypatch = monkeypatch
        for name, text in (("holdout.csv", "holdout\n"), ("holdout.json", "{}"), ("training.json", '{"t":1}'),
                           ("prior.json", '{"p":1}')):
            (self.dir / name).write_text(text, encoding="utf-8")
        (self.dir / "artifact").mkdir()
        self.training = manifest([spec("t1", "train", started=None), spec("v1", "validation", started=None),
                                  spec("e1", "test", started=None)])
        self.prior = manifest([spec("p1", "test", started=None)])
        self.external = manifest([spec("n9", "test"), spec("a9", "test", label="attack", target="esp32_01")])
        self.artifact = PacketIFArtifact(
            model=SimpleNamespace(), model_path=self.dir / "m", metadata_path=self.dir / "meta",
            training_report_path=self.dir / "rep", model_version=MODEL, threshold=THRESHOLD, bundle_sha256=BUNDLE_SHA,
            capture_policy=CapturePolicy(),
            metadata={"threshold_percentile": 99.0, "dataset_sha256": "e" * 64,
                      "manifest_sha256": file_sha256(self.dir / "training.json"), "git_commit_sha": "b" * 40,
                      "normal_policy_version": POLICY_VERSION,
                      "sessions": {"train": ["t1"], "validation": ["v1"], "test": ["e1"]}})
        self.frame = pd.DataFrame([row(1, "n9", "normal", 0), row(2, "a9", "attack", 0),
                                   row(3, "n9", "normal", 1), row(4, "a9", "attack", 1)])
        self.request_extra = {}

    def install(self):
        by_name = {"training.json": self.training, "prior.json": self.prior}
        dataset = PacketIFDataset(train=self.frame.iloc[0:0], validation=self.frame.iloc[0:0], test=self.frame,
                                  manifest=self.external)
        patch = self.monkeypatch.setattr
        patch(holdout, "load_packet_if_artifact", lambda directory, **kwargs: self.artifact)
        patch(holdout, "load_packet_if_dataset", lambda csv, path, **kwargs: dataset)
        patch(holdout, "load_packet_if_manifest", lambda path, **kwargs: by_name[Path(path).name])
        patch(holdout, "predict_packet_feature_rows", lambda artifact, rows: tuple(
            PacketIFPrediction(MODEL, -SCORES[int(item["packet_feature_log_id"])], SCORES[int(item["packet_feature_log_id"])],
                               THRESHOLD, SCORES[int(item["packet_feature_log_id"])] > THRESHOLD, (0.0,) * 6)
            for item in rows))
        patch(holdout, "_resolve_evaluation_git_provenance",
              lambda sha: _EvaluationGitProvenance(sha or "c" * 40, True, "git_worktree_verified"))

    def request(self, purpose="DEVELOPMENT", **changes):
        request = {"schema_version": "packet-external-eval-request-v1", "purpose": purpose,
                   "artifact": {"dir": "artifact", "expected_bundle_sha256": BUNDLE_SHA},
                   "dataset": {"csv": "holdout.csv", "csv_sha256": file_sha256(self.dir / "holdout.csv"),
                               "manifest": "holdout.json", "manifest_sha256": file_sha256(self.dir / "holdout.json")},
                   "training_manifest": {"path": "training.json", "sha256": file_sha256(self.dir / "training.json")},
                   "prior_manifests": [{"path": "prior.json", "sha256": file_sha256(self.dir / "prior.json"),
                                        "role": "DEVELOPMENT_EVALUATION"}]}
        if purpose == "FINAL":
            request["freeze"] = {"record_sha256": "f" * 64, "frozen_at": FROZEN_AT.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "code_commit_sha": "c" * 40}
        request.update(changes)
        (self.dir / "request.json").write_text(json.dumps(request), encoding="utf-8")
        return request

    def run(self, name="result"):
        self.install()
        return evaluate_external_holdout(self.dir / "request.json", self.out / name)


@pytest.fixture
def case(tmp_path, monkeypatch):
    return Case(tmp_path, monkeypatch)


def test_development_evaluation_publishes_metrics_without_recalculating_the_threshold(case):
    case.request()

    report = case.run()

    assert report["status"] == "PASS" and report["row_count"] == 4 and report["blockers"] == []
    published = case.out / "result"
    summary = json.loads((published / "packet-if-evaluation.json").read_text())
    assert summary["evaluation_schema_version"] == "packet-if-external-evaluation-v1"
    assert summary["artifact"]["threshold"] == THRESHOLD
    assert (summary["overall"]["tp"], summary["overall"]["tn"], summary["overall"]["fp"], summary["overall"]["fn"]) == (2, 2, 0, 0)
    external = summary["external_evaluation"]
    assert external["purpose"] == "DEVELOPMENT" and external["final_evaluation"] is False
    assert external["threshold_recalculated"] is False and external["freeze"] is None
    assert {item["role"] for item in external["non_overlap_checked_against"]} == {"training", "DEVELOPMENT_EVALUATION"}
    assert report["training_approved"] is False
    for name in ("packet-if-predictions.jsonl", "packet-if-evaluation.csv", "evaluation-manifest.json",
                 "evaluation-manifest.json.sha256"):
        assert (published / name).is_file()


def test_final_evaluation_requires_data_collected_after_the_freeze(case):
    case.request("FINAL")
    report = case.run("ok")
    assert report["status"] == "PASS"
    external = json.loads((case.out / "ok" / "packet-if-evaluation.json").read_text())["external_evaluation"]
    assert external["final_evaluation"] is True and external["freeze"]["code_commit_sha"] == "c" * 40

    case.external = manifest([spec("n9", "test", started=FROZEN_AT - timedelta(days=1)),
                              spec("a9", "test", label="attack", target="esp32_01")])
    assert "freeze:session_not_collected_after_freeze" in case.run("early")["blockers"]
    case.external = manifest([spec("n9", "test", started=None), spec("a9", "test", label="attack", target="esp32_01")])
    assert "freeze:session_not_collected_after_freeze" in case.run("unstamped")["blockers"]


@pytest.mark.parametrize("field,build,code", [
    ("session_id", lambda: spec("t1", "test"), "overlap_session_id"),
    ("group", lambda: spec("n9", "test", group="group-t1"), "overlap_source_capture_group_id"),
    ("run", lambda: replace(spec("n9", "test"), run_manifest_ref=run_ref("run-t1")), "overlap_run_id"),
    ("slot", lambda: spec("n9", "test", slot="slot-t1"), "overlap_collection_slot_id"),
    ("renamed copy", lambda: spec("n9", "test", data=("t" * 64)[:64].replace("t", "9")), None),
])
def test_holdout_sharing_anything_with_training_is_refused(case, field, build, code):
    case.request()
    case.training = manifest([replace(spec("t1", "train", started=None), data_sha256="9" * 64),
                              spec("v1", "validation", started=None), spec("e1", "test", started=None)])
    case.external = manifest([build(), spec("a9", "test", label="attack", target="esp32_01")])

    report = case.run()

    if code is None:  # same data hash under a different Session name
        assert any(item.startswith("non_overlap:overlap_data_sha256") for item in report["blockers"])
    else:
        assert f"non_overlap:{code}" in report["blockers"]
    assert not (case.out / "result" / "packet-if-evaluation.json").exists()


def test_previously_used_datasets_count_as_training_history(case):
    case.request()
    case.prior = manifest([spec("n9", "test", started=None)])

    assert "non_overlap:overlap_session_id" in case.run()["blockers"]


@pytest.mark.parametrize("change,code", [
    ("training_hash", "training_evidence:training_manifest_not_the_artifact_manifest"),
    ("training_sessions", "training_evidence:training_manifest_sessions_differ_from_artifact"),
    ("policy", "contract:capture_policy_mismatch"),
    ("normal_policy", "contract:normal_policy_mismatch"),
    ("not_test", "contract:external_sessions_not_test"),
])
def test_contract_and_evidence_mismatches_hold_the_evaluation(case, change, code):
    case.request()
    if change == "training_hash":
        case.artifact = replace(case.artifact, metadata={**case.artifact.metadata, "manifest_sha256": "0" * 64})
    elif change == "training_sessions":
        case.training = manifest([spec("t1", "train", started=None), spec("e1", "test", started=None)])
    elif change == "policy":
        case.artifact = replace(case.artifact, capture_policy=CapturePolicy(max_start_delay_seconds=1.5))
    elif change == "normal_policy":
        case.artifact = replace(case.artifact, metadata={**case.artifact.metadata, "normal_policy_version": "other"})
    else:
        case.external = manifest([spec("n9", "validation"), spec("a9", "test", label="attack", target="esp32_01")])

    assert code in case.run()["blockers"]


@pytest.mark.parametrize("target,code", [
    ("csv", "inputs:dataset_checksum"),
    ("manifest", "inputs:dataset_manifest_checksum"),
    ("training", "inputs:training_manifest_checksum"),
    ("prior", "inputs:prior_manifest_checksum"),
])
def test_input_files_must_match_their_declared_hashes(case, target, code):
    case.request()
    (case.dir / {"csv": "holdout.csv", "manifest": "holdout.json", "training": "training.json",
                 "prior": "prior.json"}[target]).write_text("tampered", encoding="utf-8")

    assert code in case.run()["blockers"]


def test_a_prediction_that_changes_the_threshold_is_not_published(case):
    case.request()
    case.install()
    original = holdout.predict_packet_feature_rows
    case.monkeypatch.setattr(holdout, "predict_packet_feature_rows", lambda artifact, rows: tuple(
        replace(item, threshold=0.1, is_anomaly=item.anomaly_score > 0.1) for item in original(artifact, rows)))

    report = evaluate_external_holdout(case.dir / "request.json", case.out / "result")

    assert report["status"] == "HOLD" and any(item.startswith("evaluation:") for item in report["blockers"])
    assert not (case.out / "result" / "packet-if-evaluation.json").exists()


def test_inputs_changed_during_evaluation_are_not_published(case):
    case.request()
    case.install()
    original = holdout.predict_packet_feature_rows

    def tampering(artifact, rows):
        (case.dir / "holdout.csv").write_text("changed while evaluating", encoding="utf-8")
        return original(artifact, rows)

    case.monkeypatch.setattr(holdout, "predict_packet_feature_rows", tampering)

    report = evaluate_external_holdout(case.dir / "request.json", case.out / "result")

    assert report["status"] == "HOLD"
    assert not (case.out / "result" / "packet-if-evaluation.json").exists()


def test_inputs_changed_right_before_publication_are_not_published(case):
    case.request()
    case.install()
    real = holdout._evaluation_staging_directory

    def late_change(output_dir, *, before_publish=None):
        original = real(output_dir, before_publish=before_publish)

        class Late:
            def __enter__(self_inner):
                staging = original.__enter__()
                (case.dir / "holdout.csv").write_text("changed just before publish", encoding="utf-8")
                return staging

            def __exit__(self_inner, *exc):
                return original.__exit__(*exc)

        return Late()

    case.monkeypatch.setattr(holdout, "_evaluation_staging_directory", late_change)

    report = evaluate_external_holdout(case.dir / "request.json", case.out / "result")

    assert report["status"] == "HOLD" and any(item.startswith("evaluation:") for item in report["blockers"])
    assert not (case.out / "result" / "packet-if-evaluation.json").exists()


def test_existing_output_directory_is_never_replaced(case):
    case.request()
    (case.out / "result").mkdir(parents=True)

    assert case.run()["blockers"] == ["preflight:FileExistsError"]
    assert list((case.out / "result").iterdir()) == []


@pytest.mark.parametrize("mutate", [
    lambda r: r.update({"unexpected": 1}),
    lambda r: r.update({"schema_version": "v0"}),
    lambda r: r.update({"purpose": "TEST"}),
    lambda r: r["dataset"].update({"csv_sha256": "xyz"}),
    lambda r: r["artifact"].update({"expected_bundle_sha256": "short"}),
    lambda r: r.update({"freeze": {"record_sha256": "f" * 64, "frozen_at": "2026-10-14T00:00:00Z",
                                   "code_commit_sha": "c" * 40}}),
    lambda r: r["prior_manifests"][0].update({"role": "lowercase"}),
    lambda r: r.pop("training_manifest"),
])
def test_malformed_requests_are_refused_before_any_output(case, mutate):
    request = case.request()
    mutate(request)
    (case.dir / "request.json").write_text(json.dumps(request), encoding="utf-8")

    report = case.run()

    assert report["status"] == "HOLD" and report["blockers"][0].startswith("preflight:")
    assert not case.out.exists()


def test_final_request_without_a_freeze_record_is_refused(case):
    request = case.request("FINAL")
    request.pop("freeze")
    (case.dir / "request.json").write_text(json.dumps(request), encoding="utf-8")

    assert case.run()["blockers"] == ["preflight:freeze_required_for_final"]


def test_cli_exit_codes(case, capsys):
    case.request()
    case.install()
    argv = ["--request", str(case.dir / "request.json")]

    assert main([*argv, "--output-dir", str(case.out / "ok")]) == 0
    assert "training_approved=false" in capsys.readouterr().out
    assert main([*argv, "--output-dir", str(case.out / "ok")]) == 2
    assert "Blockers:" in capsys.readouterr().out


# ── Real loaders and a really trained artifact (nothing but git provenance is patched) ──────────────


def _real_case(tmp_path, monkeypatch, *, rename, dataset_version=PACKET_IF_DATASET_VERSION_V2,
               rename_only=False):
    """Train a real artifact, then derive an external Holdout bundle from its Test sessions."""
    from uuid import uuid4

    from ai.packet_if_dataset import session_data_sha256s
    from ai.train_packet_isolation_forest import train_from_files
    from tests.test_train_packet_isolation_forest import GIT_COMMIT_SHA, _write_training_bundle
    from tests.test_packet_if_dataset import _write_dataset_bundle

    training_dir = tmp_path / "training"
    training_dir.mkdir()
    dataset_path, manifest_path = _write_training_bundle(training_dir)
    if dataset_version == PACKET_IF_DATASET_VERSION_V2:
        original = json.loads(manifest_path.read_text(encoding="utf-8"))
        for session in original["sessions"]:
            session.pop("data_sha256")  # Recompute after the CSV is serialized by the v2 fixture.
        dataset_path, manifest_path = _write_dataset_bundle(
            training_dir, rows=pd.read_csv(dataset_path).to_dict(orient="records"), sessions=original["sessions"],
            manifest_overrides={"dataset_version": PACKET_IF_DATASET_VERSION_V2})
    artifacts = train_from_files(dataset_path=dataset_path, manifest_path=manifest_path,
                                 artifact_dir=training_dir / "packet-if-v1", git_commit_sha=GIT_COMMIT_SHA)

    manifest_json = json.loads(manifest_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(dataset_path)
    test_ids = [item["session_id"] for item in manifest_json["sessions"] if item["split"] == "test"]
    mapping = {old: (str(uuid4()) if rename else old) for old in test_ids}
    rows = frame[frame["session_id"].isin(test_ids)].copy()
    rows["session_id"] = rows["session_id"].map(mapping)
    if rename and not rename_only:
        rows["packet_feature_log_id"] = rows["packet_feature_log_id"] + 100_000
        rows["total_bytes"] = rows["total_bytes"] + 1
        for column in ("window_start", "window_end", "segment_window_start", "segment_window_end"):
            rows[column] = (pd.to_datetime(rows[column], utc=True) + pd.Timedelta(days=7)).dt.strftime(
                "%Y-%m-%dT%H:%M:%SZ")
    holdout_dir = tmp_path / "holdout"
    holdout_dir.mkdir()
    csv_path = holdout_dir / "holdout.csv"
    rows.to_csv(csv_path, index=False)
    hashes = session_data_sha256s(csv_path)
    sessions = []
    for item in manifest_json["sessions"]:
        if item["split"] != "test":
            continue
        session = {**item, "session_id": mapping[item["session_id"]],
                   "data_sha256": hashes[mapping[item["session_id"]]]}
        if dataset_version == PACKET_IF_DATASET_VERSION_V2:
            session.pop("data_sha256")
            session.pop("run_manifest_ref")  # Write an actual matching Run and sidecar for this Session.
            if rename and not rename_only:
                session["source_capture_group_id"] = mapping[item["session_id"]]
                session["collection_slot_id"] = f"slot-{session['session_id']}"
                for column in ("started_at", "first_window_start", "ended_at"):
                    session[column] = (pd.Timestamp(session[column]) + pd.Timedelta(days=7)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ")
        sessions.append(session)
    manifest_out = holdout_dir / "holdout-manifest.json"
    if dataset_version == PACKET_IF_DATASET_VERSION_V2:
        csv_path, manifest_out = _write_dataset_bundle(
            holdout_dir, rows=rows.to_dict(orient="records"), sessions=sessions,
            manifest_overrides={"dataset_version": PACKET_IF_DATASET_VERSION_V2})
    else:
        manifest_out.write_text(json.dumps({**manifest_json, "dataset_sha256": file_sha256(csv_path), "sessions": sessions}),
                                encoding="utf-8")
    request = {"schema_version": "packet-external-eval-request-v1", "purpose": "DEVELOPMENT",
               "artifact": {"dir": (training_dir / "packet-if-v1").as_posix(), "expected_bundle_sha256": artifacts.bundle_sha256},
               "dataset": {"csv": csv_path.relative_to(tmp_path).as_posix(), "csv_sha256": file_sha256(csv_path),
                           "manifest": manifest_out.relative_to(tmp_path).as_posix(), "manifest_sha256": file_sha256(manifest_out)},
               "training_manifest": {"path": "training/" + manifest_path.name, "sha256": file_sha256(manifest_path)}}
    (tmp_path / "request.json").write_text(json.dumps(request), encoding="utf-8")
    monkeypatch.setattr(holdout, "_resolve_evaluation_git_provenance",
                        lambda sha: _EvaluationGitProvenance(sha or "c" * 40, True, "git_worktree_verified"))
    return tmp_path / "request.json", artifacts


def test_real_artifact_scores_an_independent_v2_holdout_with_its_own_threshold(tmp_path, monkeypatch):
    request, artifacts = _real_case(tmp_path, monkeypatch, rename=True)

    report = evaluate_external_holdout(request, tmp_path / "evaluation")

    assert report["status"] == "PASS", report["blockers"]
    summary = json.loads((tmp_path / "evaluation" / "packet-if-evaluation.json").read_text())
    assert summary["artifact"]["bundle_sha256"] == artifacts.bundle_sha256
    assert summary["overall"]["row_count"] == 40 and summary["external_evaluation"]["threshold_recalculated"] is False
    assert summary["dataset"]["test_session_ids"] != summary["artifact"]["training_sessions"]["test"]


def test_real_artifact_refuses_its_own_test_sessions_as_a_holdout(tmp_path, monkeypatch):
    request, _ = _real_case(tmp_path, monkeypatch, rename=False)

    report = evaluate_external_holdout(request, tmp_path / "evaluation")

    assert report["status"] == "HOLD" and "non_overlap:overlap_session_id" in report["blockers"]
    assert not (tmp_path / "evaluation" / "packet-if-evaluation.json").exists()


@pytest.mark.parametrize("version,expected", [
    (PACKET_IF_DATASET_VERSION_V1, "contract:external_dataset_requires_v2"),
    (PACKET_IF_DATASET_VERSION_V2, "non_overlap:overlap_source_capture_group_id"),
])
def test_real_renamed_copy_cannot_pass_as_an_independent_holdout(tmp_path, monkeypatch, version, expected):
    request_path, _ = _real_case(tmp_path, monkeypatch, rename=True, dataset_version=version, rename_only=True)
    request = json.loads(request_path.read_text(encoding="utf-8"))
    training_path = next((tmp_path / "training").glob("packet_if*.csv"))
    if version == PACKET_IF_DATASET_VERSION_V2:
        training_path = tmp_path / "training" / "packet_if.csv"
    training = pd.read_csv(training_path)
    original_manifest = json.loads((tmp_path / request["training_manifest"]["path"]).read_text(encoding="utf-8"))
    test_ids = [session["session_id"] for session in original_manifest["sessions"] if session["split"] == "test"]
    original = training[training["session_id"].isin(test_ids)].drop(columns="session_id").reset_index(drop=True)
    copied = pd.read_csv(tmp_path / request["dataset"]["csv"]).drop(columns="session_id")
    pd.testing.assert_frame_equal(original, copied, check_dtype=False)

    report = evaluate_external_holdout(request_path, tmp_path / "evaluation")

    assert report["status"] == "HOLD" and expected in report["blockers"]
    assert not (tmp_path / "evaluation" / "packet-if-evaluation.json").exists()


@pytest.mark.parametrize("kind,expected", [
    ("external", "contract:external_dataset_requires_v2"),
    ("training", "training_evidence:training_manifest_requires_v2"),
    ("prior", "non_overlap:prior_manifest_requires_v2"),
])
def test_every_comparison_manifest_requires_v2_provenance(case, kind, expected):
    case.request()
    setattr(case, kind, replace(getattr(case, kind), dataset_version=PACKET_IF_DATASET_VERSION_V1))

    report = case.run()

    assert report["status"] == "HOLD" and expected in report["blockers"]
    assert not (case.out / "result" / "packet-if-evaluation.json").exists()


# ── Opt-in loader mode: the default three-split contract must not change ────────────────────────────


def _validate(sessions, **kwargs):
    from ai.packet_if_dataset import _validate_manifest_sessions

    _validate_manifest_sessions(tuple(sessions), dataset_version=PACKET_IF_DATASET_VERSION_V1, **kwargs)


def test_default_loader_still_requires_all_three_splits_and_both_test_labels():
    with pytest.raises(ValueError, match="missing splits"):
        _validate([spec("n9", "test"), spec("a9", "test", label="attack", target="esp32_01")])
    with pytest.raises(ValueError, match="missing splits"):
        _validate([spec("n9", "test")], external_holdout=False)


def test_external_mode_accepts_a_normal_only_or_attack_only_holdout():
    _validate([spec("n9", "test")], external_holdout=True)
    attack = replace(spec("a9", "test", label="attack", target="esp32_01"),
                     devices=(PacketIFSessionDevice("esp32_01", "192.168.0.4"),))
    _validate([attack], external_holdout=True)


def test_external_mode_refuses_training_splits():
    with pytest.raises(ValueError, match="only test sessions"):
        _validate([spec("n9", "test"), spec("t1", "train")], external_holdout=True)
    with pytest.raises(ValueError, match="only test sessions"):
        _validate([spec("v1", "validation")], external_holdout=True)
