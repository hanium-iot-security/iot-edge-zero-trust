"""Candidate-only MQTT input linkage and split isolation, using bounded artifacts."""
import csv
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from uuid import uuid4

import pytest

from ai.export_normal_collection import MQTT_COLUMNS, SCHEMA_VERSION, mqtt_qc_policy
from ai.mqtt_if_dataset import DATASET_SCHEMA, ROLE_SPLITS, load_mqtt_if_dataset
from ai.normal_admission import REPORT_SCHEMA, REQUEST_SCHEMA, review_admission
from ai.normal_selection_policy import PHASE9_POLICY

DEVICES = ["esp32_01", "esp32_02", "pico_01"]
START = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _utc(value):
    return value.isoformat().replace("+00:00", "Z")


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _ref(path, root):
    return {"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _device_specs(start):
    return [{"device_id": device, "firmware_id": "test-installed-v1",
             "payload_schema": "pico-bme280-v1" if device == "pico_01" else "esp32-telemetry-v1",
             "profile": "P0", "effective_from": _utc(start - timedelta(hours=1)),
             "evidence": {"kind": "INSTALLED_BINARY_READBACK", "sha256": "e" * 64,
                          "observed_at": _utc(start - timedelta(minutes=1))}} for device in DEVICES]


def _dataset_spec(groups):
    return {"schema_version": DATASET_SCHEMA, "normal_selection_policy": PHASE9_POLICY,
            "device_ids": DEVICES, "groups": groups}


def _write_dataset(tmp_path: Path) -> Path:
    """Reusable synthetic fixture: eight full windows/device in each independent role.

    CSV edits only need their mqtt_features reference hash refreshed when row counts
    remain unchanged. A separate integration test below uses real admission/export.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    groups = []
    for index, (role, split) in enumerate(ROLE_SPLITS.items()):
        root = tmp_path / role
        root.mkdir()
        start = START + timedelta(days=index)
        run_id, group_id = str(uuid4()), str(uuid4())
        source = {"schema_version": SCHEMA_VERSION, "status": "RAW_CAPTURED",
                  "training_approved": False, "whole_capture_session_approved": False,
                  "run_id": run_id, "source_capture_group_id": group_id, "capture_session_pk": 1,
                  "start_utc": _utc(start), "end_utc": _utc(start + timedelta(seconds=80)),
                  "included_device_ids": DEVICES, "code_commit": "a" * 40,
                  "devices": [{"device_id": device, "status": "normal", "trust_score": 100} for device in DEVICES],
                  "snapshot": {"path": "after.db", "sha256": "b" * 64}}
        _write_json(root / "manifest.json", source)
        with (root / "mqtt-features.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=MQTT_COLUMNS)
            writer.writeheader()
            for window in range(8):
                for device_index, device in enumerate(DEVICES):
                    size = (130 if device == "pico_01" else 65) + window + index
                    writer.writerow({"id": 1 + window * 3 + device_index, "device_id": device,
                        "window_start": _utc(start + timedelta(seconds=window * 10)),
                        "window_end": _utc(start + timedelta(seconds=window * 10 + 10)),
                        "publish_count": 2, "avg_payload_size": size, "max_payload_size": size,
                        "avg_message_interval": 5, "min_message_interval": 5,
                        "topic_count": 1, "abnormal_topic_count": 0, "malformed_payload_count": 0})
        qc = {key: source[key] for key in ("schema_version", "training_approved", "whole_capture_session_approved",
              "run_id", "source_capture_group_id", "capture_session_pk", "start_utc", "end_utc", "code_commit")}
        qc.update(status="PASS", hold_reasons=[], counts={"mqtt_features": 24},
                  qc_policy={device: mqtt_qc_policy("P0") for device in DEVICES})
        _write_json(root / "qc-report.json", qc)
        specs = _device_specs(start)
        request = {"schema_version": REQUEST_SCHEMA,
                   "runs": [{"run_dir": role, "manifest_sha256": _ref(root / "manifest.json", tmp_path)["sha256"]}],
                   "final_snapshot": {"path": "final.db", "sha256": "f" * 64}, "device_specs": specs,
                   "slots": [{"collection_slot_id": role + "-1", "run_id": run_id, "split": split}]}
        _write_json(root / "request.json", request)
        report_specs = [{**{key: item[key] for key in ("device_id", "firmware_id", "payload_schema", "profile", "effective_from")},
                         "evidence_kind": item["evidence"]["kind"], "evidence_sha256": item["evidence"]["sha256"]}
                        for item in specs]
        report = {"schema_version": REPORT_SCHEMA, "status": "PASS", "official_admission": "BOUNDED_ELIGIBLE",
                  "training_approved": False, "whole_capture_session_approved": False, "blockers": [],
                  "capture_group": {"source_capture_group_id": group_id, "capture_session_pk": 1, "split": split},
                  "final_snapshot_sha256": "f" * 64, "whole_session": {"session_status": "COMPLETED", "whole_session_eligible": False},
                  "runs": [{"run_id": run_id, "run_dir": role, "candidate_qc": "PASS", "hold_reasons": [],
                            "counts": qc["counts"], "qc_profiles": {device: "P0" for device in DEVICES}}],
                  "range_consistency": [{"run_id": run_id, "match": True}], "device_specs": report_specs}
        _write_json(root / "admission-report.json", report)
        groups.append({"role": role, "admission_request": _ref(root / "request.json", tmp_path),
                       "admission_report": _ref(root / "admission-report.json", tmp_path),
                       "runs": [{"manifest": _ref(root / "manifest.json", tmp_path),
                                 "qc_report": _ref(root / "qc-report.json", tmp_path),
                                 "mqtt_features": _ref(root / "mqtt-features.csv", tmp_path)}]})
    path = tmp_path / "dataset.json"
    _write_json(path, _dataset_spec(groups))
    return path


def _edit_json(root, reference, change):
    path = root / reference["path"]
    value = _read_json(path)
    change(value)
    _write_json(path, value)
    reference.update(_ref(path, root))


@pytest.mark.parametrize("location", ["admission", "reviewed_run", "qc"])
def test_dataset_rejects_unrequested_reception_policy(tmp_path, location):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    group = spec["groups"][0]
    if location == "admission":
        _edit_json(tmp_path, group["admission_report"],
                   lambda report: report.update(reception_policy="pico-p0-wire-jitter-v1"))
    elif location == "reviewed_run":
        _edit_json(tmp_path, group["admission_report"],
                   lambda report: report["runs"][0].update(reception_policy="pico-p0-wire-jitter-v1"))
    else:
        _edit_json(tmp_path, group["runs"][0]["qc_report"],
                   lambda qc: qc.update(reception_policy="pico-p0-wire-jitter-v1"))
    _write_json(path, spec)
    with pytest.raises(ValueError, match="reception_policy_link"):
        load_mqtt_if_dataset(path)


def _edit_csv(root, reference, change):
    path = root / reference["path"]
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    change(rows)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MQTT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    reference.update(_ref(path, root))


def test_loads_typed_group_isolated_rows_and_keeps_pico_above_100_bytes(tmp_path):
    path = _write_dataset(tmp_path)
    result = load_mqtt_if_dataset(path)
    assert set(result.rows) == set(ROLE_SPLITS)
    assert all(len(rows) == 24 for rows in result.rows.values())
    assert all(isinstance(row["publish_count"], int) and isinstance(row["avg_payload_size"], float)
               for rows in result.rows.values() for row in rows)
    assert all(row["avg_payload_size"] > 100 for row in result.rows["train"] if row["device_id"] == "pico_01")
    assert result.provenance["scope"] == "offline_candidate_only"
    assert result.provenance["training_approved"] is False
    assert result.provenance["operational_activation_verified"] is False
    assert len(result.provenance["inputs"]) == 16
    assert result.provenance["manifest_sha256"] == _ref(path, tmp_path)["sha256"]
    assert result.provenance["roles"]["train"]["counts_by_device"]["pico_01"] == {
        "input_rows": 8, "selected_rows": 8, "excluded_rows": 0, "exclusion_reasons": {}}


def test_selection_follows_complete_window_validation_and_records_each_device(tmp_path):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    _edit_csv(tmp_path, spec["groups"][0]["runs"][0]["mqtt_features"],
              lambda rows: rows[0].update(publish_count="4"))
    _write_json(path, spec)
    result = load_mqtt_if_dataset(path)
    assert len(result.rows["train"]) == 23
    assert result.provenance["roles"]["train"]["counts_by_device"]["esp32_01"] == {
        "input_rows": 8, "selected_rows": 7, "excluded_rows": 1,
        "exclusion_reasons": {"publish_count_outside_1_3": 1}}


def test_each_declared_device_requires_selected_rows_in_every_role(tmp_path):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    _edit_csv(tmp_path, spec["groups"][2]["runs"][0]["mqtt_features"],
              lambda rows: [row.update(publish_count="4") for row in rows if row["device_id"] == "pico_01"])
    _write_json(path, spec)
    with pytest.raises(ValueError, match="role_device_rows_required"):
        load_mqtt_if_dataset(path)


@pytest.mark.parametrize("mutation,error", [
    (lambda rows: rows.pop(), "incomplete_mqtt_windows"),
    (lambda rows: rows.append(dict(rows[0])), "duplicate_or_invalid_feature_id"),
    (lambda rows: rows[0].update(window_end="2026-10-04T00:00:09Z"), "invalid_or_partial_mqtt_window"),
    (lambda rows: rows[0].update(device_id="unknown"), "invalid_or_partial_mqtt_window"),
    (lambda rows: rows[0].update(publish_count="2.0"), "mqtt_integer_field"),
    (lambda rows: rows[0].update(avg_payload_size="nan"), "finite"),
    (lambda rows: rows[0].update(avg_payload_size="1e99"), "float32"),
    (lambda rows: rows[0].update(publish_count="1", avg_message_interval="4"), "fallback"),
])
def test_invalid_csv_cannot_be_hidden_by_selection(tmp_path, mutation, error):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    _edit_csv(tmp_path, spec["groups"][0]["runs"][0]["mqtt_features"], mutation)
    _write_json(path, spec)
    with pytest.raises(ValueError, match=error):
        load_mqtt_if_dataset(path)


@pytest.mark.parametrize("change,error", [
    (lambda spec: spec["groups"].pop(), "role_device_rows_required"),
    (lambda spec: spec["groups"].append(spec["groups"][0]), "duplicate_capture_group"),
    (lambda spec: spec["groups"][0].update(role="calibration"), "role_split_mismatch"),
    (lambda spec: spec.update(normal_selection_policy="legacy-100b-v1"), "dataset_selection_policy"),
    (lambda spec: spec["groups"][0]["runs"][0]["mqtt_features"].update(sha256="0" * 64), "input_checksum"),
    (lambda spec: spec["groups"][0]["runs"][0]["mqtt_features"].update(path="../outside.csv"), "unsafe_relative_path"),
])
def test_rejects_leakage_missing_roles_and_unpinned_inputs(tmp_path, change, error):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    change(spec)
    _write_json(path, spec)
    with pytest.raises(ValueError, match=error):
        load_mqtt_if_dataset(path)


@pytest.mark.parametrize("artifact,change,error", [
    ("admission_report", lambda value: value.update(official_admission="HOLD"), "admission_not_eligible"),
    ("admission_report", lambda value: value.update(training_approved=True), "approval_must_remain_false"),
    ("admission_report", lambda value: value["capture_group"].update(split="UNASSIGNED"), "role_split_mismatch"),
    ("admission_report", lambda value: value["runs"][0]["counts"].update(mqtt_features=9), "qc_counts_link"),
    ("admission_report", lambda value: value["range_consistency"][0].update(match=False), "run_split_or_consistency"),
    ("admission_request", lambda value: value["runs"][0].update(manifest_sha256="0" * 64), "request_manifest_link"),
    ("admission_request", lambda value: value["slots"][0].update(collection_slot_id="train-1"), "duplicate_collection_slot"),
    ("admission_request", lambda value: value["final_snapshot"].update(sha256="0" * 64), "final_snapshot_link"),
])
def test_rejects_broken_admission_links(tmp_path, artifact, change, error):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    _edit_json(tmp_path, spec["groups"][1][artifact], change)
    _write_json(path, spec)
    with pytest.raises(ValueError, match=error):
        load_mqtt_if_dataset(path)


def test_rejects_same_run_in_another_capture_group(tmp_path):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    first_run = _read_json(tmp_path / spec["groups"][0]["runs"][0]["manifest"]["path"])["run_id"]
    _edit_json(tmp_path, spec["groups"][1]["runs"][0]["manifest"], lambda value: value.update(run_id=first_run))
    _write_json(path, spec)
    with pytest.raises(ValueError, match="duplicate_run"):
        load_mqtt_if_dataset(path)


@pytest.mark.parametrize("with_reception_review", [False, True])
def test_real_export_and_admission_outputs_load_without_mutating_sources(tmp_path, monkeypatch,
                                                                       with_reception_review):
    from tests import test_normal_collection_export as base

    groups = []
    for index, (role, split) in enumerate(ROLE_SPLITS.items()):
        root = tmp_path / role / "source"
        root.mkdir(parents=True)
        start = START + timedelta(days=index)
        monkeypatch.setattr(base, "START", start)
        package = base.package.__wrapped__(root)
        if with_reception_review and role == "calibration":
            strict = base.wire_jitter_package(package)
            assert strict["hold_reasons"] == ["mqtt:pico_01:reception_gap_or_burst"]
        source = _read_json(package / "manifest.json")
        shutil.copy(package / "after.db", root / "final.db")
        with closing(sqlite3.connect(root / "final.db")) as db:
            db.execute("UPDATE packet_capture_sessions SET status='COMPLETED', ended_at=?",
                       (_utc(start + timedelta(seconds=30)),))
            db.commit()
        request = {"schema_version": REQUEST_SCHEMA,
                   "runs": [{"run_dir": "candidate", "manifest_sha256": _ref(package / "manifest.json", tmp_path)["sha256"]}],
                   "final_snapshot": {"path": "final.db", "sha256": _ref(root / "final.db", tmp_path)["sha256"]},
                   "device_specs": _device_specs(start),
                   "slots": [{"collection_slot_id": role + "-1", "run_id": source["run_id"], "split": split}]}
        if with_reception_review and role == "calibration":
            request.update(schema_version="normal-admission-request-v2",
                           reception_policy="pico-p0-wire-jitter-v1")
            request["runs"][0]["source_qc_sha256"] = _ref(package / "qc-report.json", tmp_path)["sha256"]
        _write_json(root / "request.json", request)
        output = tmp_path / role / "review"
        report = review_admission(root, root / "request.json", output)
        assert report["status"] == "PASS", report
        groups.append({"role": role, "admission_request": _ref(root / "request.json", tmp_path),
                       "admission_report": _ref(output / "admission-report.json", tmp_path),
                       "runs": [{"manifest": _ref(package / "manifest.json", tmp_path),
                                 "qc_report": _ref(output / "qc/run-01/qc-report.json", tmp_path),
                                 "mqtt_features": _ref(output / "qc/run-01/mqtt-features.csv", tmp_path)}]})
    path = tmp_path / "dataset.json"
    _write_json(path, _dataset_spec(groups))
    before = base.tree_hashes(tmp_path)
    result = load_mqtt_if_dataset(path)
    assert [len(result.rows[role]) for role in ROLE_SPLITS] == [6, 6, 6]
    assert base.tree_hashes(tmp_path) == before
    assert result.provenance["training_approved"] is False
    if with_reception_review:
        # Even a same-Run QC with unchanged counts/evidence must be the exact reviewed file.
        entry = groups[1]["runs"][0]["qc_report"]
        _edit_json(tmp_path, entry,
                   lambda qc: qc["qc_policy"]["pico_01"].update(reception_gap_seconds=[0.0, 999.0]))
        _write_json(path, _dataset_spec(groups))
        with pytest.raises(ValueError, match="derived_qc_checksum"):
            load_mqtt_if_dataset(path)



def _terminal_dataset(tmp_path):
    path = _write_dataset(tmp_path)
    spec = _read_json(path)
    group = spec["groups"][1]
    source = _read_json(tmp_path / group["runs"][0]["manifest"]["path"])
    start = datetime.fromisoformat(source["start_utc"].replace("Z", "+00:00"))
    terminal = {"policy": "failed-after-selected-range-v1", "capture_session_pk": source["capture_session_pk"],
                "source_capture_group_id": source["source_capture_group_id"], "status": "FAILED",
                "ended_at": _utc(start + timedelta(seconds=320))}
    _edit_json(tmp_path, group["admission_request"], lambda value: value.update(
        schema_version="normal-admission-request-v3", reception_policy="strict-v1", terminal_source=terminal))
    _edit_json(tmp_path, group["admission_report"], lambda value: value.update(
        terminal_source=terminal, whole_session={"session_status": "FAILED", "whole_session_eligible": False,
        "session_ended_at": terminal["ended_at"], "ineligible_segments": [{"segment_id": 99,
        "window_start": _utc(start + timedelta(seconds=300)), "window_end": _utc(start + timedelta(seconds=310)),
        "status": "FAILED", "error_code": "PARTIAL_CAPTURE"}]}))
    _write_json(path, spec)
    return path


def test_terminal_failed_dataset_retains_explicit_contract_provenance(tmp_path):
    path = _terminal_dataset(tmp_path)
    result = load_mqtt_if_dataset(path)
    assert len(result.rows["calibration"]) == 24
    assert result.provenance["groups"][1]["terminal_source"]["status"] == "FAILED"
    assert result.provenance["training_approved"] is False


@pytest.mark.parametrize("change", ["completed", "running", "whole_eligible", "changed_end", "missing_end",
    "missing_contract", "wrong_identity", "early_end", "overlap", "empty_failures", "old_schema",
    "contract_tamper", "unknown_policy"])
def test_terminal_failed_dataset_rejects_changed_contract_or_scope(tmp_path, change):
    path = _terminal_dataset(tmp_path)
    spec = _read_json(path)
    group = spec["groups"][1]
    def alter(report):
        whole = report["whole_session"]
        if change in ("completed", "running"):
            whole["session_status"] = change.upper()
        elif change == "whole_eligible":
            whole["whole_session_eligible"] = True
        elif change == "changed_end":
            whole["session_ended_at"] = "2026-10-05T00:05:21Z"
        elif change == "missing_end":
            whole.pop("session_ended_at")
        elif change == "missing_contract":
            report.pop("terminal_source")
        elif change == "wrong_identity":
            report["capture_group"]["source_capture_group_id"] = str(uuid4())
        elif change == "overlap":
            whole["ineligible_segments"][0].update(window_start="2026-10-05T00:00:00Z",window_end="2026-10-05T00:00:10Z")
        elif change == "empty_failures":
            whole["ineligible_segments"] = []
        elif change == "contract_tamper":
            report["terminal_source"]["ended_at"] = "2026-10-05T00:05:21Z"
    if change in ("old_schema", "early_end", "unknown_policy"):
        def alter_request(request):
            if change == "old_schema":
                request["schema_version"] = "normal-admission-request-v1"
                request.pop("terminal_source")
                request.pop("reception_policy")
            elif change == "early_end":
                request["terminal_source"]["ended_at"] = "2026-10-05T00:00:10Z"
            else:
                request["terminal_source"]["policy"] = "anything"
        _edit_json(tmp_path, group["admission_request"], alter_request)
    else:
        _edit_json(tmp_path, group["admission_report"], alter)
    _write_json(path, spec)
    with pytest.raises(ValueError):
        load_mqtt_if_dataset(path)



def test_real_terminal_v3_export_admission_and_dataset_keep_sources_unchanged(tmp_path, monkeypatch):
    from tests import test_normal_admission as cases
    from tests import test_normal_collection_export as base

    groups = []
    for index, (role, split) in enumerate(ROLE_SPLITS.items()):
        root = tmp_path / role / "source"
        root.mkdir(parents=True)
        start = START + timedelta(days=index)
        monkeypatch.setattr(base, "START", start)
        monkeypatch.setattr(cases, "START", start)
        package = base.package.__wrapped__(root)
        case = cases.case.__wrapped__(package, root)
        request = cases._terminal_request(case, package, wire=role == "calibration")
        request["slots"][0].update(collection_slot_id=role + "-terminal", split=split)
        _write_json(root / "request.json", request)
        before = base.tree_hashes(root)
        report = case.review()
        assert report["status"] == "PASS", report
        assert base.tree_hashes(root) == before
        output = case.out / "review"
        groups.append({"role": role, "admission_request": _ref(root / "request.json", tmp_path),
                       "admission_report": _ref(output / "admission-report.json", tmp_path),
                       "runs": [{"manifest": _ref(package / "manifest.json", tmp_path),
                                 "qc_report": _ref(output / "qc/run-01/qc-report.json", tmp_path),
                                 "mqtt_features": _ref(output / "qc/run-01/mqtt-features.csv", tmp_path)}]})
    path = tmp_path / "dataset.json"
    _write_json(path, _dataset_spec(groups))
    before = base.tree_hashes(tmp_path)
    result = load_mqtt_if_dataset(path)
    assert [len(result.rows[role]) for role in ROLE_SPLITS] == [6, 6, 6]
    assert all(group["terminal_source"]["status"] == "FAILED" for group in result.provenance["groups"])
    assert result.provenance["training_approved"] is False
    assert base.tree_hashes(tmp_path) == before
