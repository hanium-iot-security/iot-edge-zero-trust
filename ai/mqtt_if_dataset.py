"""Load hash-pinned bounded MQTT candidates for offline experiments, without approval.

The request/report linkage checks recorded provenance, not the truth of evidence or
raw-data QC. It neither reruns admission nor promotes BOUNDED_ELIGIBLE to approval.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import re

from ai.export_normal_collection import (
    MQTT_COLUMNS, SCHEMA_VERSION as CANDIDATE_SCHEMA, TARGETS,
    _metadata, _path, _require, _time, _within,
)
from ai.mqtt_if_contract import MQTT_IF_FEATURES, MQTT_IF_INTEGER_FEATURES, mqtt_feature_matrix
from ai.normal_admission import REPORT_SCHEMA, TERMINAL_REQUEST_SCHEMA, load_request, validate_terminal_selection
from ai.normal_selection_policy import PHASE9_POLICY, exclusion_reasons
from ai.pico_reception_qc import STRICT_POLICY, WIRE_JITTER_POLICY

DATASET_SCHEMA = "mqtt-if-candidate-dataset-v1"
ROLE_SPLITS = {"train": "train", "calibration": "validation", "validation": "validation"}


@dataclass(frozen=True)
class MQTTIFDataset:
    rows: dict[str, tuple[dict, ...]]
    provenance: dict


def _exact(value, keys, code):
    _require(isinstance(value, dict) and set(value) == set(keys), code)


def _json(content):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("non_finite_json")

    return json.loads(content, object_pairs_hook=pairs, parse_constant=invalid_constant)


class _Inputs:
    def __init__(self, root):
        self.root = root
        self.files = {}

    def read(self, reference):
        _exact(reference, ("path", "sha256"), "input_reference_fields")
        name, expected = reference["path"], reference["sha256"]
        _require(isinstance(name, str) and ".." not in Path(name).parts, "unsafe_relative_path")
        path = _path(self.root, name)
        _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "invalid_sha256")
        _require(path not in self.files or self.files[path] == expected, "conflicting_input_checksum")
        content = path.read_bytes()
        _require(hashlib.sha256(content).hexdigest() == expected, "input_checksum")
        self.files[path] = expected
        return content

    def json(self, reference):
        return _json(self.read(reference))

    def records(self):
        return [{"path": path.relative_to(self.root).as_posix(), "sha256": sha}
                for path, sha in sorted(self.files.items())]

    def verify_unchanged(self):
        for path, sha in self.files.items():
            _require(hashlib.sha256(path.read_bytes()).hexdigest() == sha, "input_changed_during_load")


def _index(items, key, code):
    _require(isinstance(items, list) and all(isinstance(item, dict) and key in item for item in items), code)
    result = {item[key]: item for item in items}
    _require(len(result) == len(items), code)
    return result


def _unapproved(document):
    _require(document.get("training_approved") is False
             and document.get("whole_capture_session_approved") is False, "approval_must_remain_false")


def _count():
    return {"input_rows": 0, "selected_rows": 0, "excluded_rows": 0, "exclusion_reasons": {}}


def _read_rows(content, manifest, start, end, devices):
    reader = csv.DictReader(io.StringIO(content.decode("utf-8"), newline=""))
    _require(reader.fieldnames == list(MQTT_COLUMNS), "mqtt_csv_columns")
    rows, seen, row_ids = [], set(), set()
    integers = MQTT_IF_INTEGER_FEATURES | {"id", "topic_count", "abnormal_topic_count", "malformed_payload_count"}
    for raw in reader:
        _require(set(raw) == set(MQTT_COLUMNS) and all(value is not None for value in raw.values()), "mqtt_csv_row")
        row = dict(raw)
        for key in integers:
            _require(re.fullmatch(r"[0-9]+", raw[key]) is not None, "mqtt_integer_field")
            row[key] = int(raw[key])
        for key in set(MQTT_IF_FEATURES) - integers:
            row[key] = float(raw[key])
        _require(row["id"] > 0 and row["id"] not in row_ids, "duplicate_or_invalid_feature_id")
        _require(row["device_id"] in devices and _within(row, start, end), "invalid_or_partial_mqtt_window")
        key = (row["device_id"], _time(row["window_start"]))
        _require(key not in seen, "duplicate_mqtt_window")
        seen.add(key)
        row_ids.add(row["id"])
        row.update(source_capture_group_id=manifest["source_capture_group_id"], run_id=manifest["run_id"])
        rows.append(row)
    expected = {(device, start + timedelta(seconds=offset)) for device in devices
                for offset in range(0, int((end - start).total_seconds()), 10)}
    _require(seen == expected, "incomplete_mqtt_windows")
    mqtt_feature_matrix(rows)
    return rows


def load_mqtt_if_dataset(manifest_path: Path) -> MQTTIFDataset:
    """Read existing candidate artifacts only; require complete windows before selection."""
    manifest_path = Path(manifest_path).resolve()
    content = manifest_path.read_bytes()
    spec = _json(content)
    _exact(spec, ("schema_version", "normal_selection_policy", "device_ids", "groups"), "dataset_fields")
    _require(spec["schema_version"] == DATASET_SCHEMA, "dataset_schema")
    _require(spec["normal_selection_policy"] == PHASE9_POLICY, "dataset_selection_policy")
    devices = spec["device_ids"]
    _require(isinstance(devices, list) and devices and all(isinstance(value, str) for value in devices)
             and len(set(devices)) == len(devices) and set(devices) <= TARGETS, "dataset_devices")
    _require(isinstance(spec["groups"], list) and spec["groups"], "dataset_groups")
    inputs = _Inputs(manifest_path.parent)
    manifest_sha = hashlib.sha256(content).hexdigest()
    inputs.files[manifest_path] = manifest_sha
    rows = {role: [] for role in ROLE_SPLITS}
    roles = {role: {"group_ids": [], "run_ids": [], "row_count": 0,
                    "counts_by_device": {device: _count() for device in devices}} for role in ROLE_SPLITS}
    groups, seen_groups, seen_runs, seen_slots = [], set(), set(), set()

    for group in spec["groups"]:
        _exact(group, ("role", "admission_request", "admission_report", "runs"), "group_fields")
        role = group["role"]
        _require(isinstance(role, str) and role in ROLE_SPLITS, "dataset_role")
        _require(isinstance(group["runs"], list) and group["runs"], "group_runs")
        inputs.json(group["admission_request"])
        request = load_request(_path(inputs.root, group["admission_request"]["path"]))
        report = inputs.json(group["admission_report"])
        _unapproved(report)
        reception_policy = request.get("reception_policy", STRICT_POLICY)
        _require(report.get("reception_policy", STRICT_POLICY) == reception_policy, "reception_policy_link")
        _require(report.get("schema_version") == REPORT_SCHEMA and report.get("status") == "PASS"
                 and report.get("official_admission") == "BOUNDED_ELIGIBLE"
                 and report.get("blockers") == [], "admission_not_eligible")
        terminal = request.get("terminal_source")
        _require(report.get("final_snapshot_sha256") == request["final_snapshot"]["sha256"], "final_snapshot_link")
        if request["schema_version"] == TERMINAL_REQUEST_SCHEMA:
            _require(report.get("terminal_source") == terminal, "terminal_source_link")
        else:
            _require("terminal_source" not in report
                     and report.get("whole_session", {}).get("session_status") == "COMPLETED", "final_snapshot_link")
        capture = report["capture_group"]
        group_id, split = capture["source_capture_group_id"], capture["split"]
        _require(group_id not in seen_groups, "duplicate_capture_group")
        _require(split == ROLE_SPLITS[role], "role_split_mismatch")
        seen_groups.add(group_id)
        report_runs = _index(report["runs"], "run_id", "admission_runs")
        request_runs = _index(request["runs"], "run_dir", "request_runs")
        slots = _index(request["slots"], "run_id", "request_slots")
        consistency = _index(report["range_consistency"], "run_id", "range_consistency")
        specs = _index(request["device_specs"], "device_id", "device_specs")
        report_specs = _index(report["device_specs"], "device_id", "report_device_specs")
        _require(set(report_specs) == set(specs), "device_specs_link")
        for device, item in specs.items():
            expected_spec = {key: item[key] for key in ("device_id", "firmware_id", "payload_schema", "profile", "effective_from")}
            expected_spec.update(evidence_kind=item["evidence"]["kind"], evidence_sha256=item["evidence"]["sha256"])
            _require(report_specs[device] == expected_spec, "device_specs_link")

        run_records, bounds, group_devices, directories = [], [], set(), set()
        for entry in group["runs"]:
            _exact(entry, ("manifest", "qc_report", "mqtt_features"), "run_fields")
            source = inputs.json(entry["manifest"])
            start, end, included = _metadata(source, allow_completed=True,
                                             allow_reception_hold=reception_policy == WIRE_JITTER_POLICY)
            run_id = source["run_id"]
            _require(run_id not in seen_runs, "duplicate_run")
            seen_runs.add(run_id)
            _require(set(included) <= set(devices) and set(included) <= set(specs), "run_device_set")
            _require(source["source_capture_group_id"] == group_id
                     and source["capture_session_pk"] == capture["capture_session_pk"], "capture_group_link")
            _require(run_id in report_runs and run_id in slots and run_id in consistency, "admission_run_set")
            reviewed, slot = report_runs[run_id], slots[run_id]
            directory = reviewed["run_dir"]
            _require(directory in request_runs and directory not in directories
                     and request_runs[directory]["manifest_sha256"] == entry["manifest"]["sha256"], "request_manifest_link")
            directories.add(directory)
            _require(slot["collection_slot_id"] not in seen_slots, "duplicate_collection_slot")
            seen_slots.add(slot["collection_slot_id"])
            _require(slot["split"] == split and consistency[run_id].get("match") is True, "run_split_or_consistency")
            qc = inputs.json(entry["qc_report"])
            _unapproved(qc)
            _require(qc.get("reception_policy", STRICT_POLICY)
                     == reviewed.get("reception_policy", STRICT_POLICY) == reception_policy,
                     "reception_policy_link")
            _require(qc.get("schema_version") == CANDIDATE_SCHEMA and qc.get("status") == "PASS"
                     and qc.get("hold_reasons") == [] and reviewed.get("candidate_qc") == "PASS"
                     and reviewed.get("hold_reasons") == [], "candidate_qc_not_pass")
            _require(all(qc.get(key) == source[key] for key in
                         ("run_id", "start_utc", "end_utc", "capture_session_pk", "source_capture_group_id", "code_commit")),
                     "qc_manifest_link")
            profiles = {device: specs[device]["profile"] for device in included}
            _require(reviewed["qc_profiles"] == profiles
                     and {device: value["profile"] for device, value in qc["qc_policy"].items()} == profiles,
                     "qc_profile_link")
            _require(reviewed["counts"] == qc["counts"], "qc_counts_link")
            if reception_policy == WIRE_JITTER_POLICY:
                _require(reviewed.get("derived_qc_sha256") == entry["qc_report"]["sha256"],
                         "derived_qc_checksum")
                source_qc = qc.get("source_qc", {})
                expected_sha = request_runs[directory]["source_qc_sha256"]
                _require(source.get("status") == "HOLD" and source.get("qc_report") == "qc-report.json"
                         and source.get("collection_issues") == []
                         and qc.get("source_manifest_status") == reviewed.get("source_manifest_status") == "HOLD"
                         and source_qc == reviewed.get("source_qc")
                         and source_qc.get("sha256") == expected_sha
                         and source_qc.get("path") == "qc-report.json", "source_qc_link")
                original_path = (Path(entry["manifest"]["path"]).parent / "qc-report.json").as_posix()
                original = inputs.json({"path": original_path, "sha256": expected_sha})
                _unapproved(original)
                _require(original.get("status") == source_qc.get("status") == "HOLD"
                         and original.get("hold_reasons") == source_qc.get("hold_reasons")
                         == ["mqtt:pico_01:reception_gap_or_burst"]
                         and all(original.get(key) == source[key] for key in
                                 ("run_id", "start_utc", "end_utc", "capture_session_pk",
                                  "source_capture_group_id", "code_commit")), "source_qc_link")
                evidence = qc.get("reception_jitter", {})
                _require(evidence == reviewed.get("reception_jitter")
                         and evidence.get("policy") == reception_policy
                         and evidence.get("status") == "VERIFIED_SINGLE_RECOVERY"
                         and evidence.get("physical_cause") == "UNDETERMINED"
                         and evidence.get("run_id") == run_id
                         and evidence.get("source_capture_group_id") == group_id,
                         "reception_evidence_link")
            candidate = _read_rows(inputs.read(entry["mqtt_features"]), source, start, end, included)
            _require(type(qc["counts"]["mqtt_features"]) is int
                     and len(candidate) == qc["counts"]["mqtt_features"], "mqtt_csv_count")
            counts = {device: _count() for device in included}
            for row in candidate:
                reasons = exclusion_reasons(row, PHASE9_POLICY)
                for count in (counts[row["device_id"]], roles[role]["counts_by_device"][row["device_id"]]):
                    count["input_rows"] += 1
                    count["selected_rows" if not reasons else "excluded_rows"] += 1
                    for reason in reasons:
                        count["exclusion_reasons"][reason] = count["exclusion_reasons"].get(reason, 0) + 1
                if not reasons:
                    rows[role].append(row)
            bounds.append((start, end))
            group_devices.update(included)
            roles[role]["run_ids"].append(run_id)
            run_records.append({"run_id": run_id, "collection_slot_id": slot["collection_slot_id"],
                                "start_utc": source["start_utc"], "end_utc": source["end_utc"],
                                "code_commit": source["code_commit"], "inputs": entry,
                                "counts_by_device": counts, "reception_policy": reception_policy,
                                "reception_jitter": qc.get("reception_jitter")})
        actual_runs = {run["run_id"] for run in run_records}
        _require(actual_runs == set(report_runs) == set(slots) == set(consistency)
                 and directories == set(request_runs), "admission_run_set")
        _require(group_devices == set(specs), "group_device_specs")
        bounds.sort()
        _require(all(left[1] <= right[0] for left, right in zip(bounds, bounds[1:])), "group_runs_overlap")
        if terminal is not None:
            validate_terminal_selection(terminal, report.get("whole_session", {}), capture, bounds)
        roles[role]["group_ids"].append(group_id)
        groups.append({"role": role, **capture, "runs": run_records,
                       "admission_request": group["admission_request"],
                       "admission_report": group["admission_report"],
                       **({"terminal_source": terminal} if terminal is not None else {})})

    for role in ROLE_SPLITS:
        _require(roles[role]["group_ids"] and all(count["selected_rows"] > 0
                 for count in roles[role]["counts_by_device"].values()), "role_device_rows_required")
        roles[role]["row_count"] = len(rows[role])
    inputs.verify_unchanged()
    return MQTTIFDataset(
        rows={role: tuple(values) for role, values in rows.items()},
        provenance={"scope": "offline_candidate_only", "training_approved": False,
                    "operational_activation_verified": False, "manifest_sha256": manifest_sha,
                    "normal_selection_policy": PHASE9_POLICY, "device_ids": devices,
                    "inputs": inputs.records(), "roles": roles, "groups": groups},
    )
