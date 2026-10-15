"""Reproduce bounded Packet candidates from sealed sources; never grants approval.

v1/v2 retain their whole-session contract. This explicit v3 path reads actual
snapshot/PCAP bytes, preserves terminal facts, and keeps development roles intact.
Loading an exported dataset is read-only; only export reruns admission in a temporary
directory. Original packages, QC and approval flags are never edited.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
import csv
from dataclasses import dataclass
from datetime import timedelta
import hashlib
from pathlib import Path
import tempfile

from ai.export_normal_collection import _boundary, _path, _require, _time
from ai.mqtt_if_dataset import _Inputs, _json, load_mqtt_if_dataset
from ai.packet_if_contract import PACKET_IF_NOMINAL_WINDOW_SECONDS, packet_feature_matrix
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible
from edge.maintenance.processing import dataset_maintenance_windows, overlaps_maintenance

EXPORT_SCHEMA = "packet-bounded-export-v1"
NORMAL_POLICY = "packet-bounded-normal-v1"
ROLE_SPLITS = {"train": "train", "calibration": "validation", "validation": "test"}


@dataclass
class BoundedPacketSources:
    rows: list[dict]
    sessions: list[dict]
    capture_policy: dict
    inputs: list[dict]


def _pin(inputs, reference):
    """Hash large immutable files in streaming chunks rather than loading a DB into RAM."""
    from ai.packet_if_dataset import file_sha256
    _require(isinstance(reference, dict) and set(reference) == {"path", "sha256"}, "source_reference")
    path = _path(inputs.root, reference["path"])
    _require(path.is_file() and file_sha256(path) == reference["sha256"], "source_file_checksum")
    _require(path not in inputs.files or inputs.files[path] == reference["sha256"], "conflicting_input_checksum")
    inputs.files[path] = reference["sha256"]
    return path


def _unchanged(inputs):
    from ai.packet_if_dataset import file_sha256
    _require(all(file_sha256(path) == sha for path, sha in inputs.files.items()), "source_changed_during_load")


def _policy(value):
    policy = CapturePolicy(**{key: value[key] for key in
                             ("version", "max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds")})
    return {**{key: getattr(policy, key) for key in
               ("version", "max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds")},
            "nominal_window_seconds": PACKET_IF_NOMINAL_WINDOW_SECONDS,
            "minimum_coverage_ratio": policy.minimum_duration_seconds / PACKET_IF_NOMINAL_WINDOW_SECONDS}


def _session(db, group_id, pk):
    row = db.execute("SELECT * FROM packet_capture_sessions WHERE id=?", (pk,)).fetchone()
    _require(row is not None and row["session_id"] == group_id
             and row["status"] in {"COMPLETED", "FAILED"} and row["ended_at"] is not None,
             "source_not_terminal")
    return dict(row)


def _whole_session(db, session, policy):
    capture_policy = CapturePolicy(**{key: policy[key] for key in
                                     ("version", "max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds")})
    failures = []
    for row in db.execute("SELECT * FROM packet_capture_segments WHERE capture_session_id=? ORDER BY id", (session["id"],)):
        if not is_capture_eligible(CaptureEligibilitySegment(**{key: row[key] for key in
                ("status", "error_code", "start_delay_seconds", "captured_duration_seconds")}), capture_policy).eligible:
            failures.append({"segment_id": row["id"], **{key: row[key] for key in
                             ("window_start", "window_end", "status", "error_code")}})
    result = {"session_status": session["status"], "whole_session_eligible": not failures, "ineligible_segments": failures}
    if session["status"] == "FAILED":
        result.update(session_ended_at=session["ended_at"], whole_session_eligible=False)
    return result


def _packet_rows(db, session, selections, policy):
    """Require the entire declared grid. An ineligible selected row is never silently dropped."""
    from ai.packet_if_dataset import DATASET_REQUIRED_COLUMNS, _validate_dataset_source_row
    result, seen = [], set()
    for selection in selections:
        start, end = _boundary(selection["start_utc"]), _boundary(selection["end_utc"])
        _require(start < end and _time(session["first_window_start"]) <= start
                 and end <= _time(session["ended_at"]), "selection_outside_source")
        devices = {item["device_id"]: item["ip_address"] for item in selection["devices"]}
        _require(devices and len(devices) == len(selection["devices"]), "selection_devices")
        segments = db.execute("SELECT * FROM packet_capture_segments WHERE capture_session_id=? "
                              "AND julianday(window_start)<julianday(?) AND julianday(window_end)>julianday(?) "
                              "ORDER BY window_start", (session["id"], selection["end_utc"], selection["start_utc"])).fetchall()
        expected = {start + timedelta(seconds=offset) for offset in range(0, int((end-start).total_seconds()), 10)}
        _require(len(segments) == len(expected) and {_time(row["window_start"]) for row in segments} == expected,
                 "incomplete_selected_segments")
        capture_policy = CapturePolicy(**{key: policy[key] for key in
                                         ("version", "max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds")})
        for segment in segments:
            _require(is_capture_eligible(CaptureEligibilitySegment(**{key: segment[key] for key in
                     ("status", "error_code", "start_delay_seconds", "captured_duration_seconds")}), capture_policy).eligible,
                     "ineligible_selected_segment")
            _require(_time(segment["window_end"]) == _time(segment["window_start"]) + timedelta(seconds=10),
                     "partial_selected_segment")
            raw = db.execute("SELECT * FROM packet_feature_logs WHERE capture_segment_id=? AND direction='INBOUND' "
                             "ORDER BY id", (segment["id"],)).fetchall()
            selected = [row for row in raw if row["device_id"] in devices]
            _require(len(selected) == len(devices) and {row["device_id"] for row in selected} == set(devices),
                     "incomplete_selected_packet_grid")
            for row in selected:
                value = dict(row)
                value.update(packet_feature_log_id=row["id"], session_id=session["session_id"],
                             segment_window_start=segment["window_start"], segment_window_end=segment["window_end"],
                             segment_status=segment["status"], segment_error_code=segment["error_code"],
                             start_delay_seconds=segment["start_delay_seconds"],
                             captured_duration_seconds=segment["captured_duration_seconds"],
                             registered_device_id=row["device_id"], registered_ip_address=devices[row["device_id"]])
                _require(value["peer_ip"] == devices[row["device_id"]], "historical_device_ip_mismatch")
                _validate_dataset_source_row(value, capture_policy=capture_policy)
                key = (session["session_id"], row["device_id"], row["window_start"])
                _require(key not in seen, "duplicate_selected_window")
                seen.add(key)
                result.append({column: value[column] for column in DATASET_REQUIRED_COLUMNS})
    packet_feature_matrix(result)
    return result


def _session_payload(session, selections, rows, role, context, extra):
    group_id = session["session_id"]
    devices = sorted({(row["device_id"], row["peer_ip"]) for row in rows})
    return {"session_id": group_id, "source_capture_group_id": group_id,
            "split": ROLE_SPLITS[role], "traffic_label": "normal", "scenario": "normal_bounded",
            "target_device_id": None, "target_source_ip": None, "status": session["status"],
            "capture_interface": session["capture_interface"], "capture_filter": context["capture_filter"],
            "source_commit_sha": selections[0]["code_commit"], "normal_policy_version": NORMAL_POLICY,
            "started_at": session["started_at"], "first_window_start": session["first_window_start"],
            "ended_at": session["ended_at"], "capture_gap_start": session["capture_gap_start"],
            "capture_gap_end": session["capture_gap_end"],
            "devices": [{"device_id": device, "peer_ip": ip} for device, ip in devices],
            "included_device_ids": [device for device, _ in devices],
            "bounded_selections": selections, **extra}


def _verify_capture_artifacts(inputs, db, session, selection, artifacts):
    """Reuse candidate Capture QC for exact per-segment PCAP/diagnostic/source linkage."""
    from ai.export_normal_collection import _capture_qc
    start, end = _boundary(selection["start_utc"]), _boundary(selection["end_utc"])
    segments = [dict(row) for row in db.execute(
        "SELECT * FROM packet_capture_segments WHERE capture_session_id=? "
        "AND julianday(window_start)>=julianday(?) AND julianday(window_end)<=julianday(?) ORDER BY id",
        (session["id"], selection["start_utc"], selection["end_utc"]))]
    packets = [dict(row) for row in db.execute(
        "SELECT f.*,s.captured_duration_seconds FROM packet_feature_logs f JOIN packet_capture_segments s "
        "ON s.id=f.capture_segment_id WHERE s.capture_session_id=? "
        "AND julianday(s.window_start)>=julianday(?) AND julianday(s.window_end)<=julianday(?) ORDER BY f.id",
        (session["id"], selection["start_utc"], selection["end_utc"]))
        if row["device_id"] in selection["included_device_ids"]]
    for artifact in artifacts:
        for path_key, sha_key in (("pcap_path", "pcap_sha256"), ("diagnostics_path", "diagnostics_sha256")):
            _pin(inputs, {"path": artifact[path_key], "sha256": artifact[sha_key]})
    report = {"hold_reasons": []}
    manifest = {**selection, "source_capture_group_id": session["session_id"], "capture_artifacts": artifacts}
    _capture_qc(inputs.root, manifest, session, segments, packets, start, end, report)
    _require(not report["hold_reasons"], "selected_capture_artifacts_invalid")


def build_bounded_packet_sources(spec_path: Path, *, rerun_admission=False) -> BoundedPacketSources:
    """Read pinned inputs and re-extract source rows. No output writes unless explicitly rerunning QC."""
    from ai.normal_admission import _digest, _open_readonly, _range_rows, load_request, review_admission
    from ai.packet_if_dataset import load_packet_if_dataset
    from ai.packet_if_phase5_manifest import PACKET_IF_DATASET_VERSION_V2
    spec_path = Path(spec_path).resolve()
    inputs = _Inputs(spec_path.parent)
    spec = inputs.json({"path": spec_path.name, "sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest()})
    _require(set(spec) == {"schema_version", "normal_inputs", "capture_context", "transitions", "attack_inputs"}
             and spec["schema_version"] == EXPORT_SCHEMA, "bounded_export_schema")
    context = inputs.json(spec["capture_context"])
    _require(set(context) == {"capture_filter", "source_commits"} and isinstance(context["capture_filter"], str)
             and context["capture_filter"] and isinstance(context["source_commits"], list), "capture_context")
    normal_path = _pin(inputs, spec["normal_inputs"])
    normal_spec = _json(normal_path.read_bytes())
    # Reuse the existing strict request/report/QC/role linkage, without applying its row filter to Packet rows.
    normal = load_mqtt_if_dataset(normal_path)
    normal_inputs = _Inputs(normal_path.parent)
    for reference in normal.provenance["inputs"]:
        _pin(normal_inputs, reference)
    rows, sessions, policies, used_groups, used_slots = [], [], [], set(), set()
    with ExitStack() as stack:
        snapshots = {}

        def open_snapshot(owner, reference):
            path = _pin(owner, reference)
            if path not in snapshots:
                snapshots[path] = stack.enter_context(closing(_open_readonly(path)))
            return snapshots[path]

        for group in normal_spec["groups"]:
            role = group["role"]
            request_path = _path(normal_inputs.root, group["admission_request"]["path"])
            request = load_request(request_path)
            report = normal_inputs.json(group["admission_report"])
            if rerun_admission:
                with tempfile.TemporaryDirectory(prefix="packet-admission-") as temporary:
                    fresh = review_admission(normal_inputs.root, request_path, Path(temporary) / "review")
                _require(fresh["status"] == "PASS" and fresh["official_admission"] == "BOUNDED_ELIGIBLE"
                         and all(fresh.get(key) == report.get(key) for key in
                                 ("capture_group", "final_snapshot_sha256", "whole_session", "range_consistency")),
                         "admission_recheck_failed")
            capture = report["capture_group"]
            group_id = capture["source_capture_group_id"]
            _require(group_id not in used_groups, "duplicate_capture_group")
            used_groups.add(group_id)
            db = open_snapshot(normal_inputs, request["final_snapshot"])
            session = _session(db, group_id, capture["capture_session_pk"])
            _require(report["whole_session"]["session_status"] == session["status"], "terminal_snapshot_link")
            selections = []
            for run in group["runs"]:
                manifest = normal_inputs.json(run["manifest"])
                package_root = _path(normal_inputs.root, run["manifest"]["path"]).parent
                package_inputs = _Inputs(package_root)
                before_db = open_snapshot(package_inputs, manifest["snapshot"])
                _require(_digest(_range_rows(db, manifest, full_capture_rows=True))
                         == _digest(_range_rows(before_db, manifest, full_capture_rows=True)),
                         "selected_source_rows_changed")
                _verify_capture_artifacts(package_inputs, db, session, manifest, manifest["capture_artifacts"])
                for path, sha in package_inputs.files.items():
                    normal_inputs.files[path] = sha
                policies.append(_policy(manifest["capture_policy"]))
                _require(manifest["code_commit"] in context["source_commits"], "capture_source_commit")
                slot = next(slot for slot in request["slots"] if slot["run_id"] == manifest["run_id"])
                _require(slot["collection_slot_id"] not in used_slots, "duplicate_collection_slot")
                used_slots.add(slot["collection_slot_id"])
                selections.append({key: manifest[key] for key in
                                   ("run_id", "start_utc", "end_utc", "included_device_ids", "devices", "code_commit")}
                                  | {"collection_slot_id": slot["collection_slot_id"], "source_role": role})
            policy = policies[-1]
            _require(_whole_session(db, session, policy) == report["whole_session"], "whole_session_facts_changed")
            selected = _packet_rows(db, session, selections, policy)
            maintenance = dataset_maintenance_windows(db)
            _require(not any(overlaps_maintenance(maintenance, _time(row["window_start"]),
                             _time(row["window_end"])) for row in selected), "selected_maintenance")
            rows.extend(selected)
            sessions.append(_session_payload(session, selections, selected, role, context,
                            {"admission_request": group["admission_request"], "admission_report": group["admission_report"],
                             "device_specs": request["device_specs"], "whole_session": report["whole_session"]}))
            sessions[-1]["source_snapshot_sha256"] = request["final_snapshot"]["sha256"]

        _require(isinstance(spec["transitions"], list), "transition_sources")
        for transition in spec["transitions"]:
            from ai.packet_normal_transition import validate_transition
            _require(isinstance(transition, dict) and set(transition) == {"evidence", "capture_artifacts"},
                     "transition_source_fields")
            reference = transition["evidence"]
            evidence = validate_transition(inputs.root, reference)
            _pin(inputs, reference)
            for item in evidence["input_files"]:
                _pin(inputs, item)
            group_id = evidence["source_capture_group_id"]
            _require(evidence["capture_filter"] == context["capture_filter"]
                     and evidence["code_commit"] in context["source_commits"], "transition_capture_context")
            db = open_snapshot(inputs, evidence["snapshot"])
            session = _session(db, group_id, evidence["capture_session_pk"])
            artifacts = transition["capture_artifacts"]
            _require({(item["pcap_path"], item["pcap_sha256"]) for item in artifacts}
                     == {(item["path"], item["sha256"]) for item in evidence["pcaps"]}, "transition_pcap_inventory")
            _verify_capture_artifacts(inputs, db, session, evidence, artifacts)
            policy = _policy(evidence["capture_policy"])
            policies.append(policy)
            selected = _packet_rows(db, session, [evidence], policy)
            maintenance = dataset_maintenance_windows(db)
            _require(not any(overlaps_maintenance(maintenance, _time(row["window_start"]), _time(row["window_end"]))
                             for row in selected), "selected_maintenance")
            rows.extend(selected)
            selection = {key: evidence[key] for key in
                         ("start_utc", "end_utc", "included_device_ids", "devices", "code_commit")}
            selection.update(source_role=evidence["role"], transition_evidence=reference)
            whole = _whole_session(db, session, policy)
            _require(not any(_boundary(evidence["start_utc"]) < _time(item["window_end"])
                             and _time(item["window_start"]) < _boundary(evidence["end_utc"])
                             for item in whole["ineligible_segments"]), "transition_failure_inside_selection")
            previous = next((item for item in sessions if item["session_id"] == group_id), None)
            if previous is not None:
                _require(previous["split"] == ROLE_SPLITS[evidence["role"]], "split_crosses_capture_group")
                _require(previous["source_snapshot_sha256"] == evidence["snapshot"]["sha256"]
                         and previous["whole_session"] == whole, "transition_group_snapshot_mismatch")
                previous["bounded_selections"].append(selection)
                mappings = {(row["device_id"], row["peer_ip"]) for row in rows if row["session_id"] == group_id}
                previous["devices"] = [{"device_id": device, "peer_ip": ip} for device, ip in sorted(mappings)]
                previous["included_device_ids"] = sorted({device for device, _ in mappings})
            else:
                used_groups.add(group_id)
                sessions.append(_session_payload(session, [selection], selected, evidence["role"], context,
                                                  {"source_snapshot_sha256": evidence["snapshot"]["sha256"],
                                                   "whole_session": whole}))

    _require(policies and all(policy == policies[0] for policy in policies), "capture_policy_mismatch")
    _require(isinstance(spec["attack_inputs"], list), "attack_sources")
    for source in spec["attack_inputs"]:
        _require(isinstance(source, dict) and set(source) == {"dataset", "manifest"}, "attack_reference")
        data_path, manifest_path = _pin(inputs, source["dataset"]), _pin(inputs, source["manifest"])
        raw_manifest = _json(manifest_path.read_bytes())
        _require(raw_manifest.get("dataset_version") == PACKET_IF_DATASET_VERSION_V2, "attack_source_must_be_v2")
        external = {item["split"] for item in raw_manifest["sessions"]} == {"test"}
        inherited = load_packet_if_dataset(data_path, manifest_path, external_holdout=external)
        _require(inherited.manifest.dataset_version == PACKET_IF_DATASET_VERSION_V2, "attack_source_must_be_v2")
        _require(_policy(raw_manifest["capture_policy"]) == policies[0], "attack_capture_policy_mismatch")
        attack_ids = {item.session_id for item in inherited.manifest.sessions
                      if item.split == "test" and item.traffic_label == "attack"}
        _require(attack_ids, "attack_source_empty")
        for session in raw_manifest["sessions"]:
            if session["session_id"] not in attack_ids:
                continue
            group_id = session["source_capture_group_id"]
            _require(group_id not in used_groups and session["session_id"] not in used_groups, "duplicate_capture_group")
            used_groups.update((group_id, session["session_id"]))
            _require(session["collection_slot_id"] not in used_slots, "duplicate_collection_slot")
            used_slots.add(session["collection_slot_id"])
            sessions.append({**session, "inherited_attack": source})
        # Use CSV values, preserving the original lexical numeric representation.
        with data_path.open(newline="", encoding="utf-8") as handle:
            rows.extend(dict(row) for row in csv.DictReader(handle) if row["session_id"] in attack_ids)
    from ai.packet_if_dataset import DATASET_REQUIRED_COLUMNS
    rows = [{column: row[column] for column in DATASET_REQUIRED_COLUMNS} for row in rows]
    rows.sort(key=lambda row: (str(row["session_id"]), str(row["window_start"]), int(row["packet_feature_log_id"])))
    _require(len({(row["session_id"], row["packet_feature_log_id"]) for row in rows}) == len(rows), "duplicate_source_row")
    _unchanged(inputs)
    _unchanged(normal_inputs)
    records = inputs.records() + [{"path": str(path), "sha256": sha} for path, sha in sorted(normal_inputs.files.items())]
    return BoundedPacketSources(rows, sessions, policies[0], records)


def _csv_rows(rows):
    return [{key: "" if value is None else str(value) for key, value in row.items()} for row in rows]


def validate_bounded_packet_export(dataset_path, manifest_path, payload):
    """Re-read immutable source bytes and reject edited CSV, even if its outer hashes were refreshed."""
    from ai.packet_if_dataset import file_sha256
    inputs = _Inputs(Path(manifest_path).resolve().parent)
    source = _pin(inputs, payload["source_spec_ref"])
    expected = build_bounded_packet_sources(source)
    with Path(dataset_path).open(newline="", encoding="utf-8") as handle:
        actual = list(csv.DictReader(handle))
    _require(actual == _csv_rows(expected.rows), "bounded_packet_rows_mismatch")
    expected_sessions = [{**item, "data_sha256": payload_session["data_sha256"]}
                         for item, payload_session in zip(expected.sessions, payload["sessions"])]
    _require(len(expected.sessions) == len(payload["sessions"]) and payload["sessions"] == expected_sessions,
             "bounded_packet_provenance_mismatch")
    _require(payload["capture_policy"] == expected.capture_policy
             and payload.get("normal_policy_version") == NORMAL_POLICY
             and payload.get("training_approved") is False and payload.get("whole_capture_session_approved") is False,
             "bounded_packet_contract")
    _require(file_sha256(source) == payload["source_spec_ref"]["sha256"], "source_changed_during_load")


def export_bounded_packet_if_dataset(spec_path: Path, *, output_path: Path, manifest_path: Path):
    """Export into the input root atomically; outputs never overwrite existing artifacts."""
    from ai.export_packet_if_dataset import PacketIFExportResult, _write_csv_atomically, _write_json_atomically
    from ai.packet_if_dataset import file_sha256, load_packet_if_dataset, session_data_sha256s
    from ai.packet_if_phase5_manifest import PACKET_IF_DATASET_VERSION_V3
    spec_path, output_path, manifest_path = map(lambda path: Path(path).resolve(), (spec_path, output_path, manifest_path))
    _require(output_path.parent == manifest_path.parent == spec_path.parent, "bounded_outputs_must_share_input_root")
    _require(output_path != manifest_path and output_path != spec_path and manifest_path != spec_path, "output_path_collision")
    _require(not output_path.exists() and not manifest_path.exists(), "output_already_exists")
    sources = build_bounded_packet_sources(spec_path, rerun_admission=True)
    made = []
    try:
        _write_csv_atomically(output_path, sources.rows)
        made.append(output_path)
        hashes = session_data_sha256s(output_path)
        payload = {"dataset_version": PACKET_IF_DATASET_VERSION_V3,
                   "normal_policy_version": NORMAL_POLICY, "capture_policy_version": sources.capture_policy["version"],
                   "capture_policy": sources.capture_policy, "dataset_sha256": file_sha256(output_path),
                   "training_approved": False, "whole_capture_session_approved": False,
                   "source_spec_ref": {"path": spec_path.name, "sha256": file_sha256(spec_path)},
                   "sessions": [{**item, "data_sha256": hashes[item["session_id"]]} for item in sources.sessions]}
        _write_json_atomically(manifest_path, payload)
        made.append(manifest_path)
        # Preserve the normal/attack test requirement for trainable datasets.
        load_packet_if_dataset(output_path, manifest_path)
    except BaseException:
        for path in reversed(made):
            path.unlink(missing_ok=True)
        raise
    return PacketIFExportResult(output_path, manifest_path, len(sources.rows), 0, {},
                                payload["dataset_sha256"], file_sha256(manifest_path), sources.capture_policy["version"])
