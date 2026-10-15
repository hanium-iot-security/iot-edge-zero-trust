"""Bounded Packet inputs must retain original truth and reproduce source rows."""
from ai.packet_if_phase5_manifest import PACKET_IF_DATASET_VERSION_V3
from contextlib import closing
from datetime import timedelta
import csv
import io
import json
from pathlib import Path
import sqlite3

import dpkt
import pytest

from ai.packet_if_bounded import build_bounded_packet_sources, export_bounded_packet_if_dataset
from ai.packet_if_dataset import file_sha256, load_packet_if_dataset, session_data_sha256s
from tests import test_normal_admission as admission_cases
from tests import test_normal_collection_export as candidates
from tests import test_mqtt_if_dataset as mqtt_cases
from tests import test_packet_if_dataset as packet_cases
from tests import test_packet_normal_transition as transitions
from db.migration_runner import apply_migrations
from edge.packet.pcap_naming import build_pcap_filename


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def ref(path, root):
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)}


@pytest.fixture
def bounded(tmp_path, monkeypatch):
    groups = []
    for index, (role, split) in enumerate(mqtt_cases.ROLE_SPLITS.items()):
        root = tmp_path / role / "source"
        root.mkdir(parents=True)
        start = mqtt_cases.START + timedelta(days=index)
        monkeypatch.setattr(candidates, "START", start)
        monkeypatch.setattr(admission_cases, "START", start)
        package = candidates.package.__wrapped__(root)
        case = admission_cases.case.__wrapped__(package, root)
        request = admission_cases._terminal_request(case, package, wire=role == "calibration")
        request["slots"][0].update(collection_slot_id=role, split=split)
        write(root / "request.json", request)
        report = case.review()
        assert report["status"] == "PASS", report
        output = case.out / "review"
        # The real copied candidate tree resolves request paths from one package root.
        request["final_snapshot"]["path"] = (root / "final.db").relative_to(tmp_path).as_posix()
        directory = package.relative_to(tmp_path).as_posix()
        request["runs"][0]["run_dir"] = directory
        report["runs"][0]["run_dir"] = directory
        write(root / "request.json", request)
        write(output / "admission-report.json", report)
        groups.append({"role": role, "admission_request": ref(root / "request.json", tmp_path),
                       "admission_report": ref(output / "admission-report.json", tmp_path),
                       "runs": [{"manifest": ref(package / "manifest.json", tmp_path),
                                 "qc_report": ref(output / "qc/run-01/qc-report.json", tmp_path),
                                 "mqtt_features": ref(output / "qc/run-01/mqtt-features.csv", tmp_path)}]})
    normal = tmp_path / "normal.json"
    write(normal, mqtt_cases._dataset_spec(groups))
    context = tmp_path / "context.json"
    write(context, {"capture_filter": "tcp or udp", "source_commits": ["a" * 40]})
    attacks = tmp_path / "attacks"
    attacks.mkdir()
    attack_csv, attack_manifest = packet_cases._write_dataset_bundle(attacks)
    spec = tmp_path / "packet-spec.json"
    write(spec, {"schema_version": "packet-bounded-export-v1", "normal_inputs": ref(normal, tmp_path),
                 "capture_context": ref(context, tmp_path), "transitions": [],
                 "attack_inputs": [{"dataset": ref(attack_csv, tmp_path), "manifest": ref(attack_manifest, tmp_path)}]})
    return spec


def test_real_source_export_loader_and_trainer_preserve_truth(bounded):
    from ai.train_packet_isolation_forest import train_packet_isolation_forest
    root = bounded.parent
    before = candidates.tree_hashes(root)
    result = export_bounded_packet_if_dataset(bounded, output_path=root / "packet.csv", manifest_path=root / "packet.json")
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)
    assert (len(dataset.train), len(dataset.validation), len(dataset.test)) == (6, 6, 7)
    assert dataset.manifest.normal_policy_version == "packet-bounded-normal-v1"
    assert [item.status for item in dataset.manifest.sessions[:3]] == ["FAILED"] * 3
    payload = json.loads(result.manifest_path.read_text())
    assert payload["training_approved"] is payload["whole_capture_session_approved"] is False
    assert payload["sessions"][1]["whole_session"]["ineligible_segments"]
    assert all(candidates.digest(root / path) == sha for path, sha in before.items())
    # Existing trainer, actual estimator: no new model algorithm or runtime activation.
    trained = train_packet_isolation_forest(dataset, artifact_dir=root / "model", model_version="model", git_commit_sha="a" * 40,
                                           manifest_sha256=file_sha256(result.manifest_path))
    assert json.loads(trained.metadata_path.read_text())["dataset_version"] == PACKET_IF_DATASET_VERSION_V3
    from ai.predict_packet_isolation_forest import load_packet_if_artifact
    from ai.packet_if_artifact import packet_if_bundle_sha256
    loaded = load_packet_if_artifact(trained.metadata_path.parent,
                                    expected_bundle_sha256=packet_if_bundle_sha256(trained.metadata_path.parent))
    assert loaded.metadata["normal_policy_version"] == "packet-bounded-normal-v1"
    metadata = json.loads(trained.metadata_path.read_text())
    metadata.pop("normal_policy_version")
    write(trained.metadata_path, metadata)
    with pytest.raises(ValueError, match="normal_policy_version"):
        load_packet_if_artifact(trained.metadata_path.parent,
                                expected_bundle_sha256=packet_if_bundle_sha256(trained.metadata_path.parent))


@pytest.mark.parametrize("change", ["missing_final", "snapshot_hash", "pcap_hash", "source_commit", "cross_role",
                                    "changed_source_rows", "missing_packet", "inside_failure"])
def test_bounded_sources_refuse_incomplete_or_inconsistent_evidence(bounded, change):
    root = bounded.parent
    spec = json.loads(bounded.read_text())
    normal_path = root / spec["normal_inputs"]["path"]
    normal = json.loads(normal_path.read_text())
    group = normal["groups"][0]
    request_path = root / group["admission_request"]["path"]
    request = json.loads(request_path.read_text())
    final = root / request["final_snapshot"]["path"]
    manifest_path = root / group["runs"][0]["manifest"]["path"]
    manifest = json.loads(manifest_path.read_text())
    if change == "missing_final":
        final.unlink()
    elif change == "snapshot_hash":
        final.write_bytes(final.read_bytes() + b"tamper")
    elif change == "pcap_hash":
        pcap = manifest_path.parent / manifest["capture_artifacts"][0]["pcap_path"]
        pcap.write_bytes(pcap.read_bytes() + b"tamper")
    elif change == "source_commit":
        context = root / spec["capture_context"]["path"]
        write(context, {"capture_filter": "tcp or udp", "source_commits": ["b" * 40]})
        spec["capture_context"] = ref(context, root)
    elif change == "cross_role":
        group["role"] = "calibration"
        write(normal_path, normal)
        spec["normal_inputs"] = ref(normal_path, root)
    else:
        with closing(sqlite3.connect(final)) as db:
            if change == "changed_source_rows":
                db.execute("UPDATE packet_feature_logs SET packet_count=99 WHERE id=1")
            elif change == "missing_packet":
                db.execute("DELETE FROM packet_feature_logs WHERE id=1")
            else:
                db.execute("UPDATE packet_capture_segments SET status='FAILED',error_code='PARTIAL_CAPTURE' WHERE id=1")
            db.commit()
        # Refresh outer claims to prove actual source comparison, not just SHA mismatches.
        request["final_snapshot"] = ref(final, root)
        write(request_path, request)
        group["admission_request"] = ref(request_path, root)
        report_path = root / group["admission_report"]["path"]
        report = json.loads(report_path.read_text())
        report["final_snapshot_sha256"] = file_sha256(final)
        write(report_path, report)
        group["admission_report"] = ref(report_path, root)
        write(normal_path, normal)
        spec["normal_inputs"] = ref(normal_path, root)
    write(bounded, spec)
    with pytest.raises((ValueError, OSError)):
        build_bounded_packet_sources(bounded)


def test_forged_csv_with_refreshed_outer_hashes_is_rejected(bounded):
    root = bounded.parent
    result = export_bounded_packet_if_dataset(bounded, output_path=root / "packet.csv", manifest_path=root / "packet.json")
    with result.output_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields, rows = reader.fieldnames, list(reader)
    rows[0]["packet_count"] = "900"
    with result.output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    payload = json.loads(result.manifest_path.read_text())
    payload["dataset_sha256"] = file_sha256(result.output_path)
    hashes = session_data_sha256s(result.output_path)
    for item in payload["sessions"]:
        item["data_sha256"] = hashes[item["session_id"]]
    write(result.manifest_path, payload)
    with pytest.raises(ValueError, match="bounded_packet_rows_mismatch"):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_failed_export_removes_only_new_outputs_and_never_overwrites(bounded):
    root = bounded.parent
    output, manifest_path = root / "packet.csv", root / "packet.json"
    spec = json.loads(bounded.read_text())
    spec["attack_inputs"] = []
    write(bounded, spec)
    with pytest.raises(ValueError, match="attack"):
        export_bounded_packet_if_dataset(bounded, output_path=output, manifest_path=manifest_path)
    assert not output.exists() and not manifest_path.exists()
    output.write_text("keep")
    with pytest.raises(ValueError, match="output_already_exists"):
        export_bounded_packet_if_dataset(bounded, output_path=output, manifest_path=manifest_path)
    assert output.read_text() == "keep"


def transition_source(root):
    """Use actual TCP/MQTT bytes together with a full migrated Capture/Feature DB."""
    directory = root / "transition"
    directory.mkdir()
    evidence = transitions.make_evidence(directory)
    original = directory / "snapshot.db"
    with closing(sqlite3.connect(original)) as db:
        db.row_factory = sqlite3.Row
        mqtt = [dict(row) for row in db.execute("SELECT * FROM mqtt_logs")]
    full = directory / "full.db"
    apply_migrations(full)
    start = transitions.BASE
    capture_artifacts = []
    raw = list(dpkt.pcap.Reader(io.BytesIO((directory / "transition.pcap").read_bytes())))
    with closing(sqlite3.connect(full)) as db:
        device = evidence["devices"][0]
        candidates.insert(db, "devices", device_id=device["device_id"], ip_address=device["ip_address"])
        candidates.insert(db, "packet_capture_sessions", id=7, session_id=evidence["source_capture_group_id"],
                          capture_interface="eth0", started_at=transitions.utc(-10), first_window_start=transitions.utc(0),
                          ended_at=transitions.utc(50), status="COMPLETED")
        for row in mqtt:
            candidates.insert(db, "mqtt_logs", **row)
        for index in range(4):
            left, right = start+timedelta(seconds=index*10), start+timedelta(seconds=(index+1)*10)
            filename = build_pcap_filename(session_id=evidence["source_capture_group_id"], interface="eth0",
                                           window_start=left, window_end=right, tmp=False)
            content = io.BytesIO()
            writer = dpkt.pcap.Writer(content)
            for stamp, packet in raw:
                if left.timestamp() <= stamp < right.timestamp():
                    writer.writepkt(packet, stamp)
            pcap = directory / filename
            pcap.write_bytes(content.getvalue())
            diagnostic = directory / (filename + ".capture.json")
            write(diagnostic, {"schema_version": "packet-capture-diagnostics-v1", "session_id": evidence["source_capture_group_id"],
                  "capture_interface": "eth0", "pcap_file_name": filename, "expected_pcap_file_name": filename,
                  "window_start": candidates.utc(left), "window_end": candidates.utc(right),
                  "success": True, "completed_full_window": True, "terminated_cleanly": True, "stderr_complete": True,
                  "exit_code": 0, "packets_dropped": 0})
            segment = candidates.insert(db, "packet_capture_segments", capture_session_id=7, capture_interface="eth0",
                file_name=filename, window_start=candidates.utc(left), window_end=candidates.utc(right),
                status="PROCESSED", start_delay_seconds=0, captured_duration_seconds=10)
            candidates.insert(db, "packet_feature_logs", capture_segment_id=segment, device_id=device["device_id"],
                peer_ip=device["ip_address"], direction="INBOUND", window_start=candidates.utc(left),
                window_end=candidates.utc(right), packet_count=4, total_bytes=500, avg_packet_size=125,
                max_packet_size=200, mean_inter_arrival_time=2, distinct_dest_port_count=1)
            capture_artifacts.append({"segment_id": segment, "pcap_path": pcap.relative_to(root).as_posix(),
                "pcap_sha256": file_sha256(pcap), "diagnostics_path": diagnostic.relative_to(root).as_posix(),
                "diagnostics_sha256": file_sha256(diagnostic)})
        db.commit()
    # All references resolve from one common immutable input root.
    evidence["snapshot"] = ref(full, directory)
    evidence["capture_filter"] = "tcp or udp"
    evidence["pcaps"] = [{"path": Path(item["pcap_path"]).name, "sha256": item["pcap_sha256"]}
                          for item in capture_artifacts]
    write(directory / "evidence.json", evidence)
    # Rewrite refs recursively while preserving the original files and bytes.
    def relocate(value):
        if isinstance(value, dict):
            if set(value) == {"path", "sha256"}:
                return {"path": "transition/"+value["path"], "sha256": value["sha256"]}
            return {key: relocate(item) for key, item in value.items()}
        if isinstance(value, list):
            return [relocate(item) for item in value]
        return value
    for name in ("before", "after"):
        path = directory / evidence[name]["path"]
        write(path, relocate(json.loads(path.read_text())))
        evidence[name] = ref(path, directory)
    # Before/after refs contain already-relocated nested references.
    for key in ("before", "after", "snapshot", "operation"):
        evidence[key]["path"] = "transition/"+evidence[key]["path"]
    evidence["pcaps"] = [relocate(item) for item in evidence["pcaps"]]
    write(directory / "evidence.json", evidence)
    return {"evidence": ref(directory / "evidence.json", root), "capture_artifacts": capture_artifacts}


def test_transition_adapter_keeps_protocol_capture_and_dataset_checks_connected(bounded):
    root = bounded.parent
    transition = transition_source(root)
    spec = json.loads(bounded.read_text())
    spec["transitions"] = [transition]
    write(bounded, spec)
    result = export_bounded_packet_if_dataset(bounded, output_path=root / "packet.csv", manifest_path=root / "packet.json")
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)
    assert len(dataset.train) == 10
    source = next(item for item in json.loads(result.manifest_path.read_text())["sessions"]
                  if item["session_id"] == transitions.GROUP)
    assert source["bounded_selections"][0]["transition_evidence"] == transition["evidence"]
    diagnostic = root / transition["capture_artifacts"][0]["diagnostics_path"]
    value = json.loads(diagnostic.read_text())
    value["packets_dropped"] = 1
    write(diagnostic, value)
    transition["capture_artifacts"][0]["diagnostics_sha256"] = file_sha256(diagnostic)
    write(bounded, spec)
    with pytest.raises(ValueError, match="selected_capture_artifacts_invalid"):
        build_bounded_packet_sources(bounded)


def test_bounded_packet_dataset_has_explicit_version():
    assert PACKET_IF_DATASET_VERSION_V3 == "packet-if-dataset-v3"
