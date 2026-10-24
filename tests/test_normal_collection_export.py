"""Candidate export uses isolated, real SQLite schemas and bounded PCAP fixtures."""
from contextlib import closing
import csv
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import socket
import sqlite3
import struct
from uuid import uuid4

import dpkt
import pytest

from ai.export_normal_collection import export_normal_collection, main
from db.migration_runner import apply_migrations
from edge.packet.capture_policy import CapturePolicy
from edge.packet.pcap_naming import build_pcap_filename
from tests.device_policy_support import insert_revision_raw

START = datetime(2026, 10, 4, tzinfo=timezone.utc)
IDS = ["esp32_01", "esp32_02", "pico_01"]
IPS = {device: "192.168.0." + str(index + 4) for index, device in enumerate(IDS)}


def utc(value):
    return value.isoformat().replace("+00:00", "Z")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hashes(root):
    return {path.relative_to(root).as_posix(): digest(path)
            for path in root.rglob("*") if path.is_file()}


def insert(db, table, **values):
    return db.execute(f"INSERT INTO {table}({','.join(values)}) VALUES({','.join('?' for _ in values)})",
                      tuple(values.values())).lastrowid


def pcap_bytes(window):
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    lengths = {}
    for device in IDS:
        ip = dpkt.ip.IP(src=socket.inet_aton(IPS[device]), dst=socket.inet_aton("192.168.0.2"),
                        p=6, data=dpkt.tcp.TCP(sport=40000, dport=1883, flags=dpkt.tcp.TH_ACK,
                                              data=b"\x30\x03\x00\x01x"))
        ip.len = len(ip)
        lengths[device] = len(ip)
        frame = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6,
                                            type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
        for offset in (1, 6):
            content.extend(struct.pack("<IIII", int((window + timedelta(seconds=offset)).timestamp()),
                                       0, len(frame), len(frame)))
            content.extend(frame)
    return bytes(content), lengths


@pytest.fixture
def package(tmp_path):
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "pcap").mkdir()
    snapshot = root / "after.db"
    apply_migrations(snapshot)
    group = str(uuid4())
    manifest = {"schema_version": "phase8-normal-candidate-v1", "run_id": str(uuid4()),
        "status": "RAW_CAPTURED", "training_approved": False, "whole_capture_session_approved": False,
        "start_utc": utc(START), "end_utc": utc(START + timedelta(seconds=20)),
        "source_capture_group_id": group, "capture_session_pk": 1, "included_device_ids": IDS,
        "code_commit": "a" * 40, "capture_policy": asdict(CapturePolicy()),
        "firmware_provenance": {"status": "UNCONFIRMED"}, "devices": [], "capture_artifacts": []}
    with closing(sqlite3.connect(snapshot)) as db:
        db.row_factory = sqlite3.Row
        for device in IDS:
            insert(db, "devices", device_id=device, ip_address=IPS[device])
            insert_revision_raw(db, device_id=device, registration_state="ACTIVE",
                                effective_from=utc(START - timedelta(seconds=10)))
            manifest["devices"].append({"device_id": device, "ip_address": IPS[device],
                "mqtt_topic": f"iot/{device}/sensor", "registration_state": "ACTIVE", "current_policy_revision": 1,
                "status": "normal", "trust_score": 100})
        insert(db, "packet_capture_sessions", session_id=group, capture_interface="eth0",
               started_at=utc(START - timedelta(seconds=10)), first_window_start=utc(START), status="RUNNING")
        for index in range(2):
            window = START + timedelta(seconds=index * 10)
            end = window + timedelta(seconds=10)
            filename = build_pcap_filename(session_id=group, interface="eth0",
                                          window_start=window, window_end=end, tmp=False)
            pcap, lengths = pcap_bytes(window)
            (root / "pcap" / filename).write_bytes(pcap)
            segment = insert(db, "packet_capture_segments", capture_session_id=1, file_name=filename,
                capture_interface="eth0", window_start=utc(window), window_end=utc(end),
                status="PROCESSED", packet_count=6, start_delay_seconds=0.01, captured_duration_seconds=9.99)
            diagnostic = {"schema_version": "packet-capture-diagnostics-v1", "session_id": group,
                "capture_interface": "eth0", "window_start": utc(window), "window_end": utc(end),
                "pcap_file_name": filename, "expected_pcap_file_name": filename,
                "success": True, "error_code": None, "file_validation_error": None, "exit_code": -15,
                "completed_full_window": True, "terminated_cleanly": True, "stderr_complete": True,
                "stderr_error": None, "packets_dropped": 0, "packets_dropped_by_interface": 0}
            sidecar = root / "pcap" / (filename + ".capture.json")
            sidecar.write_text(json.dumps(diagnostic), encoding="utf-8")
            manifest["capture_artifacts"].append({"segment_id": segment, "pcap_path": "pcap/" + filename,
                "pcap_sha256": digest(root / "pcap" / filename),
                "diagnostics_path": "pcap/" + sidecar.name, "diagnostics_sha256": digest(sidecar)})
            for device in IDS:
                sizes = []
                for offset in (1, 6):
                    sequence = 100 + index * 2 + (offset == 6)
                    uptime = 100 + index * 10 + offset
                    value = {"device_id": device, "sequence": sequence, "uptime_s": uptime}
                    if device == "pico_01":
                        value = {"device_id": device, "seq": sequence, "uptime_ms": uptime * 1000,
                                 "temperature_c": 24.12, "humidity_pct": 45.32, "pressure_hpa": 1013.25}
                    payload = json.dumps(value)
                    sizes.append(len(payload.encode()))
                    insert(db, "mqtt_logs", device_id=device, topic=f"iot/{device}/sensor",
                        payload=payload, payload_size=sizes[-1], payload_raw=payload.encode(),
                        payload_decode_status="OK", received_at=utc(window + timedelta(seconds=offset)),
                        is_json_valid=1, is_topic_valid=1)
                feature = insert(db, "feature_logs", device_id=device, window_start=utc(window),
                    window_end=utc(end), publish_count=2, avg_payload_size=sum(sizes)/2,
                    max_payload_size=max(sizes), avg_message_interval=5, min_message_interval=5, topic_count=1)
                insert(db, "packet_feature_logs", capture_segment_id=segment, device_id=device,
                    peer_ip=IPS[device], direction="INBOUND", window_start=utc(window), window_end=utc(end),
                    packet_count=2, total_bytes=lengths[device]*2, avg_packet_size=lengths[device],
                    max_packet_size=lengths[device], mean_inter_arrival_time=5, distinct_dest_port_count=1)
                if device == "esp32_01" and index == 0:
                    for detector, applied in (("AI", 0), ("RULE", 1)):
                        insert(db, "detection_events", device_id=device, feature_log_id=feature,
                            detector_type=detector, event_type="AI_ANOMALY" if detector == "AI" else "LARGE_PAYLOAD",
                            applied_to_score=applied, analysis_window_start=utc(window), analysis_window_end=utc(end))
        manifest["device_policy_revisions"] = [dict(row) for row in db.execute("SELECT * FROM device_policy_revisions")]
        db.commit()
    save_manifest(root, manifest)
    return root


def save_manifest(root, manifest):
    manifest["snapshot"] = {"path": "after.db", "sha256": digest(root / "after.db")}
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def mutate_db(root, sql, params=()):
    with closing(sqlite3.connect(root / "after.db")) as db:
        db.execute(sql, params)
        db.commit()
    save_manifest(root, json.loads((root / "manifest.json").read_text()))


def csv_rows(root, filename):
    with (root / filename).open(newline="") as handle:
        return list(csv.DictReader(handle))


def mark_completed(root):
    assert export_normal_collection(root)["status"] == "PASS"
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["status"] = "CANDIDATE_QC_PASSED"
    save_manifest(root, manifest)
    return manifest


def test_bounded_pico_and_ai_observations_are_kept_without_training_approval(package):
    before = digest(package / "after.db")
    report = export_normal_collection(package)
    assert report["status"] == "PASS", report
    assert report["training_approved"] is False and report["whole_capture_session_approved"] is False
    assert report["provenance_status"] == "UNCONFIRMED" and len(report["approval_blockers"]) == 2
    assert report["counts"] == {"mqtt_raw": 12, "mqtt_features": 6, "packet_features": 6,
                                "ai_observations": 1, "applied_events": 1}
    pico = [row for row in csv_rows(package, "mqtt-features.csv") if row["device_id"] == "pico_01"]
    assert pico and all(float(row["max_payload_size"]) > 100 for row in pico)
    assert all("payload_raw_base64" in json.loads(line) for line in (package / "mqtt-raw.jsonl").read_text().splitlines())
    assert digest(package / "after.db") == before
    assert main(["--package-dir", str(package)]) == 0


def test_start_end_precision_and_other_capture_session_do_not_leak(package):
    for instant in (START-timedelta(microseconds=1), START+timedelta(seconds=20)):
        mutate_db(package, "INSERT INTO mqtt_logs(device_id,topic,payload_size,received_at) VALUES(?,?,?,?)",
                  ("pico_01", "iot/pico_01/sensor", 1, utc(instant)))
    mutate_db(package, "INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at) VALUES(?,?,?)",
              (str(uuid4()), "eth9", utc(START)))
    mutate_db(package, """INSERT INTO packet_capture_segments(capture_session_id,capture_interface,file_name,
              window_start,window_end,status) VALUES(2,'eth9','outside.pcap',?,?,'PROCESSED')""",
              (utc(START), utc(START + timedelta(seconds=10))))
    mutate_db(package, """INSERT INTO packet_feature_logs(capture_segment_id,device_id,peer_ip,direction,
              window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size)
              VALUES(3,'pico_01','192.168.0.6','INBOUND',?,?,999,999,1,1)""",
              (utc(START), utc(START + timedelta(seconds=10))))
    report = export_normal_collection(package)
    assert report["status"] == "PASS", report
    assert report["counts"]["mqtt_raw"] == 12 and report["counts"]["packet_features"] == 6
    assert not any(row["packet_count"] == "999" for row in csv_rows(package, "packet-features.csv"))


@pytest.mark.parametrize("failure", ["raw_text", "raw_null", "feature_gap", "packet_gap", "session_lost",
                                    "policy_changed", "pcap_lost", "drops", "sidecar_source", "checksum",
                                    "escape", "approval_true", "provenance_hash", "provenance_status", "collector_issue"])
def test_qc_failures_hold_and_preserve_bounded_candidates(package, failure):
    manifest = json.loads((package / "manifest.json").read_text())
    if failure == "raw_text":
        mutate_db(package, "UPDATE mqtt_logs SET payload='secret-marker' WHERE id=1")
    elif failure == "raw_null":
        # Deliberately model a legacy row; normal migration guards prevent raw erasure.
        mutate_db(package, "DROP TRIGGER trg_mqtt_logs_raw_payload_immutable")
        mutate_db(package, "UPDATE mqtt_logs SET payload_raw=NULL,payload_decode_status=NULL WHERE id=1")
    elif failure == "feature_gap":
        mutate_db(package, "DELETE FROM feature_logs WHERE id=2")
    elif failure == "packet_gap":
        mutate_db(package, "DELETE FROM packet_feature_logs WHERE id=3")
    elif failure == "session_lost":
        mutate_db(package, "DELETE FROM packet_capture_sessions")
    elif failure == "policy_changed":
        mutate_db(package, """INSERT INTO device_policy_revisions(device_id,revision,effective_from,
            registration_state,policy_profile,expected_publish_interval_seconds,publish_count_max,
            payload_size_max_bytes,packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason)
            SELECT device_id,2,?,registration_state,policy_profile,expected_publish_interval_seconds,
            publish_count_max+1,payload_size_max_bytes,packet_rate_max_pps,byte_rate_max_bytes_per_second,
            created_at,created_by,reason FROM device_policy_revisions WHERE device_id='pico_01'""",
            (utc(START + timedelta(seconds=10)),))
    elif failure == "pcap_lost":
        (package / manifest["capture_artifacts"][0]["pcap_path"]).unlink()
    elif failure in ("drops", "sidecar_source"):
        artifact = manifest["capture_artifacts"][0]
        path = package / artifact["diagnostics_path"]
        data = json.loads(path.read_text())
        data["packets_dropped" if failure == "drops" else "session_id"] = 1 if failure == "drops" else str(uuid4())
        path.write_text(json.dumps(data))
        artifact["diagnostics_sha256"] = digest(path)
    elif failure == "checksum":
        manifest["capture_artifacts"][0]["pcap_sha256"] = "0" * 64
    elif failure == "escape":
        manifest["capture_artifacts"][0]["pcap_path"] = "../outside.pcap"
    elif failure == "approval_true":
        manifest["training_approved"] = True
    elif failure == "provenance_hash":
        manifest["firmware_provenance"] = {"status": "CONFIRMED", "path": "manifest.json", "sha256": "0" * 64}
    elif failure == "provenance_status":
        manifest["firmware_provenance"] = {"status": "VERIFIED"}
    elif failure == "collector_issue":
        manifest["collection_issues"] = ["runtime_code_changed"]
    if failure in ("drops", "sidecar_source", "checksum", "escape", "approval_true",
                   "provenance_hash", "provenance_status", "collector_issue"):
        save_manifest(package, manifest)
    report = export_normal_collection(package)
    assert report["status"] == "HOLD" and report["hold_reasons"], report
    assert report["training_approved"] is False
    assert "secret-marker" not in json.dumps(report)
    assert (package / "mqtt-features.csv").exists() and (package / "mqtt-raw.jsonl").exists()
    assert main(["--package-dir", str(package)]) == 2


def test_unverified_snapshot_and_malformed_manifest_fail_closed(package):
    manifest = json.loads((package / "manifest.json").read_text())
    manifest["snapshot"]["sha256"] = "0" * 64
    (package / "manifest.json").write_text(json.dumps(manifest))
    assert export_normal_collection(package)["status"] == "HOLD"
    (package / "manifest.json").write_text('{"private-input": "secret-marker"')
    before = tree_hashes(package)
    report = export_normal_collection(package)
    assert report["status"] == "HOLD" and "secret-marker" not in json.dumps(report)
    assert tree_hashes(package) == before


def test_snapshot_trust_change_holds_with_a_valid_updated_checksum(package):
    mutate_db(package, "UPDATE devices SET trust_score=90 WHERE device_id='pico_01'")
    report = export_normal_collection(package)
    assert report["status"] == "HOLD"
    assert "policies:device_trust_changed" in report["hold_reasons"]
    assert report["counts"]["mqtt_raw"] == 12
    assert len(csv_rows(package, "mqtt-features.csv")) == 6


def test_output_symlink_cannot_write_outside_package(package, tmp_path):
    outside = tmp_path / "unchanged.csv"
    outside.write_text("unchanged")
    try:
        (package / "mqtt-features.csv").symlink_to(outside)
    except OSError:
        pytest.skip("Host does not permit symlink creation")
    assert export_normal_collection(package)["status"] == "HOLD"
    assert outside.read_text() == "unchanged"


@pytest.mark.parametrize("status", ["CANDIDATE_QC_PASSED", "HOLD", "HOLD_INCOMPLETE", "CAPTURING", "UNKNOWN", None])
def test_in_place_export_refuses_non_raw_states_without_changing_any_source_file(package, status, capsys):
    manifest = mark_completed(package)
    if status is None:
        del manifest["status"]
    else:
        manifest["status"] = status
    save_manifest(package, manifest)
    before = tree_hashes(package)

    report = export_normal_collection(package)

    assert report["status"] == "HOLD"
    assert report["hold_reasons"] == ["preflight:in_place_requires_raw_captured"]
    assert report["training_approved"] is False and report["whole_capture_session_approved"] is False
    assert tree_hashes(package) == before
    assert main(["--package-dir", str(package)]) == 2
    assert "preflight:in_place_requires_raw_captured" in capsys.readouterr().out
    assert tree_hashes(package) == before


def test_completed_package_reqc_uses_snapshot_and_new_output_without_changing_source(package, tmp_path):
    mark_completed(package)
    # Re-QC must rebuild outputs from evidence rather than copy an old CSV or PASS.
    (package / "mqtt-features.csv").write_text("stale candidate export")
    (package / "qc-report.json").write_text('{"status":"HOLD"}')
    before = tree_hashes(package)
    destination = tmp_path / "rechecked"

    report = export_normal_collection(package, output_dir=destination)

    assert report["status"] == "PASS", report
    assert report["counts"] == {"mqtt_raw": 12, "mqtt_features": 6, "packet_features": 6,
                                "ai_observations": 1, "applied_events": 1}
    assert report["training_approved"] is False and report["whole_capture_session_approved"] is False
    assert report["provenance_status"] == "UNCONFIRMED"
    assert len(csv_rows(destination, "mqtt-features.csv")) == 6
    assert len(csv_rows(destination, "packet-features.csv")) == 6
    assert json.loads((destination / "qc-report.json").read_text()) == report
    assert set(tree_hashes(destination)) == {"mqtt-features.csv", "packet-features.csv", "mqtt-raw.jsonl",
                                            "events.json", "qc-report.json"}
    assert tree_hashes(package) == before


@pytest.mark.parametrize("status", ["RAW_CAPTURED", "CANDIDATE_QC_PASSED"])
def test_cli_new_output_reqc_keeps_source_unchanged(package, tmp_path, status):
    if status == "CANDIDATE_QC_PASSED":
        mark_completed(package)
    before = tree_hashes(package)
    destination = tmp_path / "cli-rechecked"

    assert main(["--package-dir", str(package), "--output-dir", str(destination)]) == 0

    assert json.loads((destination / "qc-report.json").read_text())["status"] == "PASS"
    assert tree_hashes(package) == before


@pytest.mark.parametrize("failure", ["snapshot_checksum", "pcap_changed", "feature_changed", "collector_issue",
                                    "approval_true", "provenance_hash", "incomplete"])
def test_failed_reqc_writes_hold_only_to_new_output_and_preserves_source(package, tmp_path, failure):
    manifest = mark_completed(package)
    if failure == "snapshot_checksum":
        manifest["snapshot"]["sha256"] = "0" * 64
        (package / "manifest.json").write_text(json.dumps(manifest))
    elif failure == "pcap_changed":
        path = package / manifest["capture_artifacts"][0]["pcap_path"]
        path.write_bytes(path.read_bytes() + b"changed")
    elif failure == "feature_changed":
        mutate_db(package, "UPDATE feature_logs SET publish_count=99 WHERE id=1")
    else:
        if failure == "collector_issue":
            manifest["collection_issues"] = ["checkpoint_timeout"]
        elif failure == "approval_true":
            manifest["training_approved"] = True
        elif failure == "provenance_hash":
            manifest["firmware_provenance"] = {"status": "CONFIRMED", "path": "manifest.json", "sha256": "0" * 64}
        elif failure == "incomplete":
            manifest["status"] = "HOLD_INCOMPLETE"
        save_manifest(package, manifest)
    before = tree_hashes(package)
    destination = tmp_path / "failed-recheck"

    report = export_normal_collection(package, output_dir=destination)

    assert report["status"] == "HOLD" and report["hold_reasons"], report
    assert report["training_approved"] is False and report["whole_capture_session_approved"] is False
    assert json.loads((destination / "qc-report.json").read_text()) == report
    assert tree_hashes(package) == before


@pytest.mark.parametrize("kind", ["existing_directory", "existing_file", "same", "nested", "normalized_nested"])
def test_unsafe_output_directory_is_refused_without_modifying_existing_files(package, tmp_path, kind):
    mark_completed(package)
    if kind == "existing_directory":
        destination = tmp_path / "existing"
        destination.mkdir()
        (destination / "mqtt-features.csv").write_text("unchanged existing data")
    elif kind == "existing_file":
        destination = tmp_path / "existing-file"
        destination.write_text("unchanged file")
    elif kind == "same":
        destination = package
    elif kind == "nested":
        destination = package / "new-output"
    else:
        destination = package / "pcap" / ".." / "new-output"
    before = tree_hashes(tmp_path)

    report = export_normal_collection(package, output_dir=destination)

    assert report["status"] == "HOLD"
    reason = "output_must_be_new" if kind.startswith("existing") else "output_must_be_outside_package"
    assert report["hold_reasons"] == ["preflight:" + reason]
    assert tree_hashes(tmp_path) == before
    if kind in ("nested", "normalized_nested"):
        assert not (package / "new-output").exists()


@pytest.mark.parametrize("kind", ["directory", "dangling", "ancestor"])
def test_symlink_output_paths_are_refused_before_resolving_or_writing(package, tmp_path, kind):
    mark_completed(package)
    target = tmp_path / "link-target"
    if kind != "dangling":
        target.mkdir()
        (target / "untouched.txt").write_text("unchanged")
    link = tmp_path / "linked-output"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not permit symlink creation")
    destination = link / "new-output" if kind == "ancestor" else link
    before = tree_hashes(package)

    report = export_normal_collection(package, output_dir=destination)

    assert report["status"] == "HOLD"
    assert report["hold_reasons"] == ["preflight:output_symlink"]
    assert tree_hashes(package) == before
    assert link.is_symlink()
    if kind == "dangling":
        assert not target.exists()
    else:
        assert tree_hashes(target) == {"untouched.txt": hashlib.sha256(b"unchanged").hexdigest()}
        assert not (target / "new-output").exists()


@pytest.mark.parametrize("kind", ["directory", "ancestor"])
def test_windows_junction_output_paths_are_refused_without_writing(package, tmp_path, kind):
    winapi = pytest.importorskip("_winapi")
    mark_completed(package)
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "untouched.txt").write_text("unchanged")
    link = tmp_path / "linked-output"
    try:
        winapi.CreateJunction(str(target), str(link))
    except OSError:
        pytest.skip("Host does not permit junction creation")
    try:
        before = tree_hashes(package)
        destination = link / "new-output" if kind == "ancestor" else link

        report = export_normal_collection(package, output_dir=destination)

        assert report["status"] == "HOLD"
        assert report["hold_reasons"] == ["preflight:output_symlink"]
        assert tree_hashes(package) == before
        assert tree_hashes(target) == {"untouched.txt": hashlib.sha256(b"unchanged").hexdigest()}
        assert not (target / "new-output").exists()
    finally:
        # Removing the junction itself leaves the separate target intact.
        link.rmdir()


def test_output_preparation_error_preserves_source_and_existing_parent_file(package, tmp_path):
    mark_completed(package)
    parent = tmp_path / "parent-file"
    parent.write_text("unchanged")
    before = tree_hashes(tmp_path)

    report = export_normal_collection(package, output_dir=parent / "new-output")

    assert report["status"] == "HOLD"
    assert len(report["hold_reasons"]) == 1 and report["hold_reasons"][0].startswith("preflight:")
    assert tree_hashes(tmp_path) == before


def mqtt_publish(payload, topic=b"iot/pico_01/sensor"):
    body = len(topic).to_bytes(2, "big") + topic + payload
    remaining, encoded = len(body), bytearray()
    while True:
        value, remaining = remaining % 128, remaining // 128
        encoded.append(value | (128 if remaining else 0))
        if not remaining:
            return b"\x30" + bytes(encoded) + body


def wire_jitter_package(root, failure=None):
    """A synthetic 8 → 2 → 5 s arrival recovery, unrelated to the observed 2.825 s case."""
    arrivals = [1, 9, 11, 16]
    if failure == "edge_short":
        arrivals = [1, 3, 11, 16]
    elif failure == "long_gap":
        arrivals = [1, 12, 14, 19]
    elif failure == "unrecovered":
        arrivals = [1, 7.5, 9.5, 16]
    elif failure == "repeated_short":
        arrivals = [1, 8, 10, 12]
    elif failure == "no_short":
        arrivals = [1, 6, 11, 16]
    with closing(sqlite3.connect(root / "after.db")) as db:
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute("SELECT * FROM mqtt_logs WHERE device_id='pico_01' ORDER BY id")]
        for index, row in enumerate(rows):
            row["received_at"] = utc(START + timedelta(seconds=arrivals[index]))
            db.execute("UPDATE mqtt_logs SET received_at=? WHERE id=?", (row["received_at"], row["id"]))
        if failure == "missing_row":
            db.execute("DELETE FROM mqtt_logs WHERE id=?", (rows[1]["id"],))
        for index in range(2):
            selected = [row for row, instant in zip(rows, arrivals) if index*10 <= instant < (index+1)*10]
            moments = [instant for instant in arrivals if index*10 <= instant < (index+1)*10]
            intervals = [b-a for a, b in zip(moments, moments[1:])] or [5]
            db.execute("UPDATE feature_logs SET publish_count=?,avg_payload_size=?,max_payload_size=?,"
                       "avg_message_interval=?,min_message_interval=? WHERE device_id='pico_01' AND window_start=?",
                       (len(selected), sum(row["payload_size"] for row in selected)/len(selected),
                        max(row["payload_size"] for row in selected), sum(intervals)/len(intervals), min(intervals),
                        utc(START + timedelta(seconds=index*10))))
        if failure == "duplicate_row":
            source = rows[1]
            insert(db, "mqtt_logs", **{key: source[key] for key in source if key != "id"})
        if failure in ("restart", "sender_burst"):
            value = json.loads(rows[1]["payload"])
            value["uptime_ms"] = 0 if failure == "restart" else 102000
            # Replace this synthetic input record; never weaken the production raw-payload update trigger.
            rows[1].update(payload=json.dumps(value), payload_raw=json.dumps(value).encode())
            rows[1]["payload_size"] = len(rows[1]["payload_raw"])
            db.execute("DELETE FROM mqtt_logs WHERE id=?", (rows[1]["id"],))
            insert(db, "mqtt_logs", **rows[1])
        db.commit()
    manifest = json.loads((root / "manifest.json").read_text())
    sequence = 0xFFFFFFCE if failure == "tcp_wrap" else 1000
    frames = []
    for index, (row, instant) in enumerate(zip(rows, arrivals)):
        body = mqtt_publish(row["payload_raw"])
        if failure == "payload_mismatch" and index == 1:
            body = body[:-1] + b"!"
        if failure == "coalesced" and index == 1:
            body += body
        if failure == "missing_frame" and index == 1:
            sequence += len(body)
            continue
        flags = dpkt.tcp.TH_ACK | (dpkt.tcp.TH_FIN if failure == "control" and index == 1 else 0)
        parts = [body]
        if failure in ("fragmented", "body_stall") and index == 1:
            parts = [body[:12], body[12:]]
        part_seq = sequence
        for part_index, part in enumerate(parts):
            tcp = dpkt.tcp.TCP(sport=40000 if failure != "different_flow" or index != 2 else 40001,
                              dport=1883, seq=part_seq, flags=flags,
                              win=0 if failure == "zero_window" and index == 1 else 8192, data=part)
            ip = dpkt.ip.IP(src=socket.inet_aton(IPS["pico_01"]), dst=socket.inet_aton("192.168.0.2"), p=6, data=tcp)
            ip.len = len(ip)
            frame = bytes(dpkt.ethernet.Ethernet(src=b"\x00"*6, dst=b"\x01"*6,
                                               type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
            stamp = instant - (1.5 if failure == "receiver_delay" and index == 1 else .002)
            if len(parts) > 1 and part_index == 0:
                stamp -= 2 if failure == "body_stall" else .5
            frames.append((stamp, frame))
            part_seq += len(part)
        if failure == "duplicate_bytes" and index == 1:
            frames.append((stamp + .001, frame))
        sequence = (sequence + len(body) + (1 if failure == "byte_hole" and index == 1 else 0)) & 0xFFFFFFFF
    for index, artifact in enumerate(manifest["capture_artifacts"]):
        stream = io.BytesIO()
        writer = dpkt.pcap.Writer(stream)
        for stamp, frame in sorted(frames):
            if index*10 <= stamp < (index+1)*10:
                writer.writepkt(frame, ts=START.timestamp()+stamp)
        path = root / artifact["pcap_path"]
        path.write_bytes(stream.getvalue())
        artifact["pcap_sha256"] = digest(path)
    if failure == "invalid_pcap":
        path = root / manifest["capture_artifacts"][0]["pcap_path"]
        path.write_bytes(b"not a capture")
        manifest["capture_artifacts"][0]["pcap_sha256"] = digest(path)
    if failure == "truncated_pcap":
        path = root / manifest["capture_artifacts"][0]["pcap_path"]
        path.write_bytes(path.read_bytes() + b"\x00\x01")
        manifest["capture_artifacts"][0]["pcap_sha256"] = digest(path)
    save_manifest(root, manifest)
    strict = export_normal_collection(root)
    # Preserve a strict source HOLD and its identity; source-specific malformed cases are rejected by derived QC.
    manifest["status"] = "HOLD"
    manifest["collection_issues"] = []
    manifest["qc_report"] = "qc-report.json"
    save_manifest(root, manifest)
    if failure == "no_short":
        strict["status"] = "HOLD"
        strict["hold_reasons"] = ["mqtt:pico_01:reception_gap_or_burst"]
        (root / "qc-report.json").write_text(json.dumps(strict))
    return strict


@pytest.mark.parametrize("fragmentation", [None, "fragmented"])
def test_wire_jitter_reqc_requires_direct_bytes_and_preserves_strict_hold(package, tmp_path, fragmentation):
    strict = wire_jitter_package(package, fragmentation)
    assert strict["status"] == "HOLD" and strict["hold_reasons"] == ["mqtt:pico_01:reception_gap_or_burst"]
    before = tree_hashes(package)
    report = export_normal_collection(package, output_dir=tmp_path / "wire-qc",
                                      reception_policy="pico-p0-wire-jitter-v1")
    assert report["status"] == "PASS", report
    assert report["reception_policy"] == "pico-p0-wire-jitter-v1"
    assert report["source_manifest_status"] == "HOLD"
    assert report["source_qc"]["sha256"] == digest(package / "qc-report.json")
    evidence = report["reception_jitter"]
    assert evidence["physical_cause"] == "UNDETERMINED"
    assert evidence["reception_intervals_seconds"] == [8, 2, 5]
    assert len(evidence["samples"]) == 4 and len(evidence["pcaps"]) == 2
    assert report["training_approved"] is False and report["whole_capture_session_approved"] is False
    assert tree_hashes(package) == before


@pytest.mark.parametrize("failure", ["missing_row", "duplicate_row", "restart", "sender_burst",
    "edge_short", "long_gap", "unrecovered", "no_short", "payload_mismatch", "coalesced",
    "missing_frame", "different_flow", "control", "zero_window", "duplicate_bytes", "byte_hole",
    "receiver_delay", "invalid_pcap", "truncated_pcap", "body_stall", "repeated_short"])
def test_wire_jitter_rejects_content_and_transport_evidence_defects(package, tmp_path, failure):
    wire_jitter_package(package, failure)
    before = tree_hashes(package)
    report = export_normal_collection(package, output_dir=tmp_path / "wire-qc",
                                      reception_policy="pico-p0-wire-jitter-v1")
    assert report["status"] == "HOLD" and report["hold_reasons"], report
    assert tree_hashes(package) == before


def test_wire_jitter_preserves_contiguous_tcp_bytes_across_sequence_wrap(package, tmp_path):
    wire_jitter_package(package, "tcp_wrap")
    before = tree_hashes(package)
    report = export_normal_collection(package, output_dir=tmp_path / "wrapped-review",
                                      reception_policy="pico-p0-wire-jitter-v1")
    assert report["status"] == "PASS", report
    assert report["reception_jitter"]["status"] == "VERIFIED_SINGLE_RECOVERY"
    assert tree_hashes(package) == before


@pytest.mark.parametrize("failure", ["in_place", "source_qc_missing", "source_qc_scope", "source_qc_reason",
                                    "source_qc_approval", "source_qc_issues", "unknown_policy", "pico_p1"])
def test_wire_jitter_policy_and_original_hold_link_are_required(package, tmp_path, failure):
    wire_jitter_package(package)
    path = package / "qc-report.json"
    qc = json.loads(path.read_text())
    if failure == "source_qc_missing":
        path.unlink()
    elif failure.startswith("source_qc_"):
        if failure == "source_qc_scope":
            qc["run_id"] = str(uuid4())
        elif failure == "source_qc_reason":
            qc["hold_reasons"].append("capture:failed")
        elif failure == "source_qc_approval":
            qc["training_approved"] = True
        else:
            qc["collection_issues"] = ["unsafe"]
        path.write_text(json.dumps(qc))
    before = tree_hashes(package)
    report = export_normal_collection(package, output_dir=None if failure == "in_place" else tmp_path / "wire-qc",
        qc_profiles={"pico_01": "P1"} if failure == "pico_p1" else None,
        reception_policy="unknown" if failure == "unknown_policy" else "pico-p0-wire-jitter-v1")
    assert report["status"] == "HOLD" and report["hold_reasons"], report
    assert tree_hashes(package) == before
