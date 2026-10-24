"""Export bounded Phase 8 candidates. Content PASS never grants training approval."""
from __future__ import annotations

import argparse
import base64
from collections import defaultdict
from contextlib import closing
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import stat
import statistics
import sys
from uuid import UUID

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.packet_if_contract import transform_packet_feature_row
from ai.pico_reception_qc import STRICT_POLICY, WIRE_JITTER_POLICY, verify_reception_jitter
from edge.detection.phase4_time import parse_db_utc
from edge.maintenance.processing import dataset_maintenance_windows, overlaps_maintenance
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible
from edge.packet.pcap_naming import parse_pcap_filename
from edge.policy.device_policy_repository import get_policy_snapshot
from edge.policy.device_policy import DevicePolicyError
from firmware.pico_wh_bme280.verify_pico_telemetry import verify as verify_pico

SCHEMA_VERSION = "phase8-normal-candidate-v1"
TARGETS = {"esp32_01", "esp32_02", "pico_01"}
SAFE_ERRORS = (OSError, ValueError, TypeError, KeyError, IndexError, sqlite3.Error, OverflowError, DevicePolicyError)
# Reception cadence per Profile as the (min, max) scheduled interval in seconds. P0 is the
# 5-second default; P1 allows a 4-6 second schedule on one ESP32. Thresholds derive from these bounds.
MQTT_QC_PROFILES = {"P0": (5.0, 5.0), "P1": (4.0, 6.0)}
MQTT_COLUMNS = ("id", "device_id", "window_start", "window_end", "publish_count",
                "avg_payload_size", "max_payload_size", "avg_message_interval", "min_message_interval",
                "topic_count", "abnormal_topic_count", "malformed_payload_count")
PACKET_COLUMNS = ("id", "capture_segment_id", "device_id", "peer_ip", "direction", "window_start",
                  "window_end", "packet_count", "total_bytes", "avg_packet_size", "max_packet_size",
                  "mean_inter_arrival_time", "distinct_dest_port_count", "captured_duration_seconds")


class CandidateQCError(ValueError):
    """A fixed diagnostic code, never an input value."""


def _require(condition, code):
    if not condition:
        raise CandidateQCError(code)


def _hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path(root, relative):
    _require(isinstance(relative, str) and relative and "\\" not in relative
             and not Path(relative).is_absolute() and ":" not in relative, "unsafe_relative_path")
    path = (root / relative).resolve()
    _require(path.is_relative_to(root) and path != root, "path_escape")
    return path


def _verified(root, relative, expected):
    path = _path(root, relative)
    _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "invalid_sha256")
    _require(path.is_file() and _hash(path) == expected, "file_checksum_or_missing")
    return path


def _boundary(value):
    _require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
             "strict_utc_boundary_required")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    _require(parsed.second % 10 == 0, "ten_second_boundary_required")
    return parsed


def _uuid(value):
    _require(isinstance(value, str) and UUID(value).version == 4 and str(UUID(value)) == value,
             "canonical_uuid4_required")


def _rows(db, sql, params=()):
    return [dict(row) for row in db.execute(sql, params)]


def _time(value):
    return parse_db_utc(value, allow_subseconds=True)


def _within(row, start, end, start_key="window_start", end_key="window_end"):
    left, right = _time(row[start_key]), _time(row[end_key])
    return (start <= left < right <= end and right-left == timedelta(seconds=10)
            and left.microsecond == 0 and left.second % 10 == 0)


def _stage(report, label, function):
    try:
        function()
    except SAFE_ERRORS as exc:
        # Never echo exception text: parsing errors can contain raw payload or secrets.
        report["hold_reasons"].append(f"{label}:{exc if isinstance(exc, CandidateQCError) else type(exc).__name__}")


def _bounded(rows, predicate, report, label, reject_outside=False):
    selected = []
    for row in rows:
        def select():
            inside = predicate(row)
            if reject_outside:
                _require(inside, "invalid_or_partial_window")
            if inside:
                selected.append(row)
        _stage(report, label, select)
    return selected


def _metadata(manifest, *, allow_completed=False, allow_reception_hold=False):
    states = ("RAW_CAPTURED", "CANDIDATE_QC_PASSED") if allow_completed else ("RAW_CAPTURED",)
    if allow_reception_hold:
        states += ("HOLD",)
    _require(manifest["schema_version"] == SCHEMA_VERSION and manifest["status"] in states,
             "candidate_schema_or_state")
    _require(manifest["training_approved"] is False
             and manifest["whole_capture_session_approved"] is False, "approval_must_remain_false")
    _uuid(manifest["run_id"])
    _uuid(manifest["source_capture_group_id"])
    _require(type(manifest["capture_session_pk"]) is int and manifest["capture_session_pk"] > 0,
             "invalid_capture_pk")
    start, end = _boundary(manifest["start_utc"]), _boundary(manifest["end_utc"])
    _require(timedelta(0) < end - start <= timedelta(days=1), "invalid_bounded_duration")
    ids = manifest["included_device_ids"]
    _require(isinstance(ids, list) and ids and all(isinstance(value, str) for value in ids)
             and len(set(ids)) == len(ids) and set(ids) <= TARGETS, "invalid_target_devices")
    _require(isinstance(manifest["code_commit"], str)
             and re.fullmatch(r"[0-9a-f]{40}", manifest["code_commit"]), "invalid_code_commit")
    _require(isinstance(manifest["devices"], list)
             and {row["device_id"] for row in manifest["devices"]} == set(ids)
             and len(manifest["devices"]) == len(ids), "invalid_device_metadata")
    _require(all(row["status"] == "normal" and type(row["trust_score"]) is int
                 and 0 <= row["trust_score"] <= 100 for row in manifest["devices"]), "invalid_start_trust")
    return start, end, ids


def _policies(db, manifest, start, end):
    frozen = manifest["device_policy_revisions"]
    _require(isinstance(frozen, list) and frozen, "missing_frozen_policies")
    for row in frozen:
        actual = _rows(db, "SELECT * FROM device_policy_revisions WHERE device_id=? AND revision=?",
                       (row["device_id"], row["revision"]))
        _require(actual == [row], "frozen_policy_mismatch")
    for device in manifest["devices"]:
        device_id = device["device_id"]
        actual = _rows(db, "SELECT * FROM devices WHERE device_id=?", (device_id,))[0]
        _require(actual["ip_address"] == device["ip_address"]
                 and device["mqtt_topic"] == f"iot/{device_id}/sensor", "device_identity_mismatch")
        _require(actual["status"] == device["status"] and actual["trust_score"] == device["trust_score"],
                 "device_trust_changed")
        current = get_policy_snapshot(db, device_id, server_time=start).current
        _require(current is not None and type(device["current_policy_revision"]) is int
                 and current.revision == device["current_policy_revision"]
                 and current.registration_state == device["registration_state"] == "ACTIVE", "start_policy_mismatch")
        _require(any(row["device_id"] == device_id and row["revision"] == current.revision
                     for row in frozen), "start_policy_not_frozen")
        revisions = _rows(db, "SELECT revision,effective_from FROM device_policy_revisions WHERE device_id=?",
                          (device_id,))
        _require(not any(start <= _time(row["effective_from"]) < end and row["revision"] != current.revision
                         for row in revisions), "policy_changed_within_range")


def mqtt_qc_policy(profile):
    """Thresholds derived from a Profile's scheduled interval bounds (P0 equals the original constants)."""
    _require(profile in MQTT_QC_PROFILES, "unknown_qc_profile")
    low, high = MQTT_QC_PROFILES[profile]
    return {"profile": profile, "interval_seconds": [low, high],
            "sender_gap_seconds": [low - 1, high + 3], "sender_median_seconds": [low - 0.5, high + 1.5],
            "reception_gap_seconds": [low * 3 / 5, 2 * high], "edge_gap_seconds": 2 * high,
            "interval_max_seconds": high}


def _qc_profiles(profiles, ids):
    profiles = dict(profiles or {})
    for device_id, profile in profiles.items():
        _require(device_id in ids, "qc_profile_device_not_in_run")
        mqtt_qc_policy(profile)
        _require(device_id != "pico_01" or profile == "P0", "profile_not_supported_for_device")
    return {device_id: mqtt_qc_policy(profiles.get(device_id, "P0")) for device_id in ids}


def _mqtt_qc(raw, features, ids, start, end, report, profiles=None, verified_jitter=False):
    policies = _qc_profiles(profiles, ids)
    report["qc_policy"] = policies
    grouped = defaultdict(list)
    for device_id in ids:
        policy = policies[device_id]
        rows = [row for row in raw if row["device_id"] == device_id]
        rows.sort(key=lambda row: (_time(row["received_at"]), row["id"]))

        def check_device():
            sequences, uptimes = [], []
            for row in rows:
                payload = row.get("payload_raw")
                _require(isinstance(payload, bytes) and row.get("payload_decode_status") == "OK"
                         and type(row["payload_size"]) is int and len(payload) == row["payload_size"],
                         "raw_payload_missing_or_inconsistent")
                decoded = payload.decode("utf-8")
                value = json.loads(decoded)
                _require(isinstance(value, dict) and value.get("device_id") == device_id
                         and decoded == row["payload"] and row["topic"] == f"iot/{device_id}/sensor"
                         and row["is_json_valid"] == 1 and row["is_topic_valid"] == 1
                         and row["error_message"] in (None, ""), "invalid_mqtt_identity")
                sequence, uptime = (value["seq"], value["uptime_ms"]) if device_id == "pico_01" else (
                    value["sequence"], value["uptime_s"])
                _require(type(sequence) is int and sequence >= 1 and type(uptime) is int and uptime >= 0,
                         "invalid_sequence_or_uptime")
                sequences.append(sequence)
                uptimes.append(uptime / (1000 if device_id == "pico_01" else 1))
            _require(len(rows) >= 2, "too_few_messages")
            gap_low, gap_high = policy["sender_gap_seconds"]
            for left, right, old, new in zip(sequences, sequences[1:], uptimes, uptimes[1:]):
                _require(right == left + 1 and gap_low <= new - old <= gap_high, "sequence_or_sender_gap")
            median_low, median_high = policy["sender_median_seconds"]
            _require(median_low <= statistics.median(b-a for a, b in zip(uptimes, uptimes[1:])) <= median_high,
                     "sender_cadence")
            times = [_time(row["received_at"]) for row in rows]
            reception_low, reception_high = policy["reception_gap_seconds"]
            allow_short = device_id == "pico_01" and verified_jitter
            _require(all(0 < (b-a).total_seconds() <= reception_high
                         and (allow_short or (b-a).total_seconds() >= reception_low)
                         for a, b in zip(times, times[1:])), "reception_gap_or_burst")
            cursor = start
            while cursor < end:
                stop = min(cursor + timedelta(minutes=5), end)
                minimum = math.ceil((stop-cursor).total_seconds() / policy["interval_max_seconds"] * 58 / 60)
                _require(sum(cursor <= value < stop for value in times) >= minimum, "message_count_shortfall")
                cursor = stop
            _require((times[0]-start).total_seconds() <= policy["edge_gap_seconds"]
                     and (end-times[-1]).total_seconds() <= policy["edge_gap_seconds"], "edge_reception_gap")
            if device_id == "pico_01":
                verify_pico(rows, mode="gateway", payload_max=5120, min_samples=2,
                            check_reception_cadence=not verified_jitter)
            report["mqtt_devices"][device_id] = {"samples": len(rows), "first_seq": sequences[0],
                "last_seq": sequences[-1], "uptime_seconds_range": [uptimes[0], uptimes[-1]],
                "payload_bytes_range": [min(row["payload_size"] for row in rows),
                                        max(row["payload_size"] for row in rows)]}
        _stage(report, f"mqtt:{device_id}", check_device)
        for row in rows:
            when = _time(row["received_at"]).replace(microsecond=0)
            grouped[(device_id, when.replace(second=when.second // 10 * 10))].append(row)
    indexed = defaultdict(list)
    for row in features:
        indexed[(row["device_id"], _time(row["window_start"]))].append(row)
    cursor = start
    while cursor < end:
        for device_id in ids:
            def check_window():
                window = indexed[(device_id, cursor)]
                _require(len(window) == 1, "feature_window_missing_or_duplicate")
                feature, messages = window[0], grouped[(device_id, cursor)]
                _require(_time(feature["window_end"]) == cursor + timedelta(seconds=10)
                         and messages and feature["publish_count"] == len(messages), "feature_raw_count")
                sizes = [row["payload_size"] for row in messages]
                times = sorted(_time(row["received_at"]) for row in messages)
                intervals = [(b-a).total_seconds() for a, b in zip(times, times[1:])] or [5.0]
                expected = {"avg_payload_size": sum(sizes)/len(sizes), "max_payload_size": max(sizes),
                            "avg_message_interval": sum(intervals)/len(intervals),
                            "min_message_interval": min(intervals)}
                _require(all(math.isclose(feature[key], value, rel_tol=1e-9, abs_tol=1e-9)
                             for key, value in expected.items()), "feature_raw_values")
                _require(feature["topic_count"] == 1 and feature["abnormal_topic_count"] == 0
                         and feature["malformed_payload_count"] == 0, "feature_validity_flags")
            _stage(report, f"mqtt_feature:{device_id}:{cursor.strftime('%H%M%S')}", check_window)
        cursor += timedelta(seconds=10)


def _capture_qc(root, manifest, session, segments, packets, start, end, report):
    _require(session["session_id"] == manifest["source_capture_group_id"], "capture_source_mismatch")
    policy = CapturePolicy(**manifest["capture_policy"])
    _require(all(type(getattr(policy, field)) in (int, float) for field in
                 ("max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds")),
             "capture_policy_numeric_types")
    expected = {start + timedelta(seconds=offset) for offset in range(0, int((end-start).total_seconds()), 10)}
    _require(len(segments) == len(expected) and {_time(row["window_start"]) for row in segments} == expected,
             "segment_continuity")
    artifacts = manifest["capture_artifacts"]
    _require(isinstance(artifacts, list) and len(artifacts) == len(segments)
             and {row["segment_id"] for row in artifacts} == {row["id"] for row in segments},
             "artifact_inventory")
    by_id = {row["segment_id"]: row for row in artifacts}
    for segment in segments:
        def check_segment():
            _require(_time(segment["window_end"]) - _time(segment["window_start"]) == timedelta(seconds=10)
                     and segment["capture_interface"] == session["capture_interface"], "segment_source_window")
            result = is_capture_eligible(CaptureEligibilitySegment(**{key: segment[key] for key in
                ("status", "error_code", "start_delay_seconds", "captured_duration_seconds")}), policy)
            _require(result.eligible, "capture_ineligible")
            artifact = by_id[segment["id"]]
            pcap = _verified(root, artifact["pcap_path"], artifact["pcap_sha256"])
            diagnostic = _verified(root, artifact["diagnostics_path"], artifact["diagnostics_sha256"])
            parsed = parse_pcap_filename(pcap.name)
            _require(parsed is not None and not parsed.is_tmp and pcap.name == segment["file_name"]
                     and parsed.session_id == session["session_id"] and parsed.interface == session["capture_interface"]
                     and parsed.window_start == _time(segment["window_start"])
                     and parsed.window_end == _time(segment["window_end"]), "pcap_source_window")
            data = json.loads(diagnostic.read_text(encoding="utf-8"))
            _require(data["schema_version"] == "packet-capture-diagnostics-v1"
                     and data["session_id"] == session["session_id"]
                     and data["capture_interface"] == session["capture_interface"]
                     and data["pcap_file_name"] == pcap.name and data["expected_pcap_file_name"] == pcap.name
                     and _time(data["window_start"]) == _time(segment["window_start"])
                     and _time(data["window_end"]) == _time(segment["window_end"]), "diagnostic_source_window")
            _require(all(data.get(key) is True for key in
                         ("success", "completed_full_window", "terminated_cleanly", "stderr_complete"))
                     and type(data["exit_code"]) is int and data["exit_code"] in (0, -15)
                     and type(data["packets_dropped"]) is int and data["packets_dropped"] == 0
                     and data.get("packets_dropped_by_interface") in (None, 0)
                     and all(data.get(key) is None for key in
                             ("error_code", "file_validation_error", "stderr_error")), "capture_diagnostics_failed")
        _stage(report, f"capture_segment:{segment['id']}", check_segment)
    devices = {row["device_id"]: row["ip_address"] for row in manifest["devices"]}
    by_segment = {row["id"]: row for row in segments}
    observed = set()
    for packet in packets:
        def check_packet():
            segment = by_segment[packet["capture_segment_id"]]
            _require(packet["device_id"] in devices and devices[packet["device_id"]] == packet["peer_ip"]
                     and packet["window_start"] == segment["window_start"]
                     and packet["window_end"] == segment["window_end"], "packet_identity_window")
            transform_packet_feature_row(packet)
            if packet["direction"] == "INBOUND":
                observed.add((packet["device_id"], _time(packet["window_start"])))
        _stage(report, f"packet_feature:{packet['id']}", check_packet)
    _require(observed == {(device, window) for device in devices for window in expected},
             "inbound_target_window_missing")


def _write(root, name, data, columns=None):
    path = _path(root, name)
    _require(not (root / name).is_symlink(), "output_symlink")
    with path.open("w", encoding="utf-8", newline="") as handle:
        if columns:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
        elif name.endswith(".jsonl"):
            for row in data:
                handle.write(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n")
        else:
            json.dump(data, handle, indent=2, ensure_ascii=True, allow_nan=False)
            handle.write("\n")


def _new_output_dir(root: Path, output_dir: Path) -> Path:
    path = Path(output_dir).absolute()
    # Resolve only after rejecting dangling symlinks and Windows junctions.
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        _require(not stat.S_ISLNK(info.st_mode)
                 and not (getattr(info, "st_file_attributes", 0)
                          & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)), "output_symlink")
    path = path.resolve()
    _require(not path.is_relative_to(root), "output_must_be_outside_package")
    _require(not path.exists(), "output_must_be_new")
    path.mkdir(parents=True, exist_ok=False)
    return path


def _source_reception_hold(root, manifest):
    _require(manifest.get("status") == "HOLD" and manifest.get("collection_issues", []) == [],
             "reception_policy_requires_clean_source_hold")
    path = _path(root, "qc-report.json")
    before = _hash(path)
    source = json.loads(path.read_text(encoding="utf-8"))
    keys = ("run_id", "start_utc", "end_utc", "capture_session_pk", "source_capture_group_id", "code_commit")
    _require(isinstance(source, dict) and source.get("schema_version") == SCHEMA_VERSION
             and all(source.get(key) == manifest.get(key) for key in keys)
             and source.get("status") == "HOLD"
             and source.get("hold_reasons") == ["mqtt:pico_01:reception_gap_or_burst"]
             and source.get("training_approved") is False and source.get("whole_capture_session_approved") is False
             and source.get("collection_issues", []) == [], "source_reception_hold_mismatch")
    _require(_hash(path) == before, "source_qc_changed_during_read")
    return {"path": "qc-report.json", "sha256": before, "status": "HOLD", "hold_reasons": source["hold_reasons"]}


def export_normal_collection(package_dir: Path, *, output_dir: Path | None = None, qc_profiles=None,
                             reception_policy=STRICT_POLICY) -> dict:
    root = Path(package_dir).resolve()
    report = {"schema_version": SCHEMA_VERSION, "status": "HOLD", "training_approved": False,
              "whole_capture_session_approved": False, "provenance_status": "UNCONFIRMED",
              "approval_blockers": ["firmware_provenance_unconfirmed", "official_dataset_admission_pending"],
              "scope": "Bounded candidate content QC only; no training or whole-session approval.",
              "hold_reasons": [], "mqtt_devices": {}}
    report["counts"] = {"mqtt_raw": 0, "mqtt_features": 0, "packet_features": 0,
                        "ai_observations": 0, "applied_events": 0}
    # Decide where writes are permitted before QC can create any output files.
    # A completed package must never be overwritten by a repeated export.
    try:
        _require(reception_policy in (STRICT_POLICY, WIRE_JITTER_POLICY), "unknown_reception_policy")
        manifest = json.loads(_path(root, "manifest.json").read_text(encoding="utf-8"))
        _require(isinstance(manifest, dict), "invalid_manifest")
        if reception_policy != STRICT_POLICY:
            _require(output_dir is not None, "reception_policy_requires_external_output")
            _require("pico_01" in manifest.get("included_device_ids", [])
                     and (qc_profiles or {}).get("pico_01", "P0") == "P0", "reception_policy_requires_pico_p0")
            report.update(reception_policy=reception_policy, source_manifest_status=manifest.get("status"),
                          source_qc=_source_reception_hold(root, manifest))
        if output_dir is None:
            _require(manifest.get("status") == "RAW_CAPTURED", "in_place_requires_raw_captured")
            destination = root
        else:
            destination = _new_output_dir(root, output_dir)
    except SAFE_ERRORS as exc:
        report["hold_reasons"].append(
            f"preflight:{exc if isinstance(exc, CandidateQCError) else type(exc).__name__}")
        return report
    raw, features, packets, events = [], [], [], []
    try:
        start, end, ids = _metadata(manifest, allow_completed=output_dir is not None,
                                   allow_reception_hold=reception_policy == WIRE_JITTER_POLICY)
        report.update({key: manifest[key] for key in ("run_id", "start_utc", "end_utc",
                       "capture_session_pk", "source_capture_group_id", "code_commit")})
        _require(manifest["snapshot"]["path"] == "after.db", "snapshot_name")
        snapshot = _verified(root, "after.db", manifest["snapshot"]["sha256"])
        _require(not any(Path(str(snapshot) + suffix).exists() for suffix in ("-wal", "-shm")),
                 "snapshot_not_standalone")
        placeholders = ",".join("?" for _ in ids)
        params = (*ids, manifest["start_utc"], manifest["end_utc"])
        bounds = "julianday(window_start)>=julianday(?) AND julianday(window_end)<=julianday(?)"
        with closing(sqlite3.connect(snapshot.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            _require([row[0] for row in db.execute("PRAGMA integrity_check")] == ["ok"]
                     and not db.execute("PRAGMA foreign_key_check").fetchall(), "snapshot_integrity")
            selected_raw = _rows(db, f"SELECT * FROM mqtt_logs WHERE device_id IN ({placeholders}) "
                        "AND julianday(received_at)>=julianday(?)-0.000000012 "
                        "AND julianday(received_at)<=julianday(?)+0.000000012 ORDER BY id", params)
            raw = _bounded(selected_raw, lambda row: start <= _time(row["received_at"]) < end, report, "raw_bounds")
            selected_features = _rows(db, f"SELECT * FROM feature_logs WHERE device_id IN ({placeholders}) AND {bounds}", params)
            features = _bounded(selected_features, lambda row: _within(row, start, end), report, "feature_bounds", True)
            selected_segments = _rows(db, f"SELECT * FROM packet_capture_segments WHERE capture_session_id=? AND {bounds}",
                             (manifest["capture_session_pk"], manifest["start_utc"], manifest["end_utc"]))
            segments = _bounded(selected_segments, lambda row: _within(row, start, end), report, "segment_bounds", True)
            ips = [row["ip_address"] for row in manifest["devices"]]
            selected_packets = _rows(db, f"SELECT f.*,s.captured_duration_seconds FROM packet_feature_logs f "
                "JOIN packet_capture_segments s ON s.id=f.capture_segment_id WHERE s.capture_session_id=? "
                f"AND (f.device_id IN ({placeholders}) OR f.peer_ip IN ({placeholders})) "
                "AND julianday(s.window_start)>=julianday(?) AND julianday(s.window_end)<=julianday(?)",
                (manifest["capture_session_pk"], *ids, *ips, manifest["start_utc"], manifest["end_utc"]))
            packets = _bounded(selected_packets, lambda row: _within(row, start, end), report, "packet_bounds", True)
            selected_events = _rows(db, f"SELECT * FROM detection_events WHERE device_id IN ({placeholders}) "
                "AND julianday(analysis_window_start)>=julianday(?) "
                "AND julianday(analysis_window_end)<=julianday(?) AND (packet_feature_log_id IS NULL OR "
                "packet_feature_log_id IN (SELECT f.id FROM packet_feature_logs f JOIN packet_capture_segments s "
                "ON s.id=f.capture_segment_id WHERE s.capture_session_id=?))", (*params, manifest["capture_session_pk"]))
            events = _bounded(selected_events, lambda row: _within(row, start, end, "analysis_window_start",
                              "analysis_window_end"), report, "event_bounds", True)
            session = _rows(db, "SELECT * FROM packet_capture_sessions WHERE id=?", (manifest["capture_session_pk"],))[0]
            _stage(report, "maintenance", lambda: _require(
                not overlaps_maintenance(dataset_maintenance_windows(db), start, end),
                "approved_maintenance_interval_overlap",
            ))
            _stage(report, "policies", lambda: _policies(db, manifest, start, end))
            if reception_policy == STRICT_POLICY:
                _stage(report, "mqtt", lambda: _mqtt_qc(raw, features, ids, start, end, report, qc_profiles))
            _stage(report, "capture", lambda: _capture_qc(root, manifest, session, segments, packets, start, end, report))
            if reception_policy == WIRE_JITTER_POLICY:
                def check_jitter():
                    _require(not any(reason.startswith("capture") for reason in report["hold_reasons"]),
                             "jitter_capture_checks_failed")
                    pcaps = [(item["segment_id"], item["pcap_path"],
                              _verified(root, item["pcap_path"], item["pcap_sha256"]), item["pcap_sha256"])
                             for item in manifest["capture_artifacts"]]
                    report["reception_jitter"] = verify_reception_jitter(
                        [row for row in raw if row["device_id"] == "pico_01"],
                        run_id=manifest["run_id"], source_capture_group_id=manifest["source_capture_group_id"],
                        device_ip=next(row["ip_address"] for row in manifest["devices"] if row["device_id"] == "pico_01"),
                        pcaps=pcaps)
                _stage(report, "reception_jitter", check_jitter)
                _stage(report, "mqtt", lambda: _mqtt_qc(raw, features, ids, start, end, report, qc_profiles,
                                                       verified_jitter="reception_jitter" in report))
        _require(_hash(snapshot) == manifest["snapshot"]["sha256"], "snapshot_changed_during_export")
        if reception_policy == WIRE_JITTER_POLICY:
            _require(_hash(_path(root, "qc-report.json")) == report["source_qc"]["sha256"],
                     "source_qc_changed_during_export")
        provenance = manifest["firmware_provenance"]
        _require(isinstance(provenance, dict) and provenance.get("status") in ("UNCONFIRMED", "CONFIRMED"),
                 "invalid_firmware_provenance")
        if provenance.get("status") == "CONFIRMED":
            _verified(root, provenance["path"], provenance["sha256"])
            report["provenance_status"] = "DECLARED_EVIDENCE_HASH_MATCHED"
            report["approval_blockers"] = ["official_dataset_admission_pending"]
    except SAFE_ERRORS as exc:
        report["hold_reasons"].append(f"package:{exc if isinstance(exc, CandidateQCError) else type(exc).__name__}")
    if "manifest" in locals() and isinstance(manifest, dict):
        issues = manifest.get("collection_issues", [])
        if issues:
            report["hold_reasons"].append("collector:collection_issues_present")
    report["counts"] = {"mqtt_raw": len(raw), "mqtt_features": len(features), "packet_features": len(packets),
                        "ai_observations": sum(row["detector_type"] == "AI" for row in events),
                        "applied_events": sum(row["applied_to_score"] == 1 for row in events)}
    serialized = [{**{key: value for key, value in row.items() if key != "payload_raw"},
                   "payload_raw_base64": base64.b64encode(row["payload_raw"]).decode("ascii")
                   if isinstance(row.get("payload_raw"), bytes) else None} for row in raw]
    for name, data, columns in (("mqtt-features.csv", features, MQTT_COLUMNS),
            ("packet-features.csv", packets, PACKET_COLUMNS), ("mqtt-raw.jsonl", serialized, None),
            ("events.json", events, None)):
        _stage(report, f"output:{name}", lambda: _write(destination, name, data, columns))
    report["status"] = "HOLD" if report["hold_reasons"] else "PASS"
    _stage(report, "output:qc-report.json", lambda: _write(destination, "qc-report.json", report))
    if report["hold_reasons"]:
        report["status"] = "HOLD"
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, help="New directory outside the source package for read-only re-QC")
    parser.add_argument("--qc-profile", action="append", default=[], metavar="DEVICE_ID=PROFILE",
                        help="MQTT QC Profile for one device (P0 default, P1 for a 4-6 s ESP32 schedule)")
    parser.add_argument("--reception-policy", choices=(STRICT_POLICY, WIRE_JITTER_POLICY), default=STRICT_POLICY)
    args = parser.parse_args(argv)
    profiles = dict(item.split("=", 1) for item in args.qc_profile if "=" in item)
    if len(profiles) != len(args.qc_profile):
        parser.error("--qc-profile must look like DEVICE_ID=PROFILE")
    report = export_normal_collection(args.package_dir, output_dir=args.output_dir, qc_profiles=profiles,
                                      reception_policy=args.reception_policy)
    print(f"Candidate content QC: {report['status']}; training_approved=false; whole_session_approved=false")
    if report["hold_reasons"]:
        print("Hold reasons: " + "; ".join(report["hold_reasons"]))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
