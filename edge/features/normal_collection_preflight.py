"""Read-only operational observations; PASS never approves collection data.

Configured settings describe their source, not the running processes' mode or
models. No service control, model loading, capture creation, or firmware access.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from ipaddress import IPv4Address
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from uuid import UUID

TOOL_ROOT = Path(__file__).resolve().parents[2]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

MIN_FREE_BYTES = 1024 ** 3
DETECTORS = ("mqtt_feature_rule", "mqtt_message_rule", "packet_rule", "packet_if")
CHECKPOINT_SOURCES = {
    "mqtt_feature_builder": "mqtt_logs", "mqtt_feature_rule": "feature_logs",
    "mqtt_message_rule": "mqtt_logs", "packet_rule": "packet_feature_logs",
    "packet_if": "packet_feature_logs", "trust_score_v2": "detection_events",
}
SERVICES = ("packet-capture.service", "mqtt-subscriber.service", "mqtt-feature-builder.service",
            "detection-orchestrator.service", "packet-feature-extractor.timer", "firewall-worker.service")
NOT_EVALUATED = dict.fromkeys(("formal_collection_import", "training_approval", "new_capture_group",
                              "physical_firmware_sources", "normal_profile_p0",
                              "runtime_process_mode_and_models", "individual_model_inference"), False)
POLICY_COLUMNS = ("device_id", "revision", "effective_from", "registration_state", "policy_profile",
                  "expected_publish_interval_seconds", "publish_count_max", "payload_size_max_bytes",
                  "packet_rate_max_pps", "byte_rate_max_bytes_per_second", "created_at", "created_by", "reason")


class PreflightError(ValueError):
    """Only a fixed, non-sensitive code may cross the CLI boundary."""


def _require(condition, code):
    if not condition:
        raise PreflightError(code)


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _utc(value, *, explicit=False):
    _require(isinstance(value, str), "INVALID_UTC_TIME")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        _require(not explicit or parsed.tzinfo is not None, "INVALID_UTC_TIME")
        if parsed.tzinfo is None:  # SQLite runtime timestamps are UTC.
            parsed = parsed.replace(tzinfo=timezone.utc)
        _require(parsed.utcoffset().total_seconds() == 0, "INVALID_UTC_TIME")
        return parsed
    except (ValueError, TypeError, OverflowError):
        raise PreflightError("INVALID_UTC_TIME") from None


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def _devices(device_ids):
    _require(isinstance(device_ids, (list, tuple)) and len(device_ids) == 3, "REQUIRE_THREE_DEVICES")
    _require(all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value)
                 for value in device_ids) and len(set(device_ids)) == 3, "INVALID_DEVICE_SELECTION")
    return sorted(device_ids)


def _normalize(item, device_ids, required_free_bytes):
    """Validate first, then emit only bounded public fields; never raw input."""
    _require(isinstance(item, dict), "INVALID_OBSERVATION")
    required = ("observed_at", "code_commit", "boot_id", "tracked_worktree_dirty", "ntp_synchronized",
                "free_bytes", "configuration", "services", "running_sessions", "devices",
                "device_policy_revisions", "mqtt_latest", "checkpoints")
    _require(all(key in item for key in required), "MISSING_OBSERVATION_FIELD")
    now = _utc(item["observed_at"], explicit=True)
    _require(isinstance(item["code_commit"], str) and re.fullmatch(r"[0-9a-f]{40}", item["code_commit"]), "INVALID_COMMIT")
    _require(_uuid(item["boot_id"]), "INVALID_BOOT_ID")
    _require(item["ntp_synchronized"] is True, "NTP_NOT_SYNCHRONIZED")
    _require(item["tracked_worktree_dirty"] is False, "TRACKED_WORKTREE_DIRTY")
    _require(_integer(item["free_bytes"]) and item["free_bytes"] >= required_free_bytes, "INSUFFICIENT_FREE_SPACE")
    source = item["configuration"]
    _require(isinstance(source, dict), "INVALID_CONFIGURATION")
    _require(source.get("trust_ai_mode") == "observe" and source.get("feature_window_seconds") == 10
             and source.get("pcap_window_seconds") == 10, "INCOMPATIBLE_COLLECTION_CONFIGURATION")
    config = {key: source[key] for key in ("trust_ai_mode", "feature_window_seconds", "pcap_window_seconds")}
    for key in ("enabled_stages", "required_stages"):
        stages = source.get(key)
        _require(isinstance(stages, (list, tuple)) and len(stages) == len(DETECTORS)
                 and set(stages) == set(DETECTORS), "INCOMPATIBLE_COLLECTOR_STAGES")
        config[key] = list(stages)
    _require(source.get("database_path_matches_project") is True, "DATABASE_PATH_MISMATCH")
    config["database_path_matches_project"] = True
    policy = source.get("capture_policy")
    _require(isinstance(policy, dict), "INVALID_CAPTURE_POLICY")
    clean_policy = {}
    for key, upper in (("max_start_delay_seconds", 10), ("minimum_duration_seconds", 10), ("epsilon_seconds", 1)):
        value = policy.get(key)
        _require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= upper
                 and (key == "minimum_duration_seconds" or value < upper), "INVALID_CAPTURE_POLICY")
        clean_policy[key] = value
    version = policy.get("version")
    _require(isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", version), "INVALID_CAPTURE_POLICY")
    clean_policy["version"] = version
    config["capture_policy"] = clean_policy
    services = item["services"]
    _require(isinstance(services, dict) and all(services.get(name) == "active" for name in SERVICES), "SERVICE_NOT_ACTIVE")
    sessions = item["running_sessions"]
    _require(isinstance(sessions, list) and len(sessions) == 1, "REQUIRE_ONE_RUNNING_SESSION")
    session = sessions[0]
    _require(isinstance(session, dict) and _integer(session.get("id"), 1) and _uuid(session.get("session_id"))
             and session.get("status") == "RUNNING" and isinstance(session.get("capture_interface"), str)
             and re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", session["capture_interface"]), "INVALID_CAPTURE_SESSION")
    clean_session = {key: session[key] for key in ("id", "session_id", "status", "capture_interface")}
    devices = item["devices"]
    _require(isinstance(devices, list) and len(devices) == len(device_ids), "MISSING_DEVICE")
    clean_devices = []
    for row in devices:
        _require(isinstance(row, dict) and row.get("device_id") in device_ids, "INVALID_DEVICE")
        try:
            ip = str(IPv4Address(row.get("ip_address")))
        except (ValueError, TypeError):
            raise PreflightError("INVALID_DEVICE_IP") from None
        _require(row.get("status") == "normal" and row.get("registration_state") == "ACTIVE"
                 and _integer(row.get("trust_score")) and row["trust_score"] <= 100
                 and _integer(row.get("current_policy_revision"), 1)
                 and row.get("mqtt_topic") == f"iot/{row['device_id']}/sensor", "DEVICE_NOT_ACTIVE_NORMAL")
        clean_devices.append({"device_id": row["device_id"], "ip_address": ip,
                              **{key: row[key] for key in ("status", "trust_score", "registration_state",
                                                         "current_policy_revision", "mqtt_topic")}})
    clean_devices.sort(key=lambda row: row["device_id"])
    _require([row["device_id"] for row in clean_devices] == device_ids
             and len({row["ip_address"] for row in clean_devices}) == len(device_ids), "DUPLICATE_DEVICE_IDENTITY")
    revisions = item["device_policy_revisions"]
    _require(isinstance(revisions, list) and revisions, "MISSING_POLICY_REVISIONS")
    clean_revisions = []
    for row in revisions:
        _require(isinstance(row, dict) and all(key in row for key in POLICY_COLUMNS)
                 and row["device_id"] in device_ids and _integer(row["revision"], 1), "INVALID_POLICY_REVISIONS")
        clean_revisions.append({key: row[key] for key in POLICY_COLUMNS})
    _require(all(any(row["device_id"] == device["device_id"] and row["revision"] == device["current_policy_revision"]
                     and row["registration_state"] == "ACTIVE" for row in clean_revisions) for device in clean_devices), "MISSING_CURRENT_POLICY")
    clean_revisions.sort(key=lambda row: (row["device_id"], row["revision"]))
    policy_hash = hashlib.sha256(json.dumps(clean_revisions, sort_keys=True, allow_nan=False).encode()).hexdigest()
    latest = item["mqtt_latest"]
    _require(isinstance(latest, dict), "MISSING_MQTT_RECEIPT")
    clean_latest = {}
    for device_id in device_ids:
        row = latest.get(device_id)
        _require(isinstance(row, dict) and _integer(row.get("id"), 1), "MISSING_MQTT_RECEIPT")
        received = _utc(row.get("received_at"))
        _require(0 <= (now - received).total_seconds() <= 15, "MQTT_RECEIPT_NOT_FRESH")
        clean_latest[device_id] = {"id": row["id"], "received_at": received.isoformat()}
    _require(isinstance(item["checkpoints"], list), "MISSING_CHECKPOINT")
    checkpoints = {}
    for row in item["checkpoints"]:
        _require(isinstance(row, dict), "INVALID_CHECKPOINT")
        name = row.get("detector_name")
        if name not in CHECKPOINT_SOURCES:  # Disabled mqtt_if is outside this barrier.
            continue
        _require(name not in checkpoints, "DUPLICATE_CHECKPOINT")
        _require(all(key in row for key in ("source_table", "last_processed_id", "last_completed_window_end")), "INVALID_CHECKPOINT")
        _require(row.get("source_table") == CHECKPOINT_SOURCES[name], "CHECKPOINT_SOURCE_MISMATCH")
        identifier = row.get("last_processed_id")
        _require(_integer(identifier) or (name == "trust_score_v2" and identifier is None), "INVALID_CHECKPOINT_ID")
        end = _utc(row.get("last_completed_window_end"))
        _require(0 <= (now - end).total_seconds() <= 45 and end.timestamp() % 10 == 0, "CHECKPOINT_NOT_FRESH")
        checkpoints[name] = {"detector_name": name, "source_table": CHECKPOINT_SOURCES[name],
                             "last_processed_id": identifier, "last_completed_window_end": end.isoformat()}
    _require(set(checkpoints) == set(CHECKPOINT_SOURCES), "MISSING_CHECKPOINT")
    return {"observed_at": now.isoformat(), "code_commit": item["code_commit"], "boot_id": item["boot_id"],
            "tracked_worktree_dirty": False, "ntp_synchronized": True, "free_bytes": item["free_bytes"],
            "configuration": config, "services": {name: "active" for name in SERVICES},
            "running_sessions": [clean_session], "devices": clean_devices,
            "device_policy_revisions_sha256": policy_hash, "mqtt_latest": clean_latest,
            "checkpoints": [checkpoints[name] for name in CHECKPOINT_SOURCES]}


def _report(observations, reasons, required_free_bytes):
    return {"status": "HOLD" if reasons else "PASS", "hold_reasons": sorted(set(reasons)),
            "scope": "operational_runtime_observation_only", "not_evaluated": dict(NOT_EVALUATED),
            "training_approved": False, "whole_capture_session_approved": False,
            "configuration_source": "fresh_Settings_environment_and_project_env",
            "running_process_configuration_verified": False, "required_free_bytes": required_free_bytes,
            "observations": observations}


def assess_observations(observations, device_ids, required_free_bytes=MIN_FREE_BYTES):
    """Pure assessment of three public observations, with fail-closed output."""
    normalized, reasons = [], []
    try:
        selected = _devices(device_ids)
        _require(_integer(required_free_bytes, MIN_FREE_BYTES), "INVALID_SPACE_REQUIREMENT")
        _require(isinstance(observations, list) and len(observations) == 3, "REQUIRE_THREE_OBSERVATIONS")
        for index, item in enumerate(observations):
            try:
                normalized.append(_normalize(item, selected, required_free_bytes))
            except PreflightError as error:
                reasons.append(str(error))
                normalized.append({"observation_index": index, "valid": False})
        if reasons:
            return _report(normalized, reasons, required_free_bytes)
        stable = ("code_commit", "boot_id", "configuration", "running_sessions", "devices", "device_policy_revisions_sha256")
        for before, after in zip(normalized, normalized[1:]):
            _require(10 <= (_utc(after["observed_at"]) - _utc(before["observed_at"])).total_seconds() <= 30, "OBSERVATION_INTERVAL_OUT_OF_RANGE")
            _require(all(before[key] == after[key] for key in stable), "OPERATING_SCOPE_CHANGED")
            for device in selected:
                _require(after["mqtt_latest"][device]["id"] >= before["mqtt_latest"][device]["id"], "MQTT_ID_REGRESSION")
            for previous, current in zip(before["checkpoints"], after["checkpoints"]):
                _require(_utc(current["last_completed_window_end"]) > _utc(previous["last_completed_window_end"]), "CHECKPOINT_NOT_ADVANCING")
                old, new = previous["last_processed_id"], current["last_processed_id"]
                _require(old is None or (new is not None and new >= old), "CHECKPOINT_ID_REGRESSION")
    except PreflightError as error:
        reasons.append(str(error))
    except Exception:
        reasons.append("INVALID_OBSERVATION")
    return _report(normalized, reasons, required_free_bytes if _integer(required_free_bytes) else MIN_FREE_BYTES)


def _command(arguments):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    _require(result.returncode == 0, "HOST_QUERY_FAILED")
    return result.stdout.decode("ascii", errors="strict").strip()


def _git_head(root):
    return _command(["git", "-C", str(root), "rev-parse", "HEAD"])


def _git_tracked_dirty(root):
    return bool(_command(["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=no", "-z"]))


def _utc_now():
    return datetime.now(timezone.utc)


def _configuration(root):
    from backend.app.config import Settings
    from edge.orchestration.stage_registry import parse_stage_names
    from sqlalchemy.engine import make_url
    source = Settings(_env_file=root / ".env")
    url = make_url(source.database_url)
    _require(url.drivername == "sqlite" and url.database not in (None, "", ":memory:"), "UNSUPPORTED_DATABASE_CONFIGURATION")
    database = Path(url.database)
    database = (database if database.is_absolute() else root / database).resolve()
    return {"trust_ai_mode": source.trust_ai_mode, "feature_window_seconds": source.feature_window_seconds,
            "pcap_window_seconds": source.pcap_window_seconds,
            "enabled_stages": list(parse_stage_names(source.orchestrator_enabled_stages)),
            "required_stages": list(parse_stage_names(source.orchestrator_required_stages)),
            "database_path": str(database), "database_path_matches_project": database == (root / "backend/data/iot_security.db").resolve(),
            "capture_policy": {"max_start_delay_seconds": source.pcap_max_start_delay_seconds,
                               "minimum_duration_seconds": source.packet_min_capture_duration_seconds,
                               "epsilon_seconds": source.capture_time_epsilon_seconds, "version": source.capture_policy_version}}


def _system_observation(root):
    services = {}
    for name in SERVICES:
        result = subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        services[name] = "active" if result.returncode == 0 and result.stdout.strip() == b"active" else "not_active"
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
            "ntp_synchronized": _command(["timedatectl", "show", "--property=NTPSynchronized", "--value"]) == "yes",
            "services": services, "free_bytes": shutil.disk_usage(root).free}


def collect_observation(root, device_ids):
    """Use one SQLite mode=ro transaction; never inspect payloads or models."""
    from edge.features.collect_normal_candidate import read_db, rows
    from edge.policy.device_policy_repository import get_policy_snapshot
    root = Path(root).resolve()
    selected = _devices(device_ids)
    configuration = _configuration(root)
    _require(configuration["database_path_matches_project"] is True, "DATABASE_PATH_MISMATCH")
    system = _system_observation(root)
    with closing(read_db(Path(configuration.pop("database_path")))) as connection:
        connection.execute("BEGIN")
        placeholders = ",".join("?" for _ in selected)
        devices = rows(connection, "SELECT device_id,ip_address,status,trust_score FROM devices WHERE device_id IN (" + placeholders + ") ORDER BY device_id", selected)
        now = _utc_now()  # First SELECT anchors the snapshot before its UTC time.
        for device in devices:
            snapshot = get_policy_snapshot(connection, device["device_id"], server_time=now)
            device.update(mqtt_topic=f"iot/{device['device_id']}/sensor",
                          registration_state=snapshot.current.registration_state if snapshot.current else None,
                          current_policy_revision=snapshot.current.revision if snapshot.current else None)
        revisions = rows(connection, "SELECT " + ",".join(POLICY_COLUMNS) + " FROM device_policy_revisions WHERE device_id IN (" + placeholders + ") ORDER BY device_id,revision", selected)
        sessions = rows(connection, "SELECT id,session_id,status,capture_interface FROM packet_capture_sessions WHERE status='RUNNING' ORDER BY id")
        checkpoints = rows(connection, "SELECT detector_name,source_table,last_processed_id,last_completed_window_end FROM detector_checkpoints")
        latest = {}
        for device_id in selected:
            receipt = rows(connection, "SELECT id,received_at FROM mqtt_logs WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,))
            if receipt:
                latest[device_id] = receipt[0]
        connection.rollback()
    return {**system, "observed_at": now.isoformat(), "code_commit": _git_head(root),
            "tracked_worktree_dirty": _git_tracked_dirty(root), "configuration": configuration,
            "devices": devices, "device_policy_revisions": revisions,
            "running_sessions": sessions, "checkpoints": checkpoints, "mqtt_latest": latest}


def run_preflight(root, device_ids, *, sample_interval_seconds=12, required_free_bytes=MIN_FREE_BYTES, observe=None, sleep=None):
    _require(type(sample_interval_seconds) in (int, float) and math.isfinite(sample_interval_seconds)
             and 10 <= sample_interval_seconds <= 30, "INVALID_SAMPLE_INTERVAL")
    _devices(device_ids)
    _require(_integer(required_free_bytes, MIN_FREE_BYTES), "INVALID_SPACE_REQUIREMENT")
    getter, pause = observe or collect_observation, sleep or time.sleep
    observations = []
    try:
        for index in range(3):
            if index:
                pause(sample_interval_seconds)
            observations.append(getter(Path(root), device_ids))
        return assess_observations(observations, device_ids, required_free_bytes)
    except PreflightError as error:
        return _report([], [str(error)], required_free_bytes)
    except KeyboardInterrupt:
        return _report([], ["INTERRUPTED"], required_free_bytes)
    except Exception:
        return _report([], ["OBSERVATION_COLLECTION_FAILED"], required_free_bytes)


def validate_report_path(root, path):
    root = Path(root).resolve()
    candidate = Path(path)
    candidate = candidate if candidate.is_absolute() else root / candidate
    _require(not any(part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction())
                     for part in (candidate, *candidate.parents)), "UNSAFE_REPORT_PATH")
    candidate = candidate.resolve()
    _require(candidate.is_relative_to(root / "output") and candidate.suffix == ".json" and not candidate.exists(), "UNSAFE_REPORT_PATH")
    result = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", str(candidate.relative_to(root))], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    _require(result.returncode == 0, "REPORT_PATH_NOT_IGNORED")
    return candidate


def save_report(root, path, report):
    destination = validate_report_path(root, path)
    encoded = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination = validate_report_path(root, destination)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(encoded)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps(_report([], ["INVALID_ARGUMENTS"], MIN_FREE_BYTES)))
        raise SystemExit(2)


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=TOOL_ROOT)
    parser.add_argument("--device", action="append", required=True)
    parser.add_argument("--sample-interval-seconds", type=float, default=12)
    parser.add_argument("--required-free-bytes", type=int, default=MIN_FREE_BYTES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.report is not None:
            validate_report_path(args.project_root, args.report)
        result = run_preflight(args.project_root, args.device, sample_interval_seconds=args.sample_interval_seconds,
                               required_free_bytes=args.required_free_bytes)
        if args.report is not None:
            save_report(args.project_root, args.report, result)
    except PreflightError as error:
        result = _report([], [str(error)], MIN_FREE_BYTES)
    except Exception:
        result = _report([], ["PREFLIGHT_FAILED"], MIN_FREE_BYTES)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
