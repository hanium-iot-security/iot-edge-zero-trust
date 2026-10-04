"""Preserve bounded normal candidates without changing running devices/services.

This produces evidence, never training approval or a Verified Collection package.
Run from the gateway checkout so its existing .env is used. --project-root can
point at the live checkout when the collection tool is in a separate checkout.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

TOOL_ROOT = Path(__file__).resolve().parents[2]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from ai.export_normal_collection import export_normal_collection
from backend.app.config import settings
from edge.packet.capture_policy import CapturePolicy
from sqlalchemy.engine import make_url

STAGES = ("mqtt_feature_builder", "mqtt_feature_rule", "mqtt_message_rule",
          "packet_rule", "packet_if", "trust_score_v2")
PROTECTED = ("device_policy_revisions", "trust_score_history", "isolation_history",
             "firewall_rules", "firewall_release_requests")


def utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def rows(connection, query, args=()):
    return [dict(row) for row in connection.execute(query, args)]


def state(db_path: Path) -> dict:
    with read_db(db_path) as connection:
        revisions = rows(connection, "SELECT * FROM device_policy_revisions ORDER BY device_id,revision")
        devices = rows(connection, "SELECT device_id,ip_address,status,trust_score FROM devices ORDER BY device_id")
        now = utc(time.time())
        for device in devices:
            effective = [r for r in revisions if r["device_id"] == device["device_id"] and r["effective_from"] <= now]
            policy = effective[-1] if effective else None
            device.update(mqtt_topic="iot/" + device["device_id"] + "/sensor",
                          registration_state=policy["registration_state"] if policy else None,
                          current_policy_revision=policy["revision"] if policy else None)
        return {
            "devices": devices,
            "device_policy_revisions": revisions,
            "running_sessions": rows(connection, "SELECT * FROM packet_capture_sessions WHERE status='RUNNING'"),
            "checkpoints": rows(connection, "SELECT detector_name,last_completed_window_end FROM detector_checkpoints"),
            "protected": {table: hashlib.sha256(json.dumps(rows(connection, "SELECT * FROM " + table + " ORDER BY rowid"), sort_keys=True, default=str).encode()).hexdigest() for table in PROTECTED},
        }


def save_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def preserve_file(root: Path, filename: str, destination: Path) -> bool:
    """Only sealed artifacts; retry READY->PROCESSED moves on the next poll."""
    if (not isinstance(filename, str) or not filename or Path(filename).name != filename or filename in (".", "..")
            or any(char in filename for char in ("/", "\\", ":"))
            or filename.endswith(".tmp")):
        raise ValueError("Unsafe capture artifact name")
    if destination.is_symlink():
        raise ValueError("Unsafe evidence symlink")
    for folder in ("processed", "ready", "failed"):
        source = root / "data/pcap" / folder / filename
        if source.is_symlink() or not source.resolve().is_relative_to(root / "data/pcap"):
            raise ValueError("Capture artifact escapes source directory")
        if not source.is_file():
            continue
        try:
            if destination.exists():
                if sha256(source) != sha256(destination):
                    raise ValueError("Preserved artifact changed")
                return True
            with source.open("rb") as src, destination.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            destination.chmod(0o600)
            return True
        except FileNotFoundError:
            # A source may be moved after discovery but before it can be opened.
            continue
    return False


def preserve_segments(root: Path, db_path: Path, package: Path, manifest: dict) -> None:
    with read_db(db_path) as connection:
        segments = rows(connection, "SELECT id,file_name FROM packet_capture_segments WHERE capture_session_id=? AND window_start>=? AND window_end<=? ORDER BY window_start", (manifest["capture_session_pk"], manifest["start_utc"], manifest["end_utc"]))
    artifacts = {item["segment_id"]: item for item in manifest.get("capture_artifacts", [])}
    directory = package / "pcap"
    directory.mkdir(exist_ok=True)
    directory.chmod(0o700)
    for segment in segments:
        item = artifacts.setdefault(segment["id"], {"segment_id": segment["id"]})
        if segment["file_name"] is None:
            # A late/no-capture Segment has no filename. Keep its ID so final QC
            # records missing evidence instead of dropping the failed Window.
            continue
        for suffix, prefix in (("", "pcap"), (".capture.json", "diagnostics")):
            filename = segment["file_name"] + suffix
            target = directory / filename
            if preserve_file(root, filename, target):
                item[prefix + "_path"] = "pcap/" + filename
                item[prefix + "_sha256"] = sha256(target)
    manifest["capture_artifacts"] = sorted(artifacts.values(), key=lambda item: item["segment_id"])


def finalize(root: Path, db_path: Path, package: Path, manifest: dict, baseline: dict) -> dict:
    deadline = time.monotonic() + 120
    while True:
        current = state(db_path)
        completed = {row["detector_name"]: row["last_completed_window_end"] for row in current["checkpoints"]}
        preserve_segments(root, db_path, package, manifest)
        if all(completed.get(stage) and completed[stage] >= manifest["end_utc"] for stage in STAGES):
            break
        if time.monotonic() >= deadline:
            manifest["collection_issues"].append("checkpoint_timeout")
            break
        time.sleep(5)
    snapshot = package / "after.db"
    with read_db(db_path) as src, sqlite3.connect(snapshot) as dst:
        src.backup(dst, pages=256, sleep=0.01)
    snapshot.chmod(0o600)
    # Validate the actual frozen data rather than an earlier live observation.
    current = state(snapshot)
    save_json(package / "after-state.json", current)
    if current["protected"] != baseline["protected"]:
        manifest["collection_issues"].append("protected_history_or_policy_changed")
    if current["devices"] != baseline["devices"]:
        manifest["collection_issues"].append("device_identity_policy_or_trust_changed")
    if current["running_sessions"] != baseline["running_sessions"]:
        manifest["collection_issues"].append("capture_session_changed")
    if git_head(root) != manifest["code_commit"]:
        manifest["collection_issues"].append("runtime_code_changed")
    manifest["snapshot"] = {"path": "after.db", "sha256": sha256(snapshot)}
    manifest["status"] = "RAW_CAPTURED"
    save_json(package / "manifest.json", manifest)
    report = export_normal_collection(package)
    if manifest["collection_issues"]:
        report["hold_reasons"] = sorted(set(report.get("hold_reasons", []) + manifest["collection_issues"]))
        report["status"] = "HOLD"
        save_json(package / "qc-report.json", report)
    manifest["status"] = "CANDIDATE_QC_PASSED" if report["status"] == "PASS" else "HOLD"
    manifest["qc_report"] = "qc-report.json"
    save_json(package / "manifest.json", manifest)
    print(json.dumps({"run_finished": manifest["run_id"], "status": manifest["status"], "issues": report.get("hold_reasons", []), "package": str(package)}), flush=True)
    return report


def collect(root: Path, output: Path, slots: list[tuple[list[str], int]], poll_seconds: float = 15) -> dict:
    root = root.resolve()
    output = output.resolve()
    if not output.is_relative_to(root / "output"):
        raise ValueError("Evidence must stay under the project's ignored output directory")
    if output.exists() or not slots or not 0 < poll_seconds <= 30:
        raise ValueError("Use a new output directory and poll interval in (0,30]")
    if any(not ids or len(ids) != len(set(ids)) or duration < 60 or duration % 10 for ids, duration in slots):
        raise ValueError("Each slot needs unique devices and a duration >=60 divisible by10")
    if settings.trust_ai_mode != "observe" or settings.feature_window_seconds != 10:
        raise ValueError("Collection requires current ten-second windows and AI observe mode")
    if shutil.disk_usage(root).free < 1024 ** 3:
        raise ValueError("Less than1GiB free before collection")
    db_path = root / "backend/data/iot_security.db"
    configured_url = make_url(settings.database_url)
    if configured_url.get_backend_name() != "sqlite" or not configured_url.database or configured_url.database == ":memory:":
        raise ValueError("Collection requires the configured file-based SQLite database")
    configured_path = Path(configured_url.database)
    if not configured_path.is_absolute():
        configured_path = root / configured_path
    if configured_path.resolve() != db_path.resolve():
        raise ValueError("Configured database does not match the live checkout database")
    baseline = state(db_path)
    if len(baseline["running_sessions"]) != 1:
        raise ValueError("Expected exactly one current Capture Session")
    devices = {row["device_id"]: row for row in baseline["devices"]}
    for ids, _ in slots:
        if any(d not in devices or devices[d]["registration_state"] != "ACTIVE" or devices[d]["status"] != "normal" for d in ids):
            raise ValueError("Every target must be a registered active normal device")
    session = baseline["running_sessions"][0]
    code_commit = git_head(root)
    start = math.ceil(time.time() / 10) * 10 + 10
    output.mkdir(parents=True)
    output.chmod(0o700)
    packages = []
    for index, (ids, duration) in enumerate(slots, 1):
        run_id = str(uuid.uuid4())
        package = output / f"run-{index:02d}-{run_id}"
        package.mkdir(); package.chmod(0o700)
        manifest = {
            "schema_version": "phase8-normal-candidate-v1", "run_id": run_id,
            "status": "CAPTURING", "training_approved": False,
            "whole_capture_session_approved": False, "start_utc": utc(start),
            "end_utc": utc(start + duration), "duration_seconds": duration,
            "capture_session_pk": session["id"], "source_capture_group_id": session["session_id"],
            "included_device_ids": ids, "devices": [devices[d] for d in ids],
            "device_policy_revisions": baseline["device_policy_revisions"],
            "capture_policy": vars(CapturePolicy.from_env()), "code_commit": code_commit,
            "collection_tool_commit": git_head(TOOL_ROOT),
            "collection_tool_sha256": sha256(Path(__file__)),
            "trust_ai_mode": settings.trust_ai_mode,
            "enabled_stages": settings.orchestrator_enabled_stages,
            "firmware_provenance": {"status": "UNCONFIRMED", "note": "Gateway source checkout hashes do not authenticate firmware on physical devices", "pico_gateway_source_sha256": {p.name: sha256(p) for p in (root / "firmware/pico_wh_bme280").glob("*.py")}},
            "collection_mode": "simultaneous_target_observation" if len(ids) == 1 else "simultaneous",
            "background_traffic_present": True,
            "capture_artifacts": [], "collection_issues": [],
            "split": "UNASSIGNED", "purpose": "Normal baseline and quality evidence; no training or threshold selection approval",
        }
        save_json(package / "manifest.json", manifest)
        save_json(package / "before-state.json", baseline)
        packages.append((package, manifest)); start += duration
    plan = {"status": "RUNNING", "training_approved": False, "whole_capture_session_approved": False,
            "source_capture_group_id": session["session_id"], "all_runs_share_capture_group": True,
            "runs": [{"path": p.name, "run_id": m["run_id"], "start_utc": m["start_utc"], "end_utc": m["end_utc"], "devices": m["included_device_ids"]} for p, m in packages]}
    save_json(output / "plan.json", plan)
    print(json.dumps(plan), flush=True)
    finished = set()
    try:
        while len(finished) < len(packages):
            current = state(db_path)
            if [r["session_id"] for r in current["running_sessions"]] != [session["session_id"]]:
                raise ValueError("Capture Session changed during collection")
            if git_head(root) != code_commit or current["device_policy_revisions"] != baseline["device_policy_revisions"] or current["devices"] != baseline["devices"]:
                raise ValueError("Runtime code, device identity, policy or Trust changed during collection")
            if shutil.disk_usage(root).free < 256 * 1024 ** 2:
                raise ValueError("Storage reserve reached")
            for index, (package, manifest) in enumerate(packages):
                if index in finished:
                    continue
                preserve_segments(root, db_path, package, manifest)
                save_json(package / "manifest.json", manifest)
                if utc(time.time()) >= manifest["end_utc"]:
                    report = finalize(root, db_path, package, manifest, baseline)
                    finished.add(index)
                    if report["status"] != "PASS":
                        raise ValueError("Candidate content QC requires review")
            progress = {"utc": utc(time.time()), "finished_runs": len(finished), "preserved_segments": {p.name: len(m["capture_artifacts"]) for p, m in packages}}
            save_json(output / "progress.json", progress)
            time.sleep(poll_seconds if len(finished) < len(packages) else 0)
        plan["status"] = "CANDIDATE_COLLECTION_COMPLETE"
    except (ValueError, OSError, sqlite3.Error, KeyboardInterrupt) as error:
        # Keep collected files and explicit incomplete/HOLD manifests; never resume
        # by overwriting a run ID or by modifying runtime checkpoints.
        plan["status"] = "HOLD"
        plan["error"] = type(error).__name__ + ": " + str(error)
        for index, (package, manifest) in enumerate(packages):
            if index not in finished:
                manifest["status"] = "HOLD_INCOMPLETE"
                manifest["interrupted_at"] = utc(time.time())
                manifest["collection_issues"].append("collection_interrupted")
                snapshot = package / "after.db"
                try:
                    if not snapshot.exists():
                        with read_db(db_path) as src, sqlite3.connect(snapshot) as dst:
                            src.backup(dst, pages=256, sleep=0.01)
                        snapshot.chmod(0o600)
                    manifest["snapshot"] = {"path": "after.db", "sha256": sha256(snapshot)}
                except (OSError, sqlite3.Error):
                    manifest["collection_issues"].append("interrupted_snapshot_failed")
                save_json(package / "manifest.json", manifest)
    save_json(output / "plan.json", plan)
    print(json.dumps({"status": plan["status"], "directory": str(output)}), flush=True)
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=TOOL_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--device", action="append", default=[])
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--phase8-sequence", action="store_true", help="Pico30min, ESP1 30min, ESP2 30min, all60min; senders stay on")
    args = parser.parse_args()
    if args.phase8_sequence and args.device:
        parser.error("Choose either --phase8-sequence or --device")
    slots = [(["pico_01"], 1800), (["esp32_01"], 1800), (["esp32_02"], 1800), (["esp32_01", "esp32_02", "pico_01"], 3600)] if args.phase8_sequence else [(args.device, args.duration_seconds)]
    try:
        result = collect(args.project_root, args.output, slots)
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "HOLD", "error_type": type(error).__name__}), flush=True)
        return 2
    return 0 if result["status"] == "CANDIDATE_COLLECTION_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
