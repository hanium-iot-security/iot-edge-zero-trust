"""Review bounded normal candidates for official admission. Never grants any approval.

A candidate Run passes content QC for its selected interval only. This review re-runs that QC into
a new directory and adds what the QC does not decide: per-device firmware/payload provenance, the
final snapshot (COMPLETED by default, or explicitly pinned terminal FAILED in v3), and one consistent
capture group and split. `training_approved` and `whole_capture_session_approved` stay false.
Evidence hashes are format-checked only; the evidence files themselves are reviewed at approval time.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import re
import sqlite3
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.export_normal_collection import (
    SAFE_ERRORS,
    CandidateQCError,
    _boundary,
    _hash,
    _new_output_dir,
    _path,
    _require,
    _time,
    _uuid,
    export_normal_collection,
)
from ai.pico_reception_qc import STRICT_POLICY, WIRE_JITTER_POLICY
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible

REQUEST_SCHEMA = "normal-admission-request-v1"
RECEPTION_REQUEST_SCHEMA = "normal-admission-request-v2"
TERMINAL_REQUEST_SCHEMA = "normal-admission-request-v3"
TERMINAL_SELECTION_POLICY = "failed-after-selected-range-v1"
REPORT_SCHEMA = "normal-admission-report-v1"
SPLITS = frozenset({"train", "validation", "test", "UNASSIGNED"})
PAYLOAD_SCHEMAS = {
    "esp32-telemetry-v1": {"device_id", "sequence", "uptime_s"},
    "pico-bme280-v1": {"device_id", "seq", "uptime_ms", "temperature_c", "humidity_pct", "pressure_hpa"},
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
_BOUNDS = "julianday({column})>=julianday(?) AND julianday({column})<julianday(?)"


def _exact(value, keys, code):
    _require(isinstance(value, dict) and set(value) == keys, code)
    return value


def _identifier(value, code):
    _require(type(value) is str and _IDENTIFIER.fullmatch(value) is not None, code)
    return value


def _relative(value, code):
    _require(type(value) is str and value and "\\" not in value and ":" not in value
             and not Path(value).is_absolute() and ".." not in Path(value).parts, code)
    return value


def _sha256(value, code):
    _require(type(value) is str and _SHA256.fullmatch(value) is not None, code)
    return value


def _utc_second(value, code):
    _require(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), code)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_request(path: Path) -> dict:
    """Read and strictly validate a request. Errors are fixed codes, never input values."""
    try:
        request = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CandidateQCError("invalid_request_json") from exc
    _require(isinstance(request, dict), "request_fields")
    schema = request.get("schema_version")
    _require(schema in (REQUEST_SCHEMA, RECEPTION_REQUEST_SCHEMA, TERMINAL_REQUEST_SCHEMA), "request_schema_version")
    terminal_review = schema == TERMINAL_REQUEST_SCHEMA
    keys = {"schema_version", "runs", "final_snapshot", "device_specs", "slots"}
    if schema != REQUEST_SCHEMA:
        keys.add("reception_policy")
    if terminal_review:
        keys.add("terminal_source")
    _exact(request, keys, "request_fields")
    if schema == RECEPTION_REQUEST_SCHEMA:
        _require(request["reception_policy"] == WIRE_JITTER_POLICY, "unknown_reception_policy")
    if terminal_review:
        _require(request["reception_policy"] in (STRICT_POLICY, WIRE_JITTER_POLICY), "unknown_reception_policy")
        terminal = _exact(request["terminal_source"], {"policy", "capture_session_pk", "source_capture_group_id",
                                                    "status", "ended_at"}, "terminal_source_fields")
        _require(terminal["policy"] == TERMINAL_SELECTION_POLICY and terminal["status"] == "FAILED",
                 "terminal_source_policy")
        _require(type(terminal["capture_session_pk"]) is int and terminal["capture_session_pk"] > 0,
                 "invalid_capture_pk")
        _uuid(terminal["source_capture_group_id"])
        _require(type(terminal["ended_at"]) is str and re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", terminal["ended_at"]),
            "invalid_terminal_end")
        _time(terminal["ended_at"])
    reception_review = request.get("reception_policy", STRICT_POLICY) == WIRE_JITTER_POLICY
    for key in ("runs", "device_specs", "slots"):
        _require(isinstance(request[key], list) and request[key], f"request_{key}")
    for run in request["runs"]:
        _exact(run, {"run_dir", "manifest_sha256"} | ({"source_qc_sha256"} if reception_review else set()),
               "run_fields")
        _relative(run["run_dir"], "unsafe_relative_path")
        _sha256(run["manifest_sha256"], "invalid_sha256")
        if reception_review:
            _sha256(run["source_qc_sha256"], "invalid_sha256")
    final = _exact(request["final_snapshot"], {"path", "sha256"}, "final_snapshot_fields")
    _relative(final["path"], "unsafe_relative_path")
    _sha256(final["sha256"], "invalid_sha256")
    for spec in request["device_specs"]:
        _exact(spec, {"device_id", "firmware_id", "payload_schema", "profile", "effective_from", "evidence"},
               "device_spec_fields")
        _identifier(spec["device_id"], "invalid_device_id")
        _identifier(spec["firmware_id"], "invalid_firmware_id")
        _identifier(spec["profile"], "invalid_profile")
        _require(spec["payload_schema"] in PAYLOAD_SCHEMAS, "unknown_payload_schema")
        _boundary(spec["effective_from"])
        evidence = _exact(spec["evidence"], {"kind", "sha256", "observed_at"}, "evidence_fields")
        _identifier(evidence["kind"], "invalid_evidence_kind")
        _sha256(evidence["sha256"], "invalid_sha256")
        _utc_second(evidence["observed_at"], "invalid_evidence_time")
    for slot in request["slots"]:
        _exact(slot, {"collection_slot_id", "run_id", "split"}, "slot_fields")
        _identifier(slot["collection_slot_id"], "invalid_slot_id")
        _uuid(slot["run_id"])
        _require(slot["split"] in SPLITS, "invalid_split")
    return request


def _check(report, label, function):
    try:
        function()
    except SAFE_ERRORS as exc:
        # Never echo exception text: it can contain raw payload or paths.
        report["blockers"].append(f"{label}:{exc if isinstance(exc, CandidateQCError) else type(exc).__name__}")


def _tree(path: Path) -> dict:
    return {p.relative_to(path).as_posix(): _hash(p) for p in sorted(path.rglob("*")) if p.is_file()}


def _open_readonly(path: Path):
    _require(not any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm")), "snapshot_not_standalone")
    db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    _require([row[0] for row in db.execute("PRAGMA integrity_check")] == ["ok"]
             and not db.execute("PRAGMA foreign_key_check").fetchall(), "snapshot_integrity")
    return db


def _range_rows(db, manifest, *, full_capture_rows=False):
    """Rows of the selected interval that must not change between the candidate and final snapshot."""
    ids = manifest["included_device_ids"]
    marks = ",".join("?" for _ in ids)
    window = (manifest["start_utc"], manifest["end_utc"])

    def query(sql, params):
        return [dict(row) for row in db.execute(sql, params)]

    mqtt = query("SELECT id, device_id, topic, payload, payload_size, payload_decode_status, payload_raw, received_at, "
                 "is_json_valid, is_topic_valid, error_message "
                 f"FROM mqtt_logs WHERE device_id IN ({marks}) AND "
                 + _BOUNDS.format(column="received_at") + " ORDER BY id", (*ids, *window))
    features = query(f"SELECT * FROM feature_logs WHERE device_id IN ({marks}) AND "
                     "julianday(window_start)>=julianday(?) AND julianday(window_end)<=julianday(?) ORDER BY id",
                     (*ids, *window))
    capture_columns = "*" if full_capture_rows else "id, file_name, window_start, window_end, status, error_code"
    segments = query(f"SELECT {capture_columns} FROM packet_capture_segments WHERE capture_session_id=? AND "
                     "julianday(window_start)>=julianday(?) AND julianday(window_end)<=julianday(?) ORDER BY id",
                     (manifest["capture_session_pk"], *window))
    packets = query("SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s "
                    "ON s.id=f.capture_segment_id WHERE s.capture_session_id=? AND "
                    "julianday(s.window_start)>=julianday(?) AND julianday(s.window_end)<=julianday(?) "
                    "ORDER BY f.id", (manifest["capture_session_pk"], *window))
    return {"mqtt": mqtt, "features": features, "segments": segments, "packets": packets}


def _digest(rows) -> str:
    def plain(value):
        return value.hex() if isinstance(value, bytes) else value
    text = json.dumps(rows, sort_keys=True, default=plain, allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_terminal_selection(terminal, whole, capture, bounds):
    """Link a v3 request to disclosed terminal facts; never certifies normal behavior.

    Admission supplies facts read from its hash-pinned immutable snapshot. The
    Dataset loader only checks their recorded linkage, as for other admission facts.
    """
    _require(isinstance(whole, dict) and whole.get("session_status") == terminal["status"] == "FAILED"
             and whole.get("whole_session_eligible") is False
             and capture["capture_session_pk"] == terminal["capture_session_pk"]
             and capture["source_capture_group_id"] == terminal["source_capture_group_id"], "terminal_source_link")
    ended = _time(whole.get("session_ended_at"))
    _require(ended == _time(terminal["ended_at"]) and bounds and all(right <= ended for _, right in bounds),
             "terminal_source_end")
    failures = whole.get("ineligible_segments")
    _require(isinstance(failures, list) and failures, "terminal_source_requires_recorded_failure")
    for item in failures:
        _exact(item, {"segment_id", "window_start", "window_end", "status", "error_code"},
               "terminal_failure_fields")
        _require(type(item["segment_id"]) is int and item["segment_id"] > 0, "terminal_failure_id")
        left, right = _time(item["window_start"]), _time(item["window_end"])
        _require(left < right and not any(start < right and left < end for start, end in bounds),
                 "terminal_failure_inside_selected_range")


def review_admission(packages_dir: Path, request_path: Path, output_dir: Path) -> dict:
    report = {"schema_version": REPORT_SCHEMA, "status": "HOLD", "official_admission": "HOLD",
              "training_approved": False, "whole_capture_session_approved": False,
              "scope": "Bounded admission review only; no training or whole-session approval.",
              "blockers": [], "runs": [], "device_specs": [], "whole_session": {}, "range_consistency": []}
    root = Path(packages_dir).resolve()
    try:
        request = load_request(request_path)
        _require("qc_profiles" in inspect.signature(export_normal_collection).parameters,
                 "qc_profile_api_unavailable")
        reception_policy = request.get("reception_policy", STRICT_POLICY)
        if reception_policy != STRICT_POLICY:
            _require("reception_policy" in inspect.signature(export_normal_collection).parameters,
                     "reception_policy_api_unavailable")
        report["reception_policy"] = reception_policy
        destination = _new_output_dir(root, output_dir)
    except SAFE_ERRORS as exc:
        report["blockers"].append(f"preflight:{exc if isinstance(exc, CandidateQCError) else type(exc).__name__}")
        return report

    manifests = {}

    def rerun(entry, index):
        package = _path(root, entry["run_dir"])
        _require(package.is_dir() and _hash(package / "manifest.json") == entry["manifest_sha256"],
                 "manifest_checksum")
        manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
        _uuid(manifest["run_id"])
        before = _tree(package)
        qc_profiles = {spec["device_id"]: spec["profile"] for spec in request["device_specs"]
                       if spec["device_id"] in manifest["included_device_ids"]}
        options = {"output_dir": destination / "qc" / f"run-{index:02d}", "qc_profiles": qc_profiles}
        if reception_policy != STRICT_POLICY:
            _require(manifest.get("qc_report") == "qc-report.json"
                     and _hash(package / "qc-report.json") == entry["source_qc_sha256"], "source_qc_checksum")
            options["reception_policy"] = reception_policy
        qc = export_normal_collection(package, **options)
        _require(_tree(package) == before, "source_package_changed")
        manifests[manifest["run_id"]] = (package, manifest)
        reviewed = {"run_id": manifest["run_id"], "run_dir": entry["run_dir"],
                               "candidate_qc": qc["status"], "hold_reasons": qc["hold_reasons"],
                               "counts": qc["counts"], "qc_profiles": qc_profiles}
        if reception_policy != STRICT_POLICY:
            _require(qc.get("reception_policy") == reception_policy
                     and qc.get("source_qc", {}).get("sha256") == entry["source_qc_sha256"],
                     "source_reception_policy_link")
            reviewed.update({key: qc.get(key) for key in
                             ("reception_policy", "source_manifest_status", "source_qc", "reception_jitter")})
            reviewed["derived_qc_sha256"] = _hash(options["output_dir"] / "qc-report.json")
        report["runs"].append(reviewed)
        _require(qc["status"] == "PASS", f"candidate_qc_hold({manifest['run_id']})")

    for index, entry in enumerate(request["runs"], 1):
        _check(report, f"run:{index}", lambda: rerun(entry, index))
    runs = [manifest for _, manifest in manifests.values()]

    def group_and_splits():
        run_ids = [run["run_id"] for run in runs]
        _require(len(manifests) == len(request["runs"]) == len(set(run_ids)), "run_set")
        groups = {(run["source_capture_group_id"], run["capture_session_pk"]) for run in runs}
        _require(len(groups) == 1, "runs_span_multiple_capture_groups")
        ordered = sorted(runs, key=lambda run: run["start_utc"])
        _require(all(a["end_utc"] <= b["start_utc"] for a, b in zip(ordered, ordered[1:])), "runs_overlap")
        slots = request["slots"]
        _require(len({slot["collection_slot_id"] for slot in slots}) == len(slots), "duplicate_slot_id")
        _require(sorted(slot["run_id"] for slot in slots) == sorted(run_ids), "slots_do_not_match_runs")
        _require(len({slot["split"] for slot in slots}) == 1, "split_crosses_capture_group")
        report["capture_group"] = {"source_capture_group_id": ordered[0]["source_capture_group_id"],
                                   "capture_session_pk": ordered[0]["capture_session_pk"],
                                   "split": slots[0]["split"]}

    if runs:
        _check(report, "group", group_and_splits)

    final_rows = {}

    def final_snapshot_unchanged():
        final = _path(root, request["final_snapshot"]["path"])
        _require(final.is_file() and _hash(final) == request["final_snapshot"]["sha256"], "final_snapshot_checksum")
        _require(not any(Path(str(final) + suffix).exists() for suffix in ("-wal", "-shm")),
                 "snapshot_not_standalone")

    def final_snapshot():
        final = _path(root, request["final_snapshot"]["path"])
        final_snapshot_unchanged()
        report["final_snapshot_sha256"] = request["final_snapshot"]["sha256"]
        first = runs[0]
        with closing(_open_readonly(final)) as db:
            session = db.execute("SELECT * FROM packet_capture_sessions WHERE id=?",
                                 (first["capture_session_pk"],)).fetchone()
            terminal = request.get("terminal_source")
            _require(session is not None and session["session_id"] == first["source_capture_group_id"]
                     and (terminal is not None or session["status"] == "COMPLETED"),
                     "session_not_completed_or_mismatched")
            policy = CapturePolicy(**first["capture_policy"])
            failures = []
            for row in db.execute("SELECT * FROM packet_capture_segments WHERE capture_session_id=? ORDER BY id",
                                  (first["capture_session_pk"],)):
                segment = CaptureEligibilitySegment(**{key: row[key] for key in
                    ("status", "error_code", "start_delay_seconds", "captured_duration_seconds")})
                if not is_capture_eligible(segment, policy).eligible:
                    failures.append({"segment_id": row["id"], "window_start": row["window_start"],
                                     "window_end": row["window_end"], "status": row["status"],
                                     "error_code": row["error_code"]})
            inside = [item for item in failures if any(
                _boundary(run["start_utc"]) < _time(item["window_end"])
                and _time(item["window_start"]) < _boundary(run["end_utc"]) for run in runs)]
            report["whole_session"] = {"session_status": session["status"],
                                       "whole_session_eligible": not failures, "ineligible_segments": failures}
            for run in runs:
                final_rows[run["run_id"]] = _range_rows(db, run, full_capture_rows=terminal is not None)
            _require(not inside, "session_failure_inside_selected_range")
            if terminal is not None:
                report["whole_session"].update(session_ended_at=session["ended_at"], whole_session_eligible=False)
                validate_terminal_selection(terminal, report["whole_session"], report["capture_group"],
                                            [(_boundary(run["start_utc"]), _boundary(run["end_utc"])) for run in runs])
                report["terminal_source"] = dict(terminal)
        final_snapshot_unchanged()

    if runs:
        _check(report, "final_snapshot", final_snapshot)

    def consistency():
        for package, manifest in manifests.values():
            with closing(_open_readonly(_path(package, manifest["snapshot"]["path"]))) as db:
                candidate = _digest(_range_rows(db, manifest,
                                                full_capture_rows=request["schema_version"] == TERMINAL_REQUEST_SCHEMA))
            final = _digest(final_rows[manifest["run_id"]])
            report["range_consistency"].append({"run_id": manifest["run_id"], "match": candidate == final})
            _require(candidate == final, f"range_rows_changed({manifest['run_id']})")

    if final_rows:
        _check(report, "range_consistency", consistency)

    def device_specs():
        specs = {}
        for spec in request["device_specs"]:
            _require(spec["device_id"] not in specs, "duplicate_device_spec")
            specs[spec["device_id"]] = spec
        _require(set(specs) == {device for run in runs for device in run["included_device_ids"]},
                 "device_specs_do_not_match_runs")
        for device_id, spec in specs.items():
            effective = _boundary(spec["effective_from"])
            observed = _utc_second(spec["evidence"]["observed_at"], "invalid_evidence_time")
            keys = PAYLOAD_SCHEMAS[spec["payload_schema"]]
            for run in runs:
                if device_id not in run["included_device_ids"]:
                    continue
                start = _boundary(run["start_utc"])
                # Evidence collected after a Run cannot certify what was installed during it.
                _require(effective <= start and observed <= start, f"provenance_after_run_start({device_id})")
                for row in final_rows.get(run["run_id"], {}).get("mqtt", []):
                    if row["device_id"] == device_id:
                        value = json.loads(row["payload_raw"]) if isinstance(row["payload_raw"], bytes) else None
                        _require(isinstance(value, dict) and set(value) == keys,
                                 f"payload_schema_mismatch({device_id})")
            report["device_specs"].append({"device_id": device_id, "firmware_id": spec["firmware_id"],
                "payload_schema": spec["payload_schema"], "profile": spec["profile"],
                "effective_from": spec["effective_from"], "evidence_kind": spec["evidence"]["kind"],
                "evidence_sha256": spec["evidence"]["sha256"]})

    if runs:
        _check(report, "device_specs", device_specs)
        _check(report, "final_snapshot_unchanged", final_snapshot_unchanged)

    if not report["blockers"]:
        report["official_admission"] = "BOUNDED_ELIGIBLE"
        report["status"] = "PASS"
    _check(report, "output", lambda: (destination / "admission-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8"))
    if report["blockers"]:
        report["official_admission"], report["status"] = "HOLD", "HOLD"
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages-dir", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="New directory outside the packages")
    args = parser.parse_args(argv)
    report = review_admission(args.packages_dir, args.request, args.output_dir)
    print(f"Bounded admission: {report['official_admission']}; training_approved=false; whole_session_approved=false")
    if report["blockers"]:
        print("Blockers: " + "; ".join(report["blockers"]))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
