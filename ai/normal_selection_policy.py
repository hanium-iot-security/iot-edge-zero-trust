"""Versioned MQTT feature selection policies and a before/after selection report.

`legacy-100b-v1` reproduces the fixed filter of `ai.export_normal_features` (payload 20-100 B,
interval 4-6 s), which drops every Pico row. `phase9-normal-v1` keeps only validity rules and does not
select by payload size or arrival-interval band: size and cadence are judged by the candidate QC for each
device Profile. The report is analysis only: it writes no training CSV and grants no approval.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
import math
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.export_normal_collection import SAFE_ERRORS, CandidateQCError, _hash, _new_output_dir, _require

REPORT_SCHEMA = "normal-selection-report-v1"
LEGACY_POLICY = "legacy-100b-v1"
PHASE9_POLICY = "phase9-normal-v1"
POLICIES = {
    LEGACY_POLICY: "publish_count 1-3, avg payload 20-100 B, max payload <= 100 B, "
                   "avg and min interval 4-6 s, one normal topic, no malformed payload",
    PHASE9_POLICY: "publish_count 1-3, one normal topic, no malformed payload; "
                   "no payload-size or arrival-interval band",
}
NUMERIC_COLUMNS = ("publish_count", "avg_payload_size", "max_payload_size", "avg_message_interval",
                   "min_message_interval", "topic_count", "abnormal_topic_count", "malformed_payload_count")


def _numbers(row):
    values = {}
    for key in NUMERIC_COLUMNS:
        try:
            value = float(row[key])
        except (KeyError, TypeError, ValueError):
            return None
        if not math.isfinite(value):
            return None
        values[key] = value
    return values


def exclusion_reasons(row, policy_id: str) -> list[str]:
    """Reason codes for excluding one MQTT feature row under a policy; empty means selected."""
    _require(policy_id in POLICIES, "unknown_selection_policy")
    values = _numbers(row)
    if values is None:
        return ["non_numeric_or_non_finite_value"]
    reasons = []
    if not 1 <= values["publish_count"] <= 3:
        reasons.append("publish_count_outside_1_3")
    if values["topic_count"] != 1:
        reasons.append("topic_count_not_one")
    if values["abnormal_topic_count"] != 0:
        reasons.append("abnormal_topic")
    if values["malformed_payload_count"] != 0:
        reasons.append("malformed_payload")
    if policy_id == LEGACY_POLICY:
        if not 20 <= values["avg_payload_size"] <= 100:
            reasons.append("avg_payload_outside_20_100")
        if values["max_payload_size"] > 100:
            reasons.append("max_payload_above_100")
        if not 4 <= values["avg_message_interval"] <= 6:
            reasons.append("avg_interval_outside_4_6")
        if not 4 <= values["min_message_interval"] <= 6:
            reasons.append("min_interval_outside_4_6")
    return reasons


def select_rows(rows, policy_id: str) -> list:
    """Rows selected by the policy, in input order."""
    return [row for row in rows if not exclusion_reasons(row, policy_id)]


def _summary(rows, policy_id):
    reasons = Counter()
    included = 0
    for row in rows:
        found = exclusion_reasons(row, policy_id)
        included += not found
        reasons.update(found)
    return {"included": included, "excluded": len(rows) - included, "exclusion_reasons": dict(sorted(reasons.items()))}


def _read_candidate(qc_dir: Path):
    report_path, features_path = qc_dir / "qc-report.json", qc_dir / "mqtt-features.csv"
    _require(report_path.is_file() and features_path.is_file(), "candidate_qc_files_missing")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    _require(isinstance(report, dict) and report.get("status") == "PASS", "candidate_qc_not_pass")
    with features_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    files = [{"path": f"{qc_dir.name}/{path.name}", "sha256": _hash(path)} for path in (report_path, features_path)]
    return report["run_id"], rows, files


def build_report(qc_dirs, output_dir: Path) -> dict:
    roots = [Path(path).resolve() for path in qc_dirs]
    _require(roots and len(set(roots)) == len(roots), "qc_dirs_required_and_unique")
    destination = _new_output_dir(roots[0], output_dir)
    for root in roots[1:]:
        _require(not destination.is_relative_to(root), "output_must_be_outside_package")
    rows_by_device, runs, files = {}, [], []
    for root in roots:
        run_id, rows, hashes = _read_candidate(root)
        runs.append(run_id)
        files.extend(hashes)
        for row in rows:
            rows_by_device.setdefault(row["device_id"], []).append(row)
    devices = {}
    for device_id, rows in sorted(rows_by_device.items()):
        legacy, current = _summary(rows, LEGACY_POLICY), _summary(rows, PHASE9_POLICY)
        devices[device_id] = {"rows": len(rows), LEGACY_POLICY: legacy, PHASE9_POLICY: current,
                              "newly_included": current["included"] - legacy["included"]}
    report = {"schema_version": REPORT_SCHEMA, "training_approved": False,
              "scope": "Selection comparison only; no training CSV and no approval.",
              "policies": POLICIES, "run_ids": runs, "input_files": files, "devices": devices}
    (destination / "mqtt-selection-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qc-dir", type=Path, action="append", required=True,
                        help="Candidate QC output directory (repeatable); every Run must be PASS")
    parser.add_argument("--output-dir", type=Path, required=True, help="New directory outside the QC directories")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.qc_dir, args.output_dir)
    except SAFE_ERRORS as exc:
        print(f"Selection report failed: {exc if isinstance(exc, CandidateQCError) else type(exc).__name__}")
        return 2
    for device_id, item in report["devices"].items():
        print(f"{device_id}: rows={item['rows']} legacy={item[LEGACY_POLICY]['included']} "
              f"phase9={item[PHASE9_POLICY]['included']} newly_included={item['newly_included']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
