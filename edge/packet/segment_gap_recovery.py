"""Pure evidence and transactional recovery for explicitly approved failed Windows.

No filesystem, process, lock, backup or service operations occur here. The CLI
owns those boundaries. Capture/Feature rows remain unchanged; one audit binds
the deliberate coverage gap and both Packet checkpoint transitions. An audit
never makes failed capture data normal or eligible for training/inference.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import sqlite3
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_window_boundary
from edge.packet.confirmed_partial_capture import approved_partial_capture_gap


PLAN_SCHEMA_VERSION = "packet-segment-gap-recovery-v1"
CHAIN_PLAN_SCHEMA_VERSION = "packet-segment-gap-recovery-v2"
AUDIT_TABLE = "packet_segment_gap_recoveries"
DETECTORS = ("packet_rule", "packet_if")
SOURCE_TABLE = "packet_feature_logs"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class SegmentGapRecoveryError(ValueError):
    """The explicit recovery cannot be trusted; keep the coverage gate closed."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise SegmentGapRecoveryError(message)


def _rows(db, sql: str, params: Mapping | None = None) -> list[dict]:
    if isinstance(db, sqlite3.Connection):
        cursor = db.execute(sql, dict(params or {}))
        columns = [item[0] for item in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    return [dict(row) for row in db.execute(text(sql), dict(params or {})).mappings()]


def _one(db, sql: str, params: Mapping | None = None) -> dict | None:
    rows = _rows(db, sql, params)
    _require(len(rows) <= 1, "Ambiguous recovery evidence.")
    return rows[0] if rows else None


def _uuid(value: object) -> str:
    _require(isinstance(value, str), "Capture/operation identity must be a UUID.")
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise SegmentGapRecoveryError("Capture/operation identity must be a UUID.") from exc
    _require(parsed.version == 4 and str(parsed) == value, "A canonical version-4 UUID is required.")
    return value


def _absolute_path(value: object) -> str:
    _require(isinstance(value, str) and bool(value)
             and (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()),
             "Evidence paths must be absolute.")
    return value


def _path_name(value: str) -> str:
    return PureWindowsPath(value).name if PureWindowsPath(value).is_absolute() else PurePosixPath(value).name


def _window(value: object) -> datetime:
    try:
        parsed = require_utc_window_boundary(parse_db_utc(value), "gap boundary")
    except (ValueError, TypeError) as exc:
        raise SegmentGapRecoveryError("Gap boundary must be a UTC 10-second Window.") from exc
    _require(isinstance(value, str) and format_db_utc(parsed) == value,
             "Gap boundaries must use canonical UTC strings.")
    return parsed


def canonical_plan_sha256(plan: Mapping) -> str:
    bound = {key: value for key, value in plan.items() if key not in ("plan_sha256", "generated_at")}
    try:
        encoded = json.dumps(bound, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SegmentGapRecoveryError("Plan is not a finite JSON object.") from exc
    return hashlib.sha256(encoded).hexdigest()


# The operational CLI uses the same conventional name as older Recovery APIs.
calculate_plan_sha256 = canonical_plan_sha256


def verify_segment_gap_plan(plan: Mapping) -> None:
    _require(isinstance(plan, Mapping), "Plan must be an object.")
    if plan.get("schema_version") == CHAIN_PLAN_SCHEMA_VERSION:
        _verify_chain_plan(plan)
        return
    _require(plan.get("schema_version") == PLAN_SCHEMA_VERSION, "Unsupported gap plan schema.")
    _require(plan.get("plan_sha256") == canonical_plan_sha256(plan), "Gap plan SHA256 mismatch.")
    _uuid(plan.get("operation_id"))
    _uuid(plan.get("capture_session_id"))
    failed_id = plan.get("failed_segment_id")
    _require(isinstance(failed_id, int) and not isinstance(failed_id, bool) and failed_id > 0,
             "A positive failed Segment ID is required.")
    start, end = _window(plan.get("window_start")), _window(plan.get("window_end"))
    _require(end == start + timedelta(seconds=10), "Exactly one 10-second Window may be approved.")
    for key in ("approved_by", "reason"):
        _require(isinstance(plan.get(key), str) and bool(plan[key].strip()), "Approval identity/reason is required.")
    _require(isinstance(plan.get("repository_commit"), str)
             and _HEX40.fullmatch(plan["repository_commit"]), "Repository commit must be 40 hexadecimal characters.")
    for key in ("database_path", "backup_path", "preserved_pcap_path"):
        _absolute_path(plan.get(key))
    _require(isinstance(plan.get("pcap_sha256"), str) and _HEX64.fullmatch(plan["pcap_sha256"]),
             "Preserved PCAP SHA256 is required.")
    failed = plan.get("failed_segment")
    _require(isinstance(failed, Mapping) and failed.get("id") == failed_id
             and failed.get("status") == "FAILED" and failed.get("error_code") == "PARTIAL_CAPTURE"
             and failed.get("window_start") == plan["window_start"]
             and failed.get("window_end") == plan["window_end"], "Failed Segment binding is invalid.")
    _require(isinstance(failed.get("file_name"), str) and bool(failed["file_name"])
             and _path_name(plan["preserved_pcap_path"]) == _path_name(failed["file_name"]),
             "The preserved PCAP must keep the failed Segment filename.")
    pair = plan.get("checkpoints")
    _require(isinstance(pair, Mapping) and set(pair) == set(DETECTORS), "Both Packet checkpoints are required.")
    for detector in DETECTORS:
        item = pair[detector]
        _require(isinstance(item, Mapping) and set(item) == {"before", "after"}, "Checkpoint pair is invalid.")
        before, after = item["before"], item["after"]
        fields = {"detector_name", "source_table", "last_processed_id", "last_completed_window_end", "updated_at"}
        _require(isinstance(before, Mapping) and isinstance(after, Mapping)
                 and set(before) == fields and set(after) == fields, "Complete checkpoint snapshots are required.")
        _require(before["detector_name"] == after["detector_name"] == detector
                 and before["source_table"] == after["source_table"] == SOURCE_TABLE
                 and before["last_processed_id"] == after["last_processed_id"]
                 and before["last_completed_window_end"] == plan["window_start"]
                 and after["last_completed_window_end"] == plan["window_end"]
                 and after["updated_at"] == plan["window_end"], "Checkpoint transition binding is invalid.")
        last_id = before["last_processed_id"]
        _require(last_id is None or (isinstance(last_id, int) and not isinstance(last_id, bool) and last_id >= 0),
                 "Packet source IDs must be preserved valid integers.")
        _require(isinstance(before["updated_at"], str) and bool(before["updated_at"]),
                 "Checkpoint updated_at evidence is required.")


def _verify_chain_plan(plan: Mapping) -> None:
    _require(plan.get("plan_sha256") == canonical_plan_sha256(plan), "Gap plan SHA256 mismatch.")
    _uuid(plan.get("operation_id"))
    _uuid(plan.get("capture_session_id"))
    _require(plan.get("coverage") == "UNINSPECTED", "Chain coverage must remain UNINSPECTED.")
    entries = plan.get("failed_segments")
    _require(isinstance(entries, list) and 2 <= len(entries) <= 3,
             "An explicit chain must contain two or three failed Windows.")
    start, end = _window(plan.get("window_start")), _window(plan.get("window_end"))
    expected = start
    seen_ids, seen_operations, seen_paths = set(), {plan["operation_id"]}, set()
    for entry in entries:
        _require(isinstance(entry, Mapping) and set(entry) == {
            "operation_id", "failed_segment_id", "failed_segment", "preserved_pcap_path", "pcap_sha256",
        }, "Exact per-Window chain evidence is required.")
        _uuid(entry.get("operation_id"))
        _require(entry["operation_id"] not in seen_operations, "Chain operation IDs must be distinct.")
        seen_operations.add(entry["operation_id"])
        failed = entry.get("failed_segment")
        _require(isinstance(failed, Mapping), "Failed Segment binding is invalid.")
        # Reuse the v1 schema's exact failure, path and checkpoint invariants for
        # each ten-second entry, while the envelope binds the whole approval.
        single = {key: plan.get(key) for key in (
            "capture_session_id", "approved_by", "reason", "repository_commit", "database_path", "backup_path",
        )}
        single.update(entry)
        single.update(schema_version=PLAN_SCHEMA_VERSION, window_start=failed.get("window_start"),
                      window_end=failed.get("window_end"))
        pair = plan.get("checkpoints")
        _require(isinstance(pair, Mapping) and set(pair) == set(DETECTORS), "Both Packet checkpoints are required.")
        single["checkpoints"] = {}
        for detector in DETECTORS:
            item = pair[detector]
            _require(isinstance(item, Mapping) and set(item) == {"before", "after"}
                     and isinstance(item["before"], Mapping) and isinstance(item["after"], Mapping),
                     "Checkpoint pair is invalid.")
            before = dict(item["before"])
            after = dict(item["after"])
            before["last_completed_window_end"] = single["window_start"]
            after["last_completed_window_end"] = single["window_end"]
            after["updated_at"] = single["window_end"]
            single["checkpoints"][detector] = {"before": before, "after": after}
        single["plan_sha256"] = canonical_plan_sha256(single)
        verify_segment_gap_plan(single)
        _require(entry["failed_segment_id"] not in seen_ids, "Failed Segment IDs must be distinct.")
        seen_ids.add(entry["failed_segment_id"])
        _require(_window(single["window_start"]) == expected, "Failed Windows must be ordered and contiguous.")
        expected = _window(single["window_end"])
        _require(entry["preserved_pcap_path"] not in seen_paths, "Preserved PCAP paths must be distinct.")
        seen_paths.add(entry["preserved_pcap_path"])
    _require(expected == end, "Chain end does not match the approved Windows.")
    for detector in DETECTORS:
        before, after = plan["checkpoints"][detector]["before"], plan["checkpoints"][detector]["after"]
        _require(before["last_completed_window_end"] == plan["window_start"]
                 and after["last_completed_window_end"] == after["updated_at"] == plan["window_end"],
                 "Checkpoint transition binding is invalid.")


def _require_schema(db) -> None:
    _require(_one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=:name", {"name": AUDIT_TABLE}),
             "Migration 008 audit table is required.")
    migration = _one(db, "SELECT name FROM schema_migrations WHERE version=8")
    _require(migration is not None and migration["name"] == "packet_segment_gap_recovery",
             "Migration 008 must be recorded.")


def _checkpoint_pair(db) -> dict[str, dict]:
    pair = {}
    for detector in DETECTORS:
        row = _one(db, "SELECT detector_name,source_table,last_processed_id,last_completed_window_end,updated_at "
                        "FROM detector_checkpoints WHERE detector_name=:detector AND source_table=:source",
                   {"detector": detector, "source": SOURCE_TABLE})
        _require(row is not None, "Both Packet checkpoints must exist.")
        pair[detector] = row
    return pair


def _feature_count(db, segment: Mapping) -> int:
    rows = _rows(db, "SELECT window_start,window_end FROM packet_feature_logs WHERE capture_segment_id=:id",
                 {"id": segment["id"]})
    _require(all(row["window_start"] == segment["window_start"] and row["window_end"] == segment["window_end"]
                 for row in rows), "Feature Window differs from its Segment.")
    return len(rows)


def _no_gap_features_or_overlap(db, failed: Mapping) -> None:
    params = {"id": failed["id"], "start": failed["window_start"], "end": failed["window_end"]}
    rows = _rows(db, "SELECT id FROM packet_capture_segments WHERE id<>:id "
                 "AND unixepoch(window_start)<unixepoch(:end) AND unixepoch(window_end)>unixepoch(:start)", params)
    _require(not rows, "Another Capture Segment overlaps the failed Window.")
    rows = _rows(db, "SELECT id FROM packet_feature_logs WHERE capture_segment_id=:id OR "
                 "(unixepoch(window_start)<unixepoch(:end) AND unixepoch(window_end)>unixepoch(:start))", params)
    _require(not rows, "Failed Window has Packet Features; it cannot be skipped.")


def _healthy(db, segment: Mapping) -> bool:
    _require(_window(segment["window_end"]) == _window(segment["window_start"]) + timedelta(seconds=10),
             "Malformed Segment Window.")
    count = _feature_count(db, segment)
    return segment["error_code"] is None and ((segment["status"] == "PROCESSED" and count > 0)
                                             or (segment["status"] == "EMPTY" and count == 0))


def _validated_audit(db, failed: Mapping, *, audit: Mapping | None = None,
                     plan: Mapping | None = None, schema_checked: bool = False) -> dict | None:
    if not schema_checked:
        _require_schema(db)
    if audit is None:
        audit = _one(db, f"SELECT * FROM {AUDIT_TABLE} WHERE failed_segment_id=:id", {"id": failed["id"]})
    if audit is None:
        return None
    if plan is None:
        try:
            plan = json.loads(audit["plan_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise SegmentGapRecoveryError("Recovery audit plan JSON is invalid.") from exc
    if isinstance(plan, Mapping) and plan.get("schema_version") == CHAIN_PLAN_SCHEMA_VERSION:
        return _validated_chain_audit(db, failed, audit, plan)
    verify_segment_gap_plan(plan)
    for key in ("operation_id", "capture_session_id", "failed_segment_id", "window_start", "window_end",
                "plan_sha256", "approved_by", "reason", "repository_commit", "database_path",
                "backup_path", "preserved_pcap_path", "pcap_sha256"):
        _require(audit[key] == plan[key], "Recovery audit row differs from its bound plan.")
    _require(isinstance(audit.get("backup_sha256"), str) and _HEX64.fullmatch(audit["backup_sha256"]),
             "Recovery audit backup SHA256 is invalid.")
    current = _one(db, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": failed["id"]})
    _require(current == plan["failed_segment"], "Failed Segment changed after approval.")
    _require(all(key not in current or current[key] == value for key, value in failed.items()),
             "Supplied failed Segment differs from current evidence.")
    session = _one(db, "SELECT * FROM packet_capture_sessions WHERE session_id=:sid", {"sid": audit["capture_session_id"]})
    _require(session is not None and session["id"] == current["capture_session_id"],
             "Recovery audit belongs to another Capture Session.")
    _no_gap_features_or_overlap(db, current)
    pair = _checkpoint_pair(db)
    for detector, row in pair.items():
        _require(row["last_completed_window_end"] is not None
                 and parse_db_utc(row["last_completed_window_end"]) >= _window(audit["window_end"]),
                 "Packet checkpoints have not both crossed this approved gap.")
        actual_boundary = parse_db_utc(row["last_completed_window_end"])
        preserved_id = plan["checkpoints"][detector]["before"]["last_processed_id"]
        actual_id = row["last_processed_id"]
        if actual_boundary == _window(audit["window_end"]):
            _require(row == plan["checkpoints"][detector]["after"],
                     "Gap-end checkpoint must match its approved after snapshot.")
        elif preserved_id is not None:
            _require(isinstance(actual_id, int) and not isinstance(actual_id, bool)
                     and actual_id >= preserved_id, "Checkpoint source IDs cannot rewind after a gap.")
    result = dict(audit)
    result["checkpoints"] = plan["checkpoints"]
    result["boundary"] = _window(audit["window_end"])
    result["target_session_id"] = audit["capture_session_id"]
    return result


def _chain_row_values(plan: Mapping, entry: Mapping) -> dict:
    fields = ("capture_session_id", "plan_sha256", "approved_by", "reason", "repository_commit",
              "database_path", "backup_path")
    values = {key: plan[key] for key in fields}
    values.update({key: entry[key] for key in (
        "operation_id", "failed_segment_id", "preserved_pcap_path", "pcap_sha256",
    )})
    values.update({key: entry["failed_segment"][key] for key in ("window_start", "window_end")})
    return values


def _validated_chain_audit(db, failed: Mapping, supplied_audit: Mapping, plan: Mapping) -> dict:
    audits = _validated_chain_audits(db, supplied_audit, plan)
    _validate_supplied_chain_segment(plan, failed)
    return audits[failed["id"]]


def _validate_supplied_chain_segment(plan: Mapping, failed: Mapping) -> None:
    expected = next((entry["failed_segment"] for entry in plan["failed_segments"]
                     if entry["failed_segment_id"] == failed["id"]), None)
    _require(expected is not None and all(key not in expected or expected[key] == value for key, value in failed.items()),
             "Supplied failed Segment differs from current evidence.")


def _validated_chain_audits(db, supplied_audit: Mapping, plan: Mapping) -> dict[int, dict]:
    verify_segment_gap_plan(plan)
    session = _one(db, "SELECT * FROM packet_capture_sessions WHERE session_id=:sid",
                   {"sid": plan["capture_session_id"]})
    _require(session is not None, "Recovery audit belongs to another Capture Session.")
    all_audits = []
    for entry in plan["failed_segments"]:
        audit = _one(db, f"SELECT * FROM {AUDIT_TABLE} WHERE failed_segment_id=:id",
                     {"id": entry["failed_segment_id"]})
        _require(audit is not None, "An approved chain audit is missing.")
        values = _chain_row_values(plan, entry)
        _require(all(audit[key] == value for key, value in values.items()),
                 "Chain audit row differs from its bound plan.")
        try:
            bound = json.loads(audit["plan_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise SegmentGapRecoveryError("Recovery audit plan JSON is invalid.") from exc
        _require(bound == plan, "Chain audits do not share the complete approved envelope.")
        _require(isinstance(audit.get("backup_sha256"), str) and _HEX64.fullmatch(audit["backup_sha256"])
                 and audit["backup_sha256"] == supplied_audit["backup_sha256"],
                 "Chain audit backup SHA256 differs or is invalid.")
        current = _one(db, "SELECT * FROM packet_capture_segments WHERE id=:id",
                       {"id": entry["failed_segment_id"]})
        _require(current == entry["failed_segment"] and current["capture_session_id"] == session["id"],
                 "Failed Segment changed after chain approval.")
        _no_gap_features_or_overlap(db, current)
        all_audits.append(audit)
    _require(any(audit["id"] == supplied_audit["id"] for audit in all_audits),
             "Recovery audit is not in its approved chain.")
    # Exactly these entries may share the chain envelope; extra rows with its
    # SHA would be a malformed or partially replaced batch, never coverage.
    same_plan = _rows(db, f"SELECT id FROM {AUDIT_TABLE} WHERE plan_sha256=:sha", {"sha": plan["plan_sha256"]})
    _require({row["id"] for row in same_plan} == {row["id"] for row in all_audits},
             "Chain audit set differs from its exact approval.")
    for detector, row in _checkpoint_pair(db).items():
        _require(row["last_completed_window_end"] is not None, "Packet checkpoints have not crossed this chain.")
        actual = parse_db_utc(row["last_completed_window_end"])
        end = _window(plan["window_end"])
        _require(actual >= end, "Packet checkpoints have not both crossed this approved chain.")
        preserved_id = plan["checkpoints"][detector]["before"]["last_processed_id"]
        if actual == end:
            _require(row == plan["checkpoints"][detector]["after"],
                     "Chain-end checkpoint must match its approved after snapshot.")
        elif preserved_id is not None:
            _require(isinstance(row["last_processed_id"], int) and not isinstance(row["last_processed_id"], bool)
                     and row["last_processed_id"] >= preserved_id, "Checkpoint source IDs cannot rewind after a gap.")
    return {audit["failed_segment_id"]: {**audit, "checkpoints": plan["checkpoints"],
            "boundary": _window(plan["window_end"]), "target_session_id": plan["capture_session_id"],
            "chain_operation_id": plan["operation_id"], "coverage": plan["coverage"]} for audit in all_audits}


def approved_segment_gaps(db, segments: Sequence[Mapping]) -> list[dict | None]:
    """Fresh read-only proofs in request order; each v2 chain is checked once.

    Proofs live only in this call. Every chain still verifies all audit rows,
    original failures, overlap/Feature absence and both current checkpoints.
    A bad requested member closes that complete chain's requested results.
    """
    errors = (SegmentGapRecoveryError, sqlite3.Error, SQLAlchemyError, ValueError, TypeError, KeyError)
    results = [None] * len(segments)
    try:
        _require_schema(db)
    except errors:
        return results
    groups = {}
    for index, segment in enumerate(segments):
        try:
            audit = _one(db, f"SELECT * FROM {AUDIT_TABLE} WHERE failed_segment_id=:id", {"id": segment["id"]})
            if audit is None:
                continue
            plan = json.loads(audit["plan_json"])
            if isinstance(plan, Mapping) and plan.get("schema_version") == CHAIN_PLAN_SCHEMA_VERSION:
                key = (plan.get("operation_id"), plan.get("plan_sha256"))
                groups.setdefault(key, []).append((index, segment, audit, plan))
            else:
                results[index] = _validated_audit(db, segment, audit=audit, plan=plan, schema_checked=True)
        except errors:
            continue
    rejected_ids = set()
    for members in groups.values():
        plan = members[0][3]
        try:
            audits = _validated_chain_audits(db, members[0][2], plan)
            for _, segment, supplied_audit, supplied_plan in members:
                _require(supplied_plan == plan, "Requested chain plans differ.")
                _validate_supplied_chain_segment(plan, segment)
                _require(all(audits[segment["id"]][key] == value for key, value in supplied_audit.items()),
                         "Requested chain audit changed during validation.")
            for index, segment, _, _ in members:
                results[index] = audits[segment["id"]]
        except errors:
            # Also close a requested row whose replaced plan claims to be v1
            # while another row still binds it to this incomplete v2 chain.
            entries = plan.get("failed_segments")
            for entry in entries if isinstance(entries, list) else []:
                if isinstance(entry, Mapping) and isinstance(entry.get("failed_segment_id"), int):
                    rejected_ids.add(entry["failed_segment_id"])
    for index, segment in enumerate(segments):
        if isinstance(segment, Mapping) and isinstance(segment.get("id"), int) and segment["id"] in rejected_ids:
            results[index] = None
    return results


def approved_segment_gap(db, segment: Mapping) -> dict | None:
    """Read-only, fail-closed validation for readiness scans (008 may be absent)."""
    return approved_segment_gaps(db, [segment])[0]


def resolve_segment_gap_transition(db, boundary: datetime, checkpoint_rows: Sequence[Mapping] | Mapping) -> dict | None:
    """Both unchanged Packet source IDs must name the same approved gap end."""
    try:
        boundary_text = format_db_utc(require_utc_window_boundary(boundary, "gap boundary"))
        rows = list(checkpoint_rows.values()) if isinstance(checkpoint_rows, Mapping) else list(checkpoint_rows)
        pair = {row["detector_name"]: row for row in rows}
        _require(len(rows) == 2 and set(pair) == set(DETECTORS), "Both Packet checkpoint rows are required.")
        _require(pair == _checkpoint_pair(db), "Supplied Packet checkpoints differ from current state.")
        _require_schema(db)
        candidates = _rows(db, f"SELECT failed_segment_id FROM {AUDIT_TABLE} WHERE window_end=:boundary",
                           {"boundary": boundary_text})
        valid = []
        for candidate in candidates:
            segment = _one(db, "SELECT * FROM packet_capture_segments WHERE id=:id",
                           {"id": candidate["failed_segment_id"]})
            if segment is None:
                continue
            audit = approved_segment_gap(db, segment)
            if audit is None:
                continue
            if all(pair[detector]["source_table"] == SOURCE_TABLE
                   and pair[detector]["last_completed_window_end"] == boundary_text
                   and pair[detector]["last_processed_id"] == audit["checkpoints"][detector]["before"]["last_processed_id"]
                   for detector in DETECTORS):
                valid.append(audit)
        return valid[0] if len(valid) == 1 else None
    except (SegmentGapRecoveryError, sqlite3.Error, SQLAlchemyError, ValueError, TypeError, KeyError):
        return None


def _validate_current(db, plan: Mapping) -> None:
    verify_segment_gap_plan(plan)
    _require_schema(db)
    session = _one(db, "SELECT * FROM packet_capture_sessions WHERE session_id=:sid", {"sid": plan["capture_session_id"]})
    _require(session is not None and session["status"] == "RUNNING", "Target Capture Session must remain RUNNING.")
    running = _rows(db, "SELECT session_id FROM packet_capture_sessions WHERE status='RUNNING'")
    _require(len(running) == 1 and running[0]["session_id"] == plan["capture_session_id"],
             "Only the target Capture Session may be RUNNING.")
    entries = plan["failed_segments"] if plan["schema_version"] == CHAIN_PLAN_SCHEMA_VERSION else [plan]
    for entry in entries:
        failed = _one(db, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": entry["failed_segment_id"]})
        _require(failed == entry["failed_segment"] and failed["capture_session_id"] == session["id"],
                 "Failed Segment no longer matches its approved evidence.")
        _no_gap_features_or_overlap(db, failed)
        _require(_one(db, f"SELECT id FROM {AUDIT_TABLE} WHERE failed_segment_id=:id",
                      {"id": entry["failed_segment_id"]}) is None, "This failed Window already has a recovery audit.")
    for operation_id in {plan["operation_id"], *(entry["operation_id"] for entry in entries)}:
        _require(_one(db, f"SELECT id FROM {AUDIT_TABLE} WHERE operation_id=:operation",
                      {"operation": operation_id}) is None, "Recovery operation identity already exists.")
    pair = _checkpoint_pair(db)
    _require(all(pair[detector] == plan["checkpoints"][detector]["before"] for detector in DETECTORS),
             "A Packet checkpoint changed after plan creation.")
    expected = _window(session["first_window_start"])
    failure_start = _window(plan["window_start"])
    segments = _rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:sid ORDER BY window_start,id",
                     {"sid": session["id"]})
    for segment in segments:
        start = _window(segment["window_start"])
        if start >= failure_start:
            break
        _require(start == expected, "Original Capture prefix has a missing or overlapping Window.")
        if not _healthy(db, segment):
            _require(approved_segment_gap(db, segment) is not None
                     or approved_partial_capture_gap(db, segment) is not None,
                     "Earlier Capture gap lacks a valid approved audit.")
        expected = _window(segment["window_end"])
    _require(expected == failure_start, "The consumed prefix does not reach this failed Window.")
    following = [row for row in segments if row["window_start"] == plan["window_end"]]
    _require(len(following) == 1 and _healthy(db, following[0]),
             "A healthy contiguous Window must follow the failed Window.")


def build_segment_gap_chain_plan(connection: sqlite3.Connection, *, capture_session_id: str,
                                 failed_segment_ids: Sequence[int], preserved_pcaps: Sequence[Mapping],
                                 approved_by: str, reason: str, repository_commit: str, database_path: str,
                                 backup_path: str, generated_at: str | None = None) -> dict[str, Any]:
    """Bind two or three explicitly listed consecutive PARTIAL_CAPTURE Windows."""
    _require_schema(connection)
    _require(isinstance(failed_segment_ids, (list, tuple)) and 2 <= len(failed_segment_ids) <= 3
             and isinstance(preserved_pcaps, (list, tuple)) and len(preserved_pcaps) == len(failed_segment_ids),
             "An exact two- or three-Window ID/PCAP list is required.")
    entries = []
    for segment_id, pcap in zip(failed_segment_ids, preserved_pcaps):
        _require(isinstance(segment_id, int) and not isinstance(segment_id, bool) and segment_id > 0,
                 "A positive failed Segment ID is required.")
        failed = _one(connection, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": segment_id})
        _require(failed is not None and isinstance(pcap, Mapping) and set(pcap) == {"path", "sha256"},
                 "Failed Segment and exact preserved PCAP binding are required.")
        entries.append({"operation_id": str(uuid4()), "failed_segment_id": segment_id,
                        "failed_segment": failed, "preserved_pcap_path": pcap["path"], "pcap_sha256": pcap["sha256"]})
    pair = _checkpoint_pair(connection)
    start, end = entries[0]["failed_segment"]["window_start"], entries[-1]["failed_segment"]["window_end"]
    plan = {"schema_version": CHAIN_PLAN_SCHEMA_VERSION, "operation_id": str(uuid4()),
            "capture_session_id": capture_session_id, "coverage": "UNINSPECTED",
            "window_start": start, "window_end": end, "failed_segments": entries,
            "checkpoints": {detector: {"before": before, "after": {
                **before, "last_completed_window_end": end, "updated_at": end,
            }} for detector, before in pair.items()},
            "approved_by": approved_by, "reason": reason, "repository_commit": repository_commit,
            "database_path": str(database_path), "backup_path": str(backup_path),
            "generated_at": generated_at or datetime.now(timezone.utc).isoformat()}
    plan["plan_sha256"] = canonical_plan_sha256(plan)
    _validate_current(connection, plan)
    return plan


def build_segment_gap_plan(connection: sqlite3.Connection, *, capture_session_id: str, failed_segment_id: int,
                           approved_by: str, reason: str, repository_commit: str, database_path: str,
                           backup_path: str, preserved_pcap_path: str, pcap_sha256: str,
                           generated_at: str | None = None) -> dict[str, Any]:
    """Build a bound dry-run plan without mutating the DB or touching paths."""
    _require_schema(connection)
    failed = _one(connection, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": failed_segment_id})
    _require(failed is not None, "Failed Segment does not exist.")
    pair = _checkpoint_pair(connection)
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION, "operation_id": str(uuid4()),
        "capture_session_id": capture_session_id, "failed_segment_id": failed_segment_id,
        "window_start": failed["window_start"], "window_end": failed["window_end"],
        "failed_segment": failed,
        "checkpoints": {detector: {"before": before, "after": {
            **before, "last_completed_window_end": failed["window_end"], "updated_at": failed["window_end"],
        }} for detector, before in pair.items()},
        "approved_by": approved_by, "reason": reason, "repository_commit": repository_commit,
        "database_path": str(database_path), "backup_path": str(backup_path),
        "preserved_pcap_path": str(preserved_pcap_path), "pcap_sha256": pcap_sha256,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
    }
    plan["plan_sha256"] = canonical_plan_sha256(plan)
    _validate_current(connection, plan)
    return plan


def apply_segment_gap_plan(connection: sqlite3.Connection, plan: Mapping, *, backup_sha256: str) -> dict:
    """Revalidate and atomically change both Packet checkpoints plus bound audits.

    The caller must own its transaction and commit it only after all external
    evidence and backup checks pass. SAVEPOINT also protects callers that catch
    a failure and accidentally keep their outer transaction alive.
    """
    _require(isinstance(connection, sqlite3.Connection) and connection.in_transaction,
             "The caller must begin a protected SQLite transaction.")
    _require(isinstance(backup_sha256, str) and _HEX64.fullmatch(backup_sha256), "Backup SHA256 is required.")
    connection.execute("SAVEPOINT apply_segment_gap")
    try:
        _validate_current(connection, plan)
        changes_before = connection.total_changes
        for detector in DETECTORS:
            before, after = plan["checkpoints"][detector]["before"], plan["checkpoints"][detector]["after"]
            result = connection.execute(
                "UPDATE detector_checkpoints SET last_completed_window_end=:end,updated_at=:after_updated "
                "WHERE detector_name=:detector AND source_table=:source AND last_processed_id IS :last_id "
                "AND last_completed_window_end=:start AND updated_at=:before_updated",
                {"end": after["last_completed_window_end"], "after_updated": after["updated_at"],
                 "detector": detector, "source": SOURCE_TABLE, "last_id": before["last_processed_id"],
                 "start": before["last_completed_window_end"], "before_updated": before["updated_at"]})
            _require(result.rowcount == 1, "Packet checkpoint conditional update failed.")
        fields = ("operation_id", "capture_session_id", "failed_segment_id", "window_start", "window_end",
                  "plan_sha256", "approved_by", "reason", "repository_commit", "database_path",
                  "backup_path", "preserved_pcap_path", "pcap_sha256")
        chain = plan["schema_version"] == CHAIN_PLAN_SCHEMA_VERSION
        values = ([_chain_row_values(plan, entry) for entry in plan["failed_segments"]]
                  if chain else [{key: plan[key] for key in fields}])
        plan_json = json.dumps(dict(plan), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        for audit_values in values:
            audit_values.update(plan_json=plan_json, backup_sha256=backup_sha256)
            columns = ",".join(audit_values)
            placeholders = ",".join(":" + key for key in audit_values)
            connection.execute(f"INSERT INTO {AUDIT_TABLE} ({columns}) VALUES ({placeholders})", audit_values)
        _require(connection.total_changes - changes_before == 2 + len(values),
                 "Recovery must change exactly two checkpoints and the approved audits.")
        pair = _checkpoint_pair(connection)
        _require(all(pair[detector] == plan["checkpoints"][detector]["after"] for detector in DETECTORS),
                 "Updated checkpoint verification failed.")
        _require(not connection.execute("PRAGMA foreign_key_check").fetchall(), "Recovery foreign-key check failed.")
        failed = ([entry["failed_segment"] for entry in plan["failed_segments"]] if chain else [plan["failed_segment"]])
        audits = [_validated_audit(connection, segment) for segment in failed]
        _require(all(audit is not None for audit in audits), "Committed recovery audit cannot be validated.")
        connection.execute("RELEASE SAVEPOINT apply_segment_gap")
        return ({"operation_id": plan["operation_id"], "audits": audits,
                 "window_start": plan["window_start"], "window_end": plan["window_end"]} if chain else audits[0])
    except Exception:
        connection.execute("ROLLBACK TO SAVEPOINT apply_segment_gap")
        connection.execute("RELEASE SAVEPOINT apply_segment_gap")
        raise
