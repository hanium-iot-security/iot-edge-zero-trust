"""Phase 5 run evaluation against a read-only SQLite database."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from typing import Any, Mapping, Sequence

from edge.detection.phase4_time import parse_db_utc
from edge.phase5.contracts import EvaluationScope, ManifestStatus, RunManifest


PHASE5_EVALUATION_SCHEMA_VERSION = "phase5-evaluation-v1"
LATENCY_NO_SAMPLES_REASON = "NO_SAMPLES"
_INPUT_DIGEST_META_KEYS = (
    "_manifest_sha256",
    "_scenario_result_sha256",
    "_db_snapshot_sha256",
)


class Phase5EvaluationError(ValueError):
    pass


@dataclass(frozen=True)
class _TableRequirement:
    name: str
    columns: tuple[str, ...]


_REQUIRED_TABLES = (
    _TableRequirement(
        "devices",
        ("device_id", "ip_address", "status", "trust_score"),
    ),
    _TableRequirement(
        "detection_events",
        (
            "id",
            "device_id",
            "feature_log_id",
            "mqtt_log_id",
            "packet_feature_log_id",
            "detector_type",
            "event_type",
            "severity",
            "score_delta",
            "applied_to_score",
            "detected_at",
            "analysis_window_start",
            "analysis_window_end",
            "incident_family",
            "subject_ip",
        ),
    ),
    _TableRequirement(
        "trust_score_history",
        (
            "id",
            "device_id",
            "analysis_window_start",
            "analysis_window_end",
            "previous_score",
            "actual_delta",
            "new_score",
            "representative_event_ids_json",
            "created_at",
        ),
    ),
    _TableRequirement(
        "firewall_rules",
        (
            "id",
            "device_id",
            "source_ip",
            "status",
            "trigger_event_id",
            "created_at",
            "applied_at",
            "released_at",
        ),
    ),
    _TableRequirement(
        "packet_feature_logs",
        (
            "id",
            "capture_segment_id",
            "device_id",
            "peer_ip",
            "window_start",
            "window_end",
        ),
    ),
    _TableRequirement(
        "packet_capture_segments",
        ("id", "capture_session_id", "window_start", "window_end", "status"),
    ),
    _TableRequirement(
        "packet_capture_sessions",
        ("id", "session_id", "status"),
    ),
)


def evaluate_phase5_run(
    manifest: RunManifest,
    *,
    db_path: Path,
    evaluation_schema_version: str,
    source_commit: str,
    scenario_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate one Phase 5 run.

    The database is opened with SQLite URI mode=ro. Any missing DB/table/column
    is represented as an ENVIRONMENT_ERROR row instead of mutating the source DB.
    """
    if not isinstance(manifest, RunManifest):
        raise Phase5EvaluationError("manifest must be edge.phase5.contracts.RunManifest")
    evaluation_schema_version = _require_non_empty_string(
        evaluation_schema_version,
        "evaluation_schema_version",
    )
    source_commit = _require_non_empty_string(source_commit, "source_commit")
    scenario_result = dict(scenario_result or {})
    _validate_scenario_result_identity(manifest, scenario_result)

    db_path = Path(db_path)
    if not db_path.exists():
        return _environment_error_row(
            manifest,
            evaluation_schema_version=evaluation_schema_version,
            source_commit=source_commit,
            reason_code="DB_NOT_FOUND",
            reason=f"database not found: {db_path}",
            scenario_result=scenario_result,
        )

    conn: sqlite3.Connection | None = None
    try:
        conn = _connect_readonly(db_path)
        try:
            schema_errors = _validate_required_schema(conn)
            if schema_errors:
                return _environment_error_row(
                    manifest,
                    evaluation_schema_version=evaluation_schema_version,
                    source_commit=source_commit,
                    reason_code="SCHEMA_MISSING",
                    reason="; ".join(schema_errors),
                    scenario_result=scenario_result,
                )
            return _evaluate_with_connection(
                manifest,
                conn,
                evaluation_schema_version=evaluation_schema_version,
                source_commit=source_commit,
                scenario_result=scenario_result,
            )
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return _environment_error_row(
            manifest,
            evaluation_schema_version=evaluation_schema_version,
            source_commit=source_commit,
            reason_code="DB_OPEN_FAILED",
            reason=str(exc),
            scenario_result=scenario_result,
        )


def evaluation_identity(
    manifest: RunManifest,
    evaluation_schema_version: str,
    *,
    source_commit: str | None = None,
    manifest_sha256: str | None = None,
    scenario_result_sha256: str | None = None,
    db_snapshot_sha256: str | None = None,
) -> str:
    return ":".join(
        (
            evaluation_schema_version,
            manifest.run_id,
            _identity_part(manifest.session_id),
            manifest.scenario.scenario_id,
            _identity_part(source_commit),
            _identity_part(manifest_sha256),
            _identity_part(scenario_result_sha256),
            _identity_part(db_snapshot_sha256),
        )
    )


def summarize_evaluation_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    evaluation_schema_version: str,
    source_commit: str,
) -> dict[str, Any]:
    total_attempts = len(rows)
    status_counts = Counter(str(row.get("final_status")) for row in rows)
    failure_reason_counts: Counter[str] = Counter()
    scenario_counts: dict[str, Counter[str]] = {}
    latency_values: dict[str, list[float]] = {}
    tp = fp = tn = fn = 0
    valid_runs = 0
    valid_successes = 0
    environment_errors = 0
    capture_ineligible = 0

    for row in rows:
        scenario_id = str(row.get("scenario", {}).get("scenario_id"))
        scenario_counts.setdefault(scenario_id, Counter())[str(row.get("final_status"))] += 1
        for reason in row.get("failure_reasons", []):
            failure_reason_counts[str(reason.get("code"))] += 1

        final_status = row.get("final_status")
        data_status = row.get("statuses", {}).get("data_status")
        if final_status == ManifestStatus.ENVIRONMENT_ERROR.value:
            environment_errors += 1
        if data_status == ManifestStatus.CAPTURE_INELIGIBLE.value:
            capture_ineligible += 1
        if bool(row.get("valid_run")):
            valid_runs += 1
            if final_status == ManifestStatus.SUCCESS.value:
                valid_successes += 1
            classification = row.get("classification", {})
            tp += int(bool(classification.get("tp")))
            fp += int(bool(classification.get("fp")))
            tn += int(bool(classification.get("tn")))
            fn += int(bool(classification.get("fn")))

            for latency in row.get("latencies", []):
                if latency.get("calculable") is True:
                    latency_values.setdefault(str(latency["name"]), []).append(
                        float(latency["milliseconds"])
                    )

    return {
        "evaluation_schema_version": evaluation_schema_version,
        "source_commit": source_commit,
        "total_attempts": total_attempts,
        "valid_runs": valid_runs,
        "status_counts": dict(sorted(status_counts.items())),
        "scenario_success_rates": {
            scenario_id: _ratio(counter.get(ManifestStatus.SUCCESS.value, 0), sum(counter.values()))
            for scenario_id, counter in sorted(scenario_counts.items())
        },
        "valid_run_success_rate": _ratio(valid_successes, valid_runs),
        "overall_attempt_success_rate": _ratio(
            status_counts.get(ManifestStatus.SUCCESS.value, 0),
            total_attempts,
        ),
        "classification": {
            "official_basis": "valid_run_true_only",
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "f1": _f1(tp, fp, fn),
            "normal_run_fpr": _ratio(fp, fp + tn),
            "normal_window_fpr": {
                "value": None,
                "reason": "WINDOW_LEVEL_ROWS_NOT_EMITTED",
            },
            "attack_session_tpr": _ratio(tp, tp + fn),
        },
        "environment_error_ratio": _ratio(environment_errors, total_attempts),
        "capture_ineligible_ratio": _ratio(capture_ineligible, total_attempts),
        "latency_statistics": {
            name: _latency_stats(values)
            for name, values in sorted(latency_values.items())
        },
        "failure_reason_counts": dict(sorted(failure_reason_counts.items())),
        "packet_rule_candidate_comparison": _packet_rule_candidate_summary(rows),
        "latency_percentile_method": "nearest-rank for p95, median midpoint",
    }


def _evaluate_with_connection(
    manifest: RunManifest,
    conn: sqlite3.Connection,
    *,
    evaluation_schema_version: str,
    source_commit: str,
    scenario_result: Mapping[str, Any],
) -> dict[str, Any]:
    attack_started_at = manifest.attack_started_at or manifest.started_at
    observation_deadline_at = manifest.observation_deadline_at
    detection = _evaluate_detection(
        manifest,
        conn,
        attack_started_at=attack_started_at,
        observation_deadline_at=observation_deadline_at,
    )
    trust = _evaluate_trust(
        manifest,
        conn,
        detection_event_ids=detection["matched_detection_event_ids"],
        attack_started_at=attack_started_at,
        observation_deadline_at=observation_deadline_at,
    )
    firewall = _evaluate_firewall(
        manifest,
        conn,
        detection_event_ids=detection["matched_detection_event_ids"],
        trust_history_ids=trust["trust_score_history_ids"],
        attack_started_at=attack_started_at,
        observation_deadline_at=observation_deadline_at,
    )
    block = _evaluate_block(scenario_result, firewall)
    latencies = _build_latencies(
        manifest,
        detection,
        trust,
        firewall,
        block,
        scenario_result,
        attack_started_at=attack_started_at,
    )
    statuses, failure_reasons = _stage_statuses(
        manifest,
        scenario_result,
        detection,
        trust,
        firewall,
        block,
    )
    valid_run = statuses["data_status"] not in {
        ManifestStatus.ENVIRONMENT_ERROR.value,
        ManifestStatus.CAPTURE_INELIGIBLE.value,
        ManifestStatus.HOLD.value,
        ManifestStatus.NOT_EVALUATED.value,
    }
    classification = _classification(manifest, detection, valid_run=valid_run)
    input_digests = _input_digests(scenario_result)

    return {
        "evaluation_schema_version": evaluation_schema_version,
        "source_commit": source_commit,
        "source_commit_verification": _source_commit_verification(),
        "run_manifest_schema_version": manifest.run_manifest_schema_version,
        "evaluation_identity": evaluation_identity(
            manifest,
            evaluation_schema_version,
            source_commit=source_commit,
            manifest_sha256=input_digests.get("manifest_sha256"),
            scenario_result_sha256=input_digests.get("scenario_result_sha256"),
            db_snapshot_sha256=input_digests.get("db_snapshot_sha256"),
        ),
        "input_digests": input_digests,
        "run_id": manifest.run_id,
        "session_id": manifest.session_id,
        "scenario": manifest.scenario.to_dict(),
        "target_device_id": manifest.target_device_id,
        "source_ip": manifest.source_ip,
        "evaluation_scope": manifest.evaluation_scope.value,
        "evaluation_unit": _evaluation_unit(manifest, scenario_result),
        "valid_run": valid_run,
        "success_denominator_included": valid_run,
        "matching": detection["matching"],
        "expected_outcome": manifest.expected_outcome.to_dict(),
        "matched_ids": {
            "detection_event_ids": detection["matched_detection_event_ids"],
            "trust_score_history_ids": trust["trust_score_history_ids"],
            "firewall_rule_ids": firewall["firewall_rule_ids"],
            "trigger_event_ids": firewall["trigger_event_ids"],
        },
        "statuses": statuses,
        "scenario_status": statuses["scenario_status"],
        "detection_status": statuses["detection_status"],
        "trust_status": statuses["trust_status"],
        "firewall_status": statuses["firewall_status"],
        "block_status": statuses["block_status"],
        "data_status": statuses["data_status"],
        "final_status": statuses["final_status"],
        "failure_reasons": failure_reasons,
        "detection": detection,
        "trust": trust,
        "firewall": firewall,
        "block": block,
        "db_timestamps": {
            "detection_events.detected_at": detection["first_detection_timestamp"],
            "trust_score_history.created_at": trust["first_trust_history_created_at"],
            "firewall_rules.created_at": firewall["first_firewall_created_at"],
            "firewall_rules.applied_at": firewall["first_firewall_applied_at"],
        },
        "external_observations": _external_observations(manifest, scenario_result),
        "latencies": latencies,
        "classification": classification,
        "artifacts": [artifact.to_dict() for artifact in manifest.artifacts],
        "session_manifest_ref": _manifest_ref_payload(manifest),
    }


def _connect_readonly(db_path: Path) -> sqlite3.Connection:
    uri = db_path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _validate_required_schema(conn: sqlite3.Connection) -> list[str]:
    errors: list[str] = []
    for requirement in _REQUIRED_TABLES:
        columns = _table_columns(conn, requirement.name)
        if columns is None:
            errors.append(f"missing table: {requirement.name}")
            continue
        missing = sorted(set(requirement.columns) - columns)
        if missing:
            errors.append(f"missing columns in {requirement.name}: {missing}")
    return errors


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str] | None:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    if not rows:
        return None
    return {str(row["name"]) for row in rows}


def _evaluate_detection(
    manifest: RunManifest,
    conn: sqlite3.Connection,
    *,
    attack_started_at: datetime,
    observation_deadline_at: datetime,
) -> dict[str, Any]:
    rows = _select_detection_rows(
        conn,
        manifest,
        attack_started_at=attack_started_at,
        observation_deadline_at=observation_deadline_at,
    )
    expected_event_types = set(manifest.expected_outcome.expected_event_types)
    matched: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    time_only_candidates = 0

    for row in rows:
        event = _normalize_detection_row(row)
        detected_at = event["parsed_detected_at"]
        in_range = (
            detected_at is not None
            and attack_started_at <= detected_at <= observation_deadline_at
        )
        if not in_range:
            excluded["outside_observation_window_or_bad_timestamp"] += 1
            continue

        packet_session_id = event["packet_session_id"]
        source_ip = event["event_source_ip"]
        device_matches = (
            manifest.target_device_id is not None
            and event["device_id"] == manifest.target_device_id
        )
        source_matches = (
            manifest.source_ip is not None
            and source_ip == manifest.source_ip
        )
        session_matches = (
            manifest.session_id is not None
            and packet_session_id == manifest.session_id
        )

        if (
            packet_session_id is not None
            and manifest.session_id is not None
            and not session_matches
        ):
            excluded["session_id_mismatch"] += 1
            continue
        if session_matches:
            if event["device_id"] is not None and not device_matches:
                excluded["device_id_mismatch"] += 1
                continue
            if source_ip is not None and not source_matches:
                excluded["source_ip_mismatch"] += 1
                continue
            event["matching_strategy"] = (
                "session_id+device_id+source_ip"
                if source_ip is not None
                else "session_id"
            )
            matched.append(event)
            continue

        if device_matches and source_matches:
            event["matching_strategy"] = "device_id+source_ip+time_range"
            matched.append(event)
            continue

        if event["event_type"] in expected_event_types:
            time_only_candidates += 1
        if not device_matches:
            excluded["device_id_mismatch"] += 1
        elif not source_matches:
            excluded["source_ip_mismatch"] += 1
        else:
            excluded["missing_matching_identifier"] += 1

    expected_matches = [
        event for event in matched if event["event_type"] in expected_event_types
    ]
    unexpected_matches = [
        event for event in matched if event["event_type"] not in expected_event_types
    ]
    detection_ids = [int(event["id"]) for event in matched]
    first_detection = _min_timestamp(
        event["detected_at"]
        for event in matched
        if event["detected_at"] is not None
    )
    rule_events = [event for event in matched if event["detector_type"] == "RULE"]
    ai_events = [event for event in matched if event["detector_type"] == "AI"]

    matching_strategy = sorted(
        {str(event["matching_strategy"]) for event in matched}
    )
    return {
        "query_available": True,
        "evaluable": True,
        "reason": None,
        "expected_event_types": sorted(expected_event_types),
        "actual_event_types": sorted({str(event["event_type"]) for event in matched}),
        "unexpected_event_types": sorted(
            {str(event["event_type"]) for event in unexpected_matches}
        ),
        "expected_rule_event": _has_expected_detector(expected_event_types, "RULE"),
        "expected_ai_event": _has_expected_detector(expected_event_types, "AI"),
        "actual_rule_event": bool(rule_events),
        "actual_ai_event": bool(ai_events),
        "matched_expected_event": bool(expected_matches),
        "matched_detection_event_ids": sorted(detection_ids),
        "expected_detection_event_ids": sorted(int(event["id"]) for event in expected_matches),
        "unexpected_detection_event_ids": sorted(int(event["id"]) for event in unexpected_matches),
        "first_detection_timestamp": first_detection,
        "events": [_public_detection_event(event) for event in matched],
        "matching": {
            "strategy": matching_strategy or [],
            "available_identifiers": _available_identifiers(manifest),
            "missing_identifiers": [],
            "candidate_row_count": len(rows),
            "matched_row_count": len(matched),
            "ambiguous_candidate_exists": time_only_candidates > 1 and not matched,
            "time_only_candidate_count": time_only_candidates,
            "excluded_candidate_reasons": dict(sorted(excluded.items())),
        },
    }


def _select_detection_rows(
    conn: sqlite3.Connection,
    manifest: RunManifest,
    *,
    attack_started_at: datetime,
    observation_deadline_at: datetime,
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT
            de.id,
            de.device_id,
            de.feature_log_id,
            de.mqtt_log_id,
            de.packet_feature_log_id,
            de.detector_type,
            de.event_type,
            de.severity,
            de.score_delta,
            de.applied_to_score,
            de.detected_at,
            de.analysis_window_start,
            de.analysis_window_end,
            de.incident_family,
            de.subject_ip,
            pfl.peer_ip AS packet_peer_ip,
            pcs.session_id AS packet_session_id,
            d.ip_address AS registered_ip_address
        FROM detection_events de
        LEFT JOIN packet_feature_logs pfl
            ON pfl.id = de.packet_feature_log_id
        LEFT JOIN packet_capture_segments pcsg
            ON pcsg.id = pfl.capture_segment_id
        LEFT JOIN packet_capture_sessions pcs
            ON pcs.id = pcsg.capture_session_id
        LEFT JOIN devices d
            ON d.device_id = de.device_id
        WHERE
            de.device_id = :device_id
            OR de.subject_ip = :source_ip
            OR pfl.peer_ip = :source_ip
            OR d.ip_address = :source_ip
            OR pcs.session_id = :session_id
            OR de.detected_at BETWEEN :attack_started_at AND :observation_deadline_at
        ORDER BY de.detected_at ASC, de.id ASC
        """,
        {
            "device_id": manifest.target_device_id,
            "source_ip": manifest.source_ip,
            "session_id": manifest.session_id,
            "attack_started_at": _format_timestamp(attack_started_at),
            "observation_deadline_at": _format_timestamp(observation_deadline_at),
        },
    ).fetchall()


def _normalize_detection_row(row: sqlite3.Row) -> dict[str, Any]:
    detected_at = _parse_db_timestamp(row["detected_at"], "detection_events.detected_at")
    event_source_ip = row["subject_ip"] or row["packet_peer_ip"] or row["registered_ip_address"]
    return {
        key: row[key]
        for key in row.keys()
    } | {
        "event_source_ip": event_source_ip,
        "parsed_detected_at": detected_at["parsed"],
        "detected_at": detected_at["formatted"],
        "detected_at_parse_error": detected_at["error"],
    }


def _evaluate_trust(
    manifest: RunManifest,
    conn: sqlite3.Connection,
    *,
    detection_event_ids: Sequence[int],
    attack_started_at: datetime,
    observation_deadline_at: datetime,
) -> dict[str, Any]:
    rows = [
        _normalize_trust_row(row)
        for row in conn.execute(
            """
            SELECT
                id,
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                actual_delta,
                new_score,
                representative_event_ids_json,
                created_at
            FROM trust_score_history
            WHERE device_id = :device_id
            ORDER BY analysis_window_end ASC, id ASC
            """,
            {"device_id": manifest.target_device_id},
        ).fetchall()
    ]
    detection_ids = set(int(event_id) for event_id in detection_event_ids)
    matched: list[dict[str, Any]] = []
    for row in rows:
        created_at = row["parsed_created_at"]
        window_end = row["parsed_analysis_window_end"]
        in_range = (
            (created_at is not None and attack_started_at <= created_at <= observation_deadline_at)
            or (
                window_end is not None
                and attack_started_at <= window_end <= observation_deadline_at
            )
        )
        representative_ids = set(row["representative_event_ids"])
        if detection_ids and representative_ids.isdisjoint(detection_ids):
            continue
        if not detection_ids and representative_ids:
            continue
        if in_range:
            matched.append(row)

    before_score = None
    if matched:
        before_score = int(matched[0]["previous_score"])
    else:
        before_row = _latest_trust_before(rows, attack_started_at)
        if before_row is not None:
            before_score = int(before_row["new_score"])

    after_score = int(matched[-1]["new_score"]) if matched else before_score
    score_values = [int(row["new_score"]) for row in matched]
    trust_ids = sorted(int(row["id"]) for row in matched)
    linked_detection_ids = sorted(
        {
            event_id
            for row in matched
            for event_id in row["representative_event_ids"]
            if not detection_ids or event_id in detection_ids
        }
    )
    duplicate_check_available = bool(matched)
    representative_counter: Counter[int] = Counter(
        event_id
        for row in matched
        for event_id in row["representative_event_ids"]
    )
    duplicate_counts = {
        str(event_id): count
        for event_id, count in sorted(representative_counter.items())
        if count > 1
    }
    duplicate_suspected = bool(duplicate_counts)

    return {
        "query_available": True,
        "evaluable": True,
        "reason": None if matched else "NO_TRUST_HISTORY_MATCHED",
        "score_before": before_score,
        "score_after": after_score,
        "minimum_score": min(score_values) if score_values else after_score,
        "total_score_delta": sum(int(row["actual_delta"]) for row in matched),
        "penalty_row_count": sum(1 for row in matched if int(row["actual_delta"]) < 0),
        "recovery_row_count": sum(1 for row in matched if int(row["actual_delta"]) > 0),
        "trust_score_history_ids": trust_ids,
        "linked_detection_event_ids": linked_detection_ids,
        "trigger_event_ids": linked_detection_ids,
        "status_before": None,
        "status_after": _select_device_status(conn, manifest.target_device_id),
        "isolated": _select_device_status(conn, manifest.target_device_id) == "isolated",
        "duplicate_penalty_check_available": duplicate_check_available,
        "duplicate_penalty_suspected": duplicate_suspected,
        "duplicate_penalty_event_counts": duplicate_counts,
        "duplicate_penalty_basis": (
            "representative_event_ids_json_across_matched_history_rows"
            if duplicate_check_available
            else "TRUST_HISTORY_NOT_MATCHED"
        ),
        "first_trust_history_created_at": _min_timestamp(
            row["created_at"] for row in matched if row["created_at"] is not None
        ),
        "history_rows": [_public_trust_row(row) for row in matched],
    }


def _normalize_trust_row(row: sqlite3.Row) -> dict[str, Any]:
    created_at = _parse_db_timestamp(row["created_at"], "trust_score_history.created_at")
    window_start = _parse_db_timestamp(
        row["analysis_window_start"],
        "trust_score_history.analysis_window_start",
    )
    window_end = _parse_db_timestamp(
        row["analysis_window_end"],
        "trust_score_history.analysis_window_end",
    )
    return {
        key: row[key]
        for key in row.keys()
    } | {
        "created_at": created_at["formatted"],
        "parsed_created_at": created_at["parsed"],
        "analysis_window_start": window_start["formatted"],
        "parsed_analysis_window_start": window_start["parsed"],
        "analysis_window_end": window_end["formatted"],
        "parsed_analysis_window_end": window_end["parsed"],
        "representative_event_ids": _parse_id_json(row["representative_event_ids_json"]),
    }


def _latest_trust_before(
    rows: Sequence[Mapping[str, Any]],
    timestamp: datetime,
) -> Mapping[str, Any] | None:
    before = [
        row for row in rows
        if row["parsed_created_at"] is not None and row["parsed_created_at"] < timestamp
    ]
    if not before:
        return None
    return before[-1]


def _evaluate_firewall(
    manifest: RunManifest,
    conn: sqlite3.Connection,
    *,
    detection_event_ids: Sequence[int],
    trust_history_ids: Sequence[int],
    attack_started_at: datetime,
    observation_deadline_at: datetime,
) -> dict[str, Any]:
    rows = [
        _normalize_firewall_row(row)
        for row in conn.execute(
            """
            SELECT
                id,
                device_id,
                source_ip,
                status,
                trigger_event_id,
                created_at,
                applied_at,
                released_at
            FROM firewall_rules
            WHERE
                source_ip = :source_ip
                OR device_id = :device_id
                OR trigger_event_id IS NOT NULL
            ORDER BY created_at ASC, id ASC
            """,
            {
                "source_ip": manifest.source_ip,
                "device_id": manifest.target_device_id,
            },
        ).fetchall()
    ]
    detection_ids = set(int(event_id) for event_id in detection_event_ids)
    matched: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    for row in rows:
        created_at = row["parsed_created_at"]
        in_range = (
            created_at is not None
            and attack_started_at <= created_at <= observation_deadline_at
        )
        direct_trigger = (
            row["trigger_event_id"] is not None
            and int(row["trigger_event_id"]) in detection_ids
        )
        device_matches = (
            manifest.target_device_id is not None
            and row["device_id"] in {None, manifest.target_device_id}
        )
        source_matches = (
            manifest.source_ip is not None
            and row["source_ip"] == manifest.source_ip
        )
        if direct_trigger or (in_range and device_matches and source_matches):
            row["matching_strategy"] = (
                "trigger_event_id"
                if direct_trigger
                else "device_id+source_ip+time_range"
            )
            matched.append(row)
            continue
        if not source_matches:
            excluded["source_ip_mismatch"] += 1
        elif not device_matches:
            excluded["device_id_mismatch"] += 1
        else:
            excluded["outside_observation_window_or_bad_timestamp"] += 1

    historically_applied_rows = [
        row
        for row in matched
        if _firewall_historically_applied(
            row,
            attack_started_at=attack_started_at,
            observation_deadline_at=observation_deadline_at,
        )
    ]
    currently_applied = any(row["status"] == "APPLIED" for row in matched)

    return {
        "query_available": True,
        "evaluable": True,
        "reason": None if matched else "NO_FIREWALL_RULE_MATCHED",
        "firewall_rule_ids": sorted(int(row["id"]) for row in matched),
        "trust_score_history_ids": list(trust_history_ids),
        "trigger_event_ids": sorted(
            {
                int(row["trigger_event_id"])
                for row in matched
                if row["trigger_event_id"] is not None
            }
        ),
        "rule_created": bool(matched),
        "rule_applied": bool(historically_applied_rows),
        "rule_applied_during_run": bool(historically_applied_rows),
        "currently_applied": currently_applied,
        "rule_statuses": sorted({str(row["status"]) for row in matched}),
        "first_firewall_created_at": _min_timestamp(
            row["created_at"] for row in matched if row["created_at"] is not None
        ),
        "first_firewall_applied_at": _min_timestamp(
            row["applied_at"] for row in matched if row["applied_at"] is not None
        ),
        "first_firewall_released_at": _min_timestamp(
            row["released_at"] for row in matched if row["released_at"] is not None
        ),
        "db_external_link_status": _firewall_external_link_status(matched),
        "excluded_candidate_reasons": dict(sorted(excluded.items())),
        "rules": [_public_firewall_row(row) for row in matched],
    }


def _normalize_firewall_row(row: sqlite3.Row) -> dict[str, Any]:
    created_at = _parse_db_timestamp(row["created_at"], "firewall_rules.created_at")
    applied_at = _parse_db_timestamp(row["applied_at"], "firewall_rules.applied_at")
    released_at = _parse_db_timestamp(row["released_at"], "firewall_rules.released_at")
    return {
        key: row[key]
        for key in row.keys()
    } | {
        "created_at": created_at["formatted"],
        "parsed_created_at": created_at["parsed"],
        "applied_at": applied_at["formatted"],
        "parsed_applied_at": applied_at["parsed"],
        "released_at": released_at["formatted"],
        "parsed_released_at": released_at["parsed"],
    }


def _firewall_historically_applied(
    row: Mapping[str, Any],
    *,
    attack_started_at: datetime,
    observation_deadline_at: datetime,
) -> bool:
    applied_at = row.get("parsed_applied_at")
    if applied_at is None:
        return False
    if applied_at < attack_started_at or applied_at > observation_deadline_at:
        return False
    released_at = row.get("parsed_released_at")
    if released_at is not None and released_at < applied_at:
        return False
    return row.get("status") in {"APPLIED", "REMOVED"}


def _evaluate_block(
    scenario_result: Mapping[str, Any],
    firewall: Mapping[str, Any],
) -> dict[str, Any]:
    block_confirmed = scenario_result.get("block_confirmed")
    block_confirmed_at = _parse_external_observation(
        scenario_result.get("block_confirmed_at"),
        "block_confirmed_at",
    )
    block_confirmed_is_bool = isinstance(block_confirmed, bool)
    confirmed_success = (
        block_confirmed is True
        and block_confirmed_at["parsed"] is not None
        and block_confirmed_at["error"] is None
    )
    if not block_confirmed_is_bool:
        reason = "BLOCK_CONFIRMATION_INVALID_TYPE"
    elif block_confirmed is True and not confirmed_success:
        reason = "BLOCK_CONFIRMATION_TIMESTAMP_INVALID"
    else:
        reason = None
    return {
        "block_confirmed": block_confirmed if block_confirmed_is_bool else None,
        "block_confirmed_at": block_confirmed_at["formatted"],
        "block_confirmed_at_parse_error": block_confirmed_at["error"],
        "db_rule_and_external_confirmation_linked": (
            bool(firewall["firewall_rule_ids"]) and confirmed_success
        ),
        "confirmed_success": confirmed_success,
        "evaluable": block_confirmed_is_bool and (
            block_confirmed is False or confirmed_success
        ),
        "reason": reason,
    }


def _stage_statuses(
    manifest: RunManifest,
    scenario_result: Mapping[str, Any],
    detection: Mapping[str, Any],
    trust: Mapping[str, Any],
    firewall: Mapping[str, Any],
    block: Mapping[str, Any],
) -> tuple[dict[str, str], list[dict[str, str]]]:
    in_scope = _scope_stage_names(manifest.evaluation_scope)
    statuses = {
        "scenario_status": _scenario_status(scenario_result),
        "detection_status": ManifestStatus.NOT_APPLICABLE.value,
        "trust_status": ManifestStatus.NOT_APPLICABLE.value,
        "firewall_status": ManifestStatus.NOT_APPLICABLE.value,
        "block_status": ManifestStatus.NOT_APPLICABLE.value,
        "data_status": ManifestStatus.NOT_APPLICABLE.value,
        "final_status": ManifestStatus.SUCCESS.value,
    }
    failure_reasons: list[dict[str, str]] = []

    if statuses["scenario_status"] != ManifestStatus.SUCCESS.value:
        failure_reasons.append(
            {
                "stage": "scenario",
                "code": "SCENARIO_RESULT_NOT_SUCCESS",
                "message": str(
                    scenario_result.get("scenario_failure_reason")
                    or scenario_result.get("scenario_status")
                    or "scenario result is missing or not successful"
                ),
            }
        )

    if "data" in in_scope:
        capture_eligible = scenario_result.get("capture_eligible")
        if capture_eligible is True:
            statuses["data_status"] = ManifestStatus.SUCCESS.value
        elif capture_eligible is False:
            statuses["data_status"] = ManifestStatus.CAPTURE_INELIGIBLE.value
            failure_reasons.append(
                {
                    "stage": "data",
                    "code": "CAPTURE_INELIGIBLE",
                    "message": str(
                        scenario_result.get("capture_exclusion_reason")
                        or "capture is not eligible"
                    ),
                }
            )
        else:
            statuses["data_status"] = ManifestStatus.HOLD.value
            failure_reasons.append(
                {
                    "stage": "data",
                    "code": "CAPTURE_ELIGIBLE_MISSING_OR_INVALID",
                    "message": "scenario_result.capture_eligible must be boolean",
                }
            )

    expected = manifest.expected_outcome
    if "detection" in in_scope:
        statuses["detection_status"] = _expected_bool_status(
            expected.detection_expected,
            bool(detection["matched_expected_event"]),
            bool(detection["matched_detection_event_ids"]),
        )
        if statuses["detection_status"] == ManifestStatus.FAILED.value:
            failure_reasons.append(
                {
                    "stage": "detection",
                    "code": "DETECTION_EXPECTATION_MISMATCH",
                    "message": "detection result did not match expected outcome",
                }
            )

    if "trust" in in_scope:
        trust_changed = (
            bool(trust["trust_score_history_ids"])
            and trust["total_score_delta"] != 0
        )
        statuses["trust_status"] = _expected_bool_status(
            expected.trust_score_change_expected,
            trust_changed,
            trust_changed,
        )
        if statuses["trust_status"] == ManifestStatus.FAILED.value:
            failure_reasons.append(
                {
                    "stage": "trust",
                    "code": "TRUST_EXPECTATION_MISMATCH",
                    "message": "trust score change did not match expected outcome",
                }
            )

    if "firewall" in in_scope:
        firewall_applied = bool(firewall["rule_applied"])
        statuses["firewall_status"] = _expected_bool_status(
            expected.firewall_expected,
            firewall_applied,
            bool(firewall["firewall_rule_ids"]),
        )
        if statuses["firewall_status"] == ManifestStatus.FAILED.value:
            failure_reasons.append(
                {
                    "stage": "firewall",
                    "code": "FIREWALL_EXPECTATION_MISMATCH",
                    "message": "firewall rule state did not match expected outcome",
                }
            )

    if "block" in in_scope:
        if expected.block_expected:
            statuses["block_status"] = (
                ManifestStatus.SUCCESS.value
                if block["confirmed_success"] is True
                else ManifestStatus.FAILED.value
            )
        else:
            statuses["block_status"] = _expected_bool_status(
                False,
                False,
                block["block_confirmed"] is True,
            )
        if statuses["block_status"] == ManifestStatus.FAILED.value:
            failure_reasons.append(
                {
                    "stage": "block",
                    "code": "BLOCK_EXPECTATION_MISMATCH",
                    "message": "external block confirmation did not match expected outcome",
                }
            )

    applicable_statuses = [
        value
        for key, value in statuses.items()
        if key != "final_status" and value != ManifestStatus.NOT_APPLICABLE.value
    ]
    if statuses["data_status"] == ManifestStatus.CAPTURE_INELIGIBLE.value:
        statuses["final_status"] = ManifestStatus.CAPTURE_INELIGIBLE.value
    elif ManifestStatus.ENVIRONMENT_ERROR.value in applicable_statuses:
        statuses["final_status"] = ManifestStatus.ENVIRONMENT_ERROR.value
    elif ManifestStatus.HOLD.value in applicable_statuses:
        statuses["final_status"] = ManifestStatus.HOLD.value
    elif ManifestStatus.NOT_EVALUATED.value in applicable_statuses:
        statuses["final_status"] = ManifestStatus.NOT_EVALUATED.value
    elif ManifestStatus.FAILED.value in applicable_statuses:
        statuses["final_status"] = ManifestStatus.FAILED.value
    else:
        statuses["final_status"] = ManifestStatus.SUCCESS.value
    return statuses, failure_reasons


def _scenario_status(scenario_result: Mapping[str, Any]) -> str:
    if not scenario_result:
        return ManifestStatus.NOT_EVALUATED.value
    raw_status = scenario_result.get("scenario_status")
    if raw_status is None:
        return ManifestStatus.NOT_EVALUATED.value
    try:
        return ManifestStatus(raw_status).value
    except ValueError:
        return ManifestStatus.HOLD.value


def _scope_stage_names(scope: EvaluationScope) -> set[str]:
    if scope == EvaluationScope.FULL_E2E:
        return {"data", "detection", "trust", "firewall", "block"}
    if scope == EvaluationScope.DETECTION_ONLY:
        return {"data", "detection"}
    if scope == EvaluationScope.TRUST_ONLY:
        return {"data", "trust"}
    if scope == EvaluationScope.FIREWALL_ONLY:
        return {"data", "firewall"}
    if scope == EvaluationScope.BLOCK_ONLY:
        return {"data", "block"}
    if scope == EvaluationScope.DATA_ONLY:
        return {"data"}
    return {"data"}


def _expected_bool_status(
    expected: bool,
    matched_expected: bool,
    any_actual: bool,
) -> str:
    if expected:
        return ManifestStatus.SUCCESS.value if matched_expected else ManifestStatus.FAILED.value
    return ManifestStatus.FAILED.value if any_actual else ManifestStatus.SUCCESS.value


def _classification(
    manifest: RunManifest,
    detection: Mapping[str, Any],
    *,
    valid_run: bool,
) -> dict[str, bool | str]:
    if not valid_run:
        return {
            "tp": False,
            "fp": False,
            "tn": False,
            "fn": False,
            "basis": "excluded_from_official_metrics",
        }
    expected_detection = manifest.expected_outcome.detection_expected
    matched_expected = bool(detection["matched_expected_event"])
    any_detection = bool(detection["matched_detection_event_ids"])
    return {
        "tp": expected_detection and matched_expected,
        "fp": not expected_detection and any_detection,
        "tn": not expected_detection and not any_detection,
        "fn": expected_detection and not matched_expected,
        "basis": "expected_event_types",
    }


def _build_latencies(
    manifest: RunManifest,
    detection: Mapping[str, Any],
    trust: Mapping[str, Any],
    firewall: Mapping[str, Any],
    block: Mapping[str, Any],
    scenario_result: Mapping[str, Any],
    *,
    attack_started_at: datetime,
) -> list[dict[str, Any]]:
    detection_ts = _parse_result_timestamp(detection["first_detection_timestamp"])
    trust_ts = _parse_result_timestamp(trust["first_trust_history_created_at"])
    firewall_created_ts = _parse_result_timestamp(firewall["first_firewall_created_at"])
    firewall_applied_ts = _parse_result_timestamp(firewall["first_firewall_applied_at"])
    block_ts = _parse_result_timestamp(block["block_confirmed_at"])
    detection_observed = _parse_external_observation(
        scenario_result.get("detection_observed_at"),
        "detection_observed_at",
    )
    trust_observed = _parse_external_observation(
        scenario_result.get("trust_observed_at"),
        "trust_observed_at",
    )

    return [
        _latency(
            "detection_processing_latency",
            "internal_processing",
            attack_started_at,
            detection_ts,
            "manifest.attack_started_at",
            "detection_events.detected_at",
        ),
        _latency(
            "trust_processing_latency",
            "internal_processing",
            detection_ts,
            trust_ts,
            "detection_events.detected_at",
            "trust_score_history.created_at",
        ),
        _latency(
            "firewall_creation_latency",
            "internal_processing",
            detection_ts if firewall["trigger_event_ids"] else None,
            firewall_created_ts,
            "firewall_rules.trigger_event_id detection_events.detected_at",
            "firewall_rules.created_at",
        ),
        _latency(
            "firewall_apply_latency",
            "internal_processing",
            firewall_created_ts,
            firewall_applied_ts,
            "firewall_rules.created_at",
            "firewall_rules.applied_at",
        ),
        _latency(
            "block_e2e_latency",
            "external_confirmation",
            attack_started_at,
            block_ts,
            "manifest.attack_started_at",
            "scenario_result.block_confirmed_at",
        ),
        _latency(
            "detection_observation_delay",
            "external_observation_delay",
            detection_ts,
            detection_observed["parsed"],
            "detection_events.detected_at",
            "scenario_result.detection_observed_at",
        ),
        _latency(
            "trust_observation_delay",
            "external_observation_delay",
            trust_ts,
            trust_observed["parsed"],
            "trust_score_history.created_at",
            "scenario_result.trust_observed_at",
        ),
        _latency(
            "block_observation_delay",
            "external_observation_delay",
            firewall_applied_ts,
            block_ts,
            "firewall_rules.applied_at",
            "scenario_result.block_confirmed_at",
        ),
    ]


def _latency(
    name: str,
    category: str,
    start: datetime | None,
    end: datetime | None,
    start_basis: str,
    end_basis: str,
) -> dict[str, Any]:
    if start is None:
        return {
            "name": name,
            "category": category,
            "start_timestamp": None,
            "end_timestamp": _format_timestamp(end),
            "milliseconds": None,
            "calculable": False,
            "reason": "START_TIMESTAMP_MISSING",
            "start_basis": start_basis,
            "end_basis": end_basis,
        }
    if end is None:
        return {
            "name": name,
            "category": category,
            "start_timestamp": _format_timestamp(start),
            "end_timestamp": None,
            "milliseconds": None,
            "calculable": False,
            "reason": "END_TIMESTAMP_MISSING",
            "start_basis": start_basis,
            "end_basis": end_basis,
        }
    milliseconds = (end - start).total_seconds() * 1000.0
    if milliseconds < 0:
        return {
            "name": name,
            "category": category,
            "start_timestamp": _format_timestamp(start),
            "end_timestamp": _format_timestamp(end),
            "milliseconds": None,
            "calculable": False,
            "reason": "TIMESTAMP_ORDER_ERROR",
            "start_basis": start_basis,
            "end_basis": end_basis,
        }
    return {
        "name": name,
        "category": category,
        "start_timestamp": _format_timestamp(start),
        "end_timestamp": _format_timestamp(end),
        "milliseconds": milliseconds,
        "calculable": True,
        "reason": None,
        "start_basis": start_basis,
        "end_basis": end_basis,
    }


def _environment_error_row(
    manifest: RunManifest,
    *,
    evaluation_schema_version: str,
    source_commit: str,
    reason_code: str,
    reason: str,
    scenario_result: Mapping[str, Any],
) -> dict[str, Any]:
    input_digests = _input_digests(scenario_result)
    statuses = {
        "scenario_status": ManifestStatus.ENVIRONMENT_ERROR.value,
        "detection_status": ManifestStatus.ENVIRONMENT_ERROR.value,
        "trust_status": ManifestStatus.ENVIRONMENT_ERROR.value,
        "firewall_status": ManifestStatus.ENVIRONMENT_ERROR.value,
        "block_status": ManifestStatus.ENVIRONMENT_ERROR.value,
        "data_status": ManifestStatus.ENVIRONMENT_ERROR.value,
        "final_status": ManifestStatus.ENVIRONMENT_ERROR.value,
    }
    return {
        "evaluation_schema_version": evaluation_schema_version,
        "source_commit": source_commit,
        "source_commit_verification": _source_commit_verification(),
        "run_manifest_schema_version": manifest.run_manifest_schema_version,
        "evaluation_identity": evaluation_identity(
            manifest,
            evaluation_schema_version,
            source_commit=source_commit,
            manifest_sha256=input_digests.get("manifest_sha256"),
            scenario_result_sha256=input_digests.get("scenario_result_sha256"),
            db_snapshot_sha256=input_digests.get("db_snapshot_sha256"),
        ),
        "input_digests": input_digests,
        "run_id": manifest.run_id,
        "session_id": manifest.session_id,
        "scenario": manifest.scenario.to_dict(),
        "target_device_id": manifest.target_device_id,
        "source_ip": manifest.source_ip,
        "evaluation_scope": manifest.evaluation_scope.value,
        "evaluation_unit": _evaluation_unit(manifest, scenario_result),
        "valid_run": False,
        "success_denominator_included": False,
        "matching": {
            "strategy": [],
            "available_identifiers": _available_identifiers(manifest),
            "missing_identifiers": ["database"],
            "candidate_row_count": None,
            "matched_row_count": None,
            "ambiguous_candidate_exists": False,
            "excluded_candidate_reasons": {},
        },
        "expected_outcome": manifest.expected_outcome.to_dict(),
        "matched_ids": {
            "detection_event_ids": None,
            "trust_score_history_ids": None,
            "firewall_rule_ids": None,
            "trigger_event_ids": None,
        },
        "statuses": statuses,
        "scenario_status": statuses["scenario_status"],
        "detection_status": statuses["detection_status"],
        "trust_status": statuses["trust_status"],
        "firewall_status": statuses["firewall_status"],
        "block_status": statuses["block_status"],
        "data_status": statuses["data_status"],
        "final_status": statuses["final_status"],
        "failure_reasons": [
            {
                "stage": "data",
                "code": reason_code,
                "message": reason,
            }
        ],
        "detection": {
            "query_available": False,
            "evaluable": False,
            "reason": reason_code,
            "matched_detection_event_ids": None,
        },
        "trust": {
            "query_available": False,
            "evaluable": False,
            "reason": reason_code,
            "trust_score_history_ids": None,
        },
        "firewall": {
            "query_available": False,
            "evaluable": False,
            "reason": reason_code,
            "firewall_rule_ids": None,
            "trigger_event_ids": None,
        },
        "block": {
            "block_confirmed": None,
            "block_confirmed_at": None,
            "confirmed_success": False,
            "evaluable": False,
            "reason": reason_code,
        },
        "db_timestamps": {
            "detection_events.detected_at": None,
            "trust_score_history.created_at": None,
            "firewall_rules.created_at": None,
            "firewall_rules.applied_at": None,
        },
        "external_observations": _external_observations(manifest, scenario_result),
        "latencies": [],
        "classification": {
            "tp": False,
            "fp": False,
            "tn": False,
            "fn": False,
            "basis": "not_evaluable",
        },
        "artifacts": [artifact.to_dict() for artifact in manifest.artifacts],
        "session_manifest_ref": _manifest_ref_payload(manifest),
    }


def _parse_db_timestamp(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {"parsed": None, "formatted": None, "error": "TIMESTAMP_MISSING"}
    try:
        parsed = parse_db_utc(value, field_name).astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        return {"parsed": None, "formatted": None, "error": str(exc), "raw": value}
    return {"parsed": parsed, "formatted": _format_timestamp(parsed), "error": None, "raw": value}


def _parse_external_observation(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {"parsed": None, "formatted": None, "error": "TIMESTAMP_MISSING"}
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            return {"parsed": None, "formatted": None, "error": str(exc), "raw": value}
    else:
        return {
            "parsed": None,
            "formatted": None,
            "error": f"{field_name} must be a timestamp",
            "raw": value,
        }
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return {
            "parsed": None,
            "formatted": None,
            "error": f"{field_name} must be timezone-aware UTC",
            "raw": value,
        }
    if parsed.utcoffset().total_seconds() != 0:
        return {
            "parsed": None,
            "formatted": None,
            "error": f"{field_name} must use UTC offset",
            "raw": value,
        }
    parsed = parsed.astimezone(timezone.utc)
    return {"parsed": parsed, "formatted": _format_timestamp(parsed), "error": None, "raw": value}


def _parse_result_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    return _parse_external_observation(value, "result_timestamp")["parsed"]


def _format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    value = value.astimezone(timezone.utc)
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _parse_id_json(value: Any) -> list[int]:
    if value is None:
        return []
    try:
        raw = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    if not isinstance(raw, list):
        return []
    ids: list[int] = []
    for item in raw:
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            ids.append(item)
    return sorted(set(ids))


def _has_expected_detector(expected_event_types: set[str], detector_type: str) -> bool:
    if detector_type == "AI":
        return any("AI" in event_type for event_type in expected_event_types)
    return bool(expected_event_types) and not all(
        "AI" in event_type for event_type in expected_event_types
    )


def _public_detection_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": event["id"],
        "device_id": event["device_id"],
        "event_type": event["event_type"],
        "detector_type": event["detector_type"],
        "severity": event["severity"],
        "score_delta": event["score_delta"],
        "applied_to_score": event["applied_to_score"],
        "detected_at": event["detected_at"],
        "subject_ip": event["subject_ip"],
        "event_source_ip": event["event_source_ip"],
        "packet_session_id": event["packet_session_id"],
        "matching_strategy": event["matching_strategy"],
    }


def _public_trust_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "analysis_window_start": row["analysis_window_start"],
        "analysis_window_end": row["analysis_window_end"],
        "previous_score": row["previous_score"],
        "actual_delta": row["actual_delta"],
        "new_score": row["new_score"],
        "representative_event_ids": row["representative_event_ids"],
        "created_at": row["created_at"],
    }


def _public_firewall_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "source_ip": row["source_ip"],
        "status": row["status"],
        "trigger_event_id": row["trigger_event_id"],
        "created_at": row["created_at"],
        "applied_at": row["applied_at"],
        "released_at": row["released_at"],
        "matching_strategy": row["matching_strategy"],
    }


def _select_device_status(conn: sqlite3.Connection, device_id: str | None) -> str | None:
    if device_id is None:
        return None
    row = conn.execute(
        "SELECT status FROM devices WHERE device_id = :device_id",
        {"device_id": device_id},
    ).fetchone()
    return None if row is None else str(row["status"])


def _firewall_external_link_status(rows: Sequence[Mapping[str, Any]]) -> str:
    if not rows:
        return "RULE_NOT_CREATED"
    if any(row["trigger_event_id"] is not None for row in rows):
        return "LINKED_BY_TRIGGER_EVENT_ID"
    return "NO_DIRECT_TRIGGER_LINK"


def _external_observations(
    manifest: RunManifest,
    scenario_result: Mapping[str, Any],
) -> dict[str, Any]:
    observations = {
        name: _format_timestamp(value)
        for name, value in manifest.external_observations.items()
    }
    for field_name in (
        "detection_observed_at",
        "trust_observed_at",
        "block_confirmed_at",
    ):
        parsed = _parse_external_observation(scenario_result.get(field_name), field_name)
        observations[field_name] = parsed["formatted"]
        if parsed["error"] is not None and scenario_result.get(field_name) is not None:
            observations[f"{field_name}_error"] = parsed["error"]
    return dict(sorted(observations.items()))


def _input_digests(scenario_result: Mapping[str, Any]) -> dict[str, str | None]:
    return {
        "manifest_sha256": _optional_meta_digest(
            scenario_result,
            "_manifest_sha256",
        ),
        "scenario_result_sha256": _optional_meta_digest(
            scenario_result,
            "_scenario_result_sha256",
        ),
        "db_snapshot_sha256": _optional_meta_digest(
            scenario_result,
            "_db_snapshot_sha256",
        ),
    }


def _optional_meta_digest(
    scenario_result: Mapping[str, Any],
    key: str,
) -> str | None:
    value = scenario_result.get(key)
    return value if isinstance(value, str) and value else None


def _source_commit_verification() -> dict[str, bool | str]:
    return {
        "method": "explicit_cli_arg",
        "head_verified": False,
        "dirty_worktree_verified": False,
    }


def _identity_part(value: str | None) -> str:
    return "null" if value is None else str(value)


def _manifest_ref_payload(manifest: RunManifest) -> dict[str, str] | None:
    if manifest.session_manifest_ref is None:
        return None
    return manifest.session_manifest_ref.to_dict()


def _evaluation_unit(
    manifest: RunManifest,
    scenario_result: Mapping[str, Any],
) -> str:
    if isinstance(scenario_result.get("evaluation_unit"), str):
        return str(scenario_result["evaluation_unit"])
    if str(scenario_result.get("traffic_label", "")).lower() == "normal":
        return "normal_run"
    if str(scenario_result.get("traffic_label", "")).lower() == "attack":
        return "attack_session"
    return (
        "attack_session"
        if manifest.expected_outcome.detection_expected
        else "normal_run"
    )


def _available_identifiers(manifest: RunManifest) -> list[str]:
    identifiers = []
    if manifest.session_id:
        identifiers.append("session_id")
    if manifest.target_device_id:
        identifiers.append("target_device_id")
    if manifest.source_ip:
        identifiers.append("source_ip")
    if manifest.attack_started_at or manifest.started_at:
        identifiers.append("attack_started_at")
    if manifest.observation_deadline_at:
        identifiers.append("observation_deadline_at")
    if manifest.expected_outcome.expected_event_types:
        identifiers.append("expected_event_types")
    return identifiers


def _validate_scenario_result_identity(
    manifest: RunManifest,
    scenario_result: Mapping[str, Any],
) -> None:
    if not scenario_result:
        return
    checks = {
        "run_id": manifest.run_id,
        "session_id": manifest.session_id,
        "scenario_id": manifest.scenario.scenario_id,
    }
    for key, expected in checks.items():
        actual = scenario_result.get(key)
        if actual is not None and actual != expected:
            raise Phase5EvaluationError(
                f"scenario result {key} mismatch: expected={expected!r}, actual={actual!r}"
            )


def _min_timestamp(values: Sequence[str | None]) -> str | None:
    parsed_values = [
        parsed
        for value in values
        if (parsed := _parse_result_timestamp(value)) is not None
    ]
    if not parsed_values:
        return None
    return _format_timestamp(min(parsed_values))


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _f1(tp: int, fp: int, fn: int) -> float | None:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _latency_stats(values: Sequence[float]) -> dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "min": None,
            "median": None,
            "p95": None,
            "max": None,
            "reason": LATENCY_NO_SAMPLES_REASON,
        }
    sorted_values = sorted(values)
    count = len(sorted_values)
    midpoint = count // 2
    if count % 2:
        median = sorted_values[midpoint]
    else:
        median = (sorted_values[midpoint - 1] + sorted_values[midpoint]) / 2
    return {
        "count": count,
        "min": sorted_values[0],
        "median": median,
        "p95": _nearest_rank(sorted_values, 0.95),
        "max": sorted_values[-1],
        "reason": None,
    }


def _nearest_rank(sorted_values: Sequence[float], percentile: float) -> float:
    if not sorted_values:
        raise ValueError("sorted_values must not be empty")
    rank = max(1, int((len(sorted_values) * percentile + 0.999999999)))
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]


def _packet_rule_candidate_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counter: Counter[str] = Counter()
    for row in rows:
        for event_type in row.get("detection", {}).get("actual_event_types", []):
            if str(event_type).startswith("PACKET") or event_type in {
                "PORT_SCAN",
                "BROKER_DOS_SUSPECTED",
                "NON_MQTT_TRAFFIC",
            }:
                counter[str(event_type)] += 1
    return {
        "basis": "event_type_run_count_not_candidate_fpr",
        "counts": dict(sorted(counter.items())),
    }


def _require_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Phase5EvaluationError(f"{field_name} must be a non-empty string")
    return value.strip()
