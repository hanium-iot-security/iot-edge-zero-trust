"""Phase 4 Trust Score v2 transaction service."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.config import settings
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import (
    WINDOW_SECONDS,
    format_db_utc,
    floor_window_start,
    parse_db_utc,
    require_utc_window_boundary,
)
from edge.policy.repository import load_policy_resolver
from edge.policy.resolver import POLICY_AVAILABLE
from edge.trust import firewall_repository
from edge.trust.trust_policy import (
    AI_ANOMALY,
    AI_PACKET_ANOMALY,
    ISOLATED_STATUS,
    UNKNOWN_DEVICE,
    apply_score_delta,
    has_event_policy,
    incident_family_for_event,
    score_delta_for_event,
    status_for_trust_score,
)


TRUST_DETECTOR_NAME = "trust_score_v2"
TRUST_SOURCE_TABLE = "detection_events"
TRUST_POLICY_VERSION = "trust-score-v2"
ISOLATION_REASON = "Trust Score below threshold"
PROCESSING_APPLIED = "APPLIED_TO_TRUST"
PROCESSING_NOT_REPRESENTATIVE = "NOT_REPRESENTATIVE"
PROCESSING_ALREADY_ISOLATED = "ALREADY_ISOLATED"
PROCESSING_UNMAPPED_DEVICE = "UNMAPPED_DEVICE"
PROCESSING_UNMAPPED_EVENT_TYPE = "UNMAPPED_EVENT_TYPE"
PROCESSING_LATE_EVENT = "LATE_EVENT"
PROCESSING_LEGACY_MIGRATION = "LEGACY_MIGRATION"
PROCESSING_INVALID_INCIDENT_FAMILY = "INVALID_INCIDENT_FAMILY"
PROCESSING_NO_SCORE_EVENT = "NO_SCORE_EVENT"
PROCESSING_AI_OBSERVATION = "AI_OBSERVATION_ONLY"
AI_OBSERVATION_POLICY_VERSION = "trust-ai-observation-v1"
AI_EVENT_TYPES = frozenset((AI_ANOMALY, AI_PACKET_ANOMALY))
PROCESSING_PENDING_AT_WINDOW = "PENDING_AT_WINDOW"
PROCESSING_DISABLED_AT_WINDOW = "DISABLED_AT_WINDOW"
AI_WINDOW_CAP = -15
WINDOW_DELTA_CAP = -30
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class TrustScoreV2Change:
    device_id: str
    analysis_window_start: datetime
    analysis_window_end: datetime
    previous_score: int
    calculated_delta: int
    capped_delta: int
    actual_delta: int
    new_score: int
    representative_event_ids: list[int]
    trust_score_history_id: int | None
    isolation_history_id: int | None
    firewall_rule_id: int | None


@dataclass(frozen=True)
class TrustScoreV2RunResult:
    cutoff: datetime
    selected_event_count: int
    processed_event_count: int
    created_history_count: int
    created_isolation_count: int
    created_firewall_rule_count: int
    last_processed_id_before: int | None
    last_processed_id_after: int | None
    completed_window_end_before: datetime | None
    completed_window_end_after: datetime
    changes: list[TrustScoreV2Change] = field(default_factory=list)
    observed_ai_event_count: int = 0


def resolve_ai_mode(ai_mode: str | None = None) -> str:
    mode = settings.trust_ai_mode if ai_mode is None else ai_mode
    if mode not in ("enforce", "observe"):
        raise ValueError("trust_ai_mode must be 'enforce' or 'observe'")
    return mode


def apply_trust_score_v2_until(
    db: Session,
    *,
    cycle_range_start: datetime,
    cycle_cutoff: datetime,
    ai_mode: str | None = None,
    decision_at: datetime | None = None,
) -> TrustScoreV2RunResult:
    # Resolve once for the transaction, including direct service callers.
    mode = resolve_ai_mode(ai_mode)
    range_start = require_utc_window_boundary(cycle_range_start, "cycle_range_start")
    cutoff = require_utc_window_boundary(cycle_cutoff, "cycle_cutoff")
    if range_start >= cutoff:
        raise ValueError("cycle_range_start must be before cycle_cutoff")
    _ensure_sqlite_immediate_transaction(db)
    resolver = load_policy_resolver(db)
    response_time = decision_at or datetime.now(timezone.utc)
    checkpoint = checkpoints.get_detector_checkpoint(
        db,
        detector_name=TRUST_DETECTOR_NAME,
        source_table=TRUST_SOURCE_TABLE,
    )
    last_processed_before = (
        int(checkpoint["last_processed_id"])
        if checkpoint is not None and checkpoint["last_processed_id"] is not None
        else None
    )
    completed_before = (
        parse_db_utc(
            checkpoint["last_completed_window_end"],
            "last_completed_window_end",
        )
        if checkpoint is not None and checkpoint["last_completed_window_end"] is not None
        else None
    )
    if completed_before is not None and completed_before > cutoff:
        raise ValueError("existing Trust checkpoint exceeds cycle_cutoff")

    events = _fetch_candidate_events(
        db,
        cutoff=cutoff,
    )
    last_processed_after = last_processed_before
    for event in events:
        last_processed_after = _max_optional_id(last_processed_after, int(event["id"]))

    current_events: list[dict[str, Any]] = []
    changes: list[TrustScoreV2Change] = []
    processed_event_count = 0
    created_history_count = 0
    created_isolation_count = 0
    created_firewall_rule_count = 0
    observed_ai_event_count = 0

    for event in events:
        if _is_before_current_cycle(event, range_start):
            reason = _past_event_processing_reason(event, range_start)
            if resolver is not None and event.get("device_id"):
                window_start, _ = _event_window(event)
                resolution = resolver.resolve(str(event["device_id"]), window_start)
                registration = resolution.registration
                if registration is not None and registration.status == "PENDING":
                    reason = PROCESSING_PENDING_AT_WINDOW
                elif registration is not None and registration.status == "DISABLED":
                    reason = PROCESSING_DISABLED_AT_WINDOW
                elif resolution.reason != POLICY_AVAILABLE:
                    reason = resolution.reason
                else:
                    current_exclusion = resolver.automatic_response_exclusion(
                        str(event["device_id"]), response_time
                    )
                    if current_exclusion is not None:
                        reason = current_exclusion
            _mark_events(
                db,
                [event],
                reason,
                cutoff,
                [],
            )
            processed_event_count += 1
            continue
        current_events.append(event)

    for group in _group_events(current_events):
        processed_event_count += len(group)
        device_id = group[0]["device_id"]
        if not device_id:
            _mark_events(db, group, PROCESSING_UNMAPPED_DEVICE, cutoff, [])
            continue

        device = _fetch_device(db, str(device_id))
        if device is None:
            _mark_events(db, group, PROCESSING_UNMAPPED_DEVICE, cutoff, [])
            continue
        if resolver is not None:
            window_start, _ = _group_window(group)
            resolution = resolver.resolve(str(device_id), window_start)
            registration_status = (
                resolution.registration.status
                if resolution.registration is not None else None
            )
            if registration_status in {"PENDING", "DISABLED"}:
                reason = (
                    PROCESSING_PENDING_AT_WINDOW
                    if registration_status == "PENDING"
                    else PROCESSING_DISABLED_AT_WINDOW
                )
                _mark_events(db, group, reason, cutoff, [])
                continue
            if resolution.reason != POLICY_AVAILABLE:
                _mark_events(db, group, resolution.reason, cutoff, [])
                continue
            exclusion = resolver.automatic_response_exclusion(
                str(device_id), response_time
            )
            if exclusion is not None:
                _mark_events(db, group, exclusion, cutoff, [])
                continue
        if device["status"] == ISOLATED_STATUS:
            _mark_events(db, group, PROCESSING_ALREADY_ISOLATED, cutoff, [])
            continue

        invalid_type_events, invalid_family_events, valid_group = _partition_policy_events(
            group
        )
        if invalid_type_events:
            _mark_events(
                db,
                invalid_type_events,
                PROCESSING_UNMAPPED_EVENT_TYPE,
                cutoff,
                [],
            )
        if invalid_family_events:
            _mark_events(
                db,
                invalid_family_events,
                PROCESSING_INVALID_INCIDENT_FAMILY,
                cutoff,
                [],
            )
        if not valid_group:
            continue

        if mode == "observe":
            observed = [
                event for event in valid_group
                if event["detector_type"] == "AI" and event["event_type"] in AI_EVENT_TYPES
            ]
            for event in observed:
                _record_ai_observation(db, event, cutoff)
            observed_ai_event_count += len(observed)
            observed_ids = {event["id"] for event in observed}
            valid_group = [event for event in valid_group if event["id"] not in observed_ids]
            if not valid_group:
                continue

        selected = _select_representative_events(valid_group)
        if not selected:
            _mark_events(db, valid_group, PROCESSING_NO_SCORE_EVENT, cutoff, [])
            continue

        previous_score = int(device["trust_score"])
        calculated_delta = sum(event["effective_delta"] for event in selected)
        capped_delta = max(calculated_delta, WINDOW_DELTA_CAP)
        new_score = apply_score_delta(previous_score, capped_delta)
        actual_delta = new_score - previous_score
        new_status = status_for_trust_score(new_score)
        representative_ids = [int(event["id"]) for event in selected]
        window_start, window_end = _group_window(valid_group)

        db.execute(
            text(
                """
                UPDATE devices
                SET trust_score = :trust_score,
                    status = :status
                WHERE device_id = :device_id
                """
            ),
            {
                "trust_score": new_score,
                "status": new_status,
                "device_id": device_id,
            },
        )
        history_id = _insert_trust_history(
            db,
            device_id=str(device_id),
            analysis_window_start=window_start,
            analysis_window_end=window_end,
            previous_score=previous_score,
            calculated_delta=calculated_delta,
            capped_delta=capped_delta,
            actual_delta=actual_delta,
            new_score=new_score,
            representative_event_ids=representative_ids,
        )
        created_history_count += 1
        _mark_events(db, valid_group, PROCESSING_APPLIED, cutoff, representative_ids)

        isolation_history_id: int | None = None
        firewall_rule_id: int | None = None
        if new_score < 30 and device["status"] != ISOLATED_STATUS:
            source_ip = device["ip_address"]
            if not source_ip:
                raise ValueError(f"device has no firewall source IP: {device_id}")
            isolation_history_id = _insert_isolation_history(
                db,
                device_id=str(device_id),
                trust_score=new_score,
                trigger_event_id=representative_ids[0],
                trust_score_history_id=history_id,
            )
            created_isolation_count += 1
            firewall_rule_id = firewall_repository.create_pending_rule_for_device(
                db,
                device_id=str(device_id),
                source_ip=str(source_ip),
                reason=ISOLATION_REASON,
                trigger_event_id=representative_ids[0],
            )
            created_firewall_rule_count += 1

        changes.append(
            TrustScoreV2Change(
                device_id=str(device_id),
                analysis_window_start=window_start,
                analysis_window_end=window_end,
                previous_score=previous_score,
                calculated_delta=calculated_delta,
                capped_delta=capped_delta,
                actual_delta=actual_delta,
                new_score=new_score,
                representative_event_ids=representative_ids,
                trust_score_history_id=history_id,
                isolation_history_id=isolation_history_id,
                firewall_rule_id=firewall_rule_id,
            )
        )

    checkpoints.upsert_detector_checkpoint(
        db,
        detector_name=TRUST_DETECTOR_NAME,
        source_table=TRUST_SOURCE_TABLE,
        last_processed_id=last_processed_after,
        last_completed_window_end=cutoff,
        updated_at=cutoff,
    )

    return TrustScoreV2RunResult(
        cutoff=cutoff,
        selected_event_count=len(events),
        processed_event_count=processed_event_count,
        created_history_count=created_history_count,
        created_isolation_count=created_isolation_count,
        created_firewall_rule_count=created_firewall_rule_count,
        last_processed_id_before=last_processed_before,
        last_processed_id_after=last_processed_after,
        completed_window_end_before=completed_before,
        completed_window_end_after=cutoff,
        changes=changes,
        observed_ai_event_count=observed_ai_event_count,
    )


def _record_ai_observation(db: Session, event: dict[str, Any], cutoff: datetime) -> None:
    """Complete an AI event without creating score/isolating side effects.

    Keep detector/model evidence and the original candidate penalty. The event's
    displayed delta is zero so existing consumers do not present a -15 penalty
    for an observation. Scoring policies and detector dedupe keys stay unchanged.
    """
    raw_evidence = event.get("evidence_json")
    try:
        evidence = json.loads(raw_evidence) if raw_evidence is not None else {}
    except (TypeError, ValueError):
        evidence = {"original_evidence": raw_evidence}
    if not isinstance(evidence, dict):
        evidence = {"original_evidence": raw_evidence}
    if "trust_decision" in evidence:
        evidence["original_trust_decision"] = evidence["trust_decision"]
    evidence["trust_decision"] = {
        "ai_mode": "observe",
        "policy_version": AI_OBSERVATION_POLICY_VERSION,
        "policy_score_delta": score_delta_for_event(str(event["event_type"])),
        "original_score_delta": event["score_delta"],
        "actual_delta": 0,
        "processed_at": format_db_utc(cutoff),
    }
    db.execute(
        text(
            """
            UPDATE detection_events
            SET processed_at = :processed_at,
                processing_reason = :reason,
                applied_to_score = 0,
                score_delta = 0,
                evidence_json = :evidence_json,
                evidence_schema_version = COALESCE(evidence_schema_version, 1)
            WHERE id = :id AND processed_at IS NULL
            """
        ),
        {
            "id": event["id"],
            "processed_at": format_db_utc(cutoff),
            "reason": PROCESSING_AI_OBSERVATION,
            "evidence_json": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
        },
    )


def _ensure_sqlite_immediate_transaction(db: Session) -> None:
    """Reserve the SQLite writer before reading registration or score state."""
    if db.get_bind().dialect.name != "sqlite":
        return
    connection = db.connection()
    raw_connection = connection.connection.driver_connection
    if not raw_connection.in_transaction:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        # The caller already began a physical transaction. Upgrade its lock
        # before any state read; a conflicting snapshot must fail and roll back.
        connection.exec_driver_sql("UPDATE devices SET trust_score = trust_score WHERE 0")


def _fetch_candidate_events(
    db: Session,
    *,
    cutoff: datetime,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT *
            FROM detection_events
            WHERE processed_at IS NULL
              AND (
                  (
                      analysis_window_end IS NOT NULL
                      AND unixepoch(analysis_window_end) <= unixepoch(:cutoff)
                  )
                  OR (
                      analysis_window_end IS NULL
                      AND (
                          detected_at IS NULL
                          OR unixepoch(detected_at) < unixepoch(:cutoff)
                      )
                  )
              )
            """
        ),
        {
            "cutoff": format_db_utc(cutoff),
        },
    ).mappings()
    events = [dict(row) for row in rows]
    return sorted(
        events,
        key=lambda event: (*_event_window(event), int(event["id"])),
    )


def _group_events(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    groups: dict[tuple[str | None, str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str | None, str, str]] = []
    for event in events:
        window_start, window_end = _event_window(event)
        key = (event["device_id"], format_db_utc(window_start), format_db_utc(window_end))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(event)
    return [groups[key] for key in order]


def _event_window(event: dict[str, Any]) -> tuple[datetime, datetime]:
    if event.get("analysis_window_start") and event.get("analysis_window_end"):
        return (
            parse_db_utc(event["analysis_window_start"], "analysis_window_start"),
            parse_db_utc(event["analysis_window_end"], "analysis_window_end"),
        )
    if event.get("detected_at"):
        window_start = floor_window_start(parse_db_utc(event["detected_at"], "detected_at"))
        return window_start, window_start + timedelta(seconds=WINDOW_SECONDS)
    raise ValueError("detection event must have analysis window or detected_at")


def _group_window(group: list[dict[str, Any]]) -> tuple[datetime, datetime]:
    return _event_window(group[0])


def _select_representative_events(group: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rule_by_family: dict[str, dict[str, Any]] = {}
    ai_events: list[dict[str, Any]] = []

    for event in group:
        event_type = str(event["event_type"])
        if event_type == UNKNOWN_DEVICE:
            continue
        delta = score_delta_for_event(event_type)
        if delta >= 0:
            continue
        candidate = dict(event)
        candidate["effective_delta"] = delta
        if event["detector_type"] == "AI":
            ai_events.append(candidate)
            continue
        family = str(incident_family_for_event(event_type))
        current = rule_by_family.get(family)
        if current is None or _representative_sort_key(candidate) < _representative_sort_key(
            current
        ):
            rule_by_family[family] = candidate

    selected = list(rule_by_family.values())
    if not selected and ai_events:
        ai_rep = min(ai_events, key=_representative_sort_key)
        ai_rep["effective_delta"] = max(int(ai_rep["effective_delta"]), AI_WINDOW_CAP)
        selected.append(ai_rep)
    selected.sort(key=lambda event: int(event["id"]))
    return selected


def _representative_sort_key(event: dict[str, Any]) -> tuple[int, int, datetime, int]:
    return (
        -abs(int(event["effective_delta"])),
        -SEVERITY_RANK.get(str(event.get("severity") or "").lower(), 0),
        _event_detected_at(event),
        int(event["id"]),
    )


def _event_detected_at(event: dict[str, Any]) -> datetime:
    if event.get("detected_at"):
        return parse_db_utc(event["detected_at"], "detected_at")
    return datetime.max.replace(tzinfo=timezone.utc)


def _is_before_current_cycle(event: dict[str, Any], range_start: datetime) -> bool:
    _, window_end = _event_window(event)
    return window_end <= range_start


def _past_event_processing_reason(
    event: dict[str, Any],
    _range_start: datetime,
) -> str:
    if (
        event.get("processing_reason") == PROCESSING_LEGACY_MIGRATION
        or event.get("event_type") == PROCESSING_LEGACY_MIGRATION
    ):
        return PROCESSING_LEGACY_MIGRATION
    return PROCESSING_LATE_EVENT


def _partition_policy_events(
    group: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    invalid_type_events: list[dict[str, Any]] = []
    invalid_family_events: list[dict[str, Any]] = []
    valid_events: list[dict[str, Any]] = []

    for event in group:
        event_type = str(event["event_type"])
        expected_family = incident_family_for_event(event_type)
        if not has_event_policy(event_type) or expected_family is None:
            invalid_type_events.append(event)
            continue
        stored_family = event.get("incident_family")
        if stored_family is not None and str(stored_family) != expected_family:
            invalid_family_events.append(event)
            continue
        normalized = dict(event)
        normalized["incident_family"] = expected_family
        valid_events.append(normalized)

    return invalid_type_events, invalid_family_events, valid_events


def _fetch_device(db: Session, device_id: str) -> dict[str, Any] | None:
    row = db.execute(
        text(
            """
            SELECT device_id, ip_address, trust_score, status
            FROM devices
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).mappings().one_or_none()
    return dict(row) if row is not None else None


def _insert_trust_history(
    db: Session,
    *,
    device_id: str,
    analysis_window_start: datetime,
    analysis_window_end: datetime,
    previous_score: int,
    calculated_delta: int,
    capped_delta: int,
    actual_delta: int,
    new_score: int,
    representative_event_ids: list[int],
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version
            )
            VALUES (
                :device_id,
                :analysis_window_start,
                :analysis_window_end,
                :previous_score,
                :calculated_delta,
                :capped_delta,
                :actual_delta,
                :new_score,
                :representative_event_ids_json,
                :policy_version
            )
            """
        ),
        {
            "device_id": device_id,
            "analysis_window_start": format_db_utc(analysis_window_start),
            "analysis_window_end": format_db_utc(analysis_window_end),
            "previous_score": previous_score,
            "calculated_delta": calculated_delta,
            "capped_delta": capped_delta,
            "actual_delta": actual_delta,
            "new_score": new_score,
            "representative_event_ids_json": json.dumps(representative_event_ids),
            "policy_version": TRUST_POLICY_VERSION,
        },
    )
    return int(result.lastrowid)


def _insert_isolation_history(
    db: Session,
    *,
    device_id: str,
    trust_score: int,
    trigger_event_id: int,
    trust_score_history_id: int,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO isolation_history (
                device_id,
                action,
                reason,
                trust_score,
                trigger_event_id,
                trust_score_history_id
            )
            VALUES (
                :device_id,
                'ISOLATED',
                :reason,
                :trust_score,
                :trigger_event_id,
                :trust_score_history_id
            )
            """
        ),
        {
            "device_id": device_id,
            "reason": ISOLATION_REASON,
            "trust_score": trust_score,
            "trigger_event_id": trigger_event_id,
            "trust_score_history_id": trust_score_history_id,
        },
    )
    return int(result.lastrowid)


def _mark_events(
    db: Session,
    group: list[dict[str, Any]],
    reason: str,
    processed_at: datetime,
    representative_event_ids: list[int],
) -> None:
    representative_set = set(representative_event_ids)
    for event in group:
        is_representative = int(event["id"]) in representative_set
        event_reason = reason if is_representative else (
            PROCESSING_NOT_REPRESENTATIVE
            if reason == PROCESSING_APPLIED
            else reason
        )
        db.execute(
            text(
                """
                UPDATE detection_events
                SET processed_at = :processed_at,
                    processing_reason = :processing_reason,
                    applied_to_score = :applied_to_score
                WHERE id = :id
                """
            ),
            {
                "id": event["id"],
                "processed_at": format_db_utc(processed_at),
                "processing_reason": event_reason,
                "applied_to_score": 1 if is_representative and reason == PROCESSING_APPLIED else 0,
            },
        )


def _max_optional_id(current: int | None, candidate: int) -> int:
    return candidate if current is None else max(current, candidate)
