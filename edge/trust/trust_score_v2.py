"""Phase 4 Trust Score v2 transaction service."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import (
    WINDOW_SECONDS,
    format_db_utc,
    floor_window_start,
    parse_db_utc,
    require_utc_window_boundary,
)
from edge.trust import firewall_repository
from edge.trust.trust_policy import (
    ISOLATED_STATUS,
    UNKNOWN_DEVICE,
    apply_score_delta,
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
AI_WINDOW_CAP = -15
WINDOW_DELTA_CAP = -30


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


def apply_trust_score_v2_until(
    db: Session,
    *,
    cycle_cutoff: datetime,
) -> TrustScoreV2RunResult:
    cutoff = require_utc_window_boundary(cycle_cutoff, "cycle_cutoff")
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
        last_processed_id=last_processed_before,
        cutoff=cutoff,
    )
    last_processed_after = last_processed_before
    for event in events:
        last_processed_after = _max_optional_id(last_processed_after, int(event["id"]))

    changes: list[TrustScoreV2Change] = []
    processed_event_count = 0
    created_history_count = 0
    created_isolation_count = 0
    created_firewall_rule_count = 0

    for group in _group_events(events):
        processed_event_count += len(group)
        device_id = group[0]["device_id"]
        if not device_id:
            _mark_events(db, group, PROCESSING_UNMAPPED_DEVICE, cutoff, [])
            continue

        device = _fetch_device(db, str(device_id))
        if device is None:
            _mark_events(db, group, PROCESSING_UNMAPPED_DEVICE, cutoff, [])
            continue
        if device["status"] == ISOLATED_STATUS:
            _mark_events(db, group, PROCESSING_ALREADY_ISOLATED, cutoff, [])
            continue

        selected = _select_representative_events(group)
        if not selected:
            _mark_events(db, group, PROCESSING_UNMAPPED_EVENT_TYPE, cutoff, [])
            continue

        previous_score = int(device["trust_score"])
        calculated_delta = sum(event["effective_delta"] for event in selected)
        capped_delta = max(calculated_delta, WINDOW_DELTA_CAP)
        new_score = apply_score_delta(previous_score, capped_delta)
        actual_delta = new_score - previous_score
        new_status = status_for_trust_score(new_score)
        representative_ids = [int(event["id"]) for event in selected]
        window_start, window_end = _group_window(group)

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
        _mark_events(db, group, PROCESSING_APPLIED, cutoff, representative_ids)

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
    )


def _fetch_candidate_events(
    db: Session,
    *,
    last_processed_id: int | None,
    cutoff: datetime,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT *
            FROM detection_events
            WHERE processed_at IS NULL
              AND (:last_processed_id IS NULL OR id > :last_processed_id)
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
            ORDER BY id ASC
            """
        ),
        {
            "last_processed_id": last_processed_id,
            "cutoff": format_db_utc(cutoff),
        },
    ).mappings()
    return [dict(row) for row in rows]


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
        family = str(event.get("incident_family") or event_type)
        current = rule_by_family.get(family)
        if current is None or (delta, int(event["id"])) < (
            int(current["effective_delta"]),
            int(current["id"]),
        ):
            rule_by_family[family] = candidate

    selected = list(rule_by_family.values())
    if ai_events:
        ai_rep = min(ai_events, key=lambda event: (event["effective_delta"], int(event["id"])))
        ai_rep["effective_delta"] = max(
            sum(int(event["effective_delta"]) for event in ai_events),
            AI_WINDOW_CAP,
        )
        selected.append(ai_rep)
    selected.sort(key=lambda event: int(event["id"]))
    return selected


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
