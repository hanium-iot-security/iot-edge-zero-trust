"""Apply detection events to device Trust Scores."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sqlite3

from edge.trust.trust_policy import (
    ISOLATED_STATUS,
    UNKNOWN_DEVICE,
    apply_score_delta,
    score_delta_for_event,
    status_for_trust_score,
)


DB_PATH = Path("backend/data/iot_security.db")
ISOLATION_ACTION = "ISOLATED"
ISOLATION_REASON = "Trust Score below threshold"


@dataclass(frozen=True)
class TrustScoreChange:
    event_id: int
    feature_log_id: int | None
    device_id: str
    event_type: str
    score_delta: int
    previous_score: int
    new_score: int
    previous_status: str
    new_status: str
    isolation_recorded: bool


@dataclass
class TrustScoreUpdateResult:
    candidate_event_count: int = 0
    processed_window_count: int = 0
    applied_event_count: int = 0
    skipped_missing_device_count: int = 0
    skipped_no_score_count: int = 0
    changes: list[TrustScoreChange] = field(default_factory=list)


def connect_database(db_path: str | Path = DB_PATH) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA busy_timeout = 5000;")
    return connection


def update_trust_scores(db_path: str | Path = DB_PATH) -> TrustScoreUpdateResult:
    connection = connect_database(db_path)
    try:
        candidate_events = _fetch_candidate_events(connection)
        event_groups = _group_events_by_window(candidate_events)
        result = TrustScoreUpdateResult(
            candidate_event_count=len(candidate_events),
            processed_window_count=len(event_groups),
        )

        for events in event_groups:
            representative = _select_representative_event(events)
            if representative is None:
                result.skipped_no_score_count += 1
                continue

            device = _fetch_device(connection, representative["device_id"])
            if device is None:
                result.skipped_missing_device_count += 1
                continue

            change = _apply_representative_event(connection, representative, device)
            result.changes.append(change)
            result.applied_event_count += 1

        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _fetch_candidate_events(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    cursor = connection.execute(
        """
        SELECT
            id,
            device_id,
            feature_log_id,
            mqtt_log_id,
            detector_type,
            event_type,
            severity,
            score_delta,
            applied_to_score,
            description,
            detected_at
        FROM detection_events AS detection_event
        WHERE detection_event.applied_to_score = 0
          AND detection_event.event_type != ?
          AND (
              detection_event.feature_log_id IS NULL
              OR NOT EXISTS (
                  SELECT 1
                  FROM detection_events AS applied_event
                  WHERE applied_event.feature_log_id = detection_event.feature_log_id
                    AND applied_event.applied_to_score = 1
              )
          )
        ORDER BY
            detection_event.feature_log_id IS NULL,
            detection_event.feature_log_id,
            detection_event.id
        """,
        (UNKNOWN_DEVICE,),
    )
    return list(cursor.fetchall())


def _group_events_by_window(events: list[sqlite3.Row]) -> list[list[sqlite3.Row]]:
    groups: dict[tuple[str, int], list[sqlite3.Row]] = {}
    order: list[tuple[str, int]] = []

    for event in events:
        if event["feature_log_id"] is None:
            group_key = ("event", event["id"])
        else:
            group_key = ("feature_log", event["feature_log_id"])

        if group_key not in groups:
            groups[group_key] = []
            order.append(group_key)
        groups[group_key].append(event)

    return [groups[group_key] for group_key in order]


def _select_representative_event(events: list[sqlite3.Row]) -> sqlite3.Row | None:
    score_events = [
        event
        for event in events
        if score_delta_for_event(event["event_type"]) < 0
    ]
    if not score_events:
        return None

    return min(
        score_events,
        key=lambda event: (score_delta_for_event(event["event_type"]), event["id"]),
    )


def _fetch_device(connection: sqlite3.Connection, device_id: str) -> sqlite3.Row | None:
    cursor = connection.execute(
        """
        SELECT device_id, trust_score, status
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,),
    )
    return cursor.fetchone()


def _apply_representative_event(
    connection: sqlite3.Connection,
    representative: sqlite3.Row,
    device: sqlite3.Row,
) -> TrustScoreChange:
    event_id = representative["id"]
    device_id = representative["device_id"]
    event_type = representative["event_type"]
    score_delta = score_delta_for_event(event_type)
    previous_score = int(device["trust_score"])
    previous_status = device["status"]

    if previous_status == ISOLATED_STATUS:
        connection.execute(
            """
            UPDATE detection_events
            SET applied_to_score = 1, score_delta = 0
            WHERE id = ?
            """,
            (event_id,),
        )

        return TrustScoreChange(
            event_id=event_id,
            feature_log_id=representative["feature_log_id"],
            device_id=device_id,
            event_type=event_type,
            score_delta=0,
            previous_score=previous_score,
            new_score=previous_score,
            previous_status=previous_status,
            new_status=previous_status,
            isolation_recorded=False,
        )

    new_score = apply_score_delta(previous_score, score_delta)
    new_status = status_for_trust_score(new_score)
    isolation_recorded = (
        new_status == ISOLATED_STATUS
        and previous_status != ISOLATED_STATUS
    )

    connection.execute(
        """
        UPDATE devices
        SET trust_score = ?, status = ?
        WHERE device_id = ?
        """,
        (new_score, new_status, device_id),
    )
    connection.execute(
        """
        UPDATE detection_events
        SET applied_to_score = 1, score_delta = ?
        WHERE id = ?
        """,
        (score_delta, event_id),
    )

    if isolation_recorded:
        connection.execute(
            """
            INSERT INTO isolation_history (
                device_id,
                action,
                reason,
                trust_score,
                trigger_event_id
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                device_id,
                ISOLATION_ACTION,
                ISOLATION_REASON,
                new_score,
                event_id,
            ),
        )

    return TrustScoreChange(
        event_id=event_id,
        feature_log_id=representative["feature_log_id"],
        device_id=device_id,
        event_type=event_type,
        score_delta=score_delta,
        previous_score=previous_score,
        new_score=new_score,
        previous_status=previous_status,
        new_status=new_status,
        isolation_recorded=isolation_recorded,
    )
