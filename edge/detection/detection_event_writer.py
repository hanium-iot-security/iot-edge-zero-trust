"""Detection event writer helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Any, Mapping

from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import format_db_utc
from edge.detection.rule_detector import (
    AI_EVENT_TYPES,
    DETECTOR_AI,
    DETECTOR_RULE,
    DEVICE_ID_MISMATCH,
    RULE_EVENT_TYPES,
    UNKNOWN_DEVICE,
)
from edge.trust.trust_policy import incident_family_for_event, score_delta_for_event

# feature 기반 이벤트 (feature_log_id 기준)
_FEATURE_BASED_EVENTS = {
    event_type
    for event_type in RULE_EVENT_TYPES
    if event_type not in {UNKNOWN_DEVICE, DEVICE_ID_MISMATCH}
} | AI_EVENT_TYPES

# MQTT 원본 기반 이벤트 (mqtt_log_id 기준)
_MQTT_BASED_EVENTS = {UNKNOWN_DEVICE, DEVICE_ID_MISMATCH}

_VALID_DETECTOR_EVENTS: dict[str, set[str]] = {
    DETECTOR_RULE: RULE_EVENT_TYPES,
    DETECTOR_AI: AI_EVENT_TYPES,
}

_VALID_SEVERITIES = {"low", "medium", "high"}


@dataclass(frozen=True)
class DetectionEventWriteResult:
    event_id: int | None
    inserted: bool
    duplicate: bool


def build_dedupe_key(
    *,
    detector_name: str,
    source_table: str,
    source_id: int,
    event_type: str,
    policy_version: str,
) -> str:
    return f"{detector_name}:{source_table}:{source_id}:{event_type}:{policy_version}"


def write_detection_event(
    db: Session,
    *,
    device_id: str | None,
    detector_name: str,
    source_table: str,
    source_id: int,
    detector_type: str,
    event_type: str,
    severity: str,
    description: str,
    policy_version: str,
    detected_at: datetime,
    analysis_window_start: datetime,
    analysis_window_end: datetime,
    incident_family: str | None = None,
    subject_ip: str | None = None,
    evidence: Mapping[str, Any] | None = None,
    evidence_schema_version: int = 1,
    score_delta: int | None = None,
    feature_log_id: int | None = None,
    mqtt_log_id: int | None = None,
    packet_feature_log_id: int | None = None,
) -> DetectionEventWriteResult:
    """Insert a Phase 4 detection event without committing the caller transaction."""
    _validate_phase4_event(
        severity=severity,
        feature_log_id=feature_log_id,
        mqtt_log_id=mqtt_log_id,
        packet_feature_log_id=packet_feature_log_id,
    )
    source_fk_values = {
        "feature_logs": feature_log_id,
        "mqtt_logs": mqtt_log_id,
        "packet_feature_logs": packet_feature_log_id,
    }
    if source_fk_values.get(source_table) != source_id:
        raise ValueError("source_table/source_id must match the populated source FK")

    dedupe_key = build_dedupe_key(
        detector_name=detector_name,
        source_table=source_table,
        source_id=source_id,
        event_type=event_type,
        policy_version=policy_version,
    )
    evidence_json = _serialize_evidence(evidence)
    delta = score_delta_for_event(event_type) if score_delta is None else score_delta
    family = incident_family if incident_family is not None else incident_family_for_event(event_type)

    try:
        result = db.execute(
            text(
                """
                INSERT INTO detection_events (
                    device_id,
                    feature_log_id,
                    mqtt_log_id,
                    packet_feature_log_id,
                    detector_type,
                    event_type,
                    severity,
                    score_delta,
                    applied_to_score,
                    description,
                    detected_at,
                    analysis_window_start,
                    analysis_window_end,
                    incident_family,
                    subject_ip,
                    evidence_json,
                    evidence_schema_version,
                    dedupe_key,
                    policy_version,
                    processed_at,
                    processing_reason
                )
                VALUES (
                    :device_id,
                    :feature_log_id,
                    :mqtt_log_id,
                    :packet_feature_log_id,
                    :detector_type,
                    :event_type,
                    :severity,
                    :score_delta,
                    0,
                    :description,
                    :detected_at,
                    :analysis_window_start,
                    :analysis_window_end,
                    :incident_family,
                    :subject_ip,
                    :evidence_json,
                    :evidence_schema_version,
                    :dedupe_key,
                    :policy_version,
                    NULL,
                    NULL
                )
                ON CONFLICT(dedupe_key)
                WHERE dedupe_key IS NOT NULL
                DO NOTHING
                """
            ),
            {
                "device_id": device_id,
                "feature_log_id": feature_log_id,
                "mqtt_log_id": mqtt_log_id,
                "packet_feature_log_id": packet_feature_log_id,
                "detector_type": detector_type,
                "event_type": event_type,
                "severity": severity,
                "score_delta": delta,
                "description": description,
                "detected_at": format_db_utc(detected_at),
                "analysis_window_start": format_db_utc(analysis_window_start),
                "analysis_window_end": format_db_utc(analysis_window_end),
                "incident_family": family,
                "subject_ip": subject_ip,
                "evidence_json": evidence_json,
                "evidence_schema_version": evidence_schema_version,
                "dedupe_key": dedupe_key,
                "policy_version": policy_version,
            },
        )
    except IntegrityError:
        raise

    if result.rowcount == 0:
        return DetectionEventWriteResult(
            event_id=_find_event_id_by_dedupe_key(db, dedupe_key),
            inserted=False,
            duplicate=True,
        )
    return DetectionEventWriteResult(
        event_id=int(result.lastrowid),
        inserted=True,
        duplicate=False,
    )


def _validate_phase4_event(
    *,
    severity: str,
    feature_log_id: int | None,
    mqtt_log_id: int | None,
    packet_feature_log_id: int | None,
) -> None:
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"invalid severity: {severity!r}")
    source_count = sum(
        value is not None
        for value in (feature_log_id, mqtt_log_id, packet_feature_log_id)
    )
    if source_count != 1:
        raise ValueError("exactly one source FK must be provided")


def _serialize_evidence(evidence: Mapping[str, Any] | None) -> str | None:
    if evidence is None:
        return None
    return json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _find_event_id_by_dedupe_key(db: Session, dedupe_key: str) -> int | None:
    row = db.execute(
        text("SELECT id FROM detection_events WHERE dedupe_key = :dedupe_key"),
        {"dedupe_key": dedupe_key},
    ).first()
    return int(row[0]) if row is not None else None


def insert_detection_event(
    db: Session,
    *,
    device_id: str | None,
    detector_type: str,
    event_type: str,
    severity: str,
    description: str,
    feature_log_id: int | None = None,
    mqtt_log_id: int | None = None,
) -> int | None:
    """detection_events에 이벤트를 저장합니다.

    중복이면 None을 반환합니다. commit은 호출자(runner)가 담당합니다.

    Args:
        db: 호출자가 관리하는 SQLAlchemy Session
        device_id: 탐지된 device_id (UNKNOWN_DEVICE 시 미등록 ID)
        detector_type: RULE 또는 AI
        event_type: 이벤트 타입 상수
        severity: high / medium / low
        description: 탐지 설명
        feature_log_id: feature 기반 이벤트 시 feature_logs.id
        mqtt_log_id: MQTT 원본 기반 이벤트 시 mqtt_logs.id

    Returns:
        저장된 detection_events.id, 중복이면 None
    """
    _validate(detector_type, event_type, severity, feature_log_id, mqtt_log_id)

    if _is_duplicate(db, detector_type, event_type, feature_log_id, mqtt_log_id):
        return None

    result = db.execute(
        text(
            """
            INSERT INTO detection_events (
                device_id,
                feature_log_id,
                mqtt_log_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description
            )
            VALUES (
                :device_id,
                :feature_log_id,
                :mqtt_log_id,
                :detector_type,
                :event_type,
                :severity,
                :score_delta,
                0,
                :description
            )
            """
        ),
        {
            "device_id": device_id,
            "feature_log_id": feature_log_id,
            "mqtt_log_id": mqtt_log_id,
            "detector_type": detector_type,
            "event_type": event_type,
            "severity": severity,
            "score_delta": score_delta_for_event(event_type),
            "description": description,
        },
    )
    return int(result.lastrowid)


def _validate(
    detector_type: str,
    event_type: str,
    severity: str,
    feature_log_id: int | None,
    mqtt_log_id: int | None,
) -> None:
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"허용되지 않는 severity: {severity!r}")

    if (feature_log_id is None) == (mqtt_log_id is None):
        raise ValueError(
            f"feature_log_id와 mqtt_log_id 중 정확히 하나만 지정해야 합니다. "
            f"feature_log_id={feature_log_id}, mqtt_log_id={mqtt_log_id}"
        )

    valid_events = _VALID_DETECTOR_EVENTS.get(detector_type)
    if valid_events is None:
        raise ValueError(f"알 수 없는 detector_type: {detector_type!r}")
    if event_type not in valid_events:
        raise ValueError(
            f"detector_type={detector_type!r}에 허용되지 않는 event_type: {event_type!r}"
        )

    if feature_log_id is not None and event_type not in _FEATURE_BASED_EVENTS:
        raise ValueError(
            f"event_type={event_type!r}은 mqtt_log_id 기준 이벤트입니다. feature_log_id 사용 불가."
        )
    if mqtt_log_id is not None and event_type not in _MQTT_BASED_EVENTS:
        raise ValueError(
            f"event_type={event_type!r}은 feature_log_id 기준 이벤트입니다. mqtt_log_id 사용 불가."
        )


def _is_duplicate(
    db: Session,
    detector_type: str,
    event_type: str,
    feature_log_id: int | None,
    mqtt_log_id: int | None,
) -> bool:
    if feature_log_id is not None:
        row = db.execute(
            text(
                """
                SELECT 1 FROM detection_events
                WHERE feature_log_id = :feature_log_id
                  AND detector_type  = :detector_type
                  AND event_type     = :event_type
                LIMIT 1
                """
            ),
            {
                "feature_log_id": feature_log_id,
                "detector_type": detector_type,
                "event_type": event_type,
            },
        ).first()
    else:
        row = db.execute(
            text(
                """
                SELECT 1 FROM detection_events
                WHERE mqtt_log_id  = :mqtt_log_id
                  AND detector_type = :detector_type
                  AND event_type    = :event_type
                LIMIT 1
                """
            ),
            {
                "mqtt_log_id": mqtt_log_id,
                "detector_type": detector_type,
                "event_type": event_type,
            },
        ).first()
    return row is not None
