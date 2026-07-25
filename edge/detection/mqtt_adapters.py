"""Phase 4 MQTT detector adapters."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.ai_detector import DEFAULT_MODEL_PATH, predict_feature_window
from edge.detection.detection_event_writer import write_detection_event
from edge.detection.detector_contract import DetectorRunResult, validate_cycle_window
from edge.detection.phase4_time import (
    WINDOW_SECONDS,
    format_db_utc,
    floor_window_start,
    parse_db_utc,
)
from edge.detection.rule_detector import (
    DETECTOR_AI,
    DETECTOR_RULE,
    detect_feature_rules,
    detect_mqtt_rules,
)
from edge.trust.trust_policy import incident_family_for_event


MQTT_FEATURE_RULE_POLICY_VERSION = "mqtt-feature-rule-v1"
MQTT_MESSAGE_RULE_POLICY_VERSION = "mqtt-message-rule-v1"
MQTT_IF_POLICY_VERSION = "mqtt-if-v1"


class MqttFeatureRuleStage:
    detector_name = "mqtt_feature_rule"
    source_table = "feature_logs"
    policy_version = MQTT_FEATURE_RULE_POLICY_VERSION

    def run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
    ) -> DetectorRunResult:
        range_start, cutoff = validate_cycle_window(
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
        )
        before = _checkpoint_before(db, self.detector_name, self.source_table)
        device_ips = _registered_device_ips(db)
        rows = _select_feature_rows(
            db,
            range_start=range_start,
            cutoff=cutoff,
        )

        created_count = 0
        last_processed_after = before["last_processed_id"]
        for row in rows:
            source_id = int(row["id"])
            last_processed_after = _max_optional_id(last_processed_after, source_id)
            feature_row = dict(row)
            for event in detect_feature_rules(feature_row):
                event_type = event["event_type"]
                result = write_detection_event(
                    db,
                    device_id=feature_row["device_id"],
                    detector_name=self.detector_name,
                    source_table=self.source_table,
                    source_id=source_id,
                    detector_type=DETECTOR_RULE,
                    event_type=event_type,
                    severity=event["severity"],
                    description=_feature_rule_description(event_type, feature_row),
                    policy_version=self.policy_version,
                    detected_at=cutoff,
                    analysis_window_start=parse_db_utc(
                        feature_row["window_start"], "window_start"
                    ),
                    analysis_window_end=parse_db_utc(
                        feature_row["window_end"], "window_end"
                    ),
                    incident_family=incident_family_for_event(event_type),
                    subject_ip=device_ips.get(str(feature_row["device_id"])),
                    evidence=_feature_evidence(
                        detector_name=self.detector_name,
                        source_id=source_id,
                        event_type=event_type,
                        feature_row=feature_row,
                        range_start=range_start,
                        cutoff=cutoff,
                        policy_version=self.policy_version,
                    ),
                    feature_log_id=source_id,
                )
                if result.inserted:
                    created_count += 1

        _advance_checkpoint(
            db,
            detector_name=self.detector_name,
            source_table=self.source_table,
            last_processed_id=last_processed_after,
            completed_window_end=cutoff,
            updated_at=cutoff,
        )
        return _run_result(
            self.detector_name,
            self.source_table,
            range_start,
            cutoff,
            rows,
            created_count,
            before,
            last_processed_after,
        )


class MqttMessageRuleStage:
    detector_name = "mqtt_message_rule"
    source_table = "mqtt_logs"
    policy_version = MQTT_MESSAGE_RULE_POLICY_VERSION

    def run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
    ) -> DetectorRunResult:
        range_start, cutoff = validate_cycle_window(
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
        )
        before = _checkpoint_before(db, self.detector_name, self.source_table)
        device_ips = _registered_device_ips(db)
        registered_devices = set(device_ips)
        rows = _select_mqtt_rows(
            db,
            range_start=range_start,
            cutoff=cutoff,
        )

        created_count = 0
        last_processed_after = before["last_processed_id"]
        for row in rows:
            source_id = int(row["id"])
            last_processed_after = _max_optional_id(last_processed_after, source_id)
            mqtt_row = dict(row)
            received_at = parse_db_utc(mqtt_row["received_at"], "received_at")
            window_start = floor_window_start(received_at)
            window_end = window_start + timedelta(seconds=WINDOW_SECONDS)
            for event in detect_mqtt_rules(mqtt_row, registered_devices):
                event_type = event["event_type"]
                result = write_detection_event(
                    db,
                    device_id=event["device_id"],
                    detector_name=self.detector_name,
                    source_table=self.source_table,
                    source_id=source_id,
                    detector_type=DETECTOR_RULE,
                    event_type=event_type,
                    severity=event["severity"],
                    description=f"MQTT message rule matched: {event_type}",
                    policy_version=self.policy_version,
                    detected_at=cutoff,
                    analysis_window_start=window_start,
                    analysis_window_end=window_end,
                    incident_family=incident_family_for_event(event_type),
                    subject_ip=device_ips.get(str(event["device_id"])),
                    evidence={
                        "source_type": self.source_table,
                        "source_id": source_id,
                        "detector_name": self.detector_name,
                        "observed_values": {
                            "topic_id": event.get("topic_id"),
                            "payload_id": event.get("payload_id"),
                        },
                        "thresholds": {},
                        "policy_version": self.policy_version,
                        "cycle_range_start": format_db_utc(range_start),
                        "cycle_cutoff": format_db_utc(cutoff),
                    },
                    mqtt_log_id=source_id,
                )
                if result.inserted:
                    created_count += 1

        _advance_checkpoint(
            db,
            detector_name=self.detector_name,
            source_table=self.source_table,
            last_processed_id=last_processed_after,
            completed_window_end=cutoff,
            updated_at=cutoff,
        )
        return _run_result(
            self.detector_name,
            self.source_table,
            range_start,
            cutoff,
            rows,
            created_count,
            before,
            last_processed_after,
        )


class MqttIsolationForestStage:
    detector_name = "mqtt_if"
    source_table = "feature_logs"
    policy_version = MQTT_IF_POLICY_VERSION

    def __init__(self, *, model_path: Path = DEFAULT_MODEL_PATH) -> None:
        self.model_path = model_path

    def run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
    ) -> DetectorRunResult:
        range_start, cutoff = validate_cycle_window(
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
        )
        before = _checkpoint_before(db, self.detector_name, self.source_table)
        device_ips = _registered_device_ips(db)
        rows = _select_feature_rows(
            db,
            range_start=range_start,
            cutoff=cutoff,
        )

        created_count = 0
        last_processed_after = before["last_processed_id"]
        for row in rows:
            source_id = int(row["id"])
            last_processed_after = _max_optional_id(last_processed_after, source_id)
            feature_row = dict(row)
            result = predict_feature_window(feature_row, self.model_path)
            if not result["is_anomaly"]:
                continue
            event_type = result["event_type"]
            written = write_detection_event(
                db,
                device_id=feature_row["device_id"],
                detector_name=self.detector_name,
                source_table=self.source_table,
                source_id=source_id,
                detector_type=DETECTOR_AI,
                event_type=event_type,
                severity="medium",
                description="Isolation Forest anomaly",
                policy_version=self.policy_version,
                detected_at=cutoff,
                analysis_window_start=parse_db_utc(
                    feature_row["window_start"], "window_start"
                ),
                analysis_window_end=parse_db_utc(
                    feature_row["window_end"], "window_end"
                ),
                incident_family=incident_family_for_event(event_type),
                subject_ip=device_ips.get(str(feature_row["device_id"])),
                evidence={
                    "source_type": self.source_table,
                    "source_id": source_id,
                    "detector_name": self.detector_name,
                    "observed_values": {
                        "prediction": result["prediction"],
                        "anomaly_score": result["anomaly_score"],
                    },
                    "thresholds": {},
                    "model_version": self.policy_version,
                    "cycle_range_start": format_db_utc(range_start),
                    "cycle_cutoff": format_db_utc(cutoff),
                },
                feature_log_id=source_id,
            )
            if written.inserted:
                created_count += 1

        _advance_checkpoint(
            db,
            detector_name=self.detector_name,
            source_table=self.source_table,
            last_processed_id=last_processed_after,
            completed_window_end=cutoff,
            updated_at=cutoff,
        )
        return _run_result(
            self.detector_name,
            self.source_table,
            range_start,
            cutoff,
            rows,
            created_count,
            before,
            last_processed_after,
        )


def _checkpoint_before(
    db: Session,
    detector_name: str,
    source_table: str,
) -> dict[str, Any]:
    row = checkpoints.get_detector_checkpoint(
        db,
        detector_name=detector_name,
        source_table=source_table,
    )
    if row is None:
        return {
            "last_processed_id": None,
            "last_completed_window_end": None,
        }
    return {
        "last_processed_id": row["last_processed_id"],
        "last_completed_window_end": (
            parse_db_utc(row["last_completed_window_end"], "last_completed_window_end")
            if row["last_completed_window_end"] is not None
            else None
        ),
    }


def _advance_checkpoint(
    db: Session,
    *,
    detector_name: str,
    source_table: str,
    last_processed_id: int | None,
    completed_window_end: datetime,
    updated_at: datetime,
) -> None:
    checkpoints.upsert_detector_checkpoint(
        db,
        detector_name=detector_name,
        source_table=source_table,
        last_processed_id=last_processed_id,
        last_completed_window_end=completed_window_end,
        updated_at=updated_at,
    )


def _select_feature_rows(
    db: Session,
    *,
    range_start: datetime,
    cutoff: datetime,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT id, device_id, window_start, window_end,
                   publish_count, avg_payload_size, max_payload_size,
                   avg_message_interval, min_message_interval,
                   topic_count, abnormal_topic_count, malformed_payload_count
            FROM feature_logs
            WHERE unixepoch(window_start) >= unixepoch(:range_start)
              AND unixepoch(window_end) <= unixepoch(:cutoff)
            ORDER BY id ASC
            """
        ),
        {
            "range_start": format_db_utc(range_start),
            "cutoff": format_db_utc(cutoff),
        },
    ).mappings()
    return [dict(row) for row in rows]


def _select_mqtt_rows(
    db: Session,
    *,
    range_start: datetime,
    cutoff: datetime,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT id, device_id, topic, payload, received_at
            FROM mqtt_logs
            WHERE unixepoch(received_at) >= unixepoch(:range_start)
              AND unixepoch(received_at) < unixepoch(:cutoff)
            ORDER BY id ASC
            """
        ),
        {
            "range_start": format_db_utc(range_start),
            "cutoff": format_db_utc(cutoff),
        },
    ).mappings()
    return [dict(row) for row in rows]


def _registered_device_ips(db: Session) -> dict[str, str | None]:
    rows = db.execute(
        text(
            """
            SELECT device_id, ip_address
            FROM devices
            """
        )
    ).mappings()
    return {
        str(row["device_id"]): (
            str(row["ip_address"]) if row["ip_address"] else None
        )
        for row in rows
    }


def _feature_rule_description(event_type: str, row: dict[str, Any]) -> str:
    if event_type == "ABNORMAL_PUBLISH_RATE":
        return (
            f"publish_count={row['publish_count']}, "
            f"min_interval={row['min_message_interval']}"
        )
    if event_type == "LARGE_PAYLOAD":
        return f"max_payload_size={row['max_payload_size']}"
    if event_type == "MALFORMED_PAYLOAD":
        return f"malformed_payload_count={row['malformed_payload_count']}"
    if event_type == "ABNORMAL_TOPIC":
        return f"abnormal_topic_count={row['abnormal_topic_count']}"
    return f"MQTT feature rule matched: {event_type}"


def _feature_evidence(
    *,
    detector_name: str,
    source_id: int,
    event_type: str,
    feature_row: dict[str, Any],
    range_start: datetime,
    cutoff: datetime,
    policy_version: str,
) -> dict[str, Any]:
    thresholds = {
        "ABNORMAL_PUBLISH_RATE": {
            "publish_count": "> 15",
            "min_message_interval": "< 1.0",
        },
        "LARGE_PAYLOAD": {"max_payload_size": "> 5120"},
        "MALFORMED_PAYLOAD": {"malformed_payload_count": ">= 3"},
        "ABNORMAL_TOPIC": {"abnormal_topic_count": ">= 3"},
    }
    return {
        "source_type": "feature_logs",
        "source_id": source_id,
        "detector_name": detector_name,
        "observed_values": {
            "publish_count": feature_row.get("publish_count"),
            "min_message_interval": feature_row.get("min_message_interval"),
            "max_payload_size": feature_row.get("max_payload_size"),
            "malformed_payload_count": feature_row.get("malformed_payload_count"),
            "abnormal_topic_count": feature_row.get("abnormal_topic_count"),
        },
        "thresholds": thresholds.get(event_type, {}),
        "policy_version": policy_version,
        "cycle_range_start": format_db_utc(range_start),
        "cycle_cutoff": format_db_utc(cutoff),
    }


def _max_optional_id(current: int | None, candidate: int) -> int:
    return candidate if current is None else max(current, candidate)


def _run_result(
    detector_name: str,
    source_table: str,
    range_start: datetime,
    cutoff: datetime,
    rows: list[dict[str, Any]],
    created_count: int,
    before: dict[str, Any],
    last_processed_after: int | None,
) -> DetectorRunResult:
    return DetectorRunResult(
        detector_name=detector_name,
        source_table=source_table,
        range_start=range_start,
        cutoff=cutoff,
        selected_count=len(rows),
        created_event_count=created_count,
        last_processed_id_before=before["last_processed_id"],
        last_processed_id_after=last_processed_after,
        completed_window_end_before=before["last_completed_window_end"],
        completed_window_end_after=cutoff,
    )
