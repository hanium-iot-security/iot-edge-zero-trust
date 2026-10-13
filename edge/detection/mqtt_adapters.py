"""Phase 4 MQTT detector adapters."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

from ai.mqtt_if_artifact import (
    MQTTIFArtifact, inspect_mqtt_if_bundle, load_inspected_mqtt_if_artifact,
)
from backend.app.config import Settings, settings
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.ai_detector import (
    DEFAULT_MODEL_PATH, load_model, predict_bundle_feature_window, predict_feature_window,
)
from edge.detection.ai_run_evidence import AICompletionCollector, AICompletionRecord
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
    LARGE_PAYLOAD_BYTES,
    PUBLISH_COUNT_THRESHOLD,
    detect_feature_rules,
    detect_mqtt_rules,
)
from edge.policy.repository import load_policy_resolver
from edge.policy.resolver import DevicePolicyRevision, POLICY_AVAILABLE, PolicyResolution
from edge.policy.ai_window_decision import AIWindowDecision, require_observe_trust_mode
from edge.trust.trust_policy import POLICY_UNAVAILABLE, incident_family_for_event
from edge.maintenance.processing import maintenance_windows, overlaps_maintenance, require_processing_cutoff


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
        require_processing_cutoff(db, cutoff)
        maintenance = maintenance_windows(db)
        device_ips = _registered_device_ips(db)
        resolver = load_policy_resolver(db)
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
            window_start = parse_db_utc(feature_row["window_start"], "window_start")
            if overlaps_maintenance(maintenance, window_start, parse_db_utc(feature_row["window_end"], "window_end")):
                continue
            resolution = (
                resolver.resolve(str(feature_row["device_id"]), window_start)
                if resolver is not None else None
            )
            if resolution is not None and resolution.reason != POLICY_AVAILABLE:
                written = write_detection_event(
                    db,
                    device_id=feature_row["device_id"],
                    detector_name=self.detector_name,
                    source_table=self.source_table,
                    source_id=source_id,
                    detector_type=DETECTOR_RULE,
                    event_type=POLICY_UNAVAILABLE,
                    severity="medium",
                    description=f"Device policy resolution failed: {resolution.reason}",
                    policy_version=self.policy_version,
                    detected_at=cutoff,
                    analysis_window_start=window_start,
                    analysis_window_end=parse_db_utc(
                        feature_row["window_end"], "window_end"
                    ),
                    subject_ip=(
                        resolution.registration.ip_address
                        if resolution.registration is not None else None
                    ),
                    evidence={
                        "device_id": feature_row["device_id"],
                        "window_start": format_db_utc(window_start),
                        "reason": resolution.reason,
                        "candidate_score_delta": 0,
                    },
                    feature_log_id=source_id,
                )
                created_count += int(written.inserted)
            device_policy = resolution.policy if resolution is not None else None
            for event in detect_feature_rules(
                feature_row,
                device_policy,
                include_policy_thresholds=(
                    resolution is None or resolution.reason == POLICY_AVAILABLE
                ),
            ):
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
                    subject_ip=(
                        resolution.registration.ip_address
                        if resolution is not None and resolution.registration is not None
                        else device_ips.get(str(feature_row["device_id"])) if resolution is None
                        else None
                    ),
                    evidence=_feature_evidence(
                        detector_name=self.detector_name,
                        source_id=source_id,
                        event_type=event_type,
                        feature_row=feature_row,
                        range_start=range_start,
                        cutoff=cutoff,
                        policy_version=self.policy_version,
                        device_policy=device_policy,
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
        require_processing_cutoff(db, cutoff)
        maintenance = maintenance_windows(db)
        device_ips = _registered_device_ips(db)
        resolver = load_policy_resolver(db)
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
            received_at = parse_db_utc(
                mqtt_row["received_at"], "received_at", allow_subseconds=True
            )
            window_start = floor_window_start(received_at.replace(microsecond=0))
            window_end = window_start + timedelta(seconds=WINDOW_SECONDS)
            if overlaps_maintenance(maintenance, window_start, window_end):
                continue
            window_registered = (
                resolver.registered_ids_at(window_start)
                if resolver is not None else registered_devices
            )
            for event in detect_mqtt_rules(mqtt_row, window_registered):
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
                    subject_ip=(
                        resolver.registration_at(str(event["device_id"]), window_start).ip_address
                        if resolver is not None and event["device_id"] in window_registered
                        else device_ips.get(str(event["device_id"])) if resolver is None else None
                    ),
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
                        "window_start": format_db_utc(window_start),
                        "candidate_device_id": mqtt_row.get("device_id"),
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

    def __init__(
        self, *, model_path: Path = DEFAULT_MODEL_PATH,
        artifact: MQTTIFArtifact | None = None,
        ai_window_selector: Callable[[PolicyResolution], AIWindowDecision] | None = None,
        completion_sink: Callable[[Session, tuple[AICompletionRecord, ...]], None] | None = None,
        trust_ai_mode: str | None = None,
    ) -> None:
        if ai_window_selector is not None or artifact is not None:
            require_observe_trust_mode(
                settings.trust_ai_mode if trust_ai_mode is None else trust_ai_mode
            )
        self.model_path = model_path
        if artifact is not None and model_path != DEFAULT_MODEL_PATH:
            raise ValueError("configure either a MQTT Bundle or a legacy model path")
        self.artifact = artifact
        self.bundle_evidence = {}
        if artifact is not None:
            metadata = artifact.inspection.metadata
            self.bundle_evidence = {key: metadata[key] for key in (
                "feature_version", "feature_order", "transform_version", "score_method",
                "score_direction", "threshold_operator", "threshold_source", "interval_semantics",
            )}
            self.policy_version = (
                f"{MQTT_IF_POLICY_VERSION}:{artifact.inspection.model_version}:"
                f"{artifact.inspection.bundle_sha256[:12]}"
            )
        self.ai_window_selector = ai_window_selector
        self.completion_sink = completion_sink

    @classmethod
    def from_settings(
        cls, *, app_settings: Settings = settings,
        ai_window_selector: Callable[[PolicyResolution], AIWindowDecision] | None = None,
        completion_sink: Callable[[Session, tuple[AICompletionRecord, ...]], None] | None = None,
    ) -> "MqttIsolationForestStage":
        configured = (app_settings.mqtt_if_artifact_dir.strip(),
                      app_settings.mqtt_if_expected_model_version.strip(),
                      app_settings.mqtt_if_expected_bundle_sha256.strip())
        artifact = None
        if any(configured):
            if not all(configured):
                raise ValueError("MQTT_IF_ARTIFACT_DIR, MQTT_IF_EXPECTED_MODEL_VERSION and "
                                 "MQTT_IF_EXPECTED_BUNDLE_SHA256 must be configured together")
            require_observe_trust_mode(app_settings.trust_ai_mode)
            inspection = inspect_mqtt_if_bundle(
                Path(configured[0]), expected_model_version=configured[1],
                expected_bundle_sha256=configured[2],
            )
            artifact = load_inspected_mqtt_if_artifact(inspection)
        return cls(artifact=artifact, ai_window_selector=ai_window_selector,
                   completion_sink=completion_sink, trust_ai_mode=app_settings.trust_ai_mode)

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
        if self.ai_window_selector is not None and self.artifact is None:
            # OFF is a policy decision, not proof that an enabled model stage
            # is healthy. A missing/broken model must not advance its CP.
            load_model(self.model_path)
        before = _checkpoint_before(db, self.detector_name, self.source_table)
        require_processing_cutoff(db, cutoff)
        maintenance = maintenance_windows(db)
        device_ips = _registered_device_ips(db)
        resolver = load_policy_resolver(db)
        rows = _select_feature_rows(
            db,
            range_start=range_start,
            cutoff=cutoff,
        )

        created_count = 0
        last_processed_after = before["last_processed_id"]
        completion = AICompletionCollector(self.detector_name)
        for row in rows:
            source_id = int(row["id"])
            last_processed_after = _max_optional_id(last_processed_after, source_id)
            feature_row = dict(row)
            window_start = parse_db_utc(feature_row["window_start"], "window_start")
            device_id = str(feature_row["device_id"])
            completion.input(device_id, window_start)
            resolution = (
                resolver.resolve(str(feature_row["device_id"]), window_start)
                if resolver is not None else None
            )
            ai_decision = None
            if self.ai_window_selector is not None:
                if resolution is None:
                    raise RuntimeError("Phase 9 AI policy requires a registration snapshot")
                ai_decision = self.ai_window_selector(resolution)
                if not ai_decision.infer:
                    completion.exclude(device_id, window_start, ai_decision.reason,
                                       ai_revision=ai_decision.ai_revision,
                                       ai_mode=ai_decision.mode)
                    continue
            if overlaps_maintenance(maintenance, window_start, parse_db_utc(feature_row["window_end"], "window_end")):
                completion.exclude(device_id, window_start, "MAINTENANCE",
                                   ai_revision=ai_decision.ai_revision if ai_decision else None,
                                   ai_mode=ai_decision.mode if ai_decision else None)
                continue
            result = (predict_bundle_feature_window(feature_row, self.artifact)
                      if self.artifact is not None else predict_feature_window(feature_row, self.model_path))
            completion.inferred(
                device_id, window_start, anomaly=bool(result["is_anomaly"]),
                model_version=result.get("model_version"), bundle_sha256=result.get("bundle_sha256"),
                ai_revision=(ai_decision.ai_revision if ai_decision else None),
                ai_mode=(ai_decision.mode if ai_decision else None),
            )
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
                subject_ip=(
                    resolution.registration.ip_address
                    if resolution is not None and resolution.registration is not None
                    else device_ips.get(str(feature_row["device_id"])) if resolver is None else None
                ),
                evidence={
                    "source_type": self.source_table,
                    "source_id": source_id,
                    "detector_name": self.detector_name,
                    "observed_values": {
                        "prediction": result["prediction"],
                        "anomaly_score": result["anomaly_score"],
                    },
                    "thresholds": ({"anomaly_score": result["threshold"], "operator": "<"}
                                   if self.artifact is not None else {}),
                    "model_version": result.get("model_version"),
                    "bundle_sha256": result.get("bundle_sha256"),
                    "detection_policy_version": MQTT_IF_POLICY_VERSION,
                    **self.bundle_evidence,
                    **({key: result[key] for key in (
                        "raw_decision_score", "feature_values", "interval_is_fallback",
                    )} if self.artifact is not None else {}),
                    "device_ai_revision": (
                        ai_decision.ai_revision if ai_decision is not None else None
                    ),
                    "device_ai_mode": (
                        ai_decision.mode if ai_decision is not None else None
                    ),
                    "ai_approved_start": (
                        format_db_utc(ai_decision.approved_start)
                        if ai_decision is not None and ai_decision.approved_start is not None
                        else None
                    ),
                    "cycle_range_start": format_db_utc(range_start),
                    "cycle_cutoff": format_db_utc(cutoff),
                    "window_start": format_db_utc(window_start),
                    "registration_status_at_window": (
                        resolution.registration.status
                        if resolution is not None and resolution.registration is not None
                        else None
                    ),
                },
                feature_log_id=source_id,
            )
            if written.inserted:
                created_count += 1

        completion_records = completion.records(cutoff)
        if self.completion_sink is not None:
            self.completion_sink(db, completion_records)
        _advance_checkpoint(
            db,
            detector_name=self.detector_name,
            source_table=self.source_table,
            last_processed_id=last_processed_after,
            completed_window_end=cutoff,
            updated_at=cutoff,
        )
        return replace(_run_result(
            self.detector_name,
            self.source_table,
            range_start,
            cutoff,
            rows,
            created_count,
            before,
            last_processed_after,
        ), ai_completion_records=completion_records)


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
            SELECT id, device_id, topic, payload, received_at, is_json_valid
            FROM mqtt_logs
            WHERE unixepoch(received_at) >= unixepoch(:range_start)
              -- Include SQLite's rounded boundary second; Python applies the
              -- precise half-open interval to the original microsecond value.
              AND unixepoch(received_at) <= unixepoch(:cutoff)
            ORDER BY id ASC
            """
        ),
        {
            "range_start": format_db_utc(range_start),
            "cutoff": format_db_utc(cutoff),
        },
    ).mappings()
    selected = []
    for row in rows:
        source = dict(row)
        received_at = parse_db_utc(
            source["received_at"], "received_at", allow_subseconds=True
        )
        if range_start <= received_at < cutoff:
            selected.append(source)
    return selected


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
    device_policy: DevicePolicyRevision | None,
) -> dict[str, Any]:
    publish_limit = (
        device_policy.publish_count_max if device_policy else PUBLISH_COUNT_THRESHOLD
    )
    payload_limit = device_policy.payload_size_max if device_policy else LARGE_PAYLOAD_BYTES
    thresholds = {
        "ABNORMAL_PUBLISH_RATE": {
            "publish_count": f"> {publish_limit}",
        },
        "LARGE_PAYLOAD": {"max_payload_size": f"> {payload_limit}"},
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
        "device_id": feature_row.get("device_id"),
        "device_policy_revision": device_policy.revision if device_policy else None,
        "window_start": feature_row.get("window_start"),
        "observed_value": (
            feature_row.get("publish_count") if event_type == "ABNORMAL_PUBLISH_RATE"
            else feature_row.get("max_payload_size") if event_type == "LARGE_PAYLOAD"
            else None
        ),
        "threshold": (
            publish_limit if event_type == "ABNORMAL_PUBLISH_RATE"
            else payload_limit if event_type == "LARGE_PAYLOAD"
            else None
        ),
        "unit": (
            "messages/10s" if event_type == "ABNORMAL_PUBLISH_RATE"
            else "bytes" if event_type == "LARGE_PAYLOAD" else None
        ),
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
