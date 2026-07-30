"""Phase 4 Packet Isolation Forest detector stage."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import logging
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

from ai.packet_if_contract import (
    PACKET_IF_FEATURES,
    PACKET_IF_FEATURE_VERSION,
    PACKET_IF_NOMINAL_WINDOW_SECONDS,
    PACKET_IF_PACKET_COUNT_FORMULA,
    PACKET_IF_THRESHOLD_OPERATOR,
    PACKET_IF_TOTAL_BYTES_FORMULA,
    PACKET_IF_TRANSFORM_VERSION,
)
from ai.predict_packet_isolation_forest import (
    PacketIFArtifact,
    PacketIFPrediction,
    load_packet_if_artifact,
    predict_packet_feature_rows,
)
from backend.app.config import Settings, settings
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.detection_event_writer import write_detection_event
from edge.detection.detector_contract import DetectorRunResult, validate_cycle_window
from edge.detection.phase4_time import format_db_utc, parse_db_utc
from edge.detection.rule_detector import DETECTOR_AI
from edge.packet.capture_policy import (
    CaptureEligibilityResult,
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)
from edge.trust.trust_policy import AI_ONLY, AI_PACKET_ANOMALY


logger = logging.getLogger(__name__)

PACKET_IF_DETECTOR_NAME = "packet_if"
PACKET_IF_SOURCE_TABLE = "packet_feature_logs"
PACKET_IF_RUNTIME_POLICY_VERSION = "packet-if-runtime-v1"

PredictionFunction = Callable[
    [PacketIFArtifact, list[dict[str, Any]]],
    tuple[PacketIFPrediction, ...],
]


class PacketIsolationForestStage:
    detector_name = PACKET_IF_DETECTOR_NAME
    source_table = PACKET_IF_SOURCE_TABLE

    def __init__(
        self,
        *,
        artifact: PacketIFArtifact,
        expected_model_version: str,
        capture_policy: CapturePolicy,
        predict_rows: PredictionFunction = predict_packet_feature_rows,
    ) -> None:
        expected_version = expected_model_version.strip()
        if not expected_version:
            raise ValueError("PACKET_IF_EXPECTED_MODEL_VERSION must be configured")
        if artifact.model_version != expected_version:
            raise ValueError(
                "Packet IF model version mismatch: "
                f"expected={expected_version!r}, actual={artifact.model_version!r}"
            )

        if artifact.capture_policy != capture_policy:
            raise ValueError(
                "Packet IF Capture Policy mismatch: "
                f"expected={capture_policy!r}, "
                f"actual={artifact.capture_policy!r}"
            )

        self.artifact = artifact
        self.capture_policy = capture_policy
        self.predict_rows = predict_rows
        self.policy_version = (
            f"{PACKET_IF_RUNTIME_POLICY_VERSION}:{artifact.model_version}:"
            f"{artifact.bundle_sha256[:12]}"
        )

    @classmethod
    def from_settings(
        cls,
        *,
        app_settings: Settings | None = None,
        artifact_dir: Path | None = None,
        expected_model_version: str | None = None,
        expected_bundle_sha256: str | None = None,
        capture_policy: CapturePolicy | None = None,
    ) -> "PacketIsolationForestStage":
        configured_settings = app_settings or settings
        configured_path = (
            str(artifact_dir)
            if artifact_dir is not None
            else configured_settings.packet_if_artifact_dir.strip()
        )
        if not configured_path:
            raise ValueError("PACKET_IF_ARTIFACT_DIR must be configured")
        expected_version = (
            expected_model_version
            if expected_model_version is not None
            else configured_settings.packet_if_expected_model_version
        )
        expected_version = expected_version.strip()
        if not expected_version:
            raise ValueError(
                "PACKET_IF_EXPECTED_MODEL_VERSION must be configured"
            )
        expected_bundle = (
            expected_bundle_sha256
            if expected_bundle_sha256 is not None
            else configured_settings.packet_if_expected_bundle_sha256
        )
        expected_bundle = expected_bundle.strip()
        if not expected_bundle:
            raise ValueError(
                "PACKET_IF_EXPECTED_BUNDLE_SHA256 must be configured"
            )
        return cls(
            artifact=load_packet_if_artifact(
                Path(configured_path),
                expected_bundle_sha256=expected_bundle,
                expected_model_version=expected_version,
            ),
            expected_model_version=expected_version,
            capture_policy=capture_policy
            or CapturePolicy(
                max_start_delay_seconds=(
                    configured_settings.pcap_max_start_delay_seconds
                ),
                minimum_duration_seconds=(
                    configured_settings.packet_min_capture_duration_seconds
                ),
                epsilon_seconds=configured_settings.capture_time_epsilon_seconds,
                version=configured_settings.capture_policy_version,
            ),
        )

    def run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
    ) -> DetectorRunResult:
        return self._run_until(
            db,
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
            expected_capture_session_id=None,
        )

    def run_until_for_capture_session(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
        expected_capture_session_id: str,
    ) -> DetectorRunResult:
        return self._run_until(
            db,
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
            expected_capture_session_id=expected_capture_session_id,
        )

    def _run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
        expected_capture_session_id: str | None,
    ) -> DetectorRunResult:
        range_start, cutoff = validate_cycle_window(
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
        )
        before = _checkpoint_before(db)
        if expected_capture_session_id is not None:
            _validate_expected_capture_session(
                db,
                range_start=range_start,
                cutoff=cutoff,
                expected_capture_session_id=expected_capture_session_id,
            )
        rows = _select_packet_feature_rows(
            db,
            range_start=range_start,
            cutoff=cutoff,
            expected_capture_session_id=expected_capture_session_id,
        )
        _validate_single_capture_session(rows)

        eligible_rows: list[dict[str, Any]] = []
        eligible_source_rows: list[dict[str, Any]] = []
        exclusion_reasons: Counter[str] = Counter()
        last_processed_after = before["last_processed_id"]

        for row in rows:
            source_id = int(row["id"])
            last_processed_after = _max_optional_id(
                last_processed_after,
                source_id,
            )
            _validate_source_window(row)
            eligibility = _runtime_eligibility(row, self.capture_policy)
            if not eligibility.eligible:
                exclusion_reasons[str(eligibility.exclusion_reason)] += 1
                continue
            eligible_source_rows.append(row)
            eligible_rows.append(_prediction_row(row))

        predictions = self.predict_rows(self.artifact, eligible_rows)
        if len(predictions) != len(eligible_source_rows):
            raise RuntimeError(
                "Packet IF predictor returned a different number of results"
            )

        created_count = 0
        for row, prediction in zip(
            eligible_source_rows,
            predictions,
            strict=True,
        ):
            if not prediction.is_anomaly:
                continue
            source_id = int(row["id"])
            window_start = parse_db_utc(row["window_start"], "window_start")
            window_end = parse_db_utc(row["window_end"], "window_end")
            eligibility = _capture_eligibility(row, self.capture_policy)
            written = write_detection_event(
                db,
                device_id=str(row["device_id"]),
                detector_name=self.detector_name,
                source_table=self.source_table,
                source_id=source_id,
                detector_type=DETECTOR_AI,
                event_type=AI_PACKET_ANOMALY,
                severity="medium",
                description=(
                    "Packet Isolation Forest anomaly: "
                    f"score={prediction.anomaly_score:.6f}, "
                    f"threshold={prediction.threshold:.6f}"
                ),
                policy_version=self.policy_version,
                detected_at=cutoff,
                analysis_window_start=window_start,
                analysis_window_end=window_end,
                incident_family=AI_ONLY,
                subject_ip=str(row["peer_ip"]),
                evidence=_event_evidence(
                    row=row,
                    prediction=prediction,
                    eligibility=eligibility,
                    capture_policy=self.capture_policy,
                    bundle_sha256=self.artifact.bundle_sha256,
                    range_start=range_start,
                    cutoff=cutoff,
                    policy_version=self.policy_version,
                ),
                packet_feature_log_id=source_id,
            )
            if written.inserted:
                created_count += 1

        checkpoints.upsert_detector_checkpoint(
            db,
            detector_name=self.detector_name,
            source_table=self.source_table,
            last_processed_id=last_processed_after,
            last_completed_window_end=cutoff,
            updated_at=cutoff,
        )
        if exclusion_reasons:
            logger.info(
                "Packet IF excluded source rows: %s",
                dict(sorted(exclusion_reasons.items())),
            )

        return DetectorRunResult(
            detector_name=self.detector_name,
            source_table=self.source_table,
            range_start=range_start,
            cutoff=cutoff,
            selected_count=len(rows),
            created_event_count=created_count,
            last_processed_id_before=before["last_processed_id"],
            last_processed_id_after=last_processed_after,
            completed_window_end_before=before["last_completed_window_end"],
            completed_window_end_after=cutoff,
            capture_session_id=(
                expected_capture_session_id
                if expected_capture_session_id is not None
                else _capture_session_id(rows)
            ),
        )


def _checkpoint_before(db: Session) -> dict[str, Any]:
    row = checkpoints.get_detector_checkpoint(
        db,
        detector_name=PACKET_IF_DETECTOR_NAME,
        source_table=PACKET_IF_SOURCE_TABLE,
    )
    if row is None:
        return {
            "last_processed_id": None,
            "last_completed_window_end": None,
        }
    return {
        "last_processed_id": row["last_processed_id"],
        "last_completed_window_end": (
            parse_db_utc(
                row["last_completed_window_end"],
                "last_completed_window_end",
            )
            if row["last_completed_window_end"] is not None
            else None
        ),
    }


def _select_packet_feature_rows(
    db: Session,
    *,
    range_start: datetime,
    cutoff: datetime,
    expected_capture_session_id: str | None = None,
) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT
                pfl.id,
                pfl.capture_segment_id,
                pfl.device_id,
                pfl.peer_ip,
                pfl.direction,
                pfl.window_start,
                pfl.window_end,
                pfl.packet_count,
                pfl.total_bytes,
                pfl.avg_packet_size,
                pfl.max_packet_size,
                pfl.mean_inter_arrival_time,
                pfl.distinct_dest_port_count,
                pcs.window_start AS segment_window_start,
                pcs.window_end AS segment_window_end,
                pcs.status AS segment_status,
                pcs.error_code AS segment_error_code,
                pcs.start_delay_seconds,
                pcs.captured_duration_seconds,
                pcss.session_id,
                d.device_id AS registered_device_id,
                d.ip_address AS registered_ip_address
            FROM packet_feature_logs pfl
            JOIN packet_capture_segments pcs
                ON pcs.id = pfl.capture_segment_id
            JOIN packet_capture_sessions pcss
                ON pcss.id = pcs.capture_session_id
            LEFT JOIN devices d
                ON d.device_id = pfl.device_id
            WHERE unixepoch(pfl.window_start) >= unixepoch(:range_start)
              AND unixepoch(pfl.window_end) <= unixepoch(:cutoff)
              AND (
                    :expected_capture_session_id IS NULL
                    OR pcss.session_id = :expected_capture_session_id
              )
            ORDER BY pfl.id ASC
            """
        ),
        {
            "range_start": format_db_utc(range_start),
            "cutoff": format_db_utc(cutoff),
            "expected_capture_session_id": expected_capture_session_id,
        },
    ).mappings()
    return [dict(row) for row in rows]


def _validate_expected_capture_session(
    db: Session,
    *,
    range_start: datetime,
    cutoff: datetime,
    expected_capture_session_id: str,
) -> None:
    session_ids = {
        str(value)
        for value in db.execute(
            text(
                """
                SELECT DISTINCT pcss.session_id
                FROM packet_feature_logs pfl
                JOIN packet_capture_segments pcs
                    ON pcs.id = pfl.capture_segment_id
                JOIN packet_capture_sessions pcss
                    ON pcss.id = pcs.capture_session_id
                WHERE unixepoch(pfl.window_start) >= unixepoch(:range_start)
                  AND unixepoch(pfl.window_end) <= unixepoch(:cutoff)
                """
            ),
            {
                "range_start": format_db_utc(range_start),
                "cutoff": format_db_utc(cutoff),
            },
        ).scalars()
    }
    unexpected = session_ids - {expected_capture_session_id}
    if unexpected:
        raise RuntimeError(
            "Packet IF source rows include unexpected Capture Session(s): "
            + ", ".join(sorted(unexpected))
            + f"; expected={expected_capture_session_id}"
        )


def _validate_source_window(row: dict[str, Any]) -> None:
    feature_start = parse_db_utc(row["window_start"], "window_start")
    feature_end = parse_db_utc(row["window_end"], "window_end")
    segment_start = parse_db_utc(
        row["segment_window_start"],
        "segment_window_start",
    )
    segment_end = parse_db_utc(row["segment_window_end"], "segment_window_end")
    if feature_start != segment_start or feature_end != segment_end:
        raise ValueError(
            "Packet Feature window must match its Capture Segment window"
        )


def _validate_single_capture_session(rows: list[dict[str, Any]]) -> None:
    session_ids = {
        str(row["session_id"])
        for row in rows
    }
    if len(session_ids) > 1:
        raise RuntimeError(
            "Packet IF cycle must not mix Capture Sessions: "
            + ", ".join(sorted(session_ids))
        )


def _capture_session_id(rows: list[dict[str, Any]]) -> str | None:
    if not rows:
        return None
    return str(rows[0]["session_id"])


def _runtime_eligibility(
    row: dict[str, Any],
    capture_policy: CapturePolicy,
) -> CaptureEligibilityResult:
    if row["direction"] != "INBOUND":
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="direction_not_inbound",
            coverage_ratio=None,
        )
    if row["device_id"] is None or row["registered_device_id"] is None:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="device_not_registered",
            coverage_ratio=None,
        )
    if (
        row["registered_ip_address"] is None
        or str(row["registered_ip_address"]) != str(row["peer_ip"])
    ):
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="device_ip_mapping_changed",
            coverage_ratio=None,
        )
    return _capture_eligibility(row, capture_policy)


def _capture_eligibility(
    row: dict[str, Any],
    capture_policy: CapturePolicy,
) -> CaptureEligibilityResult:
    return is_capture_eligible(
        CaptureEligibilitySegment(
            status=str(row["segment_status"]),
            error_code=row["segment_error_code"],
            start_delay_seconds=row["start_delay_seconds"],
            captured_duration_seconds=row["captured_duration_seconds"],
        ),
        capture_policy,
    )


def _prediction_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "packet_count": row["packet_count"],
        "total_bytes": row["total_bytes"],
        "avg_packet_size": row["avg_packet_size"],
        "max_packet_size": row["max_packet_size"],
        "mean_inter_arrival_time": row["mean_inter_arrival_time"],
        "distinct_dest_port_count": row["distinct_dest_port_count"],
        "captured_duration_seconds": row["captured_duration_seconds"],
    }


def _event_evidence(
    *,
    row: dict[str, Any],
    prediction: PacketIFPrediction,
    eligibility: CaptureEligibilityResult,
    capture_policy: CapturePolicy,
    bundle_sha256: str,
    range_start: datetime,
    cutoff: datetime,
    policy_version: str,
) -> dict[str, Any]:
    normalized_values = dict(zip(PACKET_IF_FEATURES, prediction.feature_values))
    return {
        "source_type": PACKET_IF_SOURCE_TABLE,
        "source_id": int(row["id"]),
        "capture_segment_id": int(row["capture_segment_id"]),
        "capture_session_id": str(row["session_id"]),
        "detector_name": PACKET_IF_DETECTOR_NAME,
        "observed_values": _prediction_row(row),
        "normalized_values": normalized_values,
        "capture_coverage_ratio": eligibility.coverage_ratio,
        "model": {
            "model_version": prediction.model_version,
            "bundle_sha256": bundle_sha256,
            "raw_decision_score": prediction.raw_decision_score,
            "anomaly_score": prediction.anomaly_score,
            "threshold": prediction.threshold,
            "threshold_operator": PACKET_IF_THRESHOLD_OPERATOR,
            "feature_version": PACKET_IF_FEATURE_VERSION,
            "transform_version": PACKET_IF_TRANSFORM_VERSION,
        },
        "capture_policy": {
            "version": capture_policy.version,
            "nominal_window_seconds": PACKET_IF_NOMINAL_WINDOW_SECONDS,
            "max_start_delay_seconds": capture_policy.max_start_delay_seconds,
            "minimum_duration_seconds": capture_policy.minimum_duration_seconds,
            "epsilon_seconds": capture_policy.epsilon_seconds,
            "minimum_coverage_ratio": (
                capture_policy.minimum_duration_seconds
                / PACKET_IF_NOMINAL_WINDOW_SECONDS
            ),
        },
        "normalization": {
            "version": PACKET_IF_TRANSFORM_VERSION,
            "packet_count_formula": PACKET_IF_PACKET_COUNT_FORMULA,
            "total_bytes_formula": PACKET_IF_TOTAL_BYTES_FORMULA,
        },
        "policy_version": policy_version,
        "cycle_range_start": format_db_utc(range_start),
        "cycle_cutoff": format_db_utc(cutoff),
    }


def _max_optional_id(current: int | None, candidate: int) -> int:
    return candidate if current is None else max(current, candidate)
