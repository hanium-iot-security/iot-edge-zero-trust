"""Packet Detector를 Orchestrator에서 안전하게 실행하기 위한 Ready Range Gate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.detector_contract import (
    DetectorRunResult,
    DetectorStage,
    validate_cycle_window,
)
from edge.detection.phase4_time import format_db_utc
from edge.packet.capture_session_repository import (
    PacketFeatureReadiness,
    get_packet_feature_ready_through,
)


class PacketFeatureRangeNotReadyError(RuntimeError):
    """요청 범위를 한 Capture Session의 완료 Prefix로 처리할 수 없습니다."""


def get_packet_feature_readiness_for_range_start(
    db: Session,
    *,
    range_start: datetime,
) -> PacketFeatureReadiness | None:
    """range_start를 포함하는 가장 최근 Capture Session의 준비 상태를 조회합니다."""
    session_id = db.execute(
        text(
            """
            SELECT session_id
            FROM packet_capture_sessions
            WHERE first_window_start IS NOT NULL
              AND unixepoch(first_window_start) <= unixepoch(:range_start)
            ORDER BY unixepoch(first_window_start) DESC, id DESC
            LIMIT 1
            """
        ),
        {"range_start": format_db_utc(range_start)},
    ).scalar()
    if session_id is None:
        return None
    return get_packet_feature_ready_through(db, session_id=str(session_id))


def require_packet_feature_ready_range(
    db: Session,
    *,
    cycle_range_start: datetime,
    cycle_cutoff: datetime,
) -> PacketFeatureReadiness:
    """요청 범위가 단일 Session의 검증된 Packet Feature Prefix인지 검증합니다.

    공식 감사로 승인된 단일 FAILED Window만 Prefix에 포함될 수 있습니다. READY,
    미승인 실패, 누락·겹침 또는 잘못된 Feature가 있으면 Stage 실행 전에 거부합니다.
    """
    range_start, cutoff = validate_cycle_window(
        cycle_range_start=cycle_range_start,
        cycle_cutoff=cycle_cutoff,
    )
    readiness = get_packet_feature_readiness_for_range_start(
        db,
        range_start=range_start,
    )
    if readiness is None or readiness.first_window_start is None:
        raise PacketFeatureRangeNotReadyError(
            "no Capture Session covers the Packet Detector range start: "
            f"range_start={format_db_utc(range_start)}"
        )

    ready_through = readiness.packet_feature_ready_through
    if ready_through is None:
        raise PacketFeatureRangeNotReadyError(
            "Capture Session has no contiguous PROCESSED/EMPTY Packet Feature prefix: "
            f"session_id={readiness.session_id}, "
            f"range_start={format_db_utc(range_start)}"
        )
    if cutoff > ready_through:
        raise PacketFeatureRangeNotReadyError(
            "Packet Detector cutoff exceeds the contiguous Packet Feature ready range: "
            f"session_id={readiness.session_id}, "
            f"cutoff={format_db_utc(cutoff)}, "
            f"packet_feature_ready_through={format_db_utc(ready_through)}"
        )
    params = {
        "session_id": readiness.session_id,
        "range_start": format_db_utc(range_start),
        "cutoff": format_db_utc(cutoff),
    }
    overlapping_session = db.execute(
        text(
            """
            SELECT pcsg.id
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
            WHERE unixepoch(pcsg.window_start) < unixepoch(:cutoff)
              AND unixepoch(pcsg.window_end) > unixepoch(:range_start)
              AND pcs.session_id != :session_id
            LIMIT 1
            """
        ),
        params,
    ).first()
    invalid_feature = db.execute(
        text(
            """
            SELECT pfl.id
            FROM packet_feature_logs pfl
            LEFT JOIN packet_capture_segments pcsg ON pcsg.id = pfl.capture_segment_id
            LEFT JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
            WHERE (
                (unixepoch(pfl.window_start) < unixepoch(:cutoff)
                 AND unixepoch(pfl.window_end) > unixepoch(:range_start))
                OR (unixepoch(pcsg.window_start) < unixepoch(:cutoff)
                    AND unixepoch(pcsg.window_end) > unixepoch(:range_start))
            ) AND (
                pcsg.id IS NULL OR pcs.session_id != :session_id
                OR pcsg.status != 'PROCESSED' OR pcsg.error_code IS NOT NULL
                OR pfl.window_start != pcsg.window_start
                OR pfl.window_end != pcsg.window_end
            )
            LIMIT 1
            """
        ),
        params,
    ).first()
    if overlapping_session is not None or invalid_feature is not None:
        raise PacketFeatureRangeNotReadyError(
            "Packet Detector range contains overlapping capture segments or "
            "unapproved Packet Feature rows: "
            f"session_id={readiness.session_id}, "
            f"range_start={format_db_utc(range_start)}, cutoff={format_db_utc(cutoff)}"
        )
    return readiness


@dataclass(frozen=True)
class PacketFeatureReadyStage:
    """Packet Stage 앞에 Ready Range Gate를 적용하는 Orchestrator Adapter."""

    delegate: DetectorStage

    @property
    def detector_name(self) -> str:
        return self.delegate.detector_name

    @property
    def source_table(self) -> str:
        return self.delegate.source_table

    def run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
    ) -> DetectorRunResult:
        readiness = require_packet_feature_ready_range(
            db,
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
        )
        session_bound_runner = getattr(
            self.delegate,
            "run_until_for_capture_session",
            None,
        )
        if session_bound_runner is None:
            raise TypeError(
                f"{self.detector_name} must implement "
                "run_until_for_capture_session()"
            )
        return session_bound_runner(
            db,
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
            expected_capture_session_id=readiness.session_id,
        )
