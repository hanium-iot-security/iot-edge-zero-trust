"""Packet Rule Detector stage (P4-2-01).

  - 입력은 packet_feature_logs·packet_capture_segments Timing Metadata다.
  - Timing Metadata가 존재하고 공통 is_capture_eligible()이 적격으로 판정한
    Row만 사용한다 (Packet IF·Dataset Export와 동일 공통 함수 공유).
  - Raw Count가 아니라 packets_per_second = packet_count / captured_duration_seconds,
    bytes_per_second = total_bytes / captured_duration_seconds로 비교한다.
  - 미매핑 IP(device_id NULL)도 Event를 저장한다 (Trust 단계에서 점수·격리에는
    반영하지 않음).
  - NON_MQTT_TRAFFIC은 목적지 Port 목록 Feature가 아직 없어 Phase 4 Required
    Rule에서 비활성화한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
import logging
from math import isfinite
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.detection_event_writer import write_detection_event
from edge.detection.detector_contract import DetectorRunResult, validate_cycle_window
from edge.detection.phase4_time import format_db_utc, parse_db_utc
from edge.detection.rule_detector import DETECTOR_RULE
from edge.packet.capture_policy import (
    CaptureEligibilityResult,
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)
from edge.trust.trust_policy import BROKER_DOS_SUSPECTED, BYTE_RATE_ANOMALY, PACKET_RATE_ANOMALY, PORT_SCAN


logger = logging.getLogger(__name__)

PACKET_RULE_DETECTOR_NAME = "packet_rule"
PACKET_RULE_SOURCE_TABLE = "packet_feature_logs"

_SEVERITY_BY_EVENT = {
    PACKET_RATE_ANOMALY: "medium",
    BYTE_RATE_ANOMALY: "medium",
    PORT_SCAN: "high",
    BROKER_DOS_SUSPECTED: "high",
}


@dataclass(frozen=True)
class PacketRulePolicy:
    """Versioned Packet Rule Policy.

    Pilot 실측 P95/P99가 나오기 전까지의 잠정 임계값이다. 실제 정상 분포가
    확인되면 조정하되, 바꿀 때는 반드시 version도 함께 올려서 Evidence에 어떤
    Policy Version으로 판정됐는지 남긴다 (Policy Version, Session,
    표본 수, P95·P99, Commit을 기록한다).
    """

    packet_rate_threshold: float
    byte_rate_threshold: float
    port_scan_distinct_port_threshold: int
    port_scan_syn_threshold: int
    broker_dos_tcp_syn_threshold: int
    broker_dos_mqtt_packet_threshold: int
    version: str
    packet_rate_excluded_peer_ips: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for name in ("packet_rate_threshold", "byte_rate_threshold"):
            value = getattr(self, name)
            if not isfinite(value) or value < 0:
                raise ValueError(f"{name} must be a finite non-negative number, got {value!r}")
        for name in (
            "port_scan_distinct_port_threshold",
            "port_scan_syn_threshold",
            "broker_dos_tcp_syn_threshold",
            "broker_dos_mqtt_packet_threshold",
        ):
            value = getattr(self, name)
            if value < 0:
                raise ValueError(f"{name} must be >= 0, got {value!r}")
        if not self.version:
            raise ValueError("version must be a non-empty Packet Rule Policy Version string")

    @classmethod
    def from_env(cls) -> "PacketRulePolicy":
        from backend.app.config import settings

        return cls(
            packet_rate_threshold=settings.packet_rule_packet_rate_threshold,
            byte_rate_threshold=settings.packet_rule_byte_rate_threshold,
            port_scan_distinct_port_threshold=settings.packet_rule_port_scan_distinct_port_threshold,
            port_scan_syn_threshold=settings.packet_rule_port_scan_syn_threshold,
            broker_dos_tcp_syn_threshold=settings.packet_rule_broker_dos_tcp_syn_threshold,
            broker_dos_mqtt_packet_threshold=settings.packet_rule_broker_dos_mqtt_packet_threshold,
            version=settings.packet_rule_policy_version,
            packet_rate_excluded_peer_ips=_parse_packet_rate_excluded_peer_ips(
                settings.packet_rule_packet_rate_excluded_peer_ips
            ),
        )


def _parse_packet_rate_excluded_peer_ips(raw_value: str) -> frozenset[str]:
    """쉼표로 구분된 Packet Rate 제외 Peer IP를 검증·정규화한다.

    빈 값은 기존 Packet Rule 동작을 유지하기 위해 빈 집합으로 처리한다.
    잘못된 IP는 탐지 예외가 조용히 잘못 적용되지 않도록 fail-fast 한다.
    """
    normalized: set[str] = set()

    for part in raw_value.split(","):
        candidate = part.strip()

        if not candidate:
            continue

        try:
            parsed = ip_address(candidate)
        except ValueError as exc:
            raise ValueError(
                "packet_rate_excluded_peer_ips contains invalid IP address: "
                f"{candidate!r}"
            ) from exc

        normalized.add(str(parsed))

    return frozenset(normalized)


DEFAULT_PACKET_RULE_POLICY = PacketRulePolicy(
    packet_rate_threshold=50.0,
    byte_rate_threshold=100_000.0,
    port_scan_distinct_port_threshold=15,
    port_scan_syn_threshold=15,
    broker_dos_tcp_syn_threshold=30,
    broker_dos_mqtt_packet_threshold=100,
    version="packet-rule-policy-v2",
)


def effective_packets_per_second(packet_count: float, captured_duration_seconds: float) -> float:
    """packets_per_second = packet_count / captured_duration_seconds.

    Packet IF의 10초 정규화(normalize_to_ten_second_rate)와 다른 계산식이다 --
    Packet Rule은 "Raw Count가 아니라" 이 값을 그대로 비교 기준으로 쓴다.
    """
    if captured_duration_seconds <= 0:
        raise ValueError("captured_duration_seconds must be > 0; caller must filter with is_capture_eligible() first")
    return packet_count / captured_duration_seconds


def effective_bytes_per_second(total_bytes: float, captured_duration_seconds: float) -> float:
    """bytes_per_second = total_bytes / captured_duration_seconds."""
    if captured_duration_seconds <= 0:
        raise ValueError("captured_duration_seconds must be > 0; caller must filter with is_capture_eligible() first")
    return total_bytes / captured_duration_seconds


def detect_packet_rules(
    row: dict[str, Any],
    policy: PacketRulePolicy = DEFAULT_PACKET_RULE_POLICY,
) -> list[dict[str, Any]]:
    """packet_feature_logs row(+captured_duration_seconds)에서 Rule 이벤트 목록을 반환합니다.

    DB 접근 없는 순수 함수. 호출 전에 is_capture_eligible()로 이미 적격 판정이
    끝난 Row만 넘겨야 한다 (captured_duration_seconds > 0이 보장되어야 함).

    NON_MQTT_TRAFFIC은 목적지 Port 목록 Feature가 아직 없어 이 함수에서
    판정하지 않는다 (Phase 4 Required Rule에서는 비활성화한다).
    """
    events: list[dict[str, Any]] = []
    duration = float(row["captured_duration_seconds"])

    packets_per_second = effective_packets_per_second(float(row["packet_count"]), duration)
    peer_ip = str(row.get("peer_ip") or "")
    if (
        packets_per_second > policy.packet_rate_threshold
        and peer_ip not in policy.packet_rate_excluded_peer_ips
    ):
        events.append(
            {
                "event_type": PACKET_RATE_ANOMALY,
                "severity": _SEVERITY_BY_EVENT[PACKET_RATE_ANOMALY],
                "observed_value": packets_per_second,
                "threshold": policy.packet_rate_threshold,
            }
        )

    bytes_per_second = effective_bytes_per_second(float(row["total_bytes"]), duration)
    if bytes_per_second > policy.byte_rate_threshold:
        events.append(
            {
                "event_type": BYTE_RATE_ANOMALY,
                "severity": _SEVERITY_BY_EVENT[BYTE_RATE_ANOMALY],
                "observed_value": bytes_per_second,
                "threshold": policy.byte_rate_threshold,
            }
        )

    distinct_dest_port_count = int(row["distinct_dest_port_count"])
    tcp_syn_count = int(row["tcp_syn_count"])

    if (
        distinct_dest_port_count > policy.port_scan_distinct_port_threshold
        and tcp_syn_count > policy.port_scan_syn_threshold
    ):
        events.append(
            {
                "event_type": PORT_SCAN,
                "severity": _SEVERITY_BY_EVENT[PORT_SCAN],
                "observed_value": {
                    "distinct_dest_port_count": distinct_dest_port_count,
                    "tcp_syn_count": tcp_syn_count,
                },
                "threshold": {
                    "distinct_dest_port_count": policy.port_scan_distinct_port_threshold,
                    "tcp_syn_count": policy.port_scan_syn_threshold,
                },
            }
        )

    mqtt_related_packet_count = int(row["mqtt_related_packet_count"])
    if (
        tcp_syn_count > policy.broker_dos_tcp_syn_threshold
        and mqtt_related_packet_count > policy.broker_dos_mqtt_packet_threshold
    ):
        events.append(
            {
                "event_type": BROKER_DOS_SUSPECTED,
                "severity": _SEVERITY_BY_EVENT[BROKER_DOS_SUSPECTED],
                "observed_value": {
                    "tcp_syn_count": tcp_syn_count,
                    "mqtt_related_packet_count": mqtt_related_packet_count,
                },
                "threshold": {
                    "tcp_syn_count": policy.broker_dos_tcp_syn_threshold,
                    "mqtt_related_packet_count": policy.broker_dos_mqtt_packet_threshold,
                },
            }
        )

    return events


class PacketRuleDetectorStage:
    detector_name = PACKET_RULE_DETECTOR_NAME
    source_table = PACKET_RULE_SOURCE_TABLE

    def __init__(
        self,
        *,
        capture_policy: CapturePolicy | None = None,
        rule_policy: PacketRulePolicy | None = None,
    ) -> None:
        self.capture_policy = capture_policy or CapturePolicy.from_env()
        self.rule_policy = rule_policy or PacketRulePolicy.from_env()

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

        created_count = 0
        last_processed_after = before["last_processed_id"]
        excluded_count = 0

        for row in rows:
            source_id = int(row["id"])
            last_processed_after = _max_optional_id(last_processed_after, source_id)
            _validate_source_window(row)

            eligibility = _capture_eligibility(row, self.capture_policy)
            if not eligibility.eligible:
                excluded_count += 1
                continue

            window_start = parse_db_utc(row["window_start"], "window_start")
            window_end = parse_db_utc(row["window_end"], "window_end")

            for event in detect_packet_rules(row, self.rule_policy):
                # 미매핑 IP는 Event만 저장하고 점수·격리를 변경하지 않는다. device_id가 없어도 Event는 그대로 저장한다.
                written = write_detection_event(
                    db,
                    device_id=row["device_id"],
                    detector_name=self.detector_name,
                    source_table=self.source_table,
                    source_id=source_id,
                    detector_type=DETECTOR_RULE,
                    event_type=event["event_type"],
                    severity=event["severity"],
                    description=(
                        f"Packet Rule {event['event_type']}: "
                        f"observed={event['observed_value']}, threshold={event['threshold']}"
                    ),
                    policy_version=self.rule_policy.version,
                    detected_at=cutoff,
                    analysis_window_start=window_start,
                    analysis_window_end=window_end,
                    subject_ip=str(row["peer_ip"]),
                    evidence=_event_evidence(
                        row=row,
                        event=event,
                        eligibility=eligibility,
                        capture_policy=self.capture_policy,
                        rule_policy=self.rule_policy,
                        range_start=range_start,
                        cutoff=cutoff,
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
        if excluded_count:
            logger.info(
                "Packet Rule excluded %d ineligible source rows (Timing Metadata "
                "missing or Capture Policy 미충족)",
                excluded_count,
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
        detector_name=PACKET_RULE_DETECTOR_NAME,
        source_table=PACKET_RULE_SOURCE_TABLE,
    )
    if row is None:
        return {"last_processed_id": None, "last_completed_window_end": None}
    return {
        "last_processed_id": row["last_processed_id"],
        "last_completed_window_end": (
            parse_db_utc(row["last_completed_window_end"], "last_completed_window_end")
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
    # Packet Rule은 등록 Device 여부와 무관하게 INBOUND 트래픽 전체를 대상으로
    # 한다 (미매핑 IP도 Event 저장 대상, Packet IF보다 넓은 범위). PORT_SCAN·
    # BROKER_DOS_SUSPECTED 판정은 Pi로 "들어오는" 트래픽이 대상이므로
    # direction=INBOUND로 제한한다.
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
                pfl.distinct_dest_port_count,
                pfl.tcp_syn_count,
                pfl.mqtt_related_packet_count,
                pcs.window_start AS segment_window_start,
                pcs.window_end AS segment_window_end,
                pcs.status AS segment_status,
                pcs.error_code AS segment_error_code,
                pcs.start_delay_seconds,
                pcs.captured_duration_seconds,
                pcss.session_id
            FROM packet_feature_logs pfl
            JOIN packet_capture_segments pcs
                ON pcs.id = pfl.capture_segment_id
            JOIN packet_capture_sessions pcss
                ON pcss.id = pcs.capture_session_id
            WHERE pfl.direction = 'INBOUND'
              AND unixepoch(pfl.window_start) >= unixepoch(:range_start)
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
                WHERE pfl.direction = 'INBOUND'
                  AND unixepoch(pfl.window_start) >= unixepoch(:range_start)
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
            "Packet Rule source rows include unexpected Capture Session(s): "
            + ", ".join(sorted(unexpected))
            + f"; expected={expected_capture_session_id}"
        )


def _validate_source_window(row: dict[str, Any]) -> None:
    """packet_feature_logs의 Window가 자신의 Capture Segment Window와 정확히
    일치하는지 확인한다 (Packet IF와 동일한 방어적 무결성 검증)."""
    feature_start = parse_db_utc(row["window_start"], "window_start")
    feature_end = parse_db_utc(row["window_end"], "window_end")
    segment_start = parse_db_utc(row["segment_window_start"], "segment_window_start")
    segment_end = parse_db_utc(row["segment_window_end"], "segment_window_end")
    if feature_start != segment_start or feature_end != segment_end:
        raise ValueError("Packet Feature window must match its Capture Segment window")


def _validate_single_capture_session(rows: list[dict[str, Any]]) -> None:
    """Packet Session Gap 이전·이후 Row를 한 Cycle에 섞지 않는다.

    Packet IF뿐 아니라 모든 Required Detector에 적용되는 일반 규칙이므로 Packet
    Rule도 동일하게 검증한다.
    """
    session_ids = {str(row["session_id"]) for row in rows}
    if len(session_ids) > 1:
        raise RuntimeError(
            "Packet Rule cycle must not mix Capture Sessions: "
            + ", ".join(sorted(session_ids))
        )


def _capture_session_id(rows: list[dict[str, Any]]) -> str | None:
    if not rows:
        return None
    return str(rows[0]["session_id"])


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


def _event_evidence(
    *,
    row: dict[str, Any],
    event: dict[str, Any],
    eligibility: CaptureEligibilityResult,
    capture_policy: CapturePolicy,
    rule_policy: PacketRulePolicy,
    range_start: datetime,
    cutoff: datetime,
) -> dict[str, Any]:
    return {
        "source_type": PACKET_RULE_SOURCE_TABLE,
        "source_id": int(row["id"]),
        "capture_segment_id": int(row["capture_segment_id"]),
        "capture_session_id": str(row["session_id"]),
        "detector_name": PACKET_RULE_DETECTOR_NAME,
        "observed_value": event["observed_value"],
        "threshold": event["threshold"],
        "raw_counts": {
            "packet_count": row["packet_count"],
            "total_bytes": row["total_bytes"],
            "distinct_dest_port_count": row["distinct_dest_port_count"],
            "tcp_syn_count": row["tcp_syn_count"],
            "mqtt_related_packet_count": row["mqtt_related_packet_count"],
        },
        "captured_duration_seconds": row["captured_duration_seconds"],
        "capture_coverage_ratio": eligibility.coverage_ratio,
        "capture_policy": {
            "version": capture_policy.version,
            "max_start_delay_seconds": capture_policy.max_start_delay_seconds,
            "minimum_duration_seconds": capture_policy.minimum_duration_seconds,
            "epsilon_seconds": capture_policy.epsilon_seconds,
        },
        "rule_policy_version": rule_policy.version,
        "cycle_range_start": format_db_utc(range_start),
        "cycle_cutoff": format_db_utc(cutoff),
    }


def _max_optional_id(current: int | None, candidate: int) -> int:
    return candidate if current is None else max(current, candidate)