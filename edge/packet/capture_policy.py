"""Packet Capture 입력 적격 여부를 판정하는 공통 순수 함수.

    is_capture_eligible = (
        segment.status in {"PROCESSED", "EMPTY"}
        and segment.error_code is None
        and start_delay_seconds <= max_start_delay_seconds + epsilon_seconds
        and captured_duration_seconds >= minimum_duration_seconds - epsilon_seconds
    )

Packet Rule Detector, Packet Behavior Isolation Forest(Train/Validation/Test/
Inference), Dataset Export는 전부 이 모듈의 `is_capture_eligible()`을 통해서만
적격 여부를 판정하며, 각자 별도의 판정식을 만들지 않는다 (Packet Rule·Packet IF·Dataset Export는 
동일 공통 함수를 사용하고 API는 별도 판정식을 만들지 않고 동일 결과와 제외 이유를 노출한다).

적격 판정은 반올림된 coverage_ratio가 아니라 원본 Timing Metadata를 기준으로
한다. coverage_ratio는 표시·Evidence용 파생값으로만 사용한다.

이 모듈은 DB/파일시스템/네트워크에 접근하지 않는 순수 로직만 담는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import isfinite

NOMINAL_WINDOW_SECONDS = 10.0

DEFAULT_PCAP_MAX_START_DELAY_SECONDS = 1.0
DEFAULT_CAPTURE_TIME_EPSILON_SECONDS = 0.01
DEFAULT_CAPTURE_POLICY_VERSION = "packet-capture-policy-v1"

# is_capture_eligible의 status 조건에 해당하는 값들.
# READY는 아직 Feature 추출 전 상태이므로 여기 포함하지 않는다 (Detector는 PROCESSED/EMPTY의 연속 완료만 입력 준비 상태로 사용한다.
ELIGIBLE_SEGMENT_STATUSES = frozenset({"PROCESSED", "EMPTY"})


def derive_minimum_duration_seconds(max_start_delay_seconds: float) -> float:
    """PACKET_MIN_CAPTURE_DURATION_SECONDS = 10.0 - PCAP_MAX_START_DELAY_SECONDS.

    Phase 4 세부계획 2.1 절: "PACKET_MIN_CAPTURE_DURATION_SECONDS는 기본적으로
    10.0 - PCAP_MAX_START_DELAY_SECONDS에서 유도하며 Phase 4 기본값은 9.0초다."
    """
    return NOMINAL_WINDOW_SECONDS - max_start_delay_seconds


@dataclass(frozen=True)
class CapturePolicy:
    """Versioned Capture Policy.

    "최대 시작 지연·최소 Duration·Epsilon은 동일 Capture Policy Version으로
    기록한다" (2.1 절) — 이 값들은 항상 이 dataclass를 통째로 Evidence/Model
    Metadata에 함께 저장해야 하며 개별 값만 따로 기록하지 않는다.
    """

    max_start_delay_seconds: float = DEFAULT_PCAP_MAX_START_DELAY_SECONDS
    minimum_duration_seconds: float = derive_minimum_duration_seconds(
        DEFAULT_PCAP_MAX_START_DELAY_SECONDS
    )
    epsilon_seconds: float = DEFAULT_CAPTURE_TIME_EPSILON_SECONDS
    version: str = DEFAULT_CAPTURE_POLICY_VERSION

    def __post_init__(self) -> None:
        # NaN/Infinity는 <, >=, > 비교에서 항상 False를 반환하므로, 아래 min/max
        # 경계 체크만으로는 걸러지지 않는다. isfinite()로 먼저 명시적으로 걷어낸다.
        for field_name in ("max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds"):
            value = getattr(self, field_name)
            if not isfinite(value):
                raise ValueError(f"{field_name} must be a finite number, got {value!r}")

        if not (0 <= self.max_start_delay_seconds < NOMINAL_WINDOW_SECONDS):
            raise ValueError(
                f"max_start_delay_seconds must be in [0, {NOMINAL_WINDOW_SECONDS}), "
                f"got {self.max_start_delay_seconds}"
            )
        if not (0 <= self.minimum_duration_seconds <= NOMINAL_WINDOW_SECONDS):
            raise ValueError(
                f"minimum_duration_seconds must be in [0, {NOMINAL_WINDOW_SECONDS}], "
                f"got {self.minimum_duration_seconds}"
            )
        if not (0 <= self.epsilon_seconds < 1.0):
            raise ValueError(f"epsilon_seconds must be in [0, 1.0), got {self.epsilon_seconds}")
        if not self.version:
            raise ValueError("version must be a non-empty Capture Policy Version string")

    @classmethod
    def from_env(cls) -> "CapturePolicy":
        from backend.app.config import settings

        return cls(
            max_start_delay_seconds=settings.pcap_max_start_delay_seconds,
            minimum_duration_seconds=settings.packet_min_capture_duration_seconds,
            epsilon_seconds=settings.capture_time_epsilon_seconds,
            version=settings.capture_policy_version,
        )


DEFAULT_CAPTURE_POLICY = CapturePolicy()


@dataclass(frozen=True)
class CaptureEligibilitySegment:
    """is_capture_eligible 판정에 필요한 Segment 필드만 담는 최소 입력 뷰.

    packet_capture_segments row, Packet IF 학습용 DataFrame row 등 어떤
    출처에서든 이 형태로만 변환하면 동일한 판정 결과를 얻을 수 있다.
    """

    status: str
    error_code: str | None
    start_delay_seconds: float | None
    captured_duration_seconds: float | None


@dataclass(frozen=True)
class CaptureEligibilityResult:
    eligible: bool
    # eligible=True이면 None. eligible=False이면 왜 제외됐는지 나타내는 짧은 코드.
    # Packet Rule·Packet IF·Dataset Export·API가 모두 이 코드를 그대로 노출해야
    # 동일 결과와 제외 이유를 공유한다는 계약을 지킬 수 있다.
    exclusion_reason: str | None
    # 표시·Evidence용 파생값. 적격 판정 자체에는 쓰이지 않는다.
    coverage_ratio: float | None


def compute_coverage_ratio(captured_duration_seconds: float | None) -> float | None:
    """coverage_ratio = captured_duration_seconds / 10.0."""
    if captured_duration_seconds is None:
        return None
    return captured_duration_seconds / NOMINAL_WINDOW_SECONDS


def is_capture_eligible(
    segment: CaptureEligibilitySegment,
    policy: CapturePolicy = DEFAULT_CAPTURE_POLICY,
) -> CaptureEligibilityResult:
    """공통 적격 함수.

    판정 순서는 Evidence의 exclusion_reason이 항상 "가장 먼저 걸린 조건"을
    가리키도록 계약서의 and 절 순서를 그대로 따른다.
    """
    coverage_ratio = compute_coverage_ratio(segment.captured_duration_seconds)

    if segment.status not in ELIGIBLE_SEGMENT_STATUSES:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason=f"status_not_eligible:{segment.status}",
            coverage_ratio=coverage_ratio,
        )

    if segment.error_code is not None:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason=f"error_code_present:{segment.error_code}",
            coverage_ratio=coverage_ratio,
        )

    # Legacy Segment(Phase 4 이전 데이터)는 Timing Metadata가 NULL일 수 있다.
    # "Timing Metadata가 없거나 공통 함수가 부적격으로 판정한 Legacy·지연·부분
    # Segment는 학습·추론·Trust 입력에서 제외하고 이유를 기록한다" (2.1 절).
    if segment.start_delay_seconds is None or segment.captured_duration_seconds is None:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="missing_timing_metadata",
            coverage_ratio=coverage_ratio,
        )

    # NaN/Infinity는 <, >=, > 비교에서 항상 False를 반환하므로 아래의 policy 경계
    # 비교만으로는 걸러지지 않는다 (예: NaN > threshold는 False이므로 "지연 초과 아님"
    # 으로 잘못 통과함). 여기서 명시적으로 걷어낸다.
    if not isfinite(segment.start_delay_seconds) or not isfinite(segment.captured_duration_seconds):
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="non_finite_timing_metadata",
            coverage_ratio=coverage_ratio,
        )

    if segment.start_delay_seconds < 0:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="negative_start_delay_seconds",
            coverage_ratio=coverage_ratio,
        )

    if not (0 <= segment.captured_duration_seconds <= NOMINAL_WINDOW_SECONDS):
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="captured_duration_out_of_range",
            coverage_ratio=coverage_ratio,
        )

    if segment.start_delay_seconds > policy.max_start_delay_seconds + policy.epsilon_seconds:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="start_delay_exceeds_policy",
            coverage_ratio=coverage_ratio,
        )

    if segment.captured_duration_seconds < policy.minimum_duration_seconds - policy.epsilon_seconds:
        return CaptureEligibilityResult(
            eligible=False,
            exclusion_reason="captured_duration_below_policy",
            coverage_ratio=coverage_ratio,
        )

    return CaptureEligibilityResult(eligible=True, exclusion_reason=None, coverage_ratio=coverage_ratio)


def compute_effective_capture_window(
    *,
    window_start: datetime,
    window_end: datetime,
    actual_capture_started_at: datetime,
    capture_stop_requested_at: datetime,
) -> tuple[datetime, datetime, float]:
    """정상 Capture의 Coverage 계산.

        effective_start = max(actual_capture_started_at, window_start)
        effective_end   = min(capture_stop_requested_at, window_end)
        captured_duration_seconds = max(0, effective_end - effective_start)

    capture_process_exited_at(OS 스케줄링·pcap flush로 늦어질 수 있는 실제 종료
    시각)은 운영·오류 분석용이며 이 계산에 포함하지 않는다.

    Returns:
        (effective_start, effective_end, captured_duration_seconds)
    """
    effective_start = max(actual_capture_started_at, window_start)
    effective_end = min(capture_stop_requested_at, window_end)
    captured_duration_seconds = max(0.0, (effective_end - effective_start).total_seconds())
    return effective_start, effective_end, captured_duration_seconds


def normalize_to_ten_second_rate(value: float, captured_duration_seconds: float) -> float:
    """실제 captured_duration_seconds 기준 값을 10초 명목 Window 기준으로 환산.

    Packet Rule의 packets_per_second/bytes_per_second, Packet IF의 packet_count/total_bytes 입력 모두 `value * 10.0 /
    captured_duration_seconds`로 10초 기준 환산하며 Train·Validation·Test·Inference에 동일한 변환을 적용한다.

    captured_duration_seconds가 0이면 정의되지 않으므로 이 함수를 호출하기 전에
    반드시 is_capture_eligible로 걸러야 한다 (정상 적격 Segment는
    captured_duration_seconds >= minimum_duration_seconds - epsilon > 0 이 보장됨).
    """
    if captured_duration_seconds <= 0:
        raise ValueError(
            "captured_duration_seconds must be > 0; caller must filter with "
            "is_capture_eligible() before normalizing rates"
        )
    return value * NOMINAL_WINDOW_SECONDS / captured_duration_seconds