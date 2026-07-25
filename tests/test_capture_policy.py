"""edge/packet/capture_policy.py 단위 테스트 (DB/파일시스템 미사용).

Phase 4 세부계획 2.1 절의 공통 적격 함수 계약을 검증합니다.
"""

from datetime import datetime, timezone

import pytest

from edge.packet.capture_policy import (
    CaptureEligibilitySegment,
    CapturePolicy,
    compute_coverage_ratio,
    compute_effective_capture_window,
    derive_minimum_duration_seconds,
    is_capture_eligible,
    normalize_to_ten_second_rate,
)


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


DEFAULT_POLICY = CapturePolicy()


def _segment(
    *,
    status: str = "PROCESSED",
    error_code: str | None = None,
    start_delay_seconds: float | None = 0.0,
    captured_duration_seconds: float | None = 9.5,
) -> CaptureEligibilitySegment:
    return CaptureEligibilitySegment(
        status=status,
        error_code=error_code,
        start_delay_seconds=start_delay_seconds,
        captured_duration_seconds=captured_duration_seconds,
    )


class TestDeriveMinimumDurationSeconds:
    def test_default_max_start_delay_yields_nine_seconds(self) -> None:
        assert derive_minimum_duration_seconds(1.0) == 9.0

    def test_zero_max_start_delay_yields_full_window(self) -> None:
        assert derive_minimum_duration_seconds(0.0) == 10.0


class TestCapturePolicyDefaults:
    def test_default_policy_matches_phase4_baseline(self) -> None:
        policy = CapturePolicy()
        assert policy.max_start_delay_seconds == 1.0
        assert policy.minimum_duration_seconds == 9.0
        assert policy.epsilon_seconds == 0.01
        assert policy.version == "packet-capture-policy-v1"

    def test_rejects_negative_values(self) -> None:
        with pytest.raises(ValueError):
            CapturePolicy(max_start_delay_seconds=-0.1)
        with pytest.raises(ValueError):
            CapturePolicy(minimum_duration_seconds=-0.1)
        with pytest.raises(ValueError):
            CapturePolicy(epsilon_seconds=-0.1)

    def test_rejects_empty_version(self) -> None:
        with pytest.raises(ValueError):
            CapturePolicy(version="")


class TestComputeCoverageRatio:
    def test_full_window(self) -> None:
        assert compute_coverage_ratio(10.0) == 1.0

    def test_partial_window(self) -> None:
        assert compute_coverage_ratio(9.0) == pytest.approx(0.9)

    def test_none_when_duration_missing(self) -> None:
        assert compute_coverage_ratio(None) is None

    def test_is_a_display_value_not_used_for_eligibility(self) -> None:
        """coverage_ratio가 0.9 이상이어도, 원본 값이 policy 경계 미만이면 부적격이어야 한다.
        적격 판정은 반올림된 coverage_ratio가 아니라 원본 Timing Metadata를 기준으로 한다.
        """
        # captured_duration_seconds=8.995 -> coverage_ratio는 반올림하면 0.9로
        # 보일 수 있지만 minimum_duration_seconds(9.0) - epsilon(0.01) = 8.99보다
        # 작으므로 부적격이어야 한다.
        segment = _segment(captured_duration_seconds=8.98)
        result = is_capture_eligible(segment, DEFAULT_POLICY)
        assert result.eligible is False
        assert result.exclusion_reason == "captured_duration_below_policy"


class TestIsCaptureEligibleStatus:
    @pytest.mark.parametrize("status", ["PROCESSED", "EMPTY"])
    def test_eligible_statuses(self, status: str) -> None:
        result = is_capture_eligible(_segment(status=status), DEFAULT_POLICY)
        assert result.eligible is True
        assert result.exclusion_reason is None

    @pytest.mark.parametrize("status", ["READY", "FAILED"])
    def test_ineligible_statuses(self, status: str) -> None:
        result = is_capture_eligible(_segment(status=status), DEFAULT_POLICY)
        assert result.eligible is False
        assert result.exclusion_reason == f"status_not_eligible:{status}"


class TestIsCaptureEligibleErrorCode:
    def test_error_code_present_is_excluded_even_if_status_ok(self) -> None:
        result = is_capture_eligible(
            _segment(status="PROCESSED", error_code="LATE_CAPTURE"), DEFAULT_POLICY
        )
        assert result.eligible is False
        assert result.exclusion_reason == "error_code_present:LATE_CAPTURE"


class TestIsCaptureEligibleMissingTimingMetadata:
    """Legacy Segment(Phase 4 이전 데이터)는 Timing Metadata가 NULL일 수 있다."""

    def test_missing_start_delay(self) -> None:
        result = is_capture_eligible(
            _segment(start_delay_seconds=None), DEFAULT_POLICY
        )
        assert result.eligible is False
        assert result.exclusion_reason == "missing_timing_metadata"

    def test_missing_captured_duration(self) -> None:
        result = is_capture_eligible(
            _segment(captured_duration_seconds=None), DEFAULT_POLICY
        )
        assert result.eligible is False
        assert result.exclusion_reason == "missing_timing_metadata"
        assert result.coverage_ratio is None


class TestIsCaptureEligibleStartDelayBoundary:
    def test_exactly_at_max_delay_is_eligible(self) -> None:
        result = is_capture_eligible(
            _segment(start_delay_seconds=1.0, captured_duration_seconds=9.0),
            DEFAULT_POLICY,
        )
        assert result.eligible is True

    def test_within_epsilon_above_max_delay_is_eligible(self) -> None:
        # epsilon=0.01이므로 1.005는 여전히 허용 범위.
        result = is_capture_eligible(
            _segment(start_delay_seconds=1.005, captured_duration_seconds=9.0),
            DEFAULT_POLICY,
        )
        assert result.eligible is True

    def test_beyond_epsilon_above_max_delay_is_excluded(self) -> None:
        result = is_capture_eligible(
            _segment(start_delay_seconds=1.02, captured_duration_seconds=9.0),
            DEFAULT_POLICY,
        )
        assert result.eligible is False
        assert result.exclusion_reason == "start_delay_exceeds_policy"


class TestIsCaptureEligibleDurationBoundary:
    def test_exactly_at_minimum_duration_is_eligible(self) -> None:
        result = is_capture_eligible(
            _segment(captured_duration_seconds=9.0), DEFAULT_POLICY
        )
        assert result.eligible is True

    def test_within_epsilon_below_minimum_is_eligible(self) -> None:
        result = is_capture_eligible(
            _segment(captured_duration_seconds=8.995), DEFAULT_POLICY
        )
        assert result.eligible is True

    def test_beyond_epsilon_below_minimum_is_excluded(self) -> None:
        result = is_capture_eligible(
            _segment(captured_duration_seconds=8.98), DEFAULT_POLICY
        )
        assert result.eligible is False
        assert result.exclusion_reason == "captured_duration_below_policy"

    def test_full_window_ten_seconds_is_eligible(self) -> None:
        result = is_capture_eligible(
            _segment(captured_duration_seconds=10.0), DEFAULT_POLICY
        )
        assert result.eligible is True
        assert result.coverage_ratio == 1.0


class TestIsCaptureEligibleExclusionOrderMatchesContractPriority:
    """exclusion_reason은 계약서의 and 절 순서대로 "가장 먼저 걸린 조건"을 가리켜야 한다."""

    def test_status_checked_before_error_code(self) -> None:
        result = is_capture_eligible(
            _segment(status="FAILED", error_code="LATE_CAPTURE"), DEFAULT_POLICY
        )
        assert result.exclusion_reason == "status_not_eligible:FAILED"

    def test_error_code_checked_before_timing_metadata(self) -> None:
        result = is_capture_eligible(
            _segment(error_code="PARTIAL_CAPTURE", start_delay_seconds=None),
            DEFAULT_POLICY,
        )
        assert result.exclusion_reason == "error_code_present:PARTIAL_CAPTURE"

    def test_timing_metadata_checked_before_delay_threshold(self) -> None:
        result = is_capture_eligible(
            _segment(start_delay_seconds=None, captured_duration_seconds=1.0),
            DEFAULT_POLICY,
        )
        assert result.exclusion_reason == "missing_timing_metadata"


class TestIsCaptureEligibleCustomPolicy:
    """Rule·IF·Dataset Export가 서로 다른 Policy 인스턴스를 사용해도 동일 로직으로 동작해야 한다."""

    def test_stricter_policy_excludes_previously_eligible_segment(self) -> None:
        strict_policy = CapturePolicy(
            max_start_delay_seconds=0.5,
            minimum_duration_seconds=9.5,
            epsilon_seconds=0.0,
            version="packet-capture-policy-v2-strict",
        )
        segment = _segment(start_delay_seconds=1.0, captured_duration_seconds=9.0)

        assert is_capture_eligible(segment, DEFAULT_POLICY).eligible is True
        result = is_capture_eligible(segment, strict_policy)
        assert result.eligible is False
        assert result.exclusion_reason == "start_delay_exceeds_policy"


class TestComputeEffectiveCaptureWindow:
    def test_no_delay_no_early_stop_yields_full_window(self) -> None:
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)

        effective_start, effective_end, duration = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=window_start,
            capture_stop_requested_at=window_end,
        )

        assert effective_start == window_start
        assert effective_end == window_end
        assert duration == pytest.approx(10.0)

    def test_late_start_shrinks_duration(self) -> None:
        """세부계획 2.1 절 예시: 명목 10:00:10~10:00:20, 실제 시작 10:00:11이면 약 9초."""
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        actual_start = _utc(2026, 7, 15, 10, 0, 11)

        _, _, duration = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=actual_start,
            capture_stop_requested_at=window_end,
        )

        assert duration == pytest.approx(9.0)

    def test_early_capture_start_is_clamped_to_window_start(self) -> None:
        """actual_capture_started_at이 window_start보다 이르더라도 window_start로 clamp."""
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        actual_start = _utc(2026, 7, 15, 10, 0, 9)

        effective_start, _, duration = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=actual_start,
            capture_stop_requested_at=window_end,
        )

        assert effective_start == window_start
        assert duration == pytest.approx(10.0)

    def test_late_stop_request_is_clamped_to_window_end(self) -> None:
        """capture_stop_requested_at이 window_end 이후라도 window_end로 clamp."""
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        late_stop = _utc(2026, 7, 15, 10, 0, 21)

        _, effective_end, duration = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=window_start,
            capture_stop_requested_at=late_stop,
        )

        assert effective_end == window_end
        assert duration == pytest.approx(10.0)

    def test_start_after_stop_requested_yields_zero_not_negative(self) -> None:
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        actual_start = _utc(2026, 7, 15, 10, 0, 20)
        stop_requested = _utc(2026, 7, 15, 10, 0, 19)

        _, _, duration = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=actual_start,
            capture_stop_requested_at=stop_requested,
        )

        assert duration == 0.0


class TestNormalizeToTenSecondRate:
    def test_full_window_is_unchanged(self) -> None:
        assert normalize_to_ten_second_rate(100.0, 10.0) == pytest.approx(100.0)

    def test_partial_window_scales_up(self) -> None:
        # 9초 동안 90개 packet -> 10초 환산하면 100개
        assert normalize_to_ten_second_rate(90.0, 9.0) == pytest.approx(100.0)

    def test_zero_duration_raises(self) -> None:
        with pytest.raises(ValueError):
            normalize_to_ten_second_rate(90.0, 0.0)

    def test_negative_duration_raises(self) -> None:
        with pytest.raises(ValueError):
            normalize_to_ten_second_rate(90.0, -1.0)