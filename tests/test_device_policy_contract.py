"""device-policy-v1 입력 검증과 UTC 시각 규칙(순수 함수) 검증."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import pytest

from edge.policy.device_policy import (
    DevicePolicy,
    DevicePolicyValidationError,
    IpRegistrationPolicy,
    floor_to_window,
    format_utc_millis,
    format_utc_seconds,
    next_effective_boundary,
    parse_effective_from,
    validate_actor,
    validate_device_id,
    validate_device_type,
    validate_mqtt_principal,
    validate_policy,
    validate_reason,
    validate_registration_ip,
    validate_registration_state,
    validate_revision_number,
)
from tests.device_policy_support import LAN_POLICY, POLICY


def policy_with(**changes):
    return {**POLICY, **changes}


# ── 정책 값 ──────────────────────────────────────────────────────────────────


class TestValidatePolicy:
    def test_valid_policy_round_trips(self) -> None:
        policy = validate_policy(POLICY)

        assert isinstance(policy, DevicePolicy)
        assert policy.as_dict() == POLICY

    def test_integer_is_accepted_for_real_fields_and_normalized_to_float(self) -> None:
        policy = validate_policy(
            policy_with(
                expected_publish_interval_seconds=5,
                packet_rate_max_pps=10,
                byte_rate_max_bytes_per_second=2500,
            )
        )

        assert policy.expected_publish_interval_seconds == 5.0
        assert type(policy.packet_rate_max_pps) is float

    def test_upper_limits_are_accepted(self) -> None:
        validate_policy(
            policy_with(
                expected_publish_interval_seconds=86400,
                publish_count_max=10000,
                payload_size_max_bytes=1048576,
                packet_rate_max_pps=100000,
                byte_rate_max_bytes_per_second=125000000,
            )
        )

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("publish_count_max", True),  # bool은 정수가 아니다
            ("publish_count_max", "15"),  # 숫자 문자열 묵시 변환 금지
            ("publish_count_max", 15.0),  # 정수 필드에 소수 형태 금지
            ("publish_count_max", 15.5),
            ("publish_count_max", 0),
            ("publish_count_max", -1),
            ("publish_count_max", 10001),
            ("publish_count_max", None),
            ("payload_size_max_bytes", 0),
            ("payload_size_max_bytes", 1048577),
            ("expected_publish_interval_seconds", 0),  # 0은 "탐지 끄기"가 아니다
            ("expected_publish_interval_seconds", -5),
            ("expected_publish_interval_seconds", 86401),
            ("expected_publish_interval_seconds", True),
            ("expected_publish_interval_seconds", "5"),
            ("packet_rate_max_pps", 0),
            ("packet_rate_max_pps", 100001),
            ("packet_rate_max_pps", float("nan")),
            ("packet_rate_max_pps", float("inf")),
            ("packet_rate_max_pps", -float("inf")),
            ("byte_rate_max_bytes_per_second", 0.0),
            ("byte_rate_max_bytes_per_second", 125000001),
            ("byte_rate_max_bytes_per_second", None),
            # float로 표현할 수 없는 매우 큰 정수도 OverflowError가 아닌 검증 오류여야 한다
            ("expected_publish_interval_seconds", 10**400),
            ("packet_rate_max_pps", 10**400),
            ("packet_rate_max_pps", -(10**400)),
            ("byte_rate_max_bytes_per_second", 10**400),
            ("publish_count_max", 10**400),
            ("payload_size_max_bytes", 10**400),
        ],
    )
    def test_invalid_value_is_rejected_with_field_name(self, field, value) -> None:
        with pytest.raises(DevicePolicyValidationError) as caught:
            validate_policy(policy_with(**{field: value}))

        assert caught.value.field == field

    def test_extra_and_missing_fields_are_rejected(self) -> None:
        with pytest.raises(DevicePolicyValidationError, match="unsupported"):
            validate_policy(policy_with(trust_score=100))
        incomplete = dict(POLICY)
        del incomplete["publish_count_max"]
        with pytest.raises(DevicePolicyValidationError, match="missing"):
            validate_policy(incomplete)

    def test_profile_must_be_the_single_template(self) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_policy(policy_with(policy_profile="ai-observe-v1"))

    def test_non_mapping_is_rejected(self) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_policy([POLICY])  # type: ignore[arg-type]


# ── 식별자·텍스트 ────────────────────────────────────────────────────────────


class TestIdentifiers:
    @pytest.mark.parametrize("value", ["esp32_01", "pico-01", "A", "a" * 64, "9x"])
    def test_valid_device_id(self, value) -> None:
        assert validate_device_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "a" * 65,
            "_a",
            "-a",
            "a b",
            "a/b",
            "a+b",
            "a#b",
            "abc\n",  # fullmatch라 끝 개행을 통과시키지 않는다
            "한글",
            "a\x00b",
            None,
            123,
        ],
    )
    def test_invalid_device_id(self, value) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_device_id(value)

    @pytest.mark.parametrize("value", ["pico_01", "a.b-c_d", "x" * 128])
    def test_valid_principal(self, value) -> None:
        assert validate_mqtt_principal(value) == value

    @pytest.mark.parametrize("value", ["", ".a", "a b", "a/b", "x" * 129, "p\n", None])
    def test_invalid_principal(self, value) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_mqtt_principal(value)

    def test_device_type_and_state_are_closed_sets(self) -> None:
        assert validate_device_type("SENSOR") == "SENSOR"
        assert validate_registration_state("DISABLED") == "DISABLED"
        for bad in ("sensor", "ROUTER", None):
            with pytest.raises(DevicePolicyValidationError):
                validate_device_type(bad)
        for bad in ("pending", "NORMAL", None):
            with pytest.raises(DevicePolicyValidationError):
                validate_registration_state(bad)


class TestTextAndRevisionNumber:
    def test_reason_is_trimmed(self) -> None:
        assert validate_reason("  증적 ID TEST-1  ") == "증적 ID TEST-1"

    @pytest.mark.parametrize("value", ["", "   ", "a" * 501, "line1\nline2", "tab\there", "x\x00", 5, None])
    def test_invalid_reason(self, value) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_reason(value)

    def test_reason_limit_is_inclusive(self) -> None:
        assert len(validate_reason("a" * 500)) == 500

    def test_actor_is_required(self) -> None:
        assert validate_actor("recovery-admin") == "recovery-admin"
        with pytest.raises(DevicePolicyValidationError):
            validate_actor("  ")

    @pytest.mark.parametrize("value", [0, -1, 2147483648, True, 1.0, "1", None])
    def test_invalid_expected_revision(self, value) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_revision_number(value)

    def test_valid_expected_revision_bounds(self) -> None:
        assert validate_revision_number(1) == 1
        assert validate_revision_number(2147483647) == 2147483647


# ── IP ───────────────────────────────────────────────────────────────────────


class TestRegistrationIp:
    @pytest.mark.parametrize("value", ["192.168.0.6", "192.168.0.254"])
    def test_lan_host_is_accepted(self, value) -> None:
        assert validate_registration_ip(value, LAN_POLICY) == value

    @pytest.mark.parametrize(
        "value",
        [
            "8.8.8.8",  # 공인
            "127.0.0.1",  # loopback
            "169.254.1.1",  # link-local
            "::1",  # IPv6
            "192.168.000.6",  # 앞자리 0
            " 192.168.0.6",
            "192.168.0.6 ",
            "192.168.0.256",
            "192.168.0",
            "192.168.0.0",  # 네트워크 주소
            "192.168.0.255",  # 브로드캐스트
            "192.168.0.1",  # 제외(관리/보호) 주소
            "192.168.1.5",  # 허용 LAN 밖의 사설 주소
            "172.32.0.1",  # RFC1918 밖
            "",
            None,
            3232235526,
            True,
        ],
    )
    def test_invalid_ip_is_rejected(self, value) -> None:
        with pytest.raises(DevicePolicyValidationError):
            validate_registration_ip(value, LAN_POLICY)

    def test_without_network_only_rfc1918_and_exclusions_apply(self) -> None:
        policy = IpRegistrationPolicy(excluded=frozenset({ipaddress.IPv4Address("10.0.0.9")}))

        assert validate_registration_ip("10.1.2.3", policy) == "10.1.2.3"
        assert validate_registration_ip("172.16.5.5", policy) == "172.16.5.5"
        for bad in ("10.0.0.9", "11.0.0.1", "172.32.0.1"):
            with pytest.raises(DevicePolicyValidationError):
                validate_registration_ip(bad, policy)


# ── 시각 ─────────────────────────────────────────────────────────────────────


class TestUtcRules:
    @pytest.mark.parametrize(
        ("now", "expected"),
        [
            # 계약 4절 예시: 엄격히 다음 10초 경계
            (datetime(2026, 10, 2, 0, 0, 9, 900000, tzinfo=timezone.utc), "2026-10-02T00:00:10Z"),
            (datetime(2026, 10, 2, 0, 0, 10, tzinfo=timezone.utc), "2026-10-02T00:00:20Z"),
            (datetime(2026, 10, 2, 0, 0, 0, tzinfo=timezone.utc), "2026-10-02T00:00:10Z"),
            (datetime(2026, 10, 2, 0, 0, 59, 999999, tzinfo=timezone.utc), "2026-10-02T00:01:00Z"),
            (datetime(2026, 10, 2, 23, 59, 55, tzinfo=timezone.utc), "2026-10-03T00:00:00Z"),
        ],
    )
    def test_next_effective_boundary_is_strictly_after_now(self, now, expected) -> None:
        assert format_utc_seconds(next_effective_boundary(now)) == expected

    def test_non_utc_offset_is_converted(self) -> None:
        kst = timezone(timedelta(hours=9))
        now = datetime(2026, 10, 2, 9, 0, 3, tzinfo=kst)

        assert format_utc_seconds(next_effective_boundary(now)) == "2026-10-02T00:00:10Z"

    def test_naive_datetime_is_rejected_instead_of_guessed(self) -> None:
        with pytest.raises(DevicePolicyValidationError):
            next_effective_boundary(datetime(2026, 10, 2, 0, 0, 3))

    def test_floor_to_window(self) -> None:
        value = datetime(2026, 10, 2, 0, 0, 17, 5000, tzinfo=timezone.utc)

        assert floor_to_window(value) == datetime(2026, 10, 2, 0, 0, 10, tzinfo=timezone.utc)

    def test_format_utc_seconds_rejects_fractional_seconds(self) -> None:
        with pytest.raises(DevicePolicyValidationError):
            format_utc_seconds(datetime(2026, 10, 2, 0, 0, 10, 1, tzinfo=timezone.utc))

    def test_format_utc_millis(self) -> None:
        value = datetime(2026, 10, 2, 0, 0, 3, 123456, tzinfo=timezone.utc)

        assert format_utc_millis(value) == "2026-10-02T00:00:03.123Z"

    def test_parse_effective_from_accepts_boundary_only(self) -> None:
        assert parse_effective_from("2026-10-02T00:00:10Z") == datetime(
            2026, 10, 2, 0, 0, 10, tzinfo=timezone.utc
        )
        for bad in (
            "2026-10-02T00:00:13Z",  # 경계 아님
            "2026-10-02T00:00:10",  # Z 없음
            "2026-10-02 00:00:10Z",
            "2026-10-02T00:00:10.000Z",  # 소수 초
            "2026-13-02T00:00:10Z",  # 없는 달
            "2026-10-02T00:00:10+00:00",
            "",
            None,
        ):
            with pytest.raises(DevicePolicyValidationError):
                parse_effective_from(bad)
