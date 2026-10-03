"""기기 등록·정책 공유 계약(device-policy-v1)의 입력 검증, 시각 규칙, 오류 정의.

DB 접근이 없는 순수 모듈이다. Backend 명령 API와 Edge 저장소·resolver가 같은 검증과 같은
UTC 규칙을 쓰도록 한 곳에 둔다. 입력은 strict로 검사하며 묵시적 변환·보정을 하지 않는다.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


CONTRACT_VERSION = "device-policy-v1"
POLICY_PROFILE = "periodic-sensor-v1"
WINDOW_SECONDS = 10

DEVICE_TYPES = ("SENSOR", "CAMERA", "ACTUATOR", "OTHER")

STATE_PENDING = "PENDING"
STATE_ACTIVE = "ACTIVE"
STATE_DISABLED = "DISABLED"
REGISTRATION_STATES = (STATE_PENDING, STATE_ACTIVE, STATE_DISABLED)

# 상태를 바꾸는 전환. 같은 상태 유지(정책값만 변경)는 DISABLED를 제외하고 허용한다.
ALLOWED_STATE_TRANSITIONS = {
    STATE_PENDING: (STATE_PENDING, STATE_ACTIVE, STATE_DISABLED),
    STATE_ACTIVE: (STATE_ACTIVE, STATE_DISABLED),
    STATE_DISABLED: (),
}

# 계약 2절의 고정 입력 상한. 권장 탐지 임계값이나 Pi 처리 성능을 뜻하지 않는다.
EXPECTED_PUBLISH_INTERVAL_MAX_SECONDS = 86400
PUBLISH_COUNT_MAX_LIMIT = 10000
PAYLOAD_SIZE_MAX_LIMIT_BYTES = 1048576
PACKET_RATE_MAX_LIMIT_PPS = 100000
BYTE_RATE_MAX_LIMIT_BYTES_PER_SECOND = 125000000
REVISION_MAX = 2147483647
REASON_MAX_LENGTH = 500
ACTOR_MAX_LENGTH = 128

POLICY_FIELDS = (
    "policy_profile",
    "expected_publish_interval_seconds",
    "publish_count_max",
    "payload_size_max_bytes",
    "packet_rate_max_pps",
    "byte_rate_max_bytes_per_second",
)

_DEVICE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_PRINCIPAL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_EFFECTIVE_FROM_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

_PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


# ── 오류 ─────────────────────────────────────────────────────────────────────


class DevicePolicyError(Exception):
    """계약된 업무 오류. `code`는 API의 `detail.code`와 같은 값이다."""

    code = "DEVICE_POLICY_ERROR"

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.extra = extra

    def to_detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.extra}


class DevicePolicyValidationError(DevicePolicyError, ValueError):
    """입력 형식·범위 오류(API 422에 대응). 이 오류에서는 DB를 변경하지 않는다."""

    code = "VALIDATION_ERROR"

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message, field=field)
        self.field = field


class DeviceNotFoundError(DevicePolicyError):
    code = "DEVICE_NOT_FOUND"


class DeviceIdConflictError(DevicePolicyError):
    code = "DEVICE_ID_CONFLICT"


class DeviceIpConflictError(DevicePolicyError):
    code = "DEVICE_IP_CONFLICT"


class RevisionConflictError(DevicePolicyError):
    code = "REVISION_CONFLICT"

    def __init__(
        self,
        message: str,
        *,
        current_revision: int | None,
        pending_revision: int | None,
    ) -> None:
        super().__init__(
            message,
            current_revision=current_revision,
            pending_revision=pending_revision,
        )
        self.current_revision = current_revision
        self.pending_revision = pending_revision


class PendingRevisionExistsError(DevicePolicyError):
    code = "PENDING_REVISION_EXISTS"

    def __init__(
        self,
        message: str,
        *,
        current_revision: int | None,
        pending_revision: int,
    ) -> None:
        super().__init__(
            message,
            current_revision=current_revision,
            pending_revision=pending_revision,
        )
        self.current_revision = current_revision
        self.pending_revision = pending_revision


class NoPolicyChangeError(DevicePolicyError):
    code = "NO_POLICY_CHANGE"


class StateTransitionBlockedError(DevicePolicyError):
    code = "STATE_TRANSITION_BLOCKED"


class PolicyWriteBusyError(DevicePolicyError):
    """다른 연결이 쓰기 잠금을 쥐고 있어 제한 시간 안에 얻지 못했다. 전체가 rollback된다."""

    code = "POLICY_WRITE_BUSY"


class PolicyUnavailableError(DevicePolicyError):
    """등록된 기기에 정책 Revision이 없다. 임의 기본값으로 보정하지 않는다."""

    code = "POLICY_UNAVAILABLE"


class BackfillBlockedError(DevicePolicyError):
    """기존 기기 이관 사전 조건이 충족되지 않았다. 아무것도 변경하지 않는다."""

    code = "BACKFILL_BLOCKED"

    def __init__(self, message: str, *, problems: tuple[str, ...]) -> None:
        super().__init__(message, problems=list(problems))
        self.problems = problems


# ── 정책 값 ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DevicePolicy:
    """기기별 네 임계값과 설명용 주기. 불변 스냅샷이다."""

    policy_profile: str
    expected_publish_interval_seconds: float
    publish_count_max: int
    payload_size_max_bytes: int
    packet_rate_max_pps: float
    byte_rate_max_bytes_per_second: float

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in POLICY_FIELDS}


def _field_error(field: str, message: str) -> DevicePolicyValidationError:
    return DevicePolicyValidationError(f"{field}: {message}", field=field)


def _require_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    # bool은 int의 하위 타입이므로 type()으로 정확히 비교한다. 15.0·"15"도 거부한다.
    if type(value) is not int:
        raise _field_error(field, "must be an integer")
    if not minimum <= value <= maximum:
        raise _field_error(field, f"must be between {minimum} and {maximum}")
    return value


def _require_positive_real(value: Any, field: str, *, maximum: float) -> float:
    if type(value) not in (int, float):
        raise _field_error(field, "must be a number")
    try:
        number = float(value)
    except OverflowError:  # float로 표현할 수 없는 매우 큰 정수
        raise _field_error(field, f"must be greater than 0 and at most {maximum}") from None
    if not math.isfinite(number):
        raise _field_error(field, "must be finite")
    if not 0 < number <= maximum:
        raise _field_error(field, f"must be greater than 0 and at most {maximum}")
    return number


def validate_policy(raw: Mapping[str, Any] | DevicePolicy) -> DevicePolicy:
    """정책 입력을 strict하게 검사한다. 모든 필드가 필요하고 미지원 필드는 거부한다."""
    if isinstance(raw, DevicePolicy):
        raw = raw.as_dict()
    if not isinstance(raw, Mapping):
        raise _field_error("policy", "must be an object")

    unknown = sorted(str(key) for key in raw if key not in POLICY_FIELDS)
    if unknown:
        raise _field_error("policy", f"unsupported fields: {unknown}")
    missing = [name for name in POLICY_FIELDS if name not in raw]
    if missing:
        raise _field_error("policy", f"missing fields: {missing}")

    profile = raw["policy_profile"]
    if type(profile) is not str or profile != POLICY_PROFILE:
        raise _field_error("policy_profile", f"must be {POLICY_PROFILE!r}")

    return DevicePolicy(
        policy_profile=profile,
        expected_publish_interval_seconds=_require_positive_real(
            raw["expected_publish_interval_seconds"],
            "expected_publish_interval_seconds",
            maximum=EXPECTED_PUBLISH_INTERVAL_MAX_SECONDS,
        ),
        publish_count_max=_require_int(
            raw["publish_count_max"],
            "publish_count_max",
            minimum=1,
            maximum=PUBLISH_COUNT_MAX_LIMIT,
        ),
        payload_size_max_bytes=_require_int(
            raw["payload_size_max_bytes"],
            "payload_size_max_bytes",
            minimum=1,
            maximum=PAYLOAD_SIZE_MAX_LIMIT_BYTES,
        ),
        packet_rate_max_pps=_require_positive_real(
            raw["packet_rate_max_pps"],
            "packet_rate_max_pps",
            maximum=PACKET_RATE_MAX_LIMIT_PPS,
        ),
        byte_rate_max_bytes_per_second=_require_positive_real(
            raw["byte_rate_max_bytes_per_second"],
            "byte_rate_max_bytes_per_second",
            maximum=BYTE_RATE_MAX_LIMIT_BYTES_PER_SECOND,
        ),
    )


# ── 식별자·텍스트 ────────────────────────────────────────────────────────────


def validate_device_id(value: Any) -> str:
    if type(value) is not str or _DEVICE_ID_PATTERN.fullmatch(value) is None:
        raise _field_error(
            "device_id", "must be 1-64 ASCII letters, digits, '_' or '-' starting with alphanumeric"
        )
    return value


def validate_mqtt_principal(value: Any) -> str:
    if type(value) is not str or _PRINCIPAL_PATTERN.fullmatch(value) is None:
        raise _field_error(
            "mqtt_principal",
            "must be 1-128 ASCII letters, digits, '_', '.' or '-' starting with alphanumeric",
        )
    return value


def require_lookup_id(value: Any, field: str = "device_id") -> str:
    """조회용 ID. 기존 기기와 호환되도록 형식 규칙은 적용하지 않고 문자열인지, DB에 바인딩할 수
    있는 UTF-8 텍스트인지만 확인한다."""
    if type(value) is not str:
        raise _field_error(field, "must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise _field_error(field, "must be valid UTF-8 text") from None
    return value


def validate_device_type(value: Any) -> str:
    if type(value) is not str or value not in DEVICE_TYPES:
        raise _field_error("device_type", f"must be one of {list(DEVICE_TYPES)}")
    return value


def validate_registration_state(value: Any) -> str:
    if type(value) is not str or value not in REGISTRATION_STATES:
        raise _field_error("registration_state", f"must be one of {list(REGISTRATION_STATES)}")
    return value


def _require_text(value: Any, field: str, *, max_length: int) -> str:
    if type(value) is not str:
        raise _field_error(field, "must be a string")
    text = value.strip()
    if not 1 <= len(text) <= max_length:
        raise _field_error(field, f"must be 1-{max_length} characters after trimming")
    if any(unicodedata.category(char).startswith("C") for char in text):
        raise _field_error(field, "must not contain control characters")
    return text


def validate_reason(value: Any) -> str:
    return _require_text(value, "reason", max_length=REASON_MAX_LENGTH)


def validate_actor(value: Any, field: str = "created_by") -> str:
    """작성자는 호출자가 서버 인증 결과에서 전달한다. 클라이언트가 보낸 이름을 쓰지 않는다."""
    return _require_text(value, field, max_length=ACTOR_MAX_LENGTH)


def validate_revision_number(value: Any, field: str = "expected_revision") -> int:
    return _require_int(value, field, minimum=1, maximum=REVISION_MAX)


# ── IP ───────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IpRegistrationPolicy:
    """등록 가능한 IP 범위.

    `network`는 운영자가 정한 실제 LAN(서버 설정, 요청 본문으로 받지 않는다)이다. None이면
    RFC1918과 정규 형식만 검사하며 seed/backfill 같은 신뢰된 경로에서만 쓴다. 관리자 API는
    LAN을 설정하지 않았을 때 쓰기를 503으로 거부하고 이 객체를 만들지 않는다.
    `excluded`에는 Pi/관리/보호/Packet 제외 주소를 합쳐 넣는다.
    """

    network: ipaddress.IPv4Network | None = None
    excluded: frozenset[ipaddress.IPv4Address] = frozenset()


def validate_registration_ip(value: Any, policy: IpRegistrationPolicy) -> str:
    if type(value) is not str:
        raise _field_error("ip_address", "must be a string")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise _field_error("ip_address", "must be an IPv4 address") from None
    if str(address) != value:
        raise _field_error("ip_address", f"must use the canonical form {str(address)!r}")
    if not any(address in network for network in _PRIVATE_NETWORKS):
        raise _field_error("ip_address", "must be an RFC1918 private address")

    network = policy.network
    if network is not None:
        if address not in network:
            raise _field_error("ip_address", f"must be inside the registration network {network}")
        if network.prefixlen < 31 and address in (network.network_address, network.broadcast_address):
            raise _field_error("ip_address", "must not be the network or broadcast address")
    if address in policy.excluded:
        raise _field_error("ip_address", "is a protected, management or excluded address")
    return value


# ── 시각 ─────────────────────────────────────────────────────────────────────


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def require_aware(value: datetime, field: str) -> datetime:
    """naive 시각을 UTC로 추정하지 않는다. 호출자가 UTC 기준을 명확히 해서 넘긴다."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise _field_error(field, "must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def floor_to_second(value: datetime) -> datetime:
    return require_aware(value, "time").replace(microsecond=0)


def floor_to_window(value: datetime) -> datetime:
    whole = floor_to_second(value)
    return whole.replace(second=(whole.second // WINDOW_SECONDS) * WINDOW_SECONDS)


def next_effective_boundary(now: datetime) -> datetime:
    """`now`보다 엄격히 뒤인 다음 UTC 10초 경계.

    00:00:09.900 → 00:00:10, 정확히 00:00:10 → 00:00:20.
    """
    return floor_to_window(now) + timedelta(seconds=WINDOW_SECONDS)


def format_utc_seconds(value: datetime) -> str:
    """`YYYY-MM-DDTHH:MM:SSZ`. 소수 초가 있으면 오류다(효력 시각은 정수 초)."""
    aware = require_aware(value, "time")
    if aware.microsecond != 0:
        raise DevicePolicyValidationError("time must use whole-second precision")
    return f"{aware:%Y-%m-%dT%H:%M:%S}Z"


def format_utc_millis(value: datetime) -> str:
    """`YYYY-MM-DDTHH:MM:SS.mmmZ`. created_at/server_time에 쓴다."""
    aware = require_aware(value, "time")
    return f"{aware:%Y-%m-%dT%H:%M:%S}.{aware.microsecond // 1000:03d}Z"


def parse_effective_from(value: Any, field: str = "effective_from") -> datetime:
    """저장된 효력 시각을 엄격하게 읽는다(UTC `Z`, 정수 초, 10초 경계)."""
    if type(value) is not str or _EFFECTIVE_FROM_PATTERN.fullmatch(value) is None:
        raise _field_error(field, "must be UTC 'YYYY-MM-DDTHH:MM:SSZ'")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise _field_error(field, "is not a valid date and time") from None
    if parsed.second % WINDOW_SECONDS != 0:
        raise _field_error(field, "must align to a 10 second boundary")
    return parsed
