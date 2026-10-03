"""Resolve registration, identity and rule policy at the source UTC window.

The persistence layer supplies immutable revisions.  This module deliberately
does not read the current device row: delayed raw input must keep its original
registration and policy interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Mapping

from edge.detection.phase4_time import floor_window_start
from edge.policy.device_policy import (
    POLICY_PROFILE,
    validate_policy,
    validate_registration_state,
    validate_revision_number,
)


WINDOW_SECONDS = 10
REGISTERED_STATUSES = frozenset({"PENDING", "ACTIVE", "DISABLED"})
POLICY_AVAILABLE = "AVAILABLE"
POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
INVALID_POLICY_REVISION = "INVALID_POLICY_REVISION"
UNREGISTERED_AT_WINDOW = "UNREGISTERED_AT_WINDOW"
INVALID_REGISTRATION_REVISION = "INVALID_REGISTRATION_REVISION"


@dataclass(frozen=True)
class RegistrationRevision:
    device_id: str
    status: str
    effective_from: datetime
    ip_address: str | None = None
    revision: int = 1
    requested_at: datetime | None = None


@dataclass(frozen=True)
class DevicePolicyRevision:
    device_id: str
    revision: int
    effective_from: datetime
    publish_count_max: int
    payload_size_max: int
    packet_rate_max: float
    byte_rate_max: float
    # Defaults preserve the established in-memory constructor. The DB reader
    # must supply both fields explicitly and reject incomplete schemas/rows.
    policy_profile: str = POLICY_PROFILE
    expected_publish_interval_seconds: float = 5


@dataclass(frozen=True)
class PolicyResolution:
    device_id: str
    window_start: datetime
    registration: RegistrationRevision | None
    policy: DevicePolicyRevision | None
    reason: str


def next_utc_window_boundary(server_now: datetime) -> datetime:
    """The first boundary strictly after the server's UTC receipt time."""
    _require_utc(server_now, "server_now")
    return floor_window_start(server_now.replace(microsecond=0)) + timedelta(
        seconds=WINDOW_SECONDS
    )


def require_window_start(window_start: datetime) -> datetime:
    _require_utc(window_start, "window_start")
    if window_start.microsecond or window_start.second % WINDOW_SECONDS:
        raise ValueError("window_start must be an exact UTC 10-second boundary")
    return window_start


class DevicePolicyResolver:
    """Batch snapshot shared by identity, MQTT Rule, Packet Rule and Trust."""

    def __init__(
        self,
        registrations: Iterable[RegistrationRevision],
        policies: Iterable[DevicePolicyRevision],
        *,
        invalid_devices: Mapping[str, str] | None = None,
    ) -> None:
        self._registrations = tuple(registrations)
        self._policies = tuple(policies)
        self._invalid_devices = dict(invalid_devices or {})

    def registration_at(
        self, device_id: str, window_start: datetime
    ) -> RegistrationRevision | None:
        require_window_start(window_start)
        if self._invalid_devices.get(device_id) == INVALID_REGISTRATION_REVISION:
            raise ValueError(INVALID_REGISTRATION_REVISION)
        candidates = [
            row for row in self._registrations
            if row.device_id == device_id
            and _valid_boundary(row.effective_from)
            and row.effective_from <= window_start
        ]
        if any(
            row.device_id == device_id and not _valid_boundary(row.effective_from)
            for row in self._registrations
        ):
            raise ValueError(INVALID_REGISTRATION_REVISION)
        if not candidates:
            return None
        latest = max(candidates, key=lambda row: row.effective_from)
        same_boundary = [
            row for row in candidates if row.effective_from == latest.effective_from
        ]
        if (
            len(same_boundary) != 1
            or not _valid_revision_sequence(candidates)
            or latest.status not in REGISTERED_STATUSES
            or not _valid_boundary(latest.effective_from)
        ):
            raise ValueError(INVALID_REGISTRATION_REVISION)
        return latest

    def registered_ids_at(self, window_start: datetime) -> set[str]:
        require_window_start(window_start)
        ids = {row.device_id for row in self._registrations}
        registered = set()
        for device_id in ids:
            try:
                if self.registration_at(device_id, window_start) is not None:
                    registered.add(device_id)
            except ValueError:
                # Invalid membership for one device must not abort the batch.
                continue
        return registered

    def device_id_for_ip(self, ip_address: str, window_start: datetime) -> str | None:
        """Return only an unambiguous historical IP owner, including PENDING."""
        owners = [
            device_id for device_id in self.registered_ids_at(window_start)
            if self.registration_at(device_id, window_start).ip_address == ip_address
        ]
        return owners[0] if len(owners) == 1 else None

    def automatic_response_exclusion(
        self, device_id: str, decision_at: datetime
    ) -> str | None:
        """Recheck current state and accepted disable requests before scoring."""
        _require_utc(decision_at, "decision_at")
        invalid_reason = self._invalid_devices.get(device_id)
        if invalid_reason is not None:
            return invalid_reason
        accepted = [
            row for row in self._registrations
            if row.device_id == device_id
            and (row.requested_at or row.effective_from) <= decision_at
        ]
        latest_request = (
            max(accepted, key=lambda row: (row.requested_at or row.effective_from,
                                           row.revision))
            if accepted else None
        )
        if latest_request is not None and latest_request.status == "DISABLED":
            return "DISABLE_REQUESTED_OR_DISABLED"
        effective = [
            row for row in self._registrations
            if row.device_id == device_id and row.effective_from <= decision_at
        ]
        if not effective:
            return UNREGISTERED_AT_WINDOW
        current = max(effective, key=lambda row: row.effective_from)
        if current.status != "ACTIVE":
            return f"CURRENT_{current.status}"
        return None

    def resolve(self, device_id: str, window_start: datetime) -> PolicyResolution:
        require_window_start(window_start)
        try:
            registration = self.registration_at(device_id, window_start)
        except ValueError:
            return PolicyResolution(
                device_id, window_start, None, None, INVALID_REGISTRATION_REVISION
            )
        if registration is None:
            return PolicyResolution(
                device_id, window_start, None, None, UNREGISTERED_AT_WINDOW
            )
        invalid_reason = self._invalid_devices.get(device_id)
        if invalid_reason is not None:
            return PolicyResolution(
                device_id, window_start, registration, None, invalid_reason
            )
        candidates = [
            row for row in self._policies
            if row.device_id == device_id
            and _valid_boundary(row.effective_from)
            and row.effective_from <= window_start
        ]
        if any(
            row.device_id == device_id and not _valid_boundary(row.effective_from)
            for row in self._policies
        ):
            return PolicyResolution(
                device_id, window_start, registration, None, INVALID_POLICY_REVISION
            )
        if not candidates:
            return PolicyResolution(
                device_id, window_start, registration, None, POLICY_UNAVAILABLE
            )
        latest = max(candidates, key=lambda row: row.effective_from)
        same_boundary = [
            row for row in candidates if row.effective_from == latest.effective_from
        ]
        if (
            len(same_boundary) != 1
            or not _valid_revision_sequence(candidates)
            or not _valid_policy(latest)
        ):
            return PolicyResolution(
                device_id, window_start, registration, None, INVALID_POLICY_REVISION
            )
        return PolicyResolution(
            device_id, window_start, registration, latest, POLICY_AVAILABLE
        )

    def current_and_scheduled(
        self, device_id: str, server_now: datetime
    ) -> tuple[DevicePolicyRevision | None, DevicePolicyRevision | None]:
        """API view: effective now and earliest future policy are distinct."""
        _require_utc(server_now, "server_now")
        rows = [row for row in self._policies if row.device_id == device_id]
        current = [row for row in rows if row.effective_from <= server_now]
        scheduled = [row for row in rows if row.effective_from > server_now]
        return (
            max(current, key=lambda row: row.effective_from) if current else None,
            min(scheduled, key=lambda row: row.effective_from) if scheduled else None,
        )


def _require_utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be timezone-aware UTC")


def _valid_boundary(value: datetime) -> bool:
    try:
        require_window_start(value)
    except ValueError:
        return False
    return True


def _valid_policy(row: DevicePolicyRevision) -> bool:
    try:
        validate_revision_number(row.revision, "revision")
        require_window_start(row.effective_from)
        validate_policy({
            "policy_profile": row.policy_profile,
            "expected_publish_interval_seconds": row.expected_publish_interval_seconds,
            "publish_count_max": row.publish_count_max,
            "payload_size_max_bytes": row.payload_size_max,
            "packet_rate_max_pps": row.packet_rate_max,
            "byte_rate_max_bytes_per_second": row.byte_rate_max,
        })
    except (ValueError, TypeError, OverflowError):
        return False
    return True


def _valid_revision_sequence(rows: list[RegistrationRevision | DevicePolicyRevision]) -> bool:
    ordered = sorted(rows, key=lambda row: row.effective_from)
    for index, current in enumerate(ordered):
        try:
            validate_revision_number(current.revision, "revision")
            if isinstance(current, RegistrationRevision):
                validate_registration_state(current.status)
        except ValueError:
            return False
        if index and (
            current.revision <= ordered[index - 1].revision
            or current.effective_from <= ordered[index - 1].effective_from
        ):
            return False
    return True
