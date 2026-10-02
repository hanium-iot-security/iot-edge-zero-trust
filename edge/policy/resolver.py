"""Resolve registration, identity and rule policy at the source UTC window.

The persistence layer supplies immutable revisions.  This module deliberately
does not read the current device row: delayed raw input must keep its original
registration and policy interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import isfinite
from typing import Iterable

from edge.detection.phase4_time import floor_window_start


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
    ) -> None:
        self._registrations = tuple(registrations)
        self._policies = tuple(policies)

    def registration_at(
        self, device_id: str, window_start: datetime
    ) -> RegistrationRevision | None:
        require_window_start(window_start)
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
        return {
            device_id for device_id in ids
            if self.registration_at(device_id, window_start) is not None
        }

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
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be timezone-aware UTC")


def _valid_boundary(value: datetime) -> bool:
    try:
        require_window_start(value)
    except ValueError:
        return False
    return True


def _valid_policy(row: DevicePolicyRevision) -> bool:
    return (
        row.revision > 0
        and _valid_boundary(row.effective_from)
        and isinstance(row.publish_count_max, int)
        and not isinstance(row.publish_count_max, bool)
        and row.publish_count_max >= 0
        and isinstance(row.payload_size_max, int)
        and not isinstance(row.payload_size_max, bool)
        and row.payload_size_max >= 0
        and all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and isfinite(value) and value >= 0
            for value in (row.packet_rate_max, row.byte_rate_max)
        )
    )


def _valid_revision_sequence(rows: list[RegistrationRevision | DevicePolicyRevision]) -> bool:
    ordered = sorted(rows, key=lambda row: row.effective_from)
    return all(
        current.revision > 0
        and (index == 0 or current.revision > ordered[index - 1].revision)
        and (index == 0 or current.effective_from > ordered[index - 1].effective_from)
        for index, current in enumerate(ordered)
    )
