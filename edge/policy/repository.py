"""Load a consistent Migration 007 registration/policy snapshot per batch.

A malformed stored policy excludes only its device from automatic response;
identity and Raw evidence for other devices must still be processed.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.policy.device_policy import (
    POLICY_FIELDS,
    parse_effective_from,
    validate_policy,
    validate_registration_state,
    validate_revision_number,
)
from edge.policy.resolver import (
    DevicePolicyResolver,
    DevicePolicyRevision,
    INVALID_POLICY_REVISION,
    INVALID_REGISTRATION_REVISION,
    RegistrationRevision,
)


POLICY_TABLE = "device_policy_revisions"
_LEGACY_REGISTRATION_START = datetime.min.replace(tzinfo=timezone.utc)


def load_policy_resolver(db: Session) -> DevicePolicyResolver | None:
    """Return None only before Migration 007; reject an incomplete schema."""
    exists = db.execute(
        text("SELECT 1 FROM sqlite_master WHERE type='table' AND name=:name"),
        {"name": POLICY_TABLE},
    ).scalar_one_or_none()
    device_columns = {str(row[1]) for row in db.execute(text("PRAGMA table_info(devices)"))}
    if exists is None:
        migration_table = db.execute(text(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        )).scalar_one_or_none()
        migration_version = (
            db.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar_one_or_none()
            if migration_table is not None else None
        )
        phase8_columns = {"device_type", "mqtt_principal", "registration_effective_from"}
        if device_columns & phase8_columns or (migration_version or 0) >= 7:
            raise RuntimeError("Phase 8 device-policy-v1 schema is incomplete: policy table missing")
        return None

    policy_columns = {
        str(row[1]) for row in db.execute(text("PRAGMA table_info(device_policy_revisions)"))
    }
    required_device = {"device_id", "ip_address", "registration_effective_from"}
    required_policy = {
        "device_id", "revision", "effective_from", "registration_state",
        "created_at", "policy_profile", "expected_publish_interval_seconds",
        "publish_count_max", "payload_size_max_bytes", "packet_rate_max_pps",
        "byte_rate_max_bytes_per_second",
    }
    if not required_device <= device_columns or not required_policy <= policy_columns:
        raise RuntimeError("Phase 8 device-policy-v1 schema is incomplete")

    # SQLite's legacy transaction mode does not start a read transaction for
    # separate SELECTs. A registration committed between them would make its
    # policy look orphaned. One statement gives both tables the same snapshot
    # without holding a read transaction across the caller's later Raw write.
    snapshot_rows = list(db.execute(text("""
        WITH ids AS (
            SELECT device_id FROM devices
            UNION
            SELECT device_id FROM device_policy_revisions
        )
        SELECT d.device_id AS registered_device_id, d.ip_address,
               d.registration_effective_from,
               p.device_id AS policy_device_id, p.revision, p.effective_from,
               p.registration_state, p.created_at, p.policy_profile,
               p.expected_publish_interval_seconds, p.publish_count_max,
               p.payload_size_max_bytes, p.packet_rate_max_pps,
               p.byte_rate_max_bytes_per_second
        FROM ids
        LEFT JOIN devices AS d ON d.device_id = ids.device_id
        LEFT JOIN device_policy_revisions AS p ON p.device_id = ids.device_id
        ORDER BY ids.device_id, p.revision
    """)).mappings())
    devices: dict[str, dict] = {}
    by_device: dict[str, list] = defaultdict(list)
    for row in snapshot_rows:
        if row["registered_device_id"] is None:
            # An orphan row cannot establish a registered identity. Do not let
            # it prevent unrelated devices' Raw evidence from being saved.
            continue
        device_id = str(row["registered_device_id"])
        devices[device_id] = row
        if row["policy_device_id"] is not None:
            by_device[device_id].append(row)

    registrations: list[RegistrationRevision] = []
    policies: list[DevicePolicyRevision] = []
    invalid_devices: dict[str, str] = {}
    for device_id, device in devices.items():
        ip_address = str(device["ip_address"]) if device["ip_address"] else None
        legacy = device["registration_effective_from"] is None
        try:
            starts_at = (
                _LEGACY_REGISTRATION_START if legacy else parse_effective_from(
                    device["registration_effective_from"], "registration_effective_from"
                )
            )
        except ValueError:
            invalid_devices[device_id] = INVALID_REGISTRATION_REVISION
            continue

        rows = by_device[device_id]
        device_registrations: list[RegistrationRevision] = []
        for row in rows:
            try:
                revision = validate_revision_number(row["revision"], "revision")
                effective_from = parse_effective_from(row["effective_from"])
                status = validate_registration_state(row["registration_state"])
                requested_at = _parse_request_utc(row["created_at"])
            except (ValueError, TypeError, OverflowError):
                invalid_devices[device_id] = INVALID_POLICY_REVISION
                continue
            if effective_from < starts_at:
                invalid_devices[device_id] = INVALID_POLICY_REVISION
                continue
            device_registrations.append(RegistrationRevision(
                device_id=device_id,
                status=status,
                effective_from=effective_from,
                ip_address=ip_address,
                revision=revision,
                requested_at=requested_at,
            ))
            try:
                # Profile, interval, types and upper bounds are part of the
                # same v1 policy contract used by the command API.
                policy = validate_policy({name: row[name] for name in POLICY_FIELDS})
            except (ValueError, TypeError, OverflowError):
                invalid_devices[device_id] = INVALID_POLICY_REVISION
                continue
            policies.append(DevicePolicyRevision(
                device_id=device_id,
                revision=revision,
                effective_from=effective_from,
                publish_count_max=policy.publish_count_max,
                payload_size_max=policy.payload_size_max_bytes,
                packet_rate_max=policy.packet_rate_max_pps,
                byte_rate_max=policy.byte_rate_max_bytes_per_second,
                policy_profile=policy.policy_profile,
                expected_publish_interval_seconds=policy.expected_publish_interval_seconds,
            ))

        if rows:
            try:
                if validate_revision_number(rows[0]["revision"], "revision") != 1:
                    invalid_devices[device_id] = INVALID_POLICY_REVISION
            except ValueError:
                invalid_devices[device_id] = INVALID_POLICY_REVISION

        # A new registration is one atomic devices + revision-1 write. A gap
        # or an earlier revision is invalid, not an implicit ACTIVE period.
        if not legacy and rows:
            try:
                if parse_effective_from(rows[0]["effective_from"]) != starts_at:
                    invalid_devices[device_id] = INVALID_POLICY_REVISION
            except ValueError:
                invalid_devices[device_id] = INVALID_POLICY_REVISION
        first_effective = (
            min(row.effective_from for row in device_registrations)
            if device_registrations else None
        )
        if first_effective is None or first_effective > starts_at:
            # Legacy identities exist before backfill. The synthetic identity
            # boundary supplies no policy and cannot authorize a response.
            registrations.append(RegistrationRevision(
                device_id=device_id, status="ACTIVE", effective_from=starts_at,
                ip_address=ip_address, revision=1,
            ))
        # Identity revisions have their own sequence; the stored policy
        # revision has already been validated without converting its type.
        offset = int(first_effective is None or first_effective > starts_at)
        registrations.extend(RegistrationRevision(
            row.device_id, row.status, row.effective_from, row.ip_address,
            index + 1 + offset, row.requested_at,
        ) for index, row in enumerate(device_registrations))
    return DevicePolicyResolver(registrations, policies, invalid_devices=invalid_devices)


def _parse_request_utc(value: object) -> datetime:
    """Revision acceptance time may retain subsecond precision."""
    if not isinstance(value, str):
        raise ValueError("created_at must be UTC text")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("created_at must be UTC")
    return parsed.astimezone(timezone.utc)
