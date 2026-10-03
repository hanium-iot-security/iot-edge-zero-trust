"""Load Migration 007 registration and policy rows once per detector batch.

Registration state lives in device_policy_revisions, while devices stores the
first registration boundary.  Existing devices with no revision remain known
identities but have POLICY_UNAVAILABLE until an approved backfill is applied.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import parse_db_utc
from edge.policy.resolver import (
    DevicePolicyResolver,
    DevicePolicyRevision,
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
    if exists is None:
        return None

    device_columns = {str(row[1]) for row in db.execute(text("PRAGMA table_info(devices)"))}
    policy_columns = {
        str(row[1]) for row in db.execute(text("PRAGMA table_info(device_policy_revisions)"))
    }
    required_device = {"device_id", "ip_address", "registration_effective_from"}
    required_policy = {
        "device_id", "revision", "effective_from", "registration_state",
        "created_at", "publish_count_max", "payload_size_max_bytes",
        "packet_rate_max_pps", "byte_rate_max_bytes_per_second",
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
               p.registration_state, p.created_at, p.publish_count_max,
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
            raise RuntimeError("Policy revision references an unknown device")
        device_id = str(row["registered_device_id"])
        devices[device_id] = row
        if row["policy_device_id"] is not None:
            by_device[device_id].append(row)

    registrations: list[RegistrationRevision] = []
    policies: list[DevicePolicyRevision] = []
    for device_id, device in devices.items():
        ip_address = str(device["ip_address"]) if device["ip_address"] else None
        starts_at = (
            parse_db_utc(device["registration_effective_from"], "registration_effective_from")
            if device["registration_effective_from"] is not None
            else _LEGACY_REGISTRATION_START
        )
        rows = by_device.pop(device_id, [])
        first_effective = (
            parse_db_utc(rows[0]["effective_from"], "effective_from") if rows else None
        )
        if first_effective is not None and first_effective < starts_at:
            raise RuntimeError("Policy revision precedes device registration")
        registration_number = 0
        if first_effective is None or first_effective > starts_at:
            registration_number += 1
            registrations.append(RegistrationRevision(
                device_id=device_id, status="ACTIVE", effective_from=starts_at,
                ip_address=ip_address, revision=registration_number,
            ))
        for row in rows:
            effective_from = parse_db_utc(row["effective_from"], "effective_from")
            registration_number += 1
            registrations.append(RegistrationRevision(
                device_id=device_id,
                status=str(row["registration_state"]),
                effective_from=effective_from,
                ip_address=ip_address,
                revision=registration_number,
                requested_at=_parse_request_utc(row["created_at"]),
            ))
            policies.append(DevicePolicyRevision(
                device_id=device_id,
                revision=int(row["revision"]),
                effective_from=effective_from,
                publish_count_max=row["publish_count_max"],
                payload_size_max=row["payload_size_max_bytes"],
                packet_rate_max=row["packet_rate_max_pps"],
                byte_rate_max=row["byte_rate_max_bytes_per_second"],
            ))
    return DevicePolicyResolver(registrations, policies)


def _parse_request_utc(value: object) -> datetime:
    """Revision acceptance time may retain subsecond precision."""
    raw = str(value)
    parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("created_at must be UTC")
    return parsed.astimezone(timezone.utc)
