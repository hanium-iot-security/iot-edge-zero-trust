"""Management adapter for device-policy-v1; no Broker or firewall commands.

Repository writes own their DB transaction. Reads explicitly use a single
SQLite snapshot. Commands take the shared Worker lock before any DB write.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import math
import sqlite3

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.security import RecoveryAdminContext
from backend.app.schemas.device_policy_schema import DeviceRegistrationRequest, PolicyRevisionRequest
from backend.app.services.firewall_runtime_verifier import verify_runtime_firewall
from edge.policy.device_policy import (
    DeviceNotFoundError, DevicePolicyError, DevicePolicyValidationError,
    IpRegistrationPolicy, POLICY_FIELDS, PolicyUnavailableError, PolicyWriteBusyError,
    StateTransitionBlockedError, utc_now, validate_actor,
)
from edge.policy.device_policy_repository import (
    append_policy_revision, auto_response_exclusion_reason, get_policy_snapshot, get_registration_instance, register_device,
)
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust.run_firewall_worker import firewall_lock_path


class DevicePolicyConfigError(DevicePolicyError):
    code = "DEVICE_POLICY_CONFIG_UNAVAILABLE"


@contextmanager
def _connection(db: Session, *, read: bool = False):
    engine = db.get_bind()
    if engine.dialect.name != "sqlite":
        raise DevicePolicyConfigError("Device policies require the configured SQLite database")
    database = engine.url.database
    if database not in (None, "", ":memory:") and not Path(database).is_file():
        raise PolicyUnavailableError("The configured database is unavailable")
    pooled = engine.raw_connection()
    connection = pooled.driver_connection
    try:
        if connection.in_transaction:
            raise PolicyWriteBusyError("The database connection already has an open transaction")
        connection.execute("PRAGMA foreign_keys = ON")
        if read:
            connection.execute("BEGIN")
        yield connection
    finally:
        connection.rollback()
        pooled.close()


def _schema_available(connection: sqlite3.Connection) -> bool:
    device_columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
    revision_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(device_policy_revisions)")
    }
    return {"device_type", "mqtt_principal", "registration_effective_from"} <= device_columns and {
        "device_id", "revision", "effective_from", "registration_state",
        "created_at", "created_by", "reason", *POLICY_FIELDS,
    } <= revision_columns


def _require_schema(connection: sqlite3.Connection) -> None:
    if not _schema_available(connection):
        raise PolicyUnavailableError("Device-policy migration and backfill must be completed")


def _snapshot(connection: sqlite3.Connection, device_id: str, now: datetime):
    return get_policy_snapshot(connection, device_id, server_time=now)


def _snapshot_response(connection, device_id, now):
    return {**_snapshot(connection, device_id, now).as_dict(),
            "expected_instance_id": get_registration_instance(connection, device_id)}


def _device_row(connection: sqlite3.Connection, device_id: str) -> dict | None:
    cursor = connection.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = cursor.fetchone()
    return dict(zip((item[0] for item in cursor.description), row)) if row else None


def _enrich_device(connection, row: dict, now: datetime, schema_available: bool) -> dict:
    result = {
        **row,
        "device_type": row.get("device_type"),
        "mqtt_principal": row.get("mqtt_principal"),
        "mqtt_topic": f"iot/{row['device_id']}/sensor",
        "registration_effective_from": row.get("registration_effective_from"),
        "registration_state": None,
        "current_policy_revision": None,
        "pending_policy_revision": None,
        "auto_response_eligible": False,
        "auto_response_exclusion_reason": "POLICY_UNAVAILABLE",
    }
    if not schema_available:
        return result
    try:
        snapshot = _snapshot(connection, row["device_id"], now)
    except (PolicyUnavailableError, DevicePolicyValidationError):
        return result
    current, pending = snapshot.current, snapshot.pending
    result["registration_state"] = current.registration_state if current else "PENDING"
    result["current_policy_revision"] = current.revision if current else None
    result["pending_policy_revision"] = pending.revision if pending else None
    reason = auto_response_exclusion_reason(snapshot)
    result["auto_response_eligible"] = reason is None
    result["auto_response_exclusion_reason"] = reason
    return result


def list_devices(db: Session, status=None, limit=100, offset=0, include_hidden=False) -> dict:
    with _connection(db, read=True) as connection:
        now = utc_now()
        available = _schema_available(connection)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
        visibility = " AND hidden_at IS NULL" if "hidden_at" in columns and not include_hidden else ""
        total = connection.execute(
            "SELECT count(*) FROM devices WHERE (? IS NULL OR status = ?)" + visibility, (status, status),
        ).fetchone()[0]
        cursor = connection.execute(
            "SELECT * FROM devices WHERE (? IS NULL OR status = ?) " + visibility +
            " ORDER BY device_id LIMIT ? OFFSET ?", (status, status, limit, offset),
        )
        columns = [item[0] for item in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return {
            "items": [_enrich_device(connection, row, now, available) for row in rows],
            "total": int(total),
        }


def get_device(db: Session, device_id: str) -> dict | None:
    with _connection(db, read=True) as connection:
        row = _device_row(connection, device_id)
        return (_enrich_device(connection, row, utc_now(), _schema_available(connection))
                if row else None)


def get_device_policy(db: Session, device_id: str) -> dict:
    with _connection(db, read=True) as connection:
        if _device_row(connection, device_id) is None:
            raise DeviceNotFoundError(f"Device {device_id!r} is not registered")
        _require_schema(connection)
        return _snapshot_response(connection, device_id, utc_now())


def _ip_policy() -> IpRegistrationPolicy:
    try:
        validate_actor(settings.recovery_admin_principal.strip() or "recovery-admin")
        if not settings.device_registration_cidr.strip():
            raise ValueError("LAN is unset")
        network = IPv4Network(settings.device_registration_cidr.strip(), strict=True)
        private_networks = (IPv4Network("10.0.0.0/8"), IPv4Network("172.16.0.0/12"),
                            IPv4Network("192.168.0.0/16"))
        if not any(network.subnet_of(private) for private in private_networks):
            raise ValueError("LAN must be RFC1918")
        raw_excluded = ",".join((settings.firewall_protected_ips, settings.capture_interface_ip,
                                 settings.packet_rule_excluded_peer_ips))
        excluded = frozenset(IPv4Address(value.strip()) for value in raw_excluded.split(",")
                             if value.strip())
    except ValueError as exc:
        raise DevicePolicyConfigError("Registration LAN or protected-IP settings are invalid") from exc
    return IpRegistrationPolicy(network=network, excluded=excluded)


@contextmanager
def _command_connection(db: Session):
    if not math.isfinite(settings.firewall_lock_wait_seconds) or settings.firewall_lock_wait_seconds < 0:
        raise DevicePolicyConfigError("Firewall lock wait must be finite and nonnegative")
    lock_settings = settings.model_copy(update={"database_url": str(db.get_bind().url)})
    try:
        with single_instance_lock(
            firewall_lock_path(lock_settings), wait_seconds=settings.firewall_lock_wait_seconds,
        ):
            with _connection(db) as connection:
                _require_schema(connection)
                yield connection
    except RuntimeLockError as exc:
        raise PolicyWriteBusyError("Firewall operation is in progress; re-read before retrying") from exc
    except OSError as exc:
        raise DevicePolicyConfigError("The shared firewall lock is unavailable") from exc
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower() or "busy" in str(exc).lower():
            raise PolicyWriteBusyError("Database is busy; re-read before retrying") from exc
        raise


def _state_change_guard(connection, device_id: str, _from_state: str, to_state: str) -> None:
    if to_state != "DISABLED":
        # Broker/ACL and telemetry verification is an administrator runbook step.
        # The authenticated reason records its evidence, not a client bypass flag.
        return
    ip_address = _device_row(connection, device_id)["ip_address"]
    rules = connection.execute(
        "SELECT status, last_attempted_at, applied_at, released_at, updated_at, source_ip "
        "FROM firewall_rules WHERE device_id = ? OR source_ip = ?", (device_id, ip_address),
    ).fetchall()
    requests = connection.execute(
        "SELECT request.status, request.processed_at FROM firewall_release_requests request "
        "JOIN firewall_rules rule ON rule.id = request.firewall_rule_id "
        "WHERE rule.device_id = ? OR rule.source_ip = ?", (device_id, ip_address),
    ).fetchall()
    if any(row[0] in ("PENDING", "APPLIED") for row in rules) or any(
        row[0] == "PENDING" for row in requests
    ):
        raise StateTransitionBlockedError("Resolve outstanding firewall operations before disabling")
    if any(rule[5] != ip_address for rule in rules):
        # Pre-policy devices could have changed IPs. A snapshot for today's IP
        # cannot prove that a same-device rule at an older IP has been removed.
        raise StateTransitionBlockedError("Related firewall history uses another IP; verify it before disabling")
    values = []
    for rule in rules:
        values.extend([value for value in rule[1:4] if value] or [rule[4]])
    values.extend(row[1] for row in requests if row[1])
    try:
        instants = [datetime.fromisoformat(str(value).replace("Z", "+00:00")) for value in values]
        latest = max((value.replace(tzinfo=timezone.utc) if value.tzinfo is None
                      else value.astimezone(timezone.utc) for value in instants), default=None)
    except (ValueError, TypeError) as exc:
        raise StateTransitionBlockedError("Firewall operation timestamps are invalid") from exc
    runtime = verify_runtime_firewall({
        "device_id": device_id, "ip_address": ip_address,
        "last_firewall_activity_at": latest.isoformat() if latest else None,
    })
    if not runtime.get("available") or not runtime.get("passed"):
        raise StateTransitionBlockedError("A fresh, released firewall observation is required")


def create_device(db: Session, request: DeviceRegistrationRequest, admin: RecoveryAdminContext) -> dict:
    ip_policy = _ip_policy()
    with _command_connection(db) as connection:
        created = register_device(connection, **request.model_dump(), created_by=admin.principal,
                                  ip_policy=ip_policy, clock=utc_now)
        # Build all committed response fields in one fresh read snapshot while
        # the shared command lock is still held.
        connection.execute("BEGIN")
        now = datetime.fromisoformat(created.revision.created_at.replace("Z", "+00:00"))
        return {
            "device": _enrich_device(connection, _device_row(connection, request.device_id), now, True),
            "policy": _snapshot_response(connection, request.device_id, now),
        }


def revise_device_policy(db: Session, device_id: str, request: PolicyRevisionRequest,
                         admin: RecoveryAdminContext) -> dict:
    _ip_policy()
    with _command_connection(db) as connection:
        created = append_policy_revision(
            connection, device_id=device_id, **request.model_dump(), created_by=admin.principal,
            clock=utc_now, state_change_guard=_state_change_guard,
        )
        connection.execute("BEGIN")
        now = datetime.fromisoformat(created.created_at.replace("Z", "+00:00"))
        return _snapshot_response(connection, device_id, now)
