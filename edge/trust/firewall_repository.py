"""Database repository for firewall rule state."""

from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress
import json
import sqlite3
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import format_db_utc, require_utc_whole_second
from edge.policy.device_policy import DevicePolicyError, POLICY_FIELDS, validate_actor, validate_reason
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL, row_scope
from edge.policy.device_policy_repository import (
    auto_response_exclusion_reason,
    get_policy_snapshot,
)


PENDING = "PENDING"
APPLIED = "APPLIED"
FAILED = "FAILED"
REMOVED = "REMOVED"
ACTIVE_STATUSES = {PENDING, APPLIED}
MAX_TRANSIENT_RETRIES = 3


class AutomaticResponseBlockedError(ValueError):
    """The current device policy does not authorize a new automatic block."""


SCOPE_COLUMNS = {"scope", "source_rule_id", "approved_policy_revision", "requested_by", "request_id"}
DIRECT_ISOLATION_ACTOR = "system:trust-score-v2"


def has_scope_schema(db: Session) -> bool:
    """Only fully pre-011 schemas may use the legacy column-free queries."""
    connection = db.connection().connection.driver_connection
    columns = {row[1] for row in connection.execute("PRAGMA table_info(firewall_rules)")}
    try:
        version = connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
        migration = connection.execute("SELECT name FROM schema_migrations WHERE version=11").fetchone()
    except sqlite3.Error:
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE") from None
    if type(version) is not int:
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE")
    if SCOPE_COLUMNS <= columns and migration is not None and migration[0] == "pi_input_isolation":
        return True
    if not (columns & SCOPE_COLUMNS) and version < 11:
        return False
    raise AutomaticResponseBlockedError("FIREWALL_SCOPE_SCHEMA_UNAVAILABLE")


def _pending_release(db: Session, rule_id: int) -> bool:
    connection = db.connection().connection.driver_connection
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='firewall_release_requests'").fetchone() is None:
        return False
    return connection.execute("SELECT 1 FROM firewall_release_requests WHERE firewall_rule_id=? AND status='PENDING'", (rule_id,)).fetchone() is not None


def require_direct_isolation_schema(db: Session) -> None:
    """018 metadata alone cannot authorize a root rule on the old 011 table."""
    if not has_scope_schema(db):
        raise AutomaticResponseBlockedError("MIGRATION_018_REQUIRED")
    connection = db.connection().connection.driver_connection
    migration = connection.execute("SELECT name FROM schema_migrations WHERE version=18").fetchone()
    schema = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='firewall_rules'").fetchone()
    definition = " ".join(schema[0].lower().split()) if schema and schema[0] else ""
    root_branch = (
        "(scope = 'pi_input_ipv4_all' and protocol is null and dest_port is null "
        "and source_rule_id is null and device_id is not null "
        "and trigger_event_id is not null and typeof(trigger_event_id) = 'integer' "
        "and trigger_event_id > 0 "
        "and requested_by is not null and requested_by = 'system:trust-score-v2' "
        "and approved_policy_revision is not null and typeof(approved_policy_revision) = 'integer' "
        "and approved_policy_revision > 0"
    )
    if migration is None or migration[0] != "direct_ipv4_isolation" or root_branch not in definition:
        raise AutomaticResponseBlockedError("MIGRATION_018_REQUIRED")


def _audited_removal(connection, row) -> bool:
    # Completion may occur on a later cycle after REMOVED was committed. An
    # older success cannot attest a different, later removal of the same ID.
    return (row["status"] == REMOVED and row["released_at"] is not None
            and connection.execute("""SELECT 1 FROM firewall_release_requests
                WHERE firewall_rule_id=? AND status='SUCCEEDED'
                  AND unixepoch(requested_at)<=unixepoch(?)
                  AND unixepoch(?)<=unixepoch(processed_at)""",
                                   (row["id"], row["released_at"], row["released_at"])).fetchone() is not None)


def _require_wide_rule_eligible(db: Session, row: dict[str, Any], *, now: datetime) -> None:
    """Bind a management approval to its original rule and current policy/IP."""
    if row.get("source_rule_id") is None:
        _require_direct_rule_eligible(db, row, now=now)
        return
    if not has_scope_schema(db):
        raise AutomaticResponseBlockedError("MIGRATION_011_REQUIRED")
    connection = db.connection().connection.driver_connection
    source_id = row.get("source_rule_id")
    revision = row.get("approved_policy_revision")
    if type(source_id) is not int or source_id <= 0 or type(revision) is not int or revision <= 0:
        raise AutomaticResponseBlockedError("WIDE_APPROVAL_UNAVAILABLE")
    try:
        validate_actor(row.get("requested_by"))
        validate_reason(row.get("reason"))
        _require_request_id(row.get("request_id"))
    except (ValueError, DevicePolicyError):
        raise AutomaticResponseBlockedError("WIDE_APPROVAL_UNAVAILABLE") from None
    source = db.execute(text("SELECT * FROM firewall_rules WHERE id=:id"), {"id": source_id}).mappings().first()
    if source is None:
        raise AutomaticResponseBlockedError("SOURCE_RULE_NOT_FOUND")
    try:
        source_scope = row_scope(source)
    except ValueError:
        raise AutomaticResponseBlockedError("SOURCE_RULE_CHANGED") from None
    if (source_scope != MQTT_IPV4_TCP_1883
            or source["protocol"] != "tcp" or source["dest_port"] != 1883 or source["action"] != "DROP"
            or source["device_id"] != row.get("device_id") or source["source_ip"] != row.get("source_ip")):
        raise AutomaticResponseBlockedError("SOURCE_RULE_CHANGED")
    audited_removal = row.get("status") == APPLIED and _audited_removal(connection, source)
    if source["status"] != APPLIED and not audited_removal:
        raise AutomaticResponseBlockedError("SOURCE_RULE_CHANGED")
    device = connection.execute("SELECT ip_address,status FROM devices WHERE device_id=?", (row.get("device_id"),)).fetchone()
    if device is None or device[0] != row.get("source_ip"):
        raise AutomaticResponseBlockedError("DEVICE_IP_OWNERSHIP_MISMATCH")
    if device[1] != "isolated":
        raise AutomaticResponseBlockedError("DEVICE_NOT_ISOLATED")
    if _pending_release(db, source_id) or (row.get("id") is not None and _pending_release(db, row["id"])):
        raise AutomaticResponseBlockedError("FIREWALL_RELEASE_PENDING")
    _require_automatic_response_eligible(db, row, now=now)
    try:
        snapshot = get_policy_snapshot(connection, row["device_id"], server_time=now)
    except (DevicePolicyError, sqlite3.Error, ValueError, TypeError):
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE") from None
    if snapshot.current is None or snapshot.current.revision != revision:
        raise AutomaticResponseBlockedError("APPROVED_POLICY_REVISION_CHANGED")


def _require_direct_rule_eligible(db: Session, row: dict[str, Any], *, now: datetime) -> None:
    """Authorize a root isolation from the Trust transaction and fresh policy."""
    require_direct_isolation_schema(db)
    revision, trigger_id = row.get("approved_policy_revision"), row.get("trigger_event_id")
    if (row.get("requested_by") != DIRECT_ISOLATION_ACTOR
            or type(revision) is not int or revision <= 0
            or type(trigger_id) is not int or trigger_id <= 0):
        raise AutomaticResponseBlockedError("DIRECT_ISOLATION_PROVENANCE_UNAVAILABLE")
    try:
        validate_reason(row.get("reason"))
        _require_request_id(row.get("request_id"))
    except (ValueError, DevicePolicyError):
        raise AutomaticResponseBlockedError("DIRECT_ISOLATION_PROVENANCE_UNAVAILABLE") from None
    connection = db.connection().connection.driver_connection
    _require_automatic_response_eligible(db, row, now=now)
    device = connection.execute("SELECT status FROM devices WHERE device_id=?", (row["device_id"],)).fetchone()
    if device is None or device[0] != "isolated":
        raise AutomaticResponseBlockedError("DEVICE_NOT_ISOLATED")
    snapshot = get_policy_snapshot(connection, row["device_id"], server_time=now)
    if snapshot.current is None or snapshot.current.revision != revision:
        raise AutomaticResponseBlockedError("APPROVED_POLICY_REVISION_CHANGED")
    if row.get("id") is not None and _pending_release(db, row["id"]):
        raise AutomaticResponseBlockedError("FIREWALL_RELEASE_PENDING")
    history = connection.execute("""SELECT trust.representative_event_ids_json
        FROM detection_events AS event
        JOIN isolation_history AS isolation ON isolation.trigger_event_id=event.id
            AND isolation.device_id=event.device_id AND isolation.action='ISOLATED'
        JOIN trust_score_history AS trust ON trust.id=isolation.trust_score_history_id
            AND trust.device_id=event.device_id AND trust.policy_version='trust-score-v2'
            AND trust.new_score<30 AND trust.new_score=isolation.trust_score
        WHERE event.id=? AND event.device_id=? AND event.applied_to_score=1
            AND event.processing_reason='APPLIED_TO_TRUST'""", (trigger_id, row["device_id"])).fetchall()
    proven = False
    for (representatives,) in history:
        try:
            ids = json.loads(representatives)
            proven = isinstance(ids, list) and any(type(value) is int and value == trigger_id for value in ids)
        except (TypeError, ValueError):
            continue
        if proven:
            break
    if not proven:
        raise AutomaticResponseBlockedError("DIRECT_ISOLATION_PROVENANCE_UNAVAILABLE")
    # FAILED may still have OS residue after a crash. Exclude this row so its
    # retries reuse its identity. Historical and CLI removals may lack release
    # requests: permit those only with a fresh exact OS absence check by Worker.
    siblings = db.execute(text("""SELECT * FROM firewall_rules
        WHERE (device_id=:device_id OR source_ip=:source_ip)
          AND (:own_id IS NULL OR id<>:own_id)"""),
        {"device_id": row["device_id"], "source_ip": row["source_ip"], "own_id": row.get("id")}).mappings().all()
    unattested_removal_checks = []
    for sibling in siblings:
        if _pending_release(db, sibling["id"]):
            raise AutomaticResponseBlockedError("FIREWALL_RELEASE_PENDING")
        if _audited_removal(connection, sibling):
            continue
        if sibling["status"] == REMOVED and row_scope(sibling) in {MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL}:
            unattested_removal_checks.append(dict(sibling))
            continue
        raise AutomaticResponseBlockedError("EXISTING_RULE_REQUIRES_EXACT_RELEASE")
    row["_unattested_removal_checks"] = unattested_removal_checks


def _require_application_eligible(db: Session, row: dict[str, Any], *, now: datetime) -> None:
    has_scope_schema(db)
    try:
        scope = row_scope(row)
    except ValueError:
        raise AutomaticResponseBlockedError("INVALID_FIREWALL_SCOPE") from None
    if scope == PI_INPUT_IPV4_ALL:
        _require_wide_rule_eligible(db, row, now=now)
    else:
        if row.get("id") is not None and _pending_release(db, row["id"]):
            raise AutomaticResponseBlockedError("FIREWALL_RELEASE_PENDING")
        _require_automatic_response_eligible(db, row, now=now)


def _require_request_id(value: str) -> str:
    try:
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise AutomaticResponseBlockedError("INVALID_REQUEST_ID") from None
    return value


def create_pending_scope_extension(db: Session, *, source_rule_id: int, device_id: str,
                                   source_ip: str, approved_policy_revision: int, requested_by: str,
                                   reason: str, request_id: str, scope: str, now: datetime) -> tuple[dict[str, Any], bool]:
    """Caller holds Worker lock and BEGIN IMMEDIATE; no OS or old-row changes."""
    if not db.connection().connection.driver_connection.in_transaction:
        raise RuntimeError("Scope approval requires an explicit write transaction")
    if not has_scope_schema(db):
        raise AutomaticResponseBlockedError("MIGRATION_011_REQUIRED")
    if scope != PI_INPUT_IPV4_ALL:
        raise AutomaticResponseBlockedError("UNSUPPORTED_EXTENSION_SCOPE")
    _require_request_id(request_id)
    requested_by, reason = validate_actor(requested_by), validate_reason(reason)
    try:
        address = ipaddress.IPv4Address(source_ip)
        private = any(address in ipaddress.IPv4Network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        if str(address) != source_ip or not private:
            raise ValueError
    except (ValueError, TypeError):
        raise AutomaticResponseBlockedError("INVALID_SOURCE_IPV4") from None
    binding = {"device_id": device_id, "source_rule_id": source_rule_id, "source_ip": source_ip,
               "approved_policy_revision": approved_policy_revision, "requested_by": requested_by,
               "reason": reason, "request_id": request_id, "scope": scope}
    existing = db.execute(text("SELECT * FROM firewall_rules WHERE request_id=:request_id"), binding).mappings().first()
    if existing is not None:
        if not all(existing[key] == value for key, value in binding.items()):
            raise AutomaticResponseBlockedError("REQUEST_ID_BINDING_MISMATCH")
        return dict(existing), False
    _require_wide_rule_eligible(db, binding, now=now)
    previous = db.execute(text("SELECT id,status,released_at FROM firewall_rules WHERE scope=:scope AND (device_id=:device_id OR source_ip=:source_ip)"), binding).mappings().all()
    connection = db.connection().connection.driver_connection
    if any(not _audited_removal(connection, previous_row) or _pending_release(db, previous_row["id"])
           for previous_row in previous):
        raise AutomaticResponseBlockedError("WIDE_RULE_REQUIRES_EXACT_RELEASE")
    instant = format_db_utc(require_utc_whole_second(now, "now"))
    result = db.execute(text("""INSERT INTO firewall_rules
        (device_id,source_ip,scope,protocol,dest_port,action,status,reason,source_rule_id,
         approved_policy_revision,requested_by,request_id,created_at,updated_at)
        VALUES (:device_id,:source_ip,:scope,NULL,NULL,'DROP','PENDING',:reason,:source_rule_id,
                :approved_policy_revision,:requested_by,:request_id,:now,:now)"""), {**binding, "now": instant})
    row = db.execute(text("SELECT * FROM firewall_rules WHERE id=:id"), {"id": result.lastrowid}).mappings().one()
    return dict(row), True


def _begin_authorization_transaction(db: Session, *, write: bool = False) -> None:
    # A stale read snapshot cannot authorize an OS change. Worker entry points
    # own their transactions; callers must commit/rollback prior writes first.
    connection = db.connection().connection.driver_connection
    if connection.in_transaction:
        raise RuntimeError("Firewall authorization requires a fresh database transaction")
    db.execute(text("BEGIN IMMEDIATE" if write else "BEGIN"))


def _require_automatic_response_eligible(
    db: Session, row: dict[str, Any], *, now: datetime
) -> None:
    """Read current/pending policy in the caller's explicit SQLite snapshot.

    Pre-007 databases retain Phase 4 behavior. A partially migrated schema or
    missing/invalid policy after 007 never falls back to that behavior.
    """
    connection = db.connection().connection.driver_connection
    try:
        device_columns = {item[1] for item in connection.execute("PRAGMA table_info(devices)")}
        revision_columns = {
            item[1] for item in connection.execute("PRAGMA table_info(device_policy_revisions)")
        }
        migration = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        if type(migration) is not int or migration < 1:
            raise ValueError("Invalid migration metadata")
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE") from exc
    metadata = {"device_type", "mqtt_principal", "registration_effective_from"}
    if not (device_columns & metadata) and not revision_columns and (migration or 0) < 7:
        return
    if not metadata <= device_columns or not {
        "device_id", "revision", "effective_from", "registration_state",
        "created_at", "created_by", "reason", *POLICY_FIELDS,
    } <= revision_columns:
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE")
    device_id = row.get("device_id")
    try:
        owner = connection.execute(
            "SELECT ip_address FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
    except sqlite3.Error as exc:
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE") from exc
    if owner is None or owner[0] != row.get("source_ip"):
        raise AutomaticResponseBlockedError("DEVICE_IP_OWNERSHIP_MISMATCH")
    try:
        snapshot = get_policy_snapshot(connection, device_id, server_time=now)
    except (DevicePolicyError, sqlite3.Error, ValueError, TypeError) as exc:
        raise AutomaticResponseBlockedError("POLICY_UNAVAILABLE") from exc
    reason = auto_response_exclusion_reason(snapshot)
    if reason is not None:
        raise AutomaticResponseBlockedError(reason)


def authorized_automatic_rule(
    db: Session, *, rule_id: int, required_status: str, now: datetime
) -> dict[str, Any]:
    """Authorize a fresh rule snapshot, then release the read transaction.

    The caller holds the shared Worker/API file lock through the subsequent OS
    operation. SQLite does not remain locked while the wrapper runs.
    """
    _begin_authorization_transaction(db)
    try:
        result = db.execute(
            text("SELECT * FROM firewall_rules WHERE id = :id"), {"id": rule_id}
        ).mappings().first()
        if result is None or result["status"] != required_status:
            raise AutomaticResponseBlockedError(f"firewall rule is not {required_status}: {rule_id}")
        row = dict(result)
        _require_application_eligible(db, row, now=now)
        return row
    finally:
        db.rollback()


def create_pending_rule_for_device(
    db: Session,
    *,
    device_id: str,
    source_ip: str,
    reason: str,
    trigger_event_id: int,
    scope: str = MQTT_IPV4_TCP_1883,
    now: datetime | None = None,
) -> int:
    _validate_ip(source_ip)
    if scope == PI_INPUT_IPV4_ALL:
        return _create_pending_direct_isolation(
            db, device_id=device_id, source_ip=source_ip, reason=reason,
            trigger_event_id=trigger_event_id, now=now,
        )
    if scope != MQTT_IPV4_TCP_1883:
        raise AutomaticResponseBlockedError("INVALID_FIREWALL_SCOPE")
    existing = db.execute(
        text(
            """
            SELECT id
            FROM firewall_rules
            WHERE source_ip = :source_ip
              AND protocol = 'tcp'
              AND dest_port = 1883
              AND status IN ('PENDING', 'APPLIED')
            ORDER BY id ASC
            LIMIT 1
            """
        ),
        {"source_ip": source_ip},
    ).first()
    if existing is not None:
        return int(existing[0])

    result = db.execute(
        text(
            """
            INSERT INTO firewall_rules (
                device_id,
                source_ip,
                protocol,
                dest_port,
                action,
                status,
                reason,
                trigger_event_id
            )
            VALUES (
                :device_id,
                :source_ip,
                'tcp',
                1883,
                'DROP',
                'PENDING',
                :reason,
                :trigger_event_id
            )
            """
        ),
        {
            "device_id": device_id,
            "source_ip": source_ip,
            "reason": reason,
            "trigger_event_id": trigger_event_id,
        },
    )
    return int(result.lastrowid)


def _create_pending_direct_isolation(
    db: Session, *, device_id: str, source_ip: str, reason: str,
    trigger_event_id: int, now: datetime | None,
) -> int:
    """Join Trust's writer transaction; never acquire the Worker file lock here."""
    connection = db.connection().connection.driver_connection
    if not connection.in_transaction:
        raise RuntimeError("Direct isolation requires an explicit write transaction")
    require_direct_isolation_schema(db)
    if now is None:
        raise ValueError("Direct isolation requires its decision time")
    now = require_utc_whole_second(now, "now")
    # A released (or failed) trigger is consumed forever. A replay must never
    # create a replacement rule or mutate its historical scope/status.
    previous = db.execute(text("""SELECT * FROM firewall_rules
        WHERE device_id=:device_id AND trigger_event_id=:trigger_event_id
          AND scope=:scope AND source_rule_id IS NULL ORDER BY id LIMIT 1"""),
        {"device_id": device_id, "trigger_event_id": trigger_event_id, "scope": PI_INPUT_IPV4_ALL}).mappings().first()
    if previous is not None:
        if previous["source_ip"] != source_ip or previous["reason"] != reason:
            raise AutomaticResponseBlockedError("DIRECT_ISOLATION_BINDING_MISMATCH")
        return int(previous["id"])
    binding = {"device_id": device_id, "source_ip": source_ip, "reason": reason,
               "trigger_event_id": trigger_event_id, "scope": PI_INPUT_IPV4_ALL,
               "source_rule_id": None, "requested_by": DIRECT_ISOLATION_ACTOR,
               "request_id": str(uuid4())}
    _require_automatic_response_eligible(db, binding, now=now)
    snapshot = get_policy_snapshot(connection, device_id, server_time=now)
    binding["approved_policy_revision"] = snapshot.current.revision
    _require_direct_rule_eligible(db, binding, now=now)
    result = db.execute(text("""INSERT INTO firewall_rules
        (device_id,source_ip,scope,protocol,dest_port,action,status,reason,trigger_event_id,
         source_rule_id,approved_policy_revision,requested_by,request_id,created_at,updated_at)
        VALUES (:device_id,:source_ip,:scope,NULL,NULL,'DROP','PENDING',:reason,:trigger_event_id,
                NULL,:approved_policy_revision,:requested_by,:request_id,:now,:now)"""),
        {**binding, "now": format_db_utc(now)})
    return int(result.lastrowid)


def list_pending_rules(
    db: Session,
    *,
    now: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    now_utc = require_utc_whole_second(now, "now")
    rows = db.execute(
        text(
            """
            SELECT *
            FROM firewall_rules
            WHERE status = 'PENDING'
              AND (
                  next_retry_at IS NULL
                  OR unixepoch(next_retry_at) <= unixepoch(:now)
              )
            ORDER BY id ASC
            LIMIT :limit
            """
        ),
        {"now": format_db_utc(now_utc), "limit": limit},
    ).mappings()
    return [dict(row) for row in rows]


def mark_applied(db: Session, *, rule_id: int, applied_at: datetime) -> None:
    applied_utc = require_utc_whole_second(applied_at, "applied_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'APPLIED',
                applied_at = :applied_at,
                last_attempted_at = :applied_at,
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = :applied_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {"id": rule_id, "applied_at": format_db_utc(applied_utc)},
    )
    _ensure_one_row_changed(result, f"firewall rule is not PENDING: {rule_id}")


def record_transient_failure(
    db: Session,
    *,
    rule_id: int,
    attempted_at: datetime,
    error: str,
    retry_delay_seconds: int = 30,
) -> None:
    attempted_utc = require_utc_whole_second(attempted_at, "attempted_at")
    current_retry = _current_retry_count(db, rule_id, required_status=PENDING)
    retry_count = current_retry + 1
    status = FAILED if retry_count >= MAX_TRANSIENT_RETRIES else PENDING
    next_retry_at = (
        None
        if status == FAILED
        else attempted_utc + timedelta(seconds=retry_delay_seconds)
    )
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = :status,
                retry_count = :retry_count,
                last_attempted_at = :last_attempted_at,
                next_retry_at = :next_retry_at,
                last_error = :last_error,
                updated_at = :last_attempted_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {
            "id": rule_id,
            "status": status,
            "retry_count": retry_count,
            "last_attempted_at": format_db_utc(attempted_utc),
            "next_retry_at": format_db_utc(next_retry_at) if next_retry_at else None,
            "last_error": error,
        },
    )
    _ensure_one_row_changed(result, f"firewall rule is not PENDING: {rule_id}")


def record_validation_failure(
    db: Session,
    *,
    rule_id: int,
    attempted_at: datetime,
    error: str,
) -> None:
    attempted_utc = require_utc_whole_second(attempted_at, "attempted_at")
    retry_count = _current_retry_count(db, rule_id, required_status=PENDING) + 1
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'FAILED',
                retry_count = :retry_count,
                last_attempted_at = :last_attempted_at,
                next_retry_at = NULL,
                last_error = :last_error,
                updated_at = :last_attempted_at
            WHERE id = :id
              AND status = 'PENDING'
            """
        ),
        {
            "id": rule_id,
            "retry_count": retry_count,
            "last_attempted_at": format_db_utc(attempted_utc),
            "last_error": error,
        },
    )
    _ensure_one_row_changed(result, f"firewall rule is not PENDING: {rule_id}")


def mark_removed(db: Session, *, rule_id: int, released_at: datetime) -> None:
    released_utc = require_utc_whole_second(released_at, "released_at")
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'REMOVED',
                released_at = :released_at,
                next_retry_at = NULL,
                updated_at = :released_at
            WHERE id = :id
              AND status IN ('APPLIED', 'FAILED')
            """
        ),
        {"id": rule_id, "released_at": format_db_utc(released_utc)},
    )
    _ensure_one_row_changed(result, f"firewall rule is not APPLIED or FAILED: {rule_id}")


def reset_failed_to_pending(
    db: Session,
    *,
    rule_id: int,
    requested_at: datetime,
    reset_retry_count: bool = True,
) -> None:
    requested_utc = require_utc_whole_second(requested_at, "requested_at")
    # The CLI obtains the shared file lock before this write transaction. Keep
    # eligibility and FAILED -> PENDING in the same DB transaction.
    _begin_authorization_transaction(db, write=True)
    try:
        row = db.execute(
            text("SELECT * FROM firewall_rules WHERE id = :id"), {"id": rule_id}
        ).mappings().first()
        if row is None or row["status"] != FAILED:
            raise ValueError(f"firewall rule is not FAILED: {rule_id}")
        _require_application_eligible(db, dict(row), now=requested_utc)
    except Exception:
        db.rollback()
        raise
    result = db.execute(
        text(
            """
            UPDATE firewall_rules
            SET status = 'PENDING',
                retry_count = CASE WHEN :reset_retry_count THEN 0 ELSE retry_count END,
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = :requested_at
            WHERE id = :id
              AND status = 'FAILED'
            """
        ),
        {
            "id": rule_id,
            "reset_retry_count": 1 if reset_retry_count else 0,
            "requested_at": format_db_utc(requested_utc),
        },
    )
    _ensure_one_row_changed(result, f"firewall rule is not FAILED: {rule_id}")


def _current_retry_count(
    db: Session,
    rule_id: int,
    *,
    required_status: str | None = None,
) -> int:
    row = db.execute(
        text("SELECT retry_count, status FROM firewall_rules WHERE id = :id"),
        {"id": rule_id},
    ).mappings().first()
    if row is None:
        raise ValueError(f"firewall rule not found: {rule_id}")
    if required_status is not None and row["status"] != required_status:
        raise ValueError(f"firewall rule is not {required_status}: {rule_id}")
    return int(row["retry_count"])


def _ensure_one_row_changed(result, message: str) -> None:
    if result.rowcount != 1:
        raise ValueError(message)


def _validate_ip(source_ip: str) -> None:
    try:
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError(f"invalid source_ip: {source_ip!r}") from exc
