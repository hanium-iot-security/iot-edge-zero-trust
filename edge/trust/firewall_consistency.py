"""Read-only firewall DB/runtime comparison, persisted in the existing observer JSON.

This is observation evidence, never authorization to repair or release a rule.
Only the timer records warning episodes. API reads may hide outdated evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import sqlite3
from uuid import UUID

from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from edge.trust.firewall_repository import has_scope_schema
from edge.trust.firewall_runtime_snapshot import (
    SNAPSHOT_SCHEMA_VERSION, _validate_snapshot_payload,
)
from edge.trust.firewall_worker import FirewallPolicy, FirewallValidationError, validate_rule_row


VERSION = "firewall-consistency-v1"
STATUSES = {"MATCH", "MISMATCH", "WAITING", "UNKNOWN"}


class FirewallConsistencyError(ValueError):
    pass


def current_boot_id() -> str | None:
    try:
        return str(UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    except (OSError, ValueError):
        return None


def _utc(value, *, legacy=False):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ValueError("invalid timestamp")
    if value.tzinfo is None:
        if not legacy:
            raise ValueError("timestamp requires timezone")
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _stamp(value):
    return _utc(value).isoformat().replace("+00:00", "Z")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def load_firewall_state(db: Session, runtime_rule_ids=()) -> dict:
    """Read relevant current rows in the caller's explicit read transaction."""
    scoped = has_scope_schema(db)
    scope_column = "scope" if scoped else "'MQTT_IPV4_TCP_1883' AS scope"
    connection = db.connection().connection.driver_connection
    version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    release_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='firewall_release_requests'"
    ).fetchone() is not None
    migration = connection.execute("SELECT name FROM schema_migrations WHERE version=6").fetchone()
    if (version >= 6 and (not release_exists or migration is None
                         or migration[0] != "firewall_release_requests")):
        raise FirewallConsistencyError("FIREWALL_SCHEMA_UNAVAILABLE")
    pending = []
    if release_exists:
        for row in db.execute(text("""SELECT id,firewall_rule_id,requested_at,updated_at
            FROM firewall_release_requests WHERE status='PENDING' ORDER BY id""")).mappings():
            pending.append({
                "request_id": row["id"], "rule_id": row["firewall_rule_id"],
                "requested_at": _stamp(_utc(row["requested_at"], legacy=True)),
                "updated_at": _stamp(_utc(row["updated_at"], legacy=True)),
            })
    ids = tuple(sorted(set(runtime_rule_ids) | {row["rule_id"] for row in pending}))
    statement = text(f"""SELECT id,device_id,source_ip,{scope_column},protocol,dest_port,
        action,status,created_at,updated_at,last_attempted_at,applied_at,released_at
        FROM firewall_rules WHERE status IN ('APPLIED','PENDING') OR id IN :ids
        ORDER BY id""").bindparams(bindparam("ids", expanding=True))
    rows = db.execute(statement, {"ids": ids}).mappings()
    normalized = []
    for raw in rows:
        row = dict(raw)
        spec = validate_rule_row(row, FirewallPolicy(), for_cleanup=True)
        if row["status"] not in {"APPLIED", "PENDING", "FAILED", "REMOVED"}:
            raise FirewallConsistencyError("INVALID_FIREWALL_DATA")
        instants = [_utc(row[name], legacy=True) for name in (
            "created_at", "updated_at", "last_attempted_at", "applied_at", "released_at"
        ) if row[name] is not None]
        if not instants:
            raise FirewallConsistencyError("INVALID_FIREWALL_DATA")
        normalized.append({
            "rule_id": spec.rule_id, "device_id": row["device_id"],
            "source_ip": spec.source_ip, "scope": spec.scope, "status": row["status"],
            "last_change_at": _stamp(max(instants)),
        })

    if {row["rule_id"] for row in pending} - {row["rule_id"] for row in normalized}:
        raise FirewallConsistencyError("INVALID_FIREWALL_DATA")
    return {"scoped": scoped, "rules": normalized, "pending_releases": pending}


def read_firewall_state(database_url: str, runtime_rule_ids=()) -> dict:
    """Open only an existing SQLite file; never set WAL, migrate, or create a DB."""
    engine = None
    try:
        url = make_url(database_url)
        if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
            raise FirewallConsistencyError("FIREWALL_DATABASE_UNAVAILABLE")
        path = Path(url.database).expanduser().resolve(strict=True)
        if not path.is_file() or url.query:
            raise FirewallConsistencyError("FIREWALL_DATABASE_UNAVAILABLE")

        def connect():
            connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1.0)
            connection.execute("PRAGMA query_only=ON")
            return connection

        engine = create_engine("sqlite://", creator=connect)
        with Session(engine) as db, db.begin():
            db.connection().exec_driver_sql("BEGIN")
            state = load_firewall_state(db, runtime_rule_ids)
        # Bind the observation to this DB path without exposing it via the API.
        state["fingerprint"] = _hash({"database_path": str(path), **state})
        return state
    except FirewallConsistencyError:
        raise
    except (OSError, sqlite3.Error, SQLAlchemyError, FirewallValidationError, TypeError, ValueError, RuntimeError, OverflowError) as exc:
        raise FirewallConsistencyError("FIREWALL_DATABASE_UNAVAILABLE") from exc
    finally:
        if engine is not None:
            engine.dispose()


def _runtime(payload, *, now, boot_id, max_age_seconds):
    if not math.isfinite(max_age_seconds) or max_age_seconds <= 0:
        raise FirewallConsistencyError("INVALID_MAX_AGE")
    try:
        normalized = _validate_snapshot_payload(payload)
        if payload["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
            raise FirewallConsistencyError("SNAPSHOT_SCHEMA_UNAVAILABLE")
        observed = normalized["observed_at"]
        age = (_utc(now) - observed).total_seconds()
        if age < 0:
            raise FirewallConsistencyError("SNAPSHOT_FUTURE")
        if age > max_age_seconds:
            raise FirewallConsistencyError("SNAPSHOT_STALE")
        if not normalized["available"]:
            raise FirewallConsistencyError("SNAPSHOT_UNAVAILABLE")
        if boot_id is None:
            raise FirewallConsistencyError("BOOT_UNAVAILABLE")
        if str(UUID(boot_id)) != boot_id or payload.get("boot_id") != boot_id:
            raise FirewallConsistencyError("BOOT_MISMATCH")
        return normalized
    except FirewallConsistencyError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        raise FirewallConsistencyError("SNAPSHOT_MALFORMED") from exc


def unknown(reason, *, observed_at=None):
    return {"schema_version": VERSION, "status": "UNKNOWN", "reason_code": reason,
            "observed_at": observed_at, "db_fingerprint": None, "warnings": [], "waiting": []}


def _warning(kind, rule_id, expected=None, actual=None):
    identity = {"kind": kind, "rule_id": rule_id,
                "expected": expected, "actual": actual}
    return {"key": _hash(identity), **identity}


def _compare(normalized, state):
    observed = normalized["observed_at"]
    actual = {row["rule_id"]: row for row in normalized["managed_rules"]}
    rows = {row["rule_id"]: row for row in state["rules"]}
    pending = {row["rule_id"] for row in state["pending_releases"]}
    warnings, waiting = [], []
    for rule_id in sorted(rows.keys() | actual.keys()):
        row, runtime = rows.get(rule_id), actual.get(rule_id)
        if row is not None:
            if row["status"] == "PENDING" or rule_id in pending:
                waiting.append({"rule_id": rule_id, "reason_code": "OPERATION_PENDING"})
                continue
            # Worker timestamps are seconds. Same-second observations do not prove ordering.
            if observed.replace(microsecond=0) <= _utc(row["last_change_at"]).replace(microsecond=0):
                waiting.append({"rule_id": rule_id, "reason_code": "OBSERVATION_BEFORE_DB_CHANGE"})
                continue
        expected = ({"source_ip": row["source_ip"], "scope": row["scope"]}
                    if row is not None else None)
        found = ({"source_ip": runtime["source_ip"], "scope": runtime["scope"]}
                 if runtime is not None else None)
        if row is None:
            warnings.append(_warning("ORPHAN_RUNTIME", rule_id, actual=found))
        elif runtime is not None and expected != found:
            warnings.append(_warning("IDENTITY_MISMATCH", rule_id, expected, found))
        elif row["status"] == "APPLIED" and runtime is None:
            warnings.append(_warning("APPLIED_MISSING", rule_id, expected))
        elif runtime is not None and row["status"] in ("REMOVED", "FAILED"):
            warnings.append(_warning(row["status"] + "_RESIDUAL", rule_id, expected, found))
    return {
        "schema_version": VERSION,
        "status": "MISMATCH" if warnings else "WAITING" if waiting else "MATCH",
        "reason_code": None, "observed_at": _stamp(observed),
        "db_fingerprint": state["fingerprint"], "warnings": warnings, "waiting": waiting,
    }


def _stored_consistency(payload):
    value = payload.get("consistency")
    if not isinstance(value, dict) or value.get("schema_version") != VERSION:
        raise FirewallConsistencyError("CONSISTENCY_UNAVAILABLE")
    try:
        if (value["status"] not in STATUSES
                or value["observed_at"] != payload["observed_at"]
                or not isinstance(value["warnings"], list)
                or not isinstance(value["waiting"], list)
                or (value["reason_code"] is not None and not isinstance(value["reason_code"], str))):
            raise ValueError
        fingerprint = value["db_fingerprint"]
        if value["status"] != "UNKNOWN" and (
            not isinstance(fingerprint, str) or len(fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in fingerprint)
        ):
            raise ValueError
        if value["status"] == "UNKNOWN" and (value["warnings"] or value["waiting"]):
            raise ValueError
        keys = set()
        for item in value["warnings"]:
            identity = {name: item[name] for name in ("kind", "rule_id", "expected", "actual")}
            first, latest = _utc(item["first_seen_at"]), _utc(item["last_seen_at"])
            duration = item["duration_seconds"]
            if (item["key"] != _hash(identity) or item["key"] in keys
                    or first > latest or latest != _utc(payload["observed_at"])
                    or isinstance(duration, bool) or not isinstance(duration, (int, float))
                    or not math.isfinite(duration) or duration != (latest - first).total_seconds()):
                raise ValueError
            keys.add(item["key"])
        return value
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise FirewallConsistencyError("CONSISTENCY_MALFORMED") from exc


def build_consistency(payload, state, *, previous=None, now, boot_id, max_age_seconds):
    """Timer-only episode update; repeated observations never advance last_seen."""
    try:
        normalized = _runtime(payload, now=now, boot_id=boot_id, max_age_seconds=max_age_seconds)
        result = _compare(normalized, state)
        prior = None
        if isinstance(previous, dict) and previous.get("consistency") is not None:
            try:
                _runtime(previous, now=normalized["observed_at"], boot_id=boot_id,
                         max_age_seconds=max_age_seconds)
                candidate = _stored_consistency(previous)
                if candidate["status"] != "UNKNOWN":
                    prior = candidate
            except FirewallConsistencyError:
                pass  # Missing continuity starts a new observed episode.
        prior_items = {item["key"]: item for item in prior["warnings"]} if prior else {}
        for item in result["warnings"]:
            old = prior_items.get(item["key"])
            first = old["first_seen_at"] if old else result["observed_at"]
            item.update(first_seen_at=first, last_seen_at=result["observed_at"],
                        duration_seconds=(_utc(result["observed_at"]) - _utc(first)).total_seconds())
        return result
    except (FirewallConsistencyError, KeyError, TypeError, ValueError, OverflowError) as exc:
        reason = str(exc) if isinstance(exc, FirewallConsistencyError) else "CONSISTENCY_MALFORMED"
        return unknown(reason, observed_at=payload.get("observed_at") if isinstance(payload, dict) else None)


def read_snapshot(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None


def read_firewall_runtime_status(*, snapshot_path, database_url, max_age_seconds,
                                now=None, boot_id=None):
    """Read-only API guard: a newer DB cannot reuse a formerly matching snapshot."""
    now = now or datetime.now(timezone.utc)
    boot_id = boot_id if boot_id is not None else current_boot_id()
    payload = read_snapshot(snapshot_path)
    result = unknown("SNAPSHOT_MISSING")
    observed_at = None
    try:
        normalized = _runtime(payload, now=now, boot_id=boot_id, max_age_seconds=max_age_seconds)
        observed_at = _stamp(normalized["observed_at"])
        stored = _stored_consistency(payload)
        state = read_firewall_state(database_url, [row["rule_id"] for row in normalized["managed_rules"]])
        current = _compare(normalized, state)
        if stored["status"] == "UNKNOWN":
            result = stored
        elif stored["db_fingerprint"] != state["fingerprint"]:
            result = {**unknown("DB_CHANGED", observed_at=observed_at), "status": "WAITING"}
        else:
            identity_fields = ("key", "kind", "rule_id", "expected", "actual")
            identities = [{key: item[key] for key in identity_fields} for item in stored["warnings"]]
            if (stored["status"] != current["status"] or stored["waiting"] != current["waiting"]
                    or identities != current["warnings"]):
                raise FirewallConsistencyError("CONSISTENCY_MALFORMED")
            result = stored
    except (FirewallConsistencyError, KeyError, TypeError, ValueError, OverflowError) as exc:
        reason = str(exc) if isinstance(exc, FirewallConsistencyError) else "SNAPSHOT_MALFORMED"
        result = unknown(reason, observed_at=observed_at)
    return {
        "server_time": _stamp(now), "observed_at": observed_at,
        "boot_id": payload.get("boot_id") if isinstance(payload, dict) else None,
        "status": result["status"], "reason_code": result["reason_code"],
        "age_seconds": (_utc(now) - _utc(observed_at)).total_seconds() if observed_at else None,
        "max_age_seconds": max_age_seconds,
        "warnings": result["warnings"], "waiting": result["waiting"],
        "warning_count": len(result["warnings"]), "waiting_count": len(result["waiting"]),
    }
