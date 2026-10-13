"""Transactional AI runtime evidence and bounded OBSERVE warning persistence.

No helper commits, changes checkpoints, or publishes a notification. Both SQLite
connections (API reads) and SQLAlchemy Sessions (detector writes) are supported.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import sqlite3

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from edge.detection.ai_run_evidence import AICompletionRecord
from edge.detection.ai_warning_aggregation import (
    AIObservation, WarningAggregate, WarningLedger, WarningPolicy,
)


class RuntimeEvidenceUnavailable(ValueError):
    """Migration 013 or a readable, internally consistent stored record is missing."""


_TABLES = (
    "ai_runtime_snapshot", "ai_device_completions", "ai_warning_keys",
    "ai_warning_aggregates", "ai_warning_events",
)
_EVENT_TYPES = {"mqtt_if": "AI_ANOMALY", "packet_if": "AI_PACKET_ANOMALY"}


def _execute(db, sql, params=None):
    try:
        statement = sql if isinstance(db, sqlite3.Connection) else text(sql)
        return db.execute(statement, params or {})
    except (sqlite3.DatabaseError, SQLAlchemyError) as exc:
        raise RuntimeEvidenceUnavailable("AI runtime evidence database is unavailable") from exc


def _rows(db, sql, params=None):
    result = _execute(db, sql, params)
    if hasattr(result, "mappings"):
        return [dict(row) for row in result.mappings()]
    names = [column[0] for column in result.description]
    return [dict(zip(names, row)) for row in result.fetchall()]


def _require_schema(db):
    found = {row["name"] for row in _rows(
        db, "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ai_%'")}
    if not set(_TABLES).issubset(found):
        raise RuntimeEvidenceUnavailable("Migration 013 AI runtime evidence is not installed")


def _utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be UTC") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return value


def _stamp(value):
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _window(value):
    value = _utc(value)
    if value.microsecond or value.second % 10:
        raise ValueError("analysis Window must be a UTC 10-second boundary")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _json(value):
    def convert(item):
        if isinstance(item, datetime):
            return _stamp(item)
        raise TypeError("unsupported runtime evidence value")
    return json.dumps(value, default=convert, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _object(value):
    try:
        result = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("corrupt runtime evidence JSON") from exc
    if not isinstance(result, dict):
        raise RuntimeEvidenceUnavailable("runtime evidence must be an object")
    return result


def _identifier(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _context(run_id, boot_id, observed_at):
    _identifier(run_id, "run_id")
    if boot_id is not None:
        _identifier(boot_id, "boot_id")
    return {"run_id": run_id, "boot_id": boot_id, "observed_at": _stamp(observed_at)}


def _validate_snapshot(snapshot):
    if not isinstance(snapshot, dict):
        raise ValueError("runtime snapshot must be an object")
    _context(snapshot.get("run_id"), snapshot.get("boot_id"), snapshot.get("observed_at"))
    _identifier(snapshot.get("status"), "status")
    if not isinstance(snapshot.get("stages"), (dict, list)):
        raise ValueError("snapshot stages must be a mapping or list")


def save_runtime_snapshot(db, snapshot: dict):
    _require_schema(db)
    _validate_snapshot(snapshot)
    _execute(db, """INSERT INTO ai_runtime_snapshot(id,snapshot_json) VALUES(1,:snapshot)
        ON CONFLICT(id) DO UPDATE SET snapshot_json=excluded.snapshot_json""",
        {"snapshot": _json(snapshot)})


def read_runtime_snapshot(db):
    _require_schema(db)
    rows = _rows(db, "SELECT snapshot_json FROM ai_runtime_snapshot WHERE id=1")
    if not rows:
        return None
    value = _object(rows[0]["snapshot_json"])
    try:
        _validate_snapshot(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("corrupt runtime snapshot") from exc
    return value


def _completion(record):
    value = asdict(record) if isinstance(record, AICompletionRecord) else dict(record)
    if value.get("detector_name") not in _EVENT_TYPES:
        raise ValueError("unknown AI detector")
    for name in ("input_count", "inference_count", "normal_count", "anomaly_count"):
        if type(value.get(name)) is not int or value[name] < 0:
            raise ValueError("completion counters must be nonnegative integers")
    excluded = value.get("exclusion_counts")
    if not isinstance(excluded, dict) or any(
        not isinstance(reason, str) or not reason or type(count) is not int or count < 0
        for reason, count in excluded.items()
    ):
        raise ValueError("invalid exclusion counts")
    if (value["inference_count"] != value["normal_count"] + value["anomaly_count"]
            or value["input_count"] != value["inference_count"] + sum(excluded.values())):
        raise ValueError("completion counter totals do not match")
    if value.get("device_id") is not None:
        _identifier(value["device_id"], "device_id")
    if value.get("ai_mode") not in (None, "OFF", "OBSERVE"):
        raise ValueError("invalid AI mode")
    revision = value.get("ai_revision")
    if revision is not None and (type(revision) is not int or not 1 <= revision <= 2147483647):
        raise ValueError("invalid AI revision")
    value["completed_window_end"] = _window(value["completed_window_end"])
    start = value.get("window_start")
    if start is not None:
        value["window_start"] = _window(start)
        if _utc(value["completed_window_end"]) - _utc(start) != timedelta(seconds=10):
            raise ValueError("completion must describe one source Window")
    elif value["device_id"] is not None or value["input_count"] != 0:
        raise ValueError("only empty Stage evidence can omit its source Window")
    return value


def store_ai_completions(db, records, *, run_id, boot_id, observed_at, warning_policy=None):
    _require_schema(db)
    context = _context(run_id, boot_id, observed_at)
    values = [_completion(record) for record in records]
    if warning_policy is not None:
        _validate_policy(warning_policy)
    for value in values:
        # Unowned Packet peers are not registered-device evidence. The runtime
        # Stage's selected_count still records that those source rows existed.
        if value["device_id"] is None and value["input_count"]:
            continue
        key = {"detector": value["detector_name"], "device": value["device_id"] or ""}
        existing = _rows(db, """SELECT * FROM ai_device_completions
            WHERE detector_name=:detector AND device_key=:device""", key)
        if existing:
            previous = _checked_completion(existing[0])
            if previous["completed_window_end"] == value["completed_window_end"]:
                facts = {name: previous[name] for name in value}
                if facts != value:
                    raise ValueError("conflicting completion facts for the same source Window")
            elif previous["completed_window_end"] < value["completed_window_end"]:
                _write_completion(db, key, {**value, **context})
        else:
            _write_completion(db, key, {**value, **context})
        if value["inference_count"] == 0:
            _interrupt_warnings(db, value, context["observed_at"])
        if (warning_policy is not None and value["device_id"] is not None
                and value["ai_mode"] == "OBSERVE" and value["anomaly_count"] > 0
                and value["model_version"]):
            _warnings_for_completion(db, value, warning_policy, _utc(observed_at))


def _write_completion(db, key, value):
    _execute(db, """INSERT INTO ai_device_completions
        (detector_name,device_key,completed_window_end,record_json)
        VALUES(:detector,:device,:end,:record)
        ON CONFLICT(detector_name,device_key) DO UPDATE SET
        completed_window_end=excluded.completed_window_end,record_json=excluded.record_json""",
        {**key, "end": value["completed_window_end"], "record": _json(value)})


def _decode_completion(raw):
    value = _object(raw)
    try:
        facts = {name: value[name] for name in AICompletionRecord.__dataclass_fields__}
        _completion(facts)
        _context(value["run_id"], value["boot_id"], value["observed_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("corrupt AI completion record") from exc
    return value


def _checked_completion(row):
    value = _decode_completion(row["record_json"])
    if (value["detector_name"] != row["detector_name"]
            or (value["device_id"] or "") != row["device_key"]
            or value["completed_window_end"] != row["completed_window_end"]):
        raise RuntimeEvidenceUnavailable("completion identity differs from its database key")
    return value


def read_ai_completions(db, device_id=None):
    _require_schema(db)
    where = " WHERE device_key=:device" if device_id is not None else ""
    rows = _rows(db, "SELECT * FROM ai_device_completions" + where
                 + " ORDER BY detector_name,device_key", {"device": device_id})
    return [_checked_completion(row) for row in rows]


def _validate_policy(policy):
    if not isinstance(policy, WarningPolicy):
        raise ValueError("warning_policy must be a WarningPolicy")
    _identifier(policy.version, "warning policy version")
    if (type(policy.window_seconds) is not int or policy.window_seconds < 10
            or policy.window_seconds % 10
            or type(policy.count_threshold) is not int or policy.count_threshold < 1
            or type(policy.cooldown_seconds) is not int or policy.cooldown_seconds < 0):
        raise ValueError("invalid warning W/N/C")


def _stored_policy(raw):
    try:
        policy = WarningPolicy(**_object(raw))
        _validate_policy(policy)
        return policy
    except (TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("corrupt AI warning policy") from exc


def _interrupt_warnings(db, completion, observed_at):
    # No-input / fully excluded Windows do not announce normal recovery. Close
    # existing buckets so a same-bucket return cannot join pre-gap anomalies.
    boundary = (completion["window_start"] or
                _window(_utc(completion["completed_window_end"]) - timedelta(seconds=10)))
    where = "detector_name=:detector AND closed=0 AND bucket_start<=:boundary"
    params = {"detector": completion["detector_name"], "boundary": boundary,
              "observed": observed_at}
    if completion["device_id"] is not None:
        where += " AND device_id=:device"
        params["device"] = completion["device_id"]
    _execute(db, """UPDATE ai_warning_aggregates SET closed=1,
        last_decision='INPUT_INTERRUPTED',updated_at=:observed WHERE """ + where, params)


def _warnings_for_completion(db, completion, policy, observed_at):
    rows = _rows(db, """SELECT id,event_type,evidence_json FROM detection_events
        WHERE detector_type='AI' AND device_id=:device AND event_type=:event
          AND analysis_window_start=:start AND analysis_window_end=:end ORDER BY id""",
        {"device": completion["device_id"], "event": _EVENT_TYPES[completion["detector_name"]],
         "start": completion["window_start"], "end": completion["completed_window_end"]})
    for event in rows:
        try:
            evidence = json.loads(event["evidence_json"])
            if not isinstance(evidence, dict):
                continue
            model = evidence.get("model") if completion["detector_name"] == "packet_if" else evidence
            if not isinstance(model, dict) or evidence.get("detector_name") != completion["detector_name"]:
                continue
            expected = {"device_ai_mode": "OBSERVE", "device_ai_revision": completion["ai_revision"],
                        "model_version": completion["model_version"],
                        "bundle_sha256": completion["bundle_sha256"]}
            if (type(model.get("device_ai_revision")) is not int
                    or model["device_ai_revision"] < 1
                    or any(model.get(name) != value for name, value in expected.items())):
                continue
            # Partial or conflicting duplicate containers are not OBSERVE evidence.
            other = evidence if model is not evidence else evidence.get("model", {})
            if isinstance(other, dict):
                if any(name in other and other[name] != value for name, value in expected.items()):
                    continue
                if ("device_ai_mode" in other) != ("device_ai_revision" in other):
                    continue
        except (TypeError, ValueError):
            continue
        observation = AIObservation(
            event["id"], completion["device_id"], completion["detector_name"],
            event["event_type"], completion["model_version"], _utc(completion["window_start"]))
        _ingest_warning(db, observation, policy, observed_at)


def _load_aggregate(db, row):
    refs = _rows(db, "SELECT event_id,window_start FROM ai_warning_events WHERE aggregate_id=:id",
                 {"id": row["id"]})
    try:
        windows = {_utc(ref["window_start"]) for ref in refs}
        aggregate = WarningAggregate(
            _utc(row["bucket_start"]), {ref["event_id"] for ref in refs}, windows,
            _utc(row["first_window"]) if row["first_window"] else None,
            _utc(row["latest_window"]) if row["latest_window"] else None,
            _utc(row["notified_at"]) if row["notified_at"] else None,
            row["suppressed_count"], bool(row["closed"]))
        if (aggregate.count != row["count"] or not windows
                or aggregate.first_window != min(windows)
                or aggregate.latest_window != max(windows)
                or any(not aggregate.bucket_start <= window < _utc(row["bucket_end"])
                       for window in windows)):
            raise ValueError("warning references do not match aggregate")
    except (TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("corrupt AI warning aggregate") from exc
    return aggregate


def _ingest_warning(db, observation, policy, observed_at):
    key = (observation.device_id, observation.detector_name, observation.event_type,
           observation.model_version, policy.version)
    serialized_key = _json(key)
    seconds = int(observation.window_start.timestamp())
    bucket = datetime.fromtimestamp(seconds - seconds % policy.window_seconds, timezone.utc)
    bucket_text = _window(bucket)
    policy_json = _json(asdict(policy))
    states = _rows(db, "SELECT * FROM ai_warning_keys WHERE warning_key=:key", {"key": serialized_key})
    ledger = WarningLedger()
    if states:
        state = states[0]
        if _stored_policy(state["policy_json"]) != policy:
            raise ValueError("warning policy version was reused with different W/N/C")
        try:
            if state["latest_bucket"]:
                ledger.latest_bucket[key] = _utc(state["latest_bucket"])
            if state["last_notification"]:
                ledger.last_notification[key] = _utc(state["last_notification"])
        except ValueError as exc:
            raise RuntimeEvidenceUnavailable("corrupt AI warning key state") from exc
    else:
        _execute(db, "INSERT INTO ai_warning_keys(warning_key,policy_json) VALUES(:key,:policy)",
                 {"key": serialized_key, "policy": policy_json})
    latest = ledger.latest_bucket.get(key)
    saved_rows = _rows(db, """SELECT * FROM ai_warning_aggregates
        WHERE warning_key=:key AND (bucket_start=:bucket OR bucket_start=:latest)""",
        {"key": serialized_key, "bucket": bucket_text,
         "latest": _window(latest) if latest else bucket_text})
    if latest is not None and not any(row["bucket_start"] == _window(latest) for row in saved_rows):
        raise RuntimeEvidenceUnavailable("latest AI warning bucket is missing")
    row_ids = {}
    for row in saved_rows:
        aggregate = _load_aggregate(db, row)
        ledger.aggregates[(*key, aggregate.bucket_start)] = aggregate
        ledger.seen_event_ids.update(aggregate.event_ids)
        row_ids[aggregate.bucket_start] = row["id"]
    decision = ledger.ingest(observation, policy, received_at=observed_at)
    for aggregate_key, aggregate in ledger.aggregates.items():
        is_target = aggregate.bucket_start == bucket
        if not is_target:
            _execute(db, "UPDATE ai_warning_aggregates SET closed=:closed WHERE id=:id",
                     {"closed": int(aggregate.closed), "id": row_ids[aggregate.bucket_start]})
            continue
        values = dict(key=serialized_key, device=key[0], detector=key[1], event=key[2],
                      model=key[3], policy=key[4], start=bucket_text,
                      end=_window(bucket + timedelta(seconds=policy.window_seconds)),
                      count=aggregate.count, first=_window(aggregate.first_window),
                      latest=_window(aggregate.latest_window),
                      notified=_stamp(aggregate.notified_at) if aggregate.notified_at else None,
                      suppressed=aggregate.suppressed_count, closed=int(aggregate.closed),
                      decision=decision.status, observed=_stamp(observed_at))
        # A replay must not replace the actual prior decision/observation time.
        if decision.status != "DUPLICATE":
            _execute(db, """INSERT INTO ai_warning_aggregates
                (warning_key,device_id,detector_name,event_type,model_version,warning_policy_version,
                 bucket_start,bucket_end,count,first_window,latest_window,notified_at,
                 suppressed_count,closed,last_decision,updated_at)
                VALUES(:key,:device,:detector,:event,:model,:policy,:start,:end,:count,
                       :first,:latest,:notified,:suppressed,:closed,:decision,:observed)
                ON CONFLICT(warning_key,bucket_start) DO UPDATE SET
                count=excluded.count,first_window=excluded.first_window,latest_window=excluded.latest_window,
                notified_at=excluded.notified_at,suppressed_count=excluded.suppressed_count,
                closed=excluded.closed,last_decision=excluded.last_decision,updated_at=excluded.updated_at""", values)
        target = _rows(db, """SELECT id FROM ai_warning_aggregates
            WHERE warning_key=:key AND bucket_start=:start""", values)[0]["id"]
        _execute(db, """INSERT INTO ai_warning_events(aggregate_id,event_id,window_start)
            VALUES(:aggregate,:event,:window) ON CONFLICT(aggregate_id,event_id) DO NOTHING""",
            {"aggregate": target, "event": observation.event_id, "window": _window(observation.window_start)})
    _execute(db, """UPDATE ai_warning_keys SET latest_bucket=:latest,last_notification=:notified
        WHERE warning_key=:key""",
        {"key": serialized_key, "latest": _window(ledger.latest_bucket[key]),
         "notified": _stamp(ledger.last_notification[key]) if key in ledger.last_notification else None})


def list_ai_warnings(db, *, device_id=None, from_at=None, to_at=None, limit=100, offset=0):
    _require_schema(db)
    if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or offset < 0:
        raise ValueError("warning pagination requires limit 1..500 and nonnegative offset")
    # Validate the small key/configuration state, never load global event history.
    for state in _rows(db, "SELECT policy_json FROM ai_warning_keys"):
        _stored_policy(state["policy_json"])
    where, params = ["count >= json_extract(k.policy_json, '$.count_threshold')",
                     "(notified_at IS NOT NULL OR suppressed_count > 0)"], {"limit": limit, "offset": offset}
    if device_id is not None:
        where.append("device_id=:device")
        params["device"] = device_id
    if from_at is not None:
        where.append("bucket_start>=:from_at")
        lower = _utc(from_at)
        if lower.microsecond:
            try:
                lower = lower.replace(microsecond=0) + timedelta(seconds=1)
            except OverflowError as exc:
                raise ValueError("warning time range exceeds supported UTC boundary") from exc
        params["from_at"] = lower.isoformat(timespec="seconds").replace("+00:00", "Z")
    if to_at is not None:
        where.append("bucket_end<=:to_at")
        params["to_at"] = _utc(to_at).isoformat(timespec="seconds").replace("+00:00", "Z")
    if from_at is not None and to_at is not None and _utc(from_at) > _utc(to_at):
        raise ValueError("warning from_at must not follow to_at")
    clause = " WHERE " + " AND ".join(where) if where else ""
    total = _rows(db, "SELECT COUNT(*) AS total FROM ai_warning_aggregates a JOIN ai_warning_keys k USING(warning_key)" + clause, params)[0]["total"]
    items = _rows(db, "SELECT a.* FROM ai_warning_aggregates a JOIN ai_warning_keys k USING(warning_key)" + clause
                  + " ORDER BY bucket_start DESC,id DESC LIMIT :limit OFFSET :offset", params)
    for item in items:
        aggregate = _load_aggregate(db, item)
        item.pop("warning_key")
        item["closed"] = aggregate.closed
        item["event_ids"] = sorted(aggregate.event_ids)
        item["analysis_windows"] = [_window(window) for window in sorted(aggregate.analysis_windows)]
    return {"items": items, "total": total}
