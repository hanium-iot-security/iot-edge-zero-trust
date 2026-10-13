"""Prepare and atomically apply one initial, immutable AI Stage activation.

Callers own transactions and the existing Orchestrator process lock. No helper
commits, restores data, changes another Stage, or authorizes model replacement.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from edge.detection.checkpoint_repository import PHASE4_CHECKPOINT_KEYS
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.orchestration.packet_stage_readiness import require_packet_feature_ready_range
from edge.policy.device_policy import validate_actor, validate_reason


SOURCES = {"mqtt_if": "feature_logs", "packet_if": "packet_feature_logs"}
STAGE_SOURCES = dict(PHASE4_CHECKPOINT_KEYS)
KNOWN_STAGES = set(STAGE_SOURCES) - {"mqtt_feature_builder", "trust_score_v2"}
VERSION = "ai-stage-activation-v1"
_PLAN_FIELDS = {"schema_version", "activation_id", "stage_name", "source_table",
                "model_version", "bundle_sha256", "boundary", "runtime_config",
                "original_checkpoint", "trust_checkpoint", "required_checkpoints",
                "excluded_source", "approved_by", "reason", "prepared_at", "plan_sha256"}


class AiStageActivationError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _hold(message, code="AI_STAGE_ACTIVATION_HOLD"):
    raise AiStageActivationError(code, message)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _utc(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
        if not isinstance(parsed, datetime) or parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError
        return parsed
    except (TypeError, ValueError, OverflowError) as exc:
        raise AiStageActivationError("AI_STAGE_ACTIVATION_INVALID", "timestamp must be UTC") from exc


def _stamp(value):
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _boundary(value):
    parsed = _utc(value)
    if parsed.microsecond or parsed.second % 10:
        _hold("boundary must be an exact UTC 10-second boundary", "AI_STAGE_ACTIVATION_INVALID")
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _execute(db, sql, values=None):
    try:
        return db.execute(text(sql), values or {})
    except SQLAlchemyError as exc:
        raise AiStageActivationError("AI_STAGE_ACTIVATION_UNAVAILABLE",
                                     "AI activation schema or database is unavailable") from exc


def _schema(db):
    receipt = _execute(db, "SELECT name FROM schema_migrations WHERE version=14").scalar_one_or_none()
    columns = {row[1] for row in _execute(db, "PRAGMA table_info(ai_stage_activations)")}
    if receipt != "ai_stage_activations" or not {
        "activation_id", "stage_name", "source_table", "model_version", "bundle_sha256",
        "boundary", "plan_sha256", "plan_json", "applied_at",
    } <= columns:
        _hold("Migration 014 must be installed explicitly", "AI_STAGE_ACTIVATION_UNAVAILABLE")


def _identity(stage_name, model_version, bundle_sha256):
    if stage_name not in SOURCES:
        _hold("only mqtt_if or packet_if may be activated", "AI_STAGE_ACTIVATION_INVALID")
    if not isinstance(model_version, str) or not model_version.strip():
        _hold("a verified model version is required", "AI_STAGE_ACTIVATION_INVALID")
    if (not isinstance(bundle_sha256, str) or len(bundle_sha256) != 64
            or any(char not in "0123456789abcdef" for char in bundle_sha256)):
        _hold("a verified lowercase SHA256 is required", "AI_STAGE_ACTIVATION_INVALID")
    return dict(stage_name=stage_name, source_table=SOURCES[stage_name],
                model_version=model_version, bundle_sha256=bundle_sha256)


def _config(stage_name, enabled_stages, required_stages, trust_ai_mode):
    if (isinstance(enabled_stages, str) or isinstance(required_stages, str)
            or not isinstance(enabled_stages, (list, tuple))
            or not isinstance(required_stages, (list, tuple))):
        _hold("enabled/required Stages must be lists", "AI_STAGE_ACTIVATION_INVALID")
    enabled, required = list(enabled_stages), list(required_stages)
    if (any(not isinstance(name, str) for name in enabled + required)
            or len(set(enabled)) != len(enabled) or len(set(required)) != len(required)
            or set(enabled) - KNOWN_STAGES or not set(required) <= set(enabled)
            or stage_name not in enabled or trust_ai_mode != "observe"):
        _hold("activation requires matching enabled/required Stages and observe Trust mode",
              "AI_STAGE_ACTIVATION_INVALID")
    return dict(enabled_stages=enabled, required_stages=sorted(required), trust_ai_mode=trust_ai_mode)


def _checkpoint(db, stage_name):
    row = checkpoints.get_detector_checkpoint(
        db, detector_name=stage_name, source_table=STAGE_SOURCES[stage_name])
    if row is not None:
        row = dict(row)
        identifier = row["last_processed_id"]
        if identifier is not None and (type(identifier) is not int or identifier < 0):
            _hold("invalid checkpoint source ID")
        if row["last_completed_window_end"] is not None:
            _boundary(row["last_completed_window_end"])
    return row


def _source_evidence(db, stage_name, original, boundary):
    source = SOURCES[stage_name]
    start = original["last_completed_window_end"] if original else None
    if start is None:
        first = _execute(db, f"SELECT MIN(window_start) FROM {source}").scalar()
        if stage_name == "packet_if":
            segment_first = _execute(db, "SELECT MIN(window_start) FROM packet_capture_segments").scalar()
            first = min(value for value in (first, segment_first) if value is not None) if (
                first is not None or segment_first is not None) else None
        start = _boundary(first) if first is not None and _utc(first) < _utc(boundary) else boundary
    start = _boundary(start)
    if _utc(start) > _utc(boundary):
        _hold("target checkpoint already exceeds activation boundary")
    if stage_name == "packet_if" and start != boundary:
        try:
            require_packet_feature_ready_range(
                db, cycle_range_start=_utc(start), cycle_cutoff=_utc(boundary))
        except Exception as exc:
            raise AiStageActivationError("AI_STAGE_ACTIVATION_PACKET_GAP",
                "activation cannot bypass the existing Packet readiness/gap gate") from exc
    rows = _execute(db, f"""SELECT * FROM {source}
        WHERE window_start < :boundary AND window_end > :start ORDER BY id""",
        {"boundary": boundary, "start": start}).mappings()
    digest = hashlib.sha256()
    row_count = 0
    for row in rows:
        row_count += 1
        begin, end = _boundary(row["window_start"]), _boundary(row["window_end"])
        if (not start <= begin < end <= boundary
                or _utc(end) - _utc(begin) != timedelta(seconds=10)):
            _hold("excluded source row has an invalid or crossing Window")
        digest.update((_json(dict(row)) + "\n").encode("utf-8"))
    return dict(range_start=start, range_end=boundary, row_count=row_count,
                rows_sha256=digest.hexdigest())


def _facts(db, stage_name, boundary, runtime_config):
    trust = _checkpoint(db, "trust_score_v2")
    if trust is None or trust["last_completed_window_end"] is None:
        _hold("Trust completed boundary is required")
    if _boundary(trust["last_completed_window_end"]) != boundary:
        _hold("activation boundary must exactly equal the existing Trust checkpoint")
    original = _checkpoint(db, stage_name)
    if (original and original["last_completed_window_end"] is not None
            and _utc(original["last_completed_window_end"]) > _utc(boundary)):
        _hold("target checkpoint exceeds activation boundary")
    required = {}
    for name in runtime_config["required_stages"]:
        if name == stage_name:
            continue
        row = _checkpoint(db, name)
        if row is None or row["last_completed_window_end"] is None or _utc(row["last_completed_window_end"]) < _utc(boundary):
            _hold(f"required Stage {name} has not completed through activation boundary")
        required[name] = row
    return dict(original_checkpoint=original, trust_checkpoint=trust,
                required_checkpoints=required,
                excluded_source=_source_evidence(db, stage_name, original, boundary))


def _hash(plan):
    return hashlib.sha256(_json({key: value for key, value in plan.items()
                               if key != "plan_sha256"}).encode("utf-8")).hexdigest()


def _validate_plan(plan):
    try:
        if not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS or plan["schema_version"] != VERSION:
            _hold("invalid activation plan fields", "AI_STAGE_ACTIVATION_INVALID")
        if str(UUID(plan["activation_id"])) != plan["activation_id"]:
            _hold("activation_id must be canonical UUID", "AI_STAGE_ACTIVATION_INVALID")
        identity = _identity(plan["stage_name"], plan["model_version"], plan["bundle_sha256"])
        if plan["source_table"] != identity["source_table"]:
            _hold("activation source does not match Stage")
        boundary = _boundary(plan["boundary"])
        config = _config(plan["stage_name"], **plan["runtime_config"])
        if config != plan["runtime_config"]:
            _hold("activation configuration is not canonical")
        validate_actor(plan["approved_by"])
        validate_reason(plan["reason"])
        if _utc(plan["prepared_at"]) < _utc(boundary):
            _hold("activation boundary cannot be in the future")
        excluded = plan["excluded_source"]
        if (type(excluded["row_count"]) is not int or excluded["row_count"] < 0
                or _boundary(excluded["range_end"]) != boundary
                or _utc(excluded["range_start"]) > _utc(boundary)
                or len(excluded["rows_sha256"]) != 64):
            _hold("invalid excluded source evidence")
        if plan["plan_sha256"] != _hash(plan):
            _hold("activation plan hash does not match reviewed content")
    except AiStageActivationError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise AiStageActivationError("AI_STAGE_ACTIVATION_INVALID", "invalid activation plan") from exc


def prepare_activation(db, *, stage_name, model_version, bundle_sha256, boundary,
                       enabled_stages, required_stages, trust_ai_mode,
                       approved_by, reason, prepared_at, activation_id=None):
    """Read-only preparation. The caller supplies a consistent read transaction."""
    _schema(db)
    identity = _identity(stage_name, model_version, bundle_sha256)
    config = _config(stage_name, enabled_stages, required_stages, trust_ai_mode)
    if _execute(db, "SELECT 1 FROM ai_stage_activations WHERE stage_name=:stage",
                {"stage": stage_name}).first() is not None:
        _hold("Stage is already activated; model replacement is outside this operation")
    boundary = _boundary(boundary)
    plan = dict(schema_version=VERSION, activation_id=activation_id or str(uuid4()),
                **identity, boundary=boundary, runtime_config=config,
                **_facts(db, stage_name, boundary, config),
                approved_by=validate_actor(approved_by), reason=validate_reason(reason),
                prepared_at=_stamp(prepared_at))
    plan["plan_sha256"] = _hash(plan)
    _validate_plan(plan)
    return plan


def _stored_receipt(row):
    try:
        plan = json.loads(row["plan_json"])
        _validate_plan(plan)
        for name in ("activation_id", "stage_name", "source_table", "model_version",
                     "bundle_sha256", "boundary", "plan_sha256"):
            if row[name] != plan[name]:
                _hold("stored activation identity differs from its reviewed plan")
        if _utc(row["applied_at"]) < _utc(plan["prepared_at"]):
            _hold("stored activation time precedes preparation")
        return {**plan, "applied_at": row["applied_at"]}
    except (TypeError, ValueError) as exc:
        raise AiStageActivationError("AI_STAGE_ACTIVATION_UNAVAILABLE",
                                     "stored activation receipt is invalid") from exc


def _verify_activated_checkpoint(db, receipt):
    row = _checkpoint(db, receipt["stage_name"])
    if (row is None or row["last_completed_window_end"] is None
            or _utc(row["last_completed_window_end"]) < _utc(receipt["boundary"])):
        _hold("activation receipt exists but target checkpoint is below its boundary")
    original = receipt["original_checkpoint"]
    before_id = original["last_processed_id"] if original else None
    if before_id is not None and (row["last_processed_id"] is None or row["last_processed_id"] < before_id):
        _hold("activated checkpoint source ID regressed")


def get_stage_activation(db, stage_name, model_version, bundle_sha256):
    _schema(db)
    identity = _identity(stage_name, model_version, bundle_sha256)
    row = _execute(db, "SELECT * FROM ai_stage_activations WHERE stage_name=:stage",
                   {"stage": stage_name}).mappings().one_or_none()
    if row is None:
        _hold("Stage has no approved activation", "AI_STAGE_ACTIVATION_MISSING")
    receipt = _stored_receipt(row)
    if any(receipt[key] != value for key, value in identity.items()):
        _hold("runtime model differs from immutable activation", "AI_STAGE_ACTIVATION_MISMATCH")
    _verify_activated_checkpoint(db, receipt)
    return receipt


def apply_activation(db, plan, *, stage_name, model_version, bundle_sha256,
                     enabled_stages, required_stages, trust_ai_mode, applied_at):
    """Apply audit + only the target CP in the caller's write transaction."""
    if not db.in_transaction():
        _hold("caller must own an activation transaction")
    # SQLAlchemy's SQLite legacy mode may have only a logical transaction.
    if not db.connection().connection.driver_connection.in_transaction:
        _execute(db, "BEGIN IMMEDIATE")
    _schema(db)
    _validate_plan(plan)
    actual = _identity(stage_name, model_version, bundle_sha256)
    config = _config(stage_name, enabled_stages, required_stages, trust_ai_mode)
    if any(plan[key] != value for key, value in actual.items()) or config != plan["runtime_config"]:
        _hold("runtime Stage/model/configuration changed after preparation")
    applied_at = _stamp(applied_at)
    if _utc(applied_at) < _utc(plan["prepared_at"]):
        _hold("application time precedes preparation")
    existing = _execute(db, """SELECT * FROM ai_stage_activations
        WHERE stage_name=:stage OR activation_id=:id""",
        {"stage": stage_name, "id": plan["activation_id"]}).mappings().all()
    if existing:
        if len(existing) != 1:
            _hold("activation ID conflicts with an existing Stage")
        receipt = _stored_receipt(existing[0])
        if {key: receipt[key] for key in plan} != plan:
            _hold("Stage already has a different immutable activation")
        _verify_activated_checkpoint(db, receipt)
        return receipt
    actual_facts = _facts(db, stage_name, plan["boundary"], config)
    if any(plan[key] != value for key, value in actual_facts.items()):
        _hold("source data or expected checkpoints changed; prepare again")
    _execute(db, """INSERT INTO ai_stage_activations
        (activation_id,stage_name,source_table,model_version,bundle_sha256,boundary,
         plan_sha256,plan_json,applied_at)
        VALUES(:activation_id,:stage_name,:source_table,:model_version,:bundle_sha256,
               :boundary,:plan_sha256,:plan_json,:applied_at)""",
        {**{key: plan[key] for key in ("activation_id", "stage_name", "source_table",
            "model_version", "bundle_sha256", "boundary", "plan_sha256")},
         "plan_json": _json(plan), "applied_at": applied_at})
    original = plan["original_checkpoint"]
    checkpoints.upsert_detector_checkpoint(
        db, detector_name=stage_name, source_table=plan["source_table"],
        last_processed_id=original["last_processed_id"] if original else None,
        last_completed_window_end=_utc(plan["boundary"]), updated_at=_utc(plan["boundary"]))
    return get_stage_activation(db, stage_name, model_version, bundle_sha256)
