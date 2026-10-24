"""Read each AI Cycle's registration, mode history and approval in one snapshot."""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
import sqlite3

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import parse_db_utc
from edge.policy.ai_stage_activation import get_stage_activation
from edge.policy.ai_window_decision import AIRevision, AIWindowDecision, decide_ai_window
from edge.policy.repository import load_policy_resolver
from edge.policy.resolver import DevicePolicyResolver, PolicyResolution, require_window_start


class AIRuntimePolicyError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AIRuntimeSelector:
    resolver: DevicePolicyResolver
    revisions: dict[str, tuple[AIRevision, ...]]
    activation_from: datetime
    checkpoint: dict

    def __call__(self, policy: PolicyResolution) -> AIWindowDecision:
        return decide_ai_window(policy, self.revisions.get(policy.device_id, ()),
                                stage_activation_from=self.activation_from)


def load_ai_runtime_selector(db: Session, *, stage_name: str, source_table: str,
                             model_version: str, bundle_sha256: str,
                             cycle_range_start: datetime) -> AIRuntimeSelector:
    connection = db.connection()
    raw = connection.connection.driver_connection
    if not isinstance(raw, sqlite3.Connection):
        raise AIRuntimePolicyError("AI_POLICY_SCHEMA_UNAVAILABLE", "AI policy requires SQLite")
    # Legacy SQLite SELECTs do not begin a physical transaction. An owned
    # outermost savepoint keeps 007, 012, 015 and CP consistent, then releases
    # the read snapshot before inference and the caller's later writes.
    # Use the Connection so pending ORM changes are not flushed by a Session
    # savepoint. A preexisting physical transaction remains the caller's own.
    owns_snapshot = not raw.in_transaction
    try:
        with connection.begin_nested() if owns_snapshot else nullcontext():
            return _load_snapshot(
                db, stage_name=stage_name, source_table=source_table,
                model_version=model_version, bundle_sha256=bundle_sha256,
                cycle_range_start=cycle_range_start)
    except BaseException:
        # ROLLBACK TO leaves an outermost SQLite savepoint active. End only
        # our read transaction even if the caller catches the lookup failure.
        if owns_snapshot and raw.in_transaction:
            connection.exec_driver_sql("ROLLBACK")
        raise


def _load_snapshot(db: Session, *, stage_name: str, source_table: str,
                   model_version: str, bundle_sha256: str,
                   cycle_range_start: datetime) -> AIRuntimeSelector:
    receipt = get_stage_activation(db, stage_name, model_version, bundle_sha256)
    activation_from = require_window_start(parse_db_utc(receipt["boundary"]))
    row = checkpoints.get_detector_checkpoint(db, detector_name=stage_name,
                                             source_table=source_table)
    if row is None or row["last_completed_window_end"] is None:
        raise AIRuntimePolicyError("AI_STAGE_ACTIVATION_HOLD", "approved Stage checkpoint is missing")
    completed = require_window_start(parse_db_utc(row["last_completed_window_end"]))
    if completed < activation_from or cycle_range_start > completed:
        raise AIRuntimePolicyError("AI_STAGE_ACTIVATION_HOLD", "Cycle would skip unprocessed AI windows")
    checkpoint = dict(last_processed_id=row["last_processed_id"], last_completed_window_end=completed)
    try:
        resolver = load_policy_resolver(db)
        columns = {str(row[1]) for row in db.execute(text("PRAGMA table_info(device_ai_policy_revisions)"))}
        if resolver is None or not {"device_id", "revision", "mode", "effective_from",
                                    "created_at", "created_by", "reason"} <= columns:
            raise AIRuntimePolicyError("AI_POLICY_SCHEMA_UNAVAILABLE", "007/012 policy schema is incomplete")
        rows = db.execute(text("SELECT device_id, revision, mode, effective_from FROM device_ai_policy_revisions")).mappings()
        revisions = {}
        for row in rows:
            effective = row["effective_from"]
            try:
                effective = datetime.fromisoformat(effective.replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError):
                # The pure selector rejects this device; other devices survive.
                pass
            revisions.setdefault(row["device_id"], []).append(AIRevision(
                row["device_id"], row["revision"], row["mode"], effective))
    except (SQLAlchemyError, RuntimeError) as exc:
        raise AIRuntimePolicyError("AI_POLICY_SCHEMA_UNAVAILABLE", "007/012 policy schema is unavailable") from exc
    return AIRuntimeSelector(resolver, {key: tuple(value) for key, value in revisions.items()},
                             activation_from, checkpoint)
