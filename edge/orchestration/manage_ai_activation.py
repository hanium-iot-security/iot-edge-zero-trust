"""Prepare or explicitly apply one AI Stage's approved starting boundary.

Uses the Orchestrator lock and an existing SQLite database. This command does
not migrate, change configuration, start services or activate a model by itself.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
from typing import Sequence

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import Settings, settings
from edge.detection.mqtt_adapters import MqttIsolationForestStage
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.orchestration.run_detection_orchestrator import resolve_lock_path
from edge.orchestration.stage_registry import StageConfigurationError, parse_stage_names
from edge.policy.ai_stage_activation import apply_activation, prepare_activation
from edge.policy.ai_window_decision import require_observe_trust_mode
from edge.policy.device_policy import parse_effective_from
from edge.runtime_lock import RuntimeLockError, single_instance_lock


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _runtime_inputs(app_settings: Settings, stage_name: str) -> dict:
    if not app_settings.ai_device_policy_enabled:
        raise ValueError("AI_DEVICE_POLICY_ENABLED=true is required in the intended runtime configuration")
    require_observe_trust_mode(app_settings.trust_ai_mode)
    enabled = parse_stage_names(app_settings.orchestrator_enabled_stages)
    required = parse_stage_names(app_settings.orchestrator_required_stages)
    if stage_name not in enabled or not set(required) <= set(enabled):
        raise ValueError("the intended enabled/required Stage configuration is invalid")
    if stage_name == "mqtt_if":
        stage = MqttIsolationForestStage.from_settings(app_settings=app_settings)
        identity = stage.artifact.inspection
    elif stage_name == "packet_if":
        stage = PacketIsolationForestStage.from_settings(app_settings=app_settings)
        identity = stage.artifact
    else:
        raise ValueError("activation requires mqtt_if or packet_if")
    return {
        "stage_name": stage_name, "model_version": identity.model_version,
        "bundle_sha256": identity.bundle_sha256,
        "enabled_stages": enabled, "required_stages": required,
        "trust_ai_mode": app_settings.trust_ai_mode,
    }


@contextmanager
def _database(path: Path, *, write: bool):
    mode = "rw" if write else "ro"

    def connect():
        connection = sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    engine = create_engine("sqlite://", creator=connect)
    try:
        with Session(engine) as db, db.begin():
            # SQLite legacy mode otherwise leaves SELECTs outside a snapshot.
            db.connection().exec_driver_sql("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
    finally:
        engine.dispose()


def _read_plan(path: Path, database: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or set(value) != {"database_path", "activation"}
            or value["database_path"] != str(database)
            or not isinstance(value["activation"], dict)):
        raise ValueError("activation plan must belong to this exact database path")
    return value["activation"]


def main(argv: Sequence[str] | None = None, *, app_settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True, type=Path, help="existing SQLite database")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="read-only review plan; does not move a checkpoint")
    prepare.add_argument("--stage", choices=("mqtt_if", "packet_if"), required=True)
    prepare.add_argument("--boundary", required=True, help="approved UTC 10-second boundary")
    prepare.add_argument("--approved-by", required=True)
    prepare.add_argument("--reason", required=True)
    prepare.add_argument("--output", type=Path, required=True, help="new plan file; never overwritten")
    apply = commands.add_parser("apply", help="explicitly commit the reviewed plan and Stage checkpoint")
    apply.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        database = args.db.resolve(strict=True)
        if not database.is_file():
            raise ValueError("database must be an existing file")
        configured = (app_settings or settings).model_copy(update={
            "database_url": f"sqlite:///{database.as_posix()}",
        })
        if args.command == "prepare":
            inputs = _runtime_inputs(configured, args.stage)
            with _database(database, write=False) as db:
                plan = prepare_activation(
                    db, **inputs, boundary=parse_effective_from(args.boundary),
                    approved_by=args.approved_by, reason=args.reason, prepared_at=utc_now(),
                )
            envelope = {"database_path": str(database), "activation": plan}
            with args.output.open("x", encoding="utf-8") as output:
                json.dump(envelope, output, ensure_ascii=False, indent=2)
                output.write("\n")
            print(json.dumps({"status": "PREPARED", "plan": str(args.output)}, ensure_ascii=False))
        else:
            plan = _read_plan(args.plan, database)
            # Same process lock as Orchestrator; no service stop/start automation.
            with single_instance_lock(resolve_lock_path(configured)):
                inputs = _runtime_inputs(configured, plan.get("stage_name"))
                with _database(database, write=True) as db:
                    receipt = apply_activation(db, plan, **inputs, applied_at=utc_now())
            # A lost stdout response is resolved by re-reading the same stored
            # activation on retry; never compensate with a checkpoint rewind.
            print(json.dumps({"status": "APPLIED", "activation": receipt}, ensure_ascii=False))
        return 0
    except RuntimeLockError as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 3
    except (OSError, ValueError, sqlite3.Error, SQLAlchemyError, StageConfigurationError) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
