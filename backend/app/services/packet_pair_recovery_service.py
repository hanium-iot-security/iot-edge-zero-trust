"""Server-bound planning and read-only inspection; applying remains a root CLI.

No API call writes recovery audits/checkpoints, controls services, or records
progress. A verified artifact or historical root result cannot attest to the
current Orchestrator process configuration.
"""
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import uuid

from backend.app.config import settings
from backend.app.schemas.packet_pair_recovery_schema import canonical_uuid
from edge.detection import packet_checkpoint_pair_manager as manager
from edge.detection import packet_checkpoint_pair_recovery as pair
from edge.detection.phase4_time import parse_db_utc


class PairAPIError(Exception):
    def __init__(self, code: str, status_code: int = 503):
        self.code, self.status_code = code, status_code
        super().__init__(code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _server_paths() -> dict[str, Path]:
    root = manager._safe_path(settings.packet_pair_repository_root or Path(__file__).parents[3])
    if not root.is_dir() or not settings.database_url.startswith("sqlite:///"):
        raise PairAPIError("PACKET_PAIR_SERVER_CONFIGURATION_UNAVAILABLE")
    raw_database = settings.database_url.removeprefix("sqlite:///")
    if not raw_database or raw_database == ":memory:" or "?" in raw_database:
        raise PairAPIError("PACKET_PAIR_SERVER_CONFIGURATION_UNAVAILABLE")
    if any(not value.strip() for value in (settings.packet_pair_plan_dir, settings.packet_pair_artifact_dir,
                                          settings.packet_pair_manager_plan_dir)):
        raise PairAPIError("PACKET_PAIR_SERVER_CONFIGURATION_UNAVAILABLE")

    def rooted(value):
        path = Path(value)
        return manager._safe_path(path if path.is_absolute() else root / path)

    database = rooted(raw_database)
    if not database.is_file():
        raise PairAPIError("PACKET_PAIR_DATABASE_UNAVAILABLE")
    return {"root": root, "database": database,
            "plans": rooted(settings.packet_pair_plan_dir),
            "artifacts": rooted(settings.packet_pair_artifact_dir),
            "manager_plans": rooted(settings.packet_pair_manager_plan_dir)}


def _paths() -> dict[str, Path]:
    try:
        return _server_paths()
    except PairAPIError:
        raise
    except (OSError, ValueError, pair.Error) as error:
        raise PairAPIError("PACKET_PAIR_SERVER_PATH_UNAVAILABLE") from error


def _read_json(path: Path) -> dict:
    path = manager._safe_path(path)
    with path.open("rb") as stream:
        content = stream.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:
        raise pair.Error("management artifact exceeds size limit")
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict):
        raise pair.Error("management artifact is not an object")
    return value


def _load(plan_id: str):
    paths = _paths()
    try:
        canonical_uuid(plan_id)
    except ValueError as error:
        raise PairAPIError("PACKET_PAIR_PLAN_ID_INVALID", 422) from error
    try:
        path = manager._safe_path(paths["plans"] / (plan_id + ".json"))
        _read_json(path)  # Bound reads and reject unsafe entries before core validation.
        _, plan = pair._load_pair(path)
        if (plan["pair_id"] != plan_id or plan["repository_root"] != str(paths["root"])
                or plan["database_path"] != str(paths["database"])):
            raise pair.Error("server plan binding changed")
        return paths, path, plan
    except FileNotFoundError as error:
        raise PairAPIError("PACKET_PAIR_PLAN_NOT_FOUND", 404) from error
    except (OSError, ValueError, KeyError, TypeError, pair.Error) as error:
        raise PairAPIError("PACKET_PAIR_PLAN_UNAVAILABLE_OR_INVALID") from error


def _plan_summary(plan: dict) -> dict:
    children = []
    for child in plan["children"]:
        signed = child["plan"]
        children.append({
            "detector": child["detector"], "child_operation_id": child["child_operation_id"],
            "checkpoint_before": signed["checkpoint"]["before"],
            "checkpoint_after": signed["checkpoint"]["after"],
            "skipped_sessions": [{key: row.get(key) for key in (
                "session_id", "classification", "first_window_start", "packet_feature_ready_through",
            )} for row in signed["sessions_between"]],
            "blocking_reasons": signed["blocking_reasons"],
        })
    return {"plan_id": plan["pair_id"], "plan_sha256": plan["plan_sha256"],
            "source_session_id": plan["current_session_id"], "target_session_id": plan["target_session_id"],
            "approved_by": plan["approved_by"], "reason": plan["reason"],
            "generated_at": plan["generated_at"], "can_execute": plan["can_execute"],
            "blocking_reasons": plan["blocking_reasons"], "skips_processable": plan["skips_processable"],
            "boundary": plan["boundary"], "children": children, **_completion_scope(plan)}


def _completion_scope(plan):
    mode = plan.get("mode", "live-resume")
    if mode not in ("live-resume", "bounded-replay"):
        raise pair.Error("unsupported management recovery mode")
    return {"mode": mode, "replay_end": plan["bounded_replay"]["replay_end"] if mode == "bounded-replay" else None}


def create_plan(*, source_session_id: str, target_session_id: str, reason: str, principal: str) -> dict:
    paths = _paths()
    temporary = None
    try:
        paths["plans"].mkdir(parents=True, exist_ok=True, mode=0o700)
        manager._safe_path(paths["plans"])
        temporary = paths["plans"] / (".pending-" + str(uuid.uuid4()) + ".json")
        plan = pair.inspect_pair(
            db_path=paths["database"], repository_root=paths["root"],
            current_session_id=source_session_id, target_session_id=target_session_id,
            approved_by=principal, reason=reason, plan_output=temporary,
        )
        destination = manager._safe_path(paths["plans"] / (plan["pair_id"] + ".json"))
        # A hard-link publication is atomic and never replaces an existing plan.
        os.link(temporary, destination)
        return _plan_summary(plan)
    except (OSError, ValueError, KeyError, TypeError, pair.Error, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
        raise PairAPIError("PACKET_PAIR_PLAN_CREATION_UNAVAILABLE") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # Failed publication is not an executable plan. Preserve the
                # sanitized failure if storage cannot remove a staging file.
                pass


def _children(db, plan):
    pair.core.require_migration_005(db)
    result = {}
    for child in plan["children"]:
        name = child["detector"]
        row = pair.repository.get_checkpoint(db, name, pair.SOURCE)
        audit = pair.repository.get_recovery_audit(db, child["child_operation_id"])
        result[name] = {"state": "COMMITTED_UNVERIFIED" if audit is not None else "PENDING_UNVERIFIED",
                        "audit_present": audit is not None, "checkpoint": dict(row) if row is not None else None}
    return result


def _status(plan, children):
    count = sum(child["audit_present"] for child in children.values())
    return {"plan_id": plan["pair_id"], "plan_sha256": plan["plan_sha256"],
            "observed_at": _now(), "database_committed": count > 0,
            "operation_status": "COMMITTED_UNVERIFIED" if count == 2 else "PARTIAL_HOLD" if count else "PENDING",
            "children": children, "verification": {"status": "NOT_REQUESTED"}, **_completion_scope(plan)}


def get_plan_status(plan_id: str) -> dict:
    paths, _, plan = _load(plan_id)
    try:
        with closing(pair._read_db(paths["database"])) as db:
            return _status(plan, _children(db, plan))
    except (OSError, sqlite3.DatabaseError, KeyError, TypeError, pair.Error) as error:
        raise PairAPIError("PACKET_PAIR_DATABASE_INSPECTION_UNAVAILABLE") from error


def _recorded_checkpoint(db, name, table, old):
    current = pair.repository.get_checkpoint(db, name, table)
    if current is None or old["detector_name"] != name or old["source_table"] != table:
        raise pair.Error("root recorded checkpoint identity changed")
    old_end, new_end = parse_db_utc(old["last_completed_window_end"]), parse_db_utc(current["last_completed_window_end"])
    if new_end < old_end or old["last_processed_id"] is not None and (
            current["last_processed_id"] is None or current["last_processed_id"] < old["last_processed_id"]) or (
            new_end == old_end and dict(current) != old):
        raise pair.Error("root recorded checkpoint regressed")
    return old_end


def _root_manager_completion(paths, path, plan, db):
    """Read a bound historical journal; never attest the current services."""
    proof = {"root_completion_recorded": False, "root_completion_evidence_status": "UNAVAILABLE"}
    manager_path = paths["manager_plans"] / (plan["pair_id"] + ".manager.json")
    try:
        _read_json(manager_path)
    except FileNotFoundError:
        return proof
    managed = manager._load_plan(manager_path)
    if (managed["pair_plan_file"] != str(path) or managed["pair_plan_sha256"] != plan["plan_sha256"]
            or managed["database_path"] != str(paths["database"])
            or managed["artifact_dir"] != str(paths["artifacts"])):
        raise pair.Error("root manager plan binding changed")
    journal_path = manager._safe_path(paths["artifacts"] / ("manager-" + managed["manager_id"]) / "journal.json")
    try:
        _read_json(journal_path)
    except FileNotFoundError:
        return proof
    journal = manager._journal(managed)
    verified = journal.get("verification", {})
    expected = "REPLAY_COMPLETE" if _completion_scope(plan)["mode"] == "bounded-replay" else "COMPLETE"
    if journal["phase"] in ("COMPLETE", "REPLAY_COMPLETE") and journal["phase"] != expected:
        raise pair.Error("historical manager completion scope changed")
    recorded = (journal["phase"] == expected and not journal.get("restoration_failures")
                and verified.get("operation_status") == expected
                and verified.get("pair_id") == plan["pair_id"]
                and verified.get("plan_sha256") == plan["plan_sha256"]
                and verified.get("children") == dict.fromkeys(pair.DETECTORS, "APPLIED"))
    if not recorded:
        return dict(proof, root_completion_evidence_status="NOT_COMPLETED")
    recorded_at = journal["generated_at"]
    if parse_db_utc(recorded_at) > datetime.now(timezone.utc):
        raise pair.Error("manager completion timestamp is in the future")
    if expected == "REPLAY_COMPLETE":
        replay_end = parse_db_utc(plan["bounded_replay"]["replay_end"])
        if (verified.get("mode") != "bounded-replay" or verified.get("replay_end") != plan["bounded_replay"]["replay_end"]
                or verified.get("live_recovery_complete") is not False):
            raise pair.Error("historical replay completion boundary changed")
        entries = [(name, pair.SOURCE) for name in pair.DETECTORS] + [("trust_score_v2", "detection_events")]
        entries += [(name, "feature_logs" if name == "mqtt_feature_rule" else "mqtt_logs")
                    for name in ("mqtt_feature_rule", "mqtt_message_rule") if name in plan["runtime"]["required"]]
        for name, table in entries:
            old = verified["checkpoints"][name]
            end = _recorded_checkpoint(db, name, table, old)
            if old["updated_at"] != old["last_completed_window_end"] or (
                    end != replay_end if name in (*pair.DETECTORS, "trust_score_v2") else end < replay_end):
                raise pair.Error("historical replay processing incomplete")
    return dict(proof, root_completion_recorded=True, root_completion_evidence_status="RECORDED",
                historical_completion_status=expected, historical_completion_source="ROOT_MANAGER",
                historical_completion_recorded_at=recorded_at)


def _root_progress(paths, path, plan, db):
    if _completion_scope(plan)["mode"] == "bounded-replay":
        # Bounded status intentionally never creates progress.json. Its fixed
        # end is distinct from a live target's two continuing advances.
        return {"root_progress_status": "NOT_APPLICABLE", **_root_manager_completion(paths, path, plan, db)}
    group = manager._safe_path(paths["artifacts"] / plan["pair_id"])
    progress = _read_json(group / "progress.json")
    pair.core.verify_plan_sha256(progress)
    if (progress["pair_id"] != plan["pair_id"] or progress["approval_sha256"] != plan["plan_sha256"]
            or any(progress["runtime"].get(key) != plan["runtime"].get(key)
                   for key in ("boot_id", "enabled", "required", "capture_policy"))):
        raise pair.Error("root progress approval binding changed")
    observed = parse_db_utc(progress["observed_at"])
    age = (datetime.now(timezone.utc) - observed).total_seconds()
    if age < 0:
        raise pair.Error("root progress timestamp is in the future")
    if type(progress["advances"]) is not int or not 0 <= progress["advances"] <= 2 or type(progress["eligible"]) is not bool:
        raise pair.Error("root progress counters are invalid")
    if progress["advances"] and not progress["eligible"]:
        raise pair.Error("ineligible root progress claims advances")
    for name, table in [(name, pair.SOURCE) for name in pair.DETECTORS] + [("trust_score_v2", "detection_events")]:
        old = progress["checkpoints"][name]
        old_end = _recorded_checkpoint(db, name, table, old)
        if progress["eligible"] and (not parse_db_utc(plan["boundary"]) < old_end <= observed
                or (observed - old_end).total_seconds() > pair.FRESH_SECONDS
                or old["updated_at"] != old["last_completed_window_end"]):
            raise pair.Error("eligible root progress checkpoint was not fresh")
    proof = {"root_progress_verified": True, "root_progress_status": "VERIFIED",
             "root_progress_observed_at": progress["observed_at"], "root_progress_age_seconds": age,
             "root_progress_fresh": age <= pair.FRESH_SECONDS,
             "root_progress_max_age_seconds": pair.FRESH_SECONDS,
             "root_completion_recorded": False, "root_completion_evidence_status": "UNAVAILABLE"}
    if progress["eligible"] and progress["advances"] == 2:
        runtime = progress["runtime"]
        if (runtime.get("clock_synchronized") is not True or any(runtime["services"].get(name) is not True for name in pair.SERVICES)
                or any(name not in runtime["enabled"] or name not in runtime["required"] for name in pair.DETECTORS)):
            raise pair.Error("root completion runtime evidence was not eligible")
        ends = {name: parse_db_utc(progress["checkpoints"][name]["last_completed_window_end"])
                for name in (*pair.DETECTORS, "trust_score_v2")}
        if ends["trust_score_v2"] > min(ends[name] for name in pair.DETECTORS):
            raise pair.Error("root completion Trust passed Packet progress")
        proof.update(historical_completion_status="COMPLETE", historical_completion_source="ROOT_PROGRESS",
                     historical_completion_recorded_at=progress["observed_at"])
    manager_proof = _root_manager_completion(paths, path, plan, db)
    if manager_proof["root_completion_recorded"] and not (progress["eligible"] and progress["advances"] == 2):
        raise pair.Error("manager completion lacks complete root progress")
    proof.update(manager_proof)
    return proof


def verify_plan(plan_id: str) -> dict:
    paths, path, plan = _load(plan_id)
    try:
        with closing(pair._read_db(paths["database"])) as db:
            result = _status(plan, _children(db, plan))
            try:
                group = manager._safe_path(paths["artifacts"] / plan_id)
                if not group.exists() or not (group / "intent.json").exists():
                    result.update(operation_status="HOLD", verification={"status": "UNKNOWN", "error_code": "ROOT_INTENT_UNAVAILABLE"})
                    return result
                _read_json(group / "intent.json")
                pair._intent(plan, group)
                attempts = list(group.glob("attempt-*.json"))
                if len(attempts) > 256:
                    raise pair.Error("too many execution attempts to verify")
                for attempt in attempts:
                    _read_json(attempt)
                for child in plan["children"]:
                    audit = pair.repository.get_recovery_audit(db, child["child_operation_id"])
                    if audit is not None:
                        backup = manager._safe_path(audit["backup_path"])
                        manager._safe_path(backup.with_suffix(backup.suffix + ".sha256"))
                # All live audit/CAS/source-ID/integrity observations use the
                # same read-only transaction. Backup verification is also RO.
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
                    raise pair.Error("database integrity failed")
                states, _, _ = pair._states(db, plan, group)
                for name, state in states.items():
                    result["children"][name]["state"] = state
                result["verification"] = {"status": "VERIFIED_AUDITS"}
                if all(state == "APPLIED" for state in states.values()):
                    result["operation_status"] = "APPLIED_VERIFY_REQUIRED"
                    try:
                        result["verification"].update(_root_progress(paths, path, plan, db))
                    except FileNotFoundError:
                        result["verification"].update(root_progress_status="UNAVAILABLE", error_code="ROOT_PROGRESS_UNAVAILABLE")
                elif any(state == "APPLIED" for state in states.values()):
                    result["operation_status"] = "PARTIAL_HOLD"
                else:
                    result["operation_status"] = "PENDING"
                return result
            except PermissionError as error:
                raise PairAPIError("ROOT_RECOVERY_ARTIFACT_UNAVAILABLE") from error
            except (OSError, ValueError, KeyError, TypeError, sqlite3.DatabaseError, pair.Error) as error:
                result.update(operation_status="HOLD", verification={"status": "HOLD", "error_code": "PACKET_PAIR_EVIDENCE_INVALID_OR_UNAVAILABLE"})
                return result
    except PairAPIError:
        raise
    except (OSError, sqlite3.DatabaseError, KeyError, TypeError, pair.Error) as error:
        raise PairAPIError("PACKET_PAIR_DATABASE_INSPECTION_UNAVAILABLE") from error
