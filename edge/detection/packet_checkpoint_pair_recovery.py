"""Explicit paired live resume; DB audit is authoritative after response loss."""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import uuid

from backend.app.config import settings
from edge.detection import packet_checkpoint_recovery as core
from edge.detection import packet_checkpoint_recovery_repository as repository
from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_window_boundary
from edge.orchestration.stage_registry import parse_stage_names
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible
from edge.scripts.phase4_cutover_storage import DatabaseVerification, expected_backup_sha256

SCHEMA = "packet-checkpoint-pair-live-resume-v1"
REPLAY_SCHEMA = "packet-checkpoint-pair-bounded-replay-v1"
DETECTORS = ("packet_rule", "packet_if")
SOURCE = "packet_feature_logs"
CONFIRM = "APPLY-PACKET-PAIR-LIVE-RESUME:"
REPLAY_CONFIRM = "APPLY-PACKET-PAIR-BOUNDED-REPLAY:"
COMPLETE_STATUSES = {"COMPLETE", "REPLAY_COMPLETE"}


def confirmation_prefix(plan):
    return REPLAY_CONFIRM if plan["mode"] == core.BOUNDED_REPLAY_MODE else CONFIRM
SKIP_CONFIRM = "SKIP-PROCESSABLE-PAIR:"
SERVICES = ("packet-capture.service", "packet-feature-extractor.timer", "mqtt-subscriber.service",
            "mqtt-feature-builder.service", "detection-orchestrator.service")
FRESH_SECONDS = 45
Error = core.PacketCheckpointRecoveryError


def _runtime_observation():
    """Read Linux boot/services/configuration; never start or stop anything."""
    if os.name != "posix":
        return {"boot_id": None, "services": {}, "enabled": [], "required": [],
                "clock_synchronized": False, "capture_policy": asdict(CapturePolicy.from_env())}
    boot = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    services = {}
    for name in SERVICES:
        result = subprocess.run(["systemctl", "is-active", name], capture_output=True,
                                text=True, timeout=5, check=False)
        services[name] = result.returncode == 0 and result.stdout.strip() == "active"
    clock = subprocess.run(["timedatectl", "show", "--property=NTPSynchronized", "--value"],
                           capture_output=True, text=True, timeout=5, check=False)
    return {"boot_id": boot, "services": services,
            "clock_synchronized": clock.returncode == 0 and clock.stdout.strip() == "yes",
            "capture_policy": asdict(CapturePolicy.from_env()),
            "enabled": list(parse_stage_names(settings.orchestrator_enabled_stages)),
            "required": list(parse_stage_names(settings.orchestrator_required_stages))}


def _read_db(database):
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("BEGIN")
    return connection


def verify_database_readonly(database_path: Path) -> DatabaseVerification:
    """Inspect one read-only SQLite snapshot without creating or writing a DB."""
    database = Path(database_path).resolve(strict=True)
    if not database.is_file():
        raise Error("verification database is not a file")
    with closing(_read_db(database)) as db:
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        violations = tuple(tuple(row) for row in db.execute("PRAGMA foreign_key_check").fetchall())
    return DatabaseVerification(integrity_check=integrity, foreign_key_violations=violations)


def _configured_locks(root, database):
    configured = settings.orchestrator_lock_path.strip()
    return core.resolve_recovery_locks(repository_root=Path(root), database_url=f"sqlite:///{database}",
                                       orchestrator_lock_path=Path(configured) if configured else None,
                                       manual_lock_path=None, extractor_lock_path=None)


def _require_configured_locks(plan, database):
    if list(core.serialize_resolved_locks(_configured_locks(plan["repository_root"], database))) != plan["locks"]:
        raise Error("runtime recovery lock configuration changed")


def _load_pair(path):
    path, plan = core._load_plan(path)
    expected_schema = {core.LIVE_RESUME_MODE: SCHEMA, core.BOUNDED_REPLAY_MODE: REPLAY_SCHEMA}.get(plan.get("mode"))
    if expected_schema is None or plan.get("plan_schema_version") != expected_schema:
        raise Error("unsupported paired recovery schema or mode")
    pair_id = uuid.UUID(plan["pair_id"])
    if pair_id.version != 4 or str(pair_id) != plan["pair_id"]:
        raise Error("invalid pair identity")
    allow_failed = plan.get("allow_failed_current_session", False)
    if type(allow_failed) is not bool:
        raise Error("failed-current-session approval must be boolean")
    children = plan.get("children", [])
    if [child.get("detector") for child in children] != list(DETECTORS):
        raise Error("paired detectors must be Rule then IF")
    for child in children:
        signed = child["plan"]
        core.verify_plan_sha256(signed)
        if child["child_operation_id"] != str(uuid.uuid5(pair_id, child["detector"])):
            raise Error("child identity mismatch")
        for key in ("database_path", "repository_root", "repository_commit", "repository_state",
                    "current_session_id", "target_session_id", "approved_by", "reason", "locks", "mode"):
            if signed[key] != plan[key]:
                raise Error("child approval binding mismatch")
        if (signed["detector_name"] != child["detector"] or signed["source_table"] != SOURCE
                or type(signed.get("allow_failed_current_session")) is not bool
                or signed["allow_failed_current_session"] != allow_failed
                or signed["plan_schema_version"] != core.PLAN_SCHEMA_VERSION
                or signed["checkpoint"]["after"] is not None and (
                    signed["checkpoint"]["after"]["last_completed_window_end"] != plan["boundary"]
                    or signed["checkpoint"]["after"]["last_processed_id"] != signed["checkpoint"]["before"]["last_processed_id"])):
            raise Error("child recovery contract mismatch")
        if plan["mode"] == core.BOUNDED_REPLAY_MODE and (
                signed.get("bounded_replay") != plan.get("bounded_replay") or not plan.get("bounded_replay")):
            raise Error("child bounded replay binding mismatch")
    if (plan["skips_processable"] != any(child["plan"]["summary"]["skips_processable_sessions"] for child in children)
            or plan["can_execute"] and any(not child["plan"]["can_execute"] for child in children)):
        raise Error("paired executability or skip summary mismatch")
    return path, plan


def inspect_pair(*, db_path, repository_root, current_session_id, target_session_id,
                 approved_by, reason, plan_output, allow_failed_current_session=False, mode=core.LIVE_RESUME_MODE):
    if mode not in (core.LIVE_RESUME_MODE, core.BOUNDED_REPLAY_MODE):
        raise Error("unsupported paired recovery mode")
    if type(allow_failed_current_session) is not bool:
        raise Error("failed-current-session approval must be boolean")
    if not approved_by.strip() or not reason.strip():
        raise Error("approval principal and reason are required")
    database = core.resolve_database_path(db_path)
    root = Path(repository_root).resolve(strict=True)
    output = core.validate_generated_paths(repository_root=root, plan_output=Path(plan_output))["plan_output"]
    if output.exists():
        raise Error("pair plan output must be new")
    state = core.inspect_repository_state(root)
    locks = _configured_locks(root, database)
    entries = list(core.serialize_resolved_locks(locks))
    core.validate_generated_paths(repository_root=root, lock_paths=tuple(lock.path for lock in locks))
    pair_id = uuid.uuid4()
    runtime = _runtime_observation()
    children = []
    with closing(_read_db(database)) as db:
        core.require_migration_005(db)
        target = repository.get_capture_session(db, target_session_id)
        target_identity = {key: target[key] for key in (
            "id", "session_id", "capture_interface", "started_at", "first_window_start", "created_at",
            "ended_at", "capture_gap_start", "capture_gap_end"
        )} if target is not None else None
        failed_target = _target_failed(db, target_session_id)
        for name in DETECTORS:
            signed = core.attach_plan_sha256(core.build_recovery_plan(
                db, repository_state=state, database_path=database, detector_name=name,
                current_session_id=current_session_id, target_session_id=target_session_id,
                approved_by=approved_by, reason=reason, lock_entries=entries, mode=mode,
                allow_failed_current_session=allow_failed_current_session,
            ), generated_at=core._utc_now().replace(microsecond=0))
            children.append({"detector": name, "child_operation_id": str(uuid.uuid5(pair_id, name)), "plan": signed})
    first = children[0]["plan"]
    boundary = first["checkpoint"]["after"]["last_completed_window_end"] if first["checkpoint"]["after"] else None
    blockers = [f"{child['detector']}:{code}" for child in children for code in child["plan"]["blocking_reasons"]]
    if any(child["plan"]["checkpoint"]["after"] is None or
           child["plan"]["checkpoint"]["after"]["last_completed_window_end"] != boundary for child in children):
        blockers.append("PAIR_BOUNDARY_MISMATCH")
    if not runtime.get("boot_id"):
        blockers.append("RUNTIME_BOOT_UNCONFIRMED")
    if failed_target:
        blockers.append("PAIR_TARGET_FAILED")
    payload = {key: first[key] for key in ("database_path", "repository_root", "repository_commit", "repository_state",
               "current_session_id", "target_session_id", "approved_by", "reason", "locks", "mode",
               "allow_failed_current_session")}
    if mode == core.BOUNDED_REPLAY_MODE:
        payload["bounded_replay"] = first["bounded_replay"]
    payload.update(plan_schema_version=REPLAY_SCHEMA if mode == core.BOUNDED_REPLAY_MODE else SCHEMA,
                   pair_id=str(pair_id), children=children, boundary=boundary,
                   runtime=runtime, target_identity=target_identity,
                   can_execute=not blockers, blocking_reasons=blockers,
                   skips_processable=any(child["plan"]["summary"]["skips_processable_sessions"] for child in children))
    plan = core.attach_plan_sha256(payload, generated_at=core._utc_now().replace(microsecond=0))
    core._write_json_atomically(output, plan)
    return plan


def _group(plan, artifact_dir):
    root = core.require_existing_directory(Path(artifact_dir), field_name="artifact_dir")
    root = core.validate_generated_path(Path(plan["repository_root"]), root, field_name="artifact_dir")
    return root / plan["pair_id"]


def _same_boot(plan, runtime):
    if not runtime.get("boot_id") or runtime["boot_id"] != plan["runtime"]["boot_id"]:
        raise Error("runtime boot changed or unconfirmed")
    if any(runtime.get(key) != plan["runtime"].get(key) for key in ("enabled", "required", "capture_policy")):
        raise Error("required or enabled stage configuration changed")


def _intent(plan, group):
    path = group / "intent.json"
    if not path.is_file() or json.loads(path.read_text(encoding="utf-8")) != plan:
        raise Error("approved pair intent missing or changed")


def _checkpoint_equal(row, expected):
    return row is not None and dict(row) == expected


def _target_failed(db, session_id):
    return db.execute("SELECT 1 FROM packet_capture_segments g JOIN packet_capture_sessions s ON s.id=g.capture_session_id "
                      "WHERE s.session_id=? AND g.status='FAILED' LIMIT 1", (session_id,)).fetchone() is not None


def _validate_audit(db, plan, child, audit, checkpoint, group, readiness):
    signed = child["plan"]
    before, after = signed["checkpoint"]["before"], signed["checkpoint"]["after"]
    expected = {"operation_id": child["child_operation_id"], "detector_name": child["detector"], "source_table": SOURCE,
                "current_capture_session_id": plan["current_session_id"], "target_capture_session_id": plan["target_session_id"],
                "plan_sha256": signed["plan_sha256"], "approved_by": plan["approved_by"], "reason": plan["reason"],
                "repository_commit": plan["repository_commit"], "database_path": plan["database_path"],
                "skipped_session_count": len(signed["sessions_between"]),
                "skipped_processable_session_count": sum(row["classification"] == "SKIPPED_FULL_READY_COMPLETED" for row in signed["sessions_between"])}
    for key in ("last_processed_id", "last_completed_window_end", "updated_at"):
        expected[key + "_before"] = before[key]
    expected.update(last_processed_id_after=after["last_processed_id"], last_completed_window_end_after=plan["boundary"])
    if any(audit[key] != value for key, value in expected.items()) or json.loads(audit["plan_json"]) != signed:
        raise Error("child audit does not match approved operation")
    parse_db_utc(audit["updated_at_after"], "audit updated_at")
    backup = Path(audit["backup_path"])
    if (not backup.is_absolute() or str(backup.resolve()) != str(backup) or not backup.is_relative_to(group)
            or backup.parent.name != child["child_operation_id"] or not backup.is_file()):
        raise Error("child backup path does not match paired operation")
    attempts = [json.loads(path.read_text(encoding="utf-8")) for path in group.glob("attempt-*.json")]
    if not any(attempt.get("backup_paths", {}).get(child["detector"]) == str(backup) for attempt in attempts):
        raise Error("child backup missing from execution intent")
    if (core.file_sha256(backup) != audit["backup_sha256"] or
            expected_backup_sha256(backup.with_suffix(backup.suffix + ".sha256"), backup) != audit["backup_sha256"]):
        raise Error("child backup checksum mismatch")
    checked = verify_database_readonly(backup)
    if checked.integrity_check != "ok" or checked.foreign_key_violations:
        raise Error("child backup integrity failed")
    with closing(_read_db(backup)) as snapshot:
        if not _checkpoint_equal(repository.get_checkpoint(snapshot, child["detector"], SOURCE), before):
            raise Error("child backup does not contain approved before checkpoint")
    if core.file_sha256(backup) != audit["backup_sha256"]:
        raise Error("child backup changed during verification")
    if db.execute("SELECT 1 FROM packet_checkpoint_recoveries WHERE detector_name=? AND source_table=? AND id>?",
                  (child["detector"], SOURCE, audit["id"])).fetchone():
        raise Error("another recovery occurred after this child")
    exact = dict(after, updated_at=audit["updated_at_after"])
    if _checkpoint_equal(checkpoint, exact):
        return
    if checkpoint is None:
        raise Error("committed checkpoint missing")
    boundary = parse_db_utc(checkpoint["last_completed_window_end"], "checkpoint")
    require_utc_window_boundary(boundary, "checkpoint")
    start = parse_db_utc(plan["boundary"], "pair boundary")
    if (boundary <= start or checkpoint["updated_at"] != checkpoint["last_completed_window_end"] or
            readiness.packet_feature_ready_through is None or boundary > readiness.packet_feature_ready_through):
        raise Error("checkpoint does not show normal target processing")
    old_id, new_id = after["last_processed_id"], checkpoint["last_processed_id"]
    if old_id is not None and (new_id is None or new_id < old_id):
        raise Error("checkpoint source ID regressed")
    # Match each detector's actual selection, including excluded/unmapped rows.
    maximum = db.execute(
        "SELECT MAX(f.id) FROM packet_feature_logs f "
        "JOIN packet_capture_segments g ON g.id=f.capture_segment_id "
        "JOIN packet_capture_sessions s ON s.id=g.capture_session_id "
        "WHERE s.session_id=? AND unixepoch(f.window_start)>=unixepoch(?) "
        "AND unixepoch(f.window_end)<=unixepoch(?) AND (?='packet_if' OR f.direction='INBOUND')",
        (plan["target_session_id"], plan["boundary"], checkpoint["last_completed_window_end"], child["detector"])).fetchone()[0]
    expected_id = max(value for value in (old_id, maximum) if value is not None) if any(
        value is not None for value in (old_id, maximum)) else None
    if new_id != expected_id:
        raise Error("checkpoint did not consume actual target feature IDs")
    if new_id != old_id:
        owner = db.execute("SELECT f.window_start,f.window_end,s.session_id FROM packet_feature_logs f "
                           "JOIN packet_capture_segments g ON g.id=f.capture_segment_id "
                           "JOIN packet_capture_sessions s ON s.id=g.capture_session_id WHERE f.id=?", (new_id,)).fetchone()
        if (owner is None or owner["session_id"] != plan["target_session_id"] or
                parse_db_utc(owner["window_start"]) < start or parse_db_utc(owner["window_end"]) > boundary):
            raise Error("checkpoint source ID not owned by processed target range")


def _states(db, plan, group):
    core.require_migration_005(db)
    target = repository.get_capture_session(db, plan["target_session_id"])
    running = repository.list_running_capture_sessions(db)
    readiness = repository.calculate_packet_feature_readiness(db, plan["target_session_id"])
    if plan["mode"] == core.BOUNDED_REPLAY_MODE:
        if (target is None or target["status"] != "COMPLETED" or len(running) > 1
                or readiness is None or not readiness.full_ready
                or core._bounded_replay_evidence(db, plan["target_session_id"]) != plan["bounded_replay"]
                or target["first_window_start"] != plan["boundary"]
                or any(target[key] != value for key, value in plan["target_identity"].items())):
            raise Error("bounded replay target or fixed input changed")
    elif (target is None or target["status"] != "RUNNING" or target["ended_at"] is not None or
            target["first_window_start"] != plan["boundary"] or _target_failed(db, plan["target_session_id"]) or
            any(target[key] != value for key, value in plan["target_identity"].items()) or
            len(running) != 1 or running[0]["session_id"] != plan["target_session_id"] or
            readiness is None or readiness.live_resume_blocking_reasons):
        raise Error("live target changed or contains failed/unready input")
    states, checkpoints = {}, {}
    for child in plan["children"]:
        name = child["detector"]
        if plan["mode"] == core.BOUNDED_REPLAY_MODE:
            source = repository.get_capture_session(db, plan["current_session_id"])
            signed = child["plan"]
            if signed["allow_failed_current_session"]:
                if (source is None or source["status"] != "FAILED"
                        or core._failed_capture_tail_evidence(db, source, signed["checkpoint"]["before"])
                        != signed["failed_current_tail"]):
                    raise Error("approved failed source tail changed")
            else:
                source_ready = repository.calculate_packet_feature_readiness(db, plan["current_session_id"])
                if (source is None or source["status"] != "COMPLETED" or source_ready is None
                        or not source_ready.full_ready or source_ready.packet_feature_ready_through
                        != parse_db_utc(signed["checkpoint"]["before"]["last_completed_window_end"])):
                    raise Error("approved completed source changed")
        row = repository.get_checkpoint(db, name, SOURCE)
        audit = repository.get_recovery_audit(db, child["child_operation_id"])
        existing = repository.get_existing_recovery(db, detector_name=name, source_table=SOURCE,
                                                    target_session_id=plan["target_session_id"])
        if audit is not None:
            _validate_audit(db, plan, child, audit, row, group, readiness)
            states[name] = "APPLIED"
        elif existing is not None or not _checkpoint_equal(row, child["plan"]["checkpoint"]["before"]):
            raise Error("pending child checkpoint or audit changed")
        else:
            states[name] = "PENDING"
        checkpoints[name] = dict(row)
    if states["packet_if"] == "APPLIED" and states["packet_rule"] != "APPLIED":
        raise Error("IF applied without this pair's Rule audit")
    return states, checkpoints, readiness


def _require_target_quality(db, plan, end):
    policy = CapturePolicy(**plan["runtime"]["capture_policy"])
    rows = db.execute(
        "SELECT g.status,g.error_code,g.start_delay_seconds,g.captured_duration_seconds "
        "FROM packet_capture_segments g JOIN packet_capture_sessions s ON s.id=g.capture_session_id "
        "WHERE s.session_id=? AND unixepoch(g.window_start)>=unixepoch(?) AND unixepoch(g.window_end)<=unixepoch(?)",
        (plan["target_session_id"], plan["boundary"], format_db_utc(end)))
    for row in rows:
        if not is_capture_eligible(CaptureEligibilitySegment(**dict(row)), policy).eligible:
            raise Error("processed target capture timing is ineligible or missing")


def _result(plan, states, *, error=None):
    applied = sum(value in {"APPLIED", "COMMITTED_UNVERIFIED"} for value in states.values())
    return {"pair_id": plan["pair_id"], "plan_sha256": plan["plan_sha256"], "children": states,
            "database_committed": applied > 0,
            "operation_status": "APPLIED_PENDING_PROGRESS" if applied == 2 and error is None else
                                "PARTIAL_HOLD" if applied == 1 else "HOLD" if error else "PENDING",
            "error": error, "progress_advances": 0}


def execute_pair(*, plan_file, db_path, artifact_dir, confirm, confirm_skip_processable=None, resume=False):
    core.require_execute_platform(core._current_platform_name())
    path, plan = _load_pair(plan_file)
    database = core.require_plan_database_path(plan, db_path)
    if not plan["can_execute"] or confirm != confirmation_prefix(plan) + plan["plan_sha256"]:
        raise Error("paired approval mismatch or blocked plan")
    expected_skip = SKIP_CONFIRM + plan["plan_sha256"] if plan["skips_processable"] else None
    if confirm_skip_processable != expected_skip:
        raise Error("paired processable skip approval mismatch")
    group = _group(plan, artifact_dir)
    _require_configured_locks(plan, database)
    locks = core._locks_from_plan(plan)
    with core.acquire_recovery_locks(locks):
        if _load_pair(path)[1] != plan:
            raise Error("pair plan changed before execution")
        _same_boot(plan, _runtime_observation())
        if group.exists():
            _intent(plan, group)
        else:
            if resume:
                raise Error("resume requires existing paired intent")
            group.mkdir()
            core._write_json_atomically(group / "intent.json", plan)
        with closing(_read_db(database)) as db:
            states, _, _ = _states(db, plan, group)
            if all(value == "APPLIED" for value in states.values()):
                return status_pair(plan_file=path, db_path=database, artifact_dir=artifact_dir)
            if not resume and any(value == "APPLIED" for value in states.values()):
                return _result(plan, states, error="explicit resume required")
            for child in plan["children"]:
                if states[child["detector"]] == "PENDING":
                    core._require_same_canonical_plan(child["plan"], core._rebuild_execute_plan(
                        db, plan=child["plan"], repository_state=core.inspect_repository_state(plan["repository_root"]),
                        database=database, locks=locks))
        attempt_id = "attempt-" + str(uuid.uuid4())
        attempt = group / attempt_id
        attempt.mkdir()
        backup_paths = {child["detector"]: str(attempt / child["detector"] / child["child_operation_id"] / "database.backup.db")
                        for child in plan["children"]}
        core._write_json_atomically(group / (attempt_id + ".json"), {"backup_paths": backup_paths})
        error = None
        for child in plan["children"]:
            name = child["detector"]
            if states[name] == "APPLIED":
                continue
            try:
                if _load_pair(path)[1] != plan:
                    raise Error("pair plan changed between child operations")
                _same_boot(plan, _runtime_observation())
                with closing(_read_db(database)) as db:
                    states, _, _ = _states(db, plan, group)
                if states[name] != "PENDING":
                    raise Error("pending child changed before execution")
                child_root = attempt / name
                child_root.mkdir()
                child_file = child_root / "plan.json"
                core._write_json_atomically(child_file, child["plan"])
                prepared = core._prepare_recovery_execution(
                    plan_file=child_file, db_path=database, artifact_dir=child_root,
                    confirm=core.recovery_execute_confirmation(child["plan"]),
                    confirm_skip_processable=core.PROCESSABLE_SKIP_PREFIX + child["plan"]["plan_sha256"]
                    if child["plan"]["summary"]["skips_processable_sessions"] else None,
                    operation_id=child["child_operation_id"])
                core._execute_locked_recovery(**prepared)
                states[name] = "APPLIED"
            except Exception as exc:
                error = type(exc).__name__
                # COMMIT may precede a lost response. Never infer rollback from the exception.
                with closing(_read_db(database)) as db:
                    if repository.get_recovery_audit(db, child["child_operation_id"]) is not None:
                        states[name] = "APPLIED"
                break
        # Reconcile both operations from full audit even when a child lost its response.
        try:
            with closing(_read_db(database)) as db:
                states, _, _ = _states(db, plan, group)
        except Exception as exc:
            error = type(exc).__name__
            states = {name: "COMMITTED_UNVERIFIED" if value == "APPLIED" else value for name, value in states.items()}
        result = _result(plan, states, error=error)
        core._write_json_atomically(attempt / "result.json", result)
        return result


def status_pair(*, plan_file, db_path, artifact_dir):
    _, plan = _load_pair(plan_file)
    database = core.require_plan_database_path(plan, db_path)
    group = _group(plan, artifact_dir)
    _intent(plan, group)
    runtime = _runtime_observation()
    _same_boot(plan, runtime)
    _require_configured_locks(plan, database)
    if core.inspect_repository_state(plan["repository_root"]) != plan["repository_state"]:
        raise Error("repository state changed from paired approval")
    checked = verify_database_readonly(database)
    if checked.integrity_check != "ok" or checked.foreign_key_violations:
        raise Error("live database integrity failed")
    with closing(_read_db(database)) as db:
        states, checkpoints, readiness = _states(db, plan, group)
        result = _result(plan, states)
        if not all(value == "APPLIED" for value in states.values()):
            return result
        trust = repository.get_checkpoint(db, "trust_score_v2", "detection_events")
        producer = repository.get_checkpoint(db, "mqtt_feature_builder", "mqtt_logs")
        if trust is None or producer is None:
            return _result(plan, states, error="required processing checkpoint missing")
        checkpoints["trust_score_v2"] = dict(trust)
        now = core._utc_now().replace(microsecond=0)
        producer_end = parse_db_utc(producer["last_completed_window_end"])
        trust_end = require_utc_window_boundary(parse_db_utc(trust["last_completed_window_end"]), "trust checkpoint")
        packet_end = min(parse_db_utc(checkpoints[name]["last_completed_window_end"]) for name in DETECTORS)
        _require_target_quality(db, plan, max(parse_db_utc(checkpoints[name]["last_completed_window_end"]) for name in DETECTORS))
        if db.execute("SELECT 1 FROM detection_events WHERE processed_at IS NULL AND ("
                      "(analysis_window_end IS NOT NULL AND (unixepoch(analysis_window_end) IS NULL OR unixepoch(analysis_window_end)<=unixepoch(?))) OR "
                      "(analysis_window_end IS NULL AND (detected_at IS NULL OR unixepoch(detected_at) IS NULL OR unixepoch(detected_at)<unixepoch(?))) OR "
                      "(analysis_window_start IS NOT NULL AND unixepoch(analysis_window_start) IS NULL)) LIMIT 1",
                      (trust["last_completed_window_end"], trust["last_completed_window_end"])).fetchone():
            raise Error("Trust cutoff still contains unprocessed eligible events")
        if trust["last_processed_id"] is not None and not db.execute(
            "SELECT 1 FROM detection_events WHERE id=? AND processed_at IS NOT NULL "
            "AND unixepoch(processed_at)<=unixepoch(?) AND ((analysis_window_end IS NOT NULL AND unixepoch(analysis_window_end)<=unixepoch(?)) "
            "OR (analysis_window_end IS NULL AND (detected_at IS NULL OR unixepoch(detected_at)<unixepoch(?))))",
            (trust["last_processed_id"], trust["last_completed_window_end"], trust["last_completed_window_end"], trust["last_completed_window_end"])).fetchone():
            raise Error("Trust checkpoint source ID lacks processed event evidence")
        if plan["mode"] == core.BOUNDED_REPLAY_MODE:
            replay_end = parse_db_utc(plan["bounded_replay"]["replay_end"])
            mqtt_names = [name for name in ("mqtt_feature_rule", "mqtt_message_rule")
                          if name in runtime["required"]]
            for name in mqtt_names:
                source = "feature_logs" if name == "mqtt_feature_rule" else "mqtt_logs"
                row = repository.get_checkpoint(db, name, source)
                if row is None:
                    return _result(plan, states, error="required MQTT replay checkpoint missing")
                checkpoints[name] = dict(row)
            complete = (all(parse_db_utc(checkpoints[name]["last_completed_window_end"]) == replay_end
                            for name in DETECTORS)
                        and trust_end == replay_end and trust["updated_at"] == trust["last_completed_window_end"]
                        and producer_end >= replay_end
                        and all(parse_db_utc(checkpoints[name]["last_completed_window_end"]) >= replay_end
                                and checkpoints[name]["updated_at"] == checkpoints[name]["last_completed_window_end"]
                                for name in mqtt_names))
            latest_runtime = _runtime_observation()
            _same_boot(plan, latest_runtime)
            active = all(observed.get("clock_synchronized") is True
                         and all(observed["services"].get(name) is True for name in SERVICES)
                         and all(name in observed["enabled"] and name in observed["required"] for name in DETECTORS)
                         for observed in (runtime, latest_runtime))
            result.update(mode=plan["mode"], replay_end=plan["bounded_replay"]["replay_end"],
                          checkpoints=checkpoints, live_recovery_complete=False)
            if complete and active:
                result["operation_status"] = "REPLAY_COMPLETE"
            return result
        fresh = (parse_db_utc(plan["boundary"]) < trust_end <= packet_end and
                 trust["updated_at"] == trust["last_completed_window_end"] and
                 all(timedelta(0) <= now - parse_db_utc(row["last_completed_window_end"]) <= timedelta(seconds=FRESH_SECONDS)
                    and parse_db_utc(row["last_completed_window_end"]) <= producer_end for row in checkpoints.values())
                 )
        active = runtime.get("clock_synchronized") is True and all(runtime["services"].get(name) is True for name in SERVICES) and all(
            name in runtime["enabled"] and name in runtime["required"] for name in DETECTORS)
        latest_runtime = _runtime_observation()
        _same_boot(plan, latest_runtime)
        active = active and latest_runtime.get("clock_synchronized") is True and all(latest_runtime["services"].get(name) is True for name in SERVICES)
    observation = {"pair_id": plan["pair_id"], "plan_sha256": plan["plan_sha256"], "runtime": runtime,
                   "observed_at": format_db_utc(now), "checkpoints": checkpoints,
                   "eligible": fresh and active, "advances": 0}
    progress = group / "progress.json"
    with core.single_instance_lock(group / ".progress.lock"):
        if progress.exists():
            previous = json.loads(progress.read_text(encoding="utf-8"))
            core.verify_plan_sha256(previous)
            if (previous["pair_id"] != plan["pair_id"] or previous["approval_sha256"] != plan["plan_sha256"]
                    or any(previous["runtime"].get(key) != runtime.get(key) for key in ("boot_id", "enabled", "required", "capture_policy"))):
                raise Error("progress observation binding changed")
            old_time = parse_db_utc(previous["observed_at"])
            if now < old_time:
                raise Error("observation clock regressed")
            advanced = True
            for name, row in checkpoints.items():
                old = previous["checkpoints"][name]
                old_end, new_end = parse_db_utc(old["last_completed_window_end"]), parse_db_utc(row["last_completed_window_end"])
                if (new_end < old_end or old["last_processed_id"] is not None and (
                        row["last_processed_id"] is None or row["last_processed_id"] < old["last_processed_id"]) or
                        new_end == old_end and row != old):
                    raise Error("processing checkpoint regressed or changed at same boundary")
                advanced = advanced and new_end > old_end
            if (fresh and active and previous["eligible"] and now - old_time <= timedelta(seconds=FRESH_SECONDS)):
                observation["advances"] = (2 if previous["advances"] >= 2 else
                    min(2, previous["advances"] + 1) if advanced and now > old_time else previous["advances"])
        observation.pop("plan_sha256")
        observation["approval_sha256"] = plan["plan_sha256"]
        core._write_json_atomically(progress, core.attach_plan_sha256(observation, generated_at=now))
    result["progress_advances"] = observation["advances"]
    if fresh and active and observation["advances"] >= 2:
        result["operation_status"] = "COMPLETE"
    return result
