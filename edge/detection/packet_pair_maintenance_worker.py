"""Pi-only canonical pair application while an administrator holds maintenance.

This worker never controls services or retries an operation. Root must seal the
reviewed request, stop/reap writers, and classify before deciding restoration.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import subprocess

from edge.detection import packet_checkpoint_pair_recovery as pair

core = pair.core
SCHEMA = "packet-pair-maintenance-request-v1"
UNITS = (*pair.SERVICES, "packet-feature-extractor.service",
         "firewall-runtime-snapshot.timer", "firewall-runtime-snapshot.service",
         "firewall-worker.service", "gateway-metrics.service", "iot-edge-api.service")
STATE_FLAGS = {"rerun": False, "restore_database": False, "runtime_complete": False,
               "database_committed": None,
               "children": {name: "UNVERIFIED" for name in pair.DETECTORS}}


def _require(condition, message):
    if not condition:
        raise pair.Error(message)


def _require_pi():
    _require(os.name == "posix" and os.getuid() == os.geteuid() == 1000,
             "maintenance SQLite worker requires pi UID1000")


def _require_quiescent(keep_capture=False):
    """Read OS state only; root independently owns stopping and writer reap."""
    units = ("packet-feature-extractor.timer", "detection-orchestrator.service",
             "packet-feature-extractor.service") if keep_capture else UNITS
    for unit in units:
        result = subprocess.run(["systemctl", "show", unit, "--property=LoadState", "--property=ActiveState",
                                 "--property=MainPID", "--property=ControlGroup"],
                                capture_output=True, text=True, timeout=5, check=True)
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        _require(fields.get("LoadState") == "loaded"
                 and fields.get("ActiveState") in {"inactive", "failed"}
                 and fields.get("MainPID", "0" if unit.endswith(".timer") else None) == "0",
                 "writer or timer is not quiescent: " + unit)
        group = fields.get("ControlGroup")
        if group:
            path = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
            _require(group.startswith("/") and ".." not in Path(group).parts, "invalid cgroup")
            _require(not path.exists() or "populated 0" in path.read_text().splitlines(),
                     "writer cgroup is populated: " + unit)
    jobs = subprocess.run(["systemctl", "list-jobs", "--no-legend", "--no-pager"],
                          capture_output=True, text=True, timeout=5, check=True)
    pending = jobs.stdout.strip()
    if keep_capture:
        pending = "\n".join(line for line in pending.splitlines() if set(line.split()) & set(units))
    _require(not pending, "systemd jobs are pending")


def _keep_capture(scope):
    value = scope.get("allow_capture_appends", False)
    _require(type(value) is bool, "capture append approval must be boolean")
    return value


def _check_quiescent(request):
    if _keep_capture(request["scope"]):
        _require_quiescent(True)
    else:
        _require_quiescent()


def _scope(plan):
    """Only pause mode may replace the reviewed running Capture lifecycle."""
    value = core.canonical_plan_binding(plan)
    value.pop("pair_id")
    value["runtime"].pop("services")
    keep = _keep_capture(plan)
    if not keep:
        value["bounded_replay"].pop("later_running_session")
    for child in value["children"]:
        child.pop("child_operation_id")
        signed = child["plan"]
        if not keep:
            signed.pop("running_sessions")
            signed["summary"].pop("running_sessions")
            signed["bounded_replay"].pop("later_running_session")
    return value


def _same_scope(request, plan):
    current, expected = _scope(plan), request["scope"]
    if _keep_capture(expected) and expected["mode"] == core.LIVE_RESUME_MODE:
        # Reuse the core's exact comparison, including its sole readiness-growth exception.
        _require(len(current["children"]) == len(expected["children"]), "child scope changed")
        for before, after in zip(expected["children"], current["children"]):
            _require(before["detector"] == after["detector"], "child order changed")
            core._require_same_canonical_plan(before["plan"], after["plan"])
        current, expected = dict(current), dict(expected)
        current.pop("children")
        expected.pop("children")
    _require(current == expected, "fresh plan differs from reviewed semantic scope")


def _eligible(plan):
    keep = _keep_capture(plan)
    mode_ok = plan["mode"] == core.BOUNDED_REPLAY_MODE or (keep and plan["mode"] == core.LIVE_RESUME_MODE)
    _require(mode_ok and plan["can_execute"] is True
             and plan["skips_processable"] is False
             and all(not child["plan"]["sessions_between"] for child in plan["children"]),
             "maintenance requires an executable approved pair without skipped sessions")


def _running_identity(db):
    rows = pair.repository.list_running_capture_sessions(db)
    _require(len(rows) == 1, "exactly one retained RUNNING Capture required")
    return dict(pair.repository.get_capture_session(db, rows[0]["session_id"]))


def _identities(db, plan):
    return {name: dict(pair.repository.get_capture_session(db, plan[name]))
            for name in ("current_session_id", "target_session_id")}


def prepare(*, plan_file, request_output):
    """Read a reviewed canonical plan and DB; only write the new request artifact."""
    _require_pi()
    _, plan = pair._load_pair(plan_file)
    _eligible(plan)
    database = core.require_plan_database_path(plan, plan["database_path"])
    pair._same_boot(plan, pair._runtime_observation())
    pair._require_configured_locks(plan, database)
    _require(core.canonical_plan_binding(core.inspect_repository_state(plan["repository_root"]))
             == _scope(plan)["repository_state"], "reviewed repository changed")
    with closing(pair._read_db(database)) as db:
        states, _, _ = pair._states(db, plan, Path(plan["repository_root"]))
        _require(all(state == "PENDING" for state in states.values()), "reviewed operation already applied")
        identities = _identities(db, plan)
        capture = _running_identity(db) if _keep_capture(plan) else None
    output = core.validate_generated_paths(repository_root=Path(plan["repository_root"]),
                                           plan_output=Path(request_output))["plan_output"]
    _require(not output.exists(), "request output must be new")
    fields = {"plan_schema_version": SCHEMA,
        "reference_plan_sha256": plan["plan_sha256"], "scope": _scope(plan), "session_identities": identities}
    if capture is not None:
        fields["capture_session_identity"] = capture
    request = core.attach_plan_sha256(fields, generated_at=core._utc_now().replace(microsecond=0))
    core._write_json_atomically(output, request)
    return request


def _request(request_file, request_sha256):
    _, request = core._load_plan(request_file)
    _require(request.get("plan_schema_version") == SCHEMA
             and request["plan_sha256"] == request_sha256, "approved request SHA or schema changed")
    return request


def _require_private_directory(directory):
    _require(directory.stat().st_uid == 1000 and directory.stat().st_mode & 0o022 == 0,
             "artifact directory must be private and owned by pi")


def _artifacts(request, artifact_dir):
    directory = core.require_existing_directory(Path(artifact_dir), field_name="artifact_dir")
    directory = core.validate_generated_path(Path(request["scope"]["repository_root"]),
                                              directory, field_name="artifact_dir")
    _require_private_directory(directory)
    return directory


def _verify_paused(request, plan, database):
    _eligible(plan)
    _same_scope(request, plan)
    if not _keep_capture(request["scope"]):
        _require(plan["bounded_replay"]["later_running_session"] is None,
                 "maintenance plan must have no RUNNING Capture")
    pair._same_boot(plan, pair._runtime_observation())
    pair._require_configured_locks(plan, database)
    _require(core.canonical_plan_binding(core.inspect_repository_state(plan["repository_root"]))
             == request["scope"]["repository_state"], "approved repository changed")
    with closing(pair._read_db(database)) as db:
        _verify_capture(db, request)
        _require(_identities(db, plan) == request["session_identities"], "approved session identity changed")


def _verify_capture(db, request):
    if _keep_capture(request["scope"]):
        _require(_running_identity(db) == request.get("capture_session_identity"),
                 "retained Capture full identity changed")
    else:
        _require(not pair.repository.list_running_capture_sessions(db), "RUNNING Capture exists")


def classify(*, request_file, request_sha256, artifact_dir):
    """Read-only actual audit classification after root has reaped the worker."""
    _require_pi()
    try:
        request = _request(request_file, request_sha256)
        directory = _artifacts(request, artifact_dir)
        intent = json.loads((directory / "worker-intent.json").read_text(encoding="utf-8"))
        _require(intent == {"request_sha256": request_sha256}, "worker intent changed")
        _, plan = pair._load_pair(directory / "plan.json")
        database = core.require_plan_database_path(plan, request["scope"]["database_path"])
        _check_quiescent(request)
        _verify_paused(request, plan, database)
        checked = pair.verify_database_readonly(database)
        _require(checked.integrity_check == "ok" and not checked.foreign_key_violations,
                 "database integrity or foreign keys failed")
        group = pair._group(plan, directory)
        if group.exists():
            pair._intent(plan, group)
        with closing(pair._read_db(database)) as db:
            states, checkpoints, _ = pair._states(db, plan, group)
            _verify_capture(db, request)
        _check_quiescent(request)
        applied = sum(value == "APPLIED" for value in states.values())
        state = {0: "NOT_COMMITTED_VERIFIED", 1: "PARTIAL_HOLD", 2: "COMMITTED_VERIFIED"}[applied]
        return dict(STATE_FLAGS, state=state, children=states, checkpoints=checkpoints,
                    verified_audit_count=applied, plan_sha256=plan["plan_sha256"],
                    pair_id=plan["pair_id"], request_sha256=request_sha256,
                    artifact_dir=str(directory), database_committed=applied > 0)
    except Exception as exc:
        return dict(STATE_FLAGS, state="UNKNOWN_HOLD", verified_audit_count=None,
                    request_sha256=request_sha256, artifact_dir=str(artifact_dir),
                    error_type=type(exc).__name__, error=str(exc))


def execute(*, request_file, request_sha256, artifact_dir):
    """Build a fresh paused plan, execute once, then classify actual durable state."""
    _require_pi()
    request = _request(request_file, request_sha256)
    directory = _artifacts(request, artifact_dir)
    _require(not any(directory.iterdir()), "artifact directory is already used; classify instead")
    _check_quiescent(request)
    scope = request["scope"]
    database = core.resolve_database_path(scope["database_path"])
    with closing(pair._read_db(database)) as db:
        _verify_capture(db, request)
    # Exclusive creation survives worker death and forbids an automatic second execute.
    with (directory / "worker-intent.json").open("x", encoding="utf-8") as stream:
        json.dump({"request_sha256": request_sha256}, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    error = None
    try:
        plan = pair.inspect_pair(db_path=database, repository_root=scope["repository_root"],
            current_session_id=scope["current_session_id"], target_session_id=scope["target_session_id"],
            approved_by=scope["approved_by"], reason=scope["reason"], mode=scope["mode"],
            allow_failed_current_session=scope["allow_failed_current_session"],
            allow_failed_target_session=scope["allow_failed_target_session"], plan_output=directory / "plan.json",
            **({"allow_capture_appends": True} if _keep_capture(scope) else {}))
        _verify_paused(request, plan, database)
        _require(_request(request_file, request_sha256) == request, "approved request replaced")
        _check_quiescent(request)
        pair.execute_pair(plan_file=directory / "plan.json", db_path=database, artifact_dir=directory,
                          confirm=pair.confirmation_prefix(plan) + plan["plan_sha256"])
    except Exception as exc:
        error = str(exc)
    result = classify(request_file=request_file, request_sha256=request_sha256, artifact_dir=directory)
    if error is not None:
        result["execution_error"] = error
    core._write_json_atomically(directory / "result.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    before = commands.add_parser("prepare")
    before.add_argument("--plan-file", required=True)
    before.add_argument("--request-output", required=True)
    for name in ("execute", "classify"):
        command = commands.add_parser(name)
        command.add_argument("--request-file", required=True)
        command.add_argument("--request-sha256", required=True)
        command.add_argument("--artifact-dir", required=True)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    try:
        result = {"prepare": prepare, "execute": execute, "classify": classify}[command](**args)
    except Exception as exc:
        result = dict(STATE_FLAGS, state="UNKNOWN_HOLD", error_type=type(exc).__name__, error=str(exc))
        if command != "prepare":
            result.update(request_sha256=args["request_sha256"], artifact_dir=args["artifact_dir"])
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0 if command == "prepare" and result.get("plan_schema_version") == SCHEMA or result.get(
        "state") in {"NOT_COMMITTED_VERIFIED", "COMMITTED_VERIFIED"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
