"""One-shot service manager around the unchanged, audited pair engine."""
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from edge.detection import packet_checkpoint_pair_recovery as pair
from edge.maintenance.run_planned_maintenance import SystemOperations

core = pair.core
Error = core.PacketCheckpointRecoveryError
SCHEMA = "packet-pair-manager-v1"
UNITS = ("packet-feature-extractor.timer", "detection-orchestrator.service", "packet-feature-extractor.service")
BUDGETS = {"stop_unit_seconds": 35, "pair_worker_seconds": 120, "terminate_grace_seconds": 5,
           "kill_reap_seconds": 5, "restore_unit_seconds": 35, "verify_observation_start_seconds": 120}


def _safe_path(value):
    path = Path(value).absolute()
    if any(part.is_symlink() or getattr(part, "is_junction", lambda: False)() for part in (path, *path.parents)):
        raise Error("unsafe manager path")
    return path.resolve()


def _save(path, value):
    core._write_json_atomically(path, core.attach_plan_sha256(value, generated_at=core._utc_now()))
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _load_json(path):
    value = json.loads(_safe_path(path).read_text(encoding="utf-8"))
    core.verify_plan_sha256(value)
    return value


class Services(SystemOperations):
    def state(self, unit):
        if unit not in UNITS:
            raise Error("unapproved service")
        result = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        value = result.stdout.strip()
        if (result.returncode, value) not in ((0, "active"), (3, "inactive")):
            raise Error("service state unconfirmed")
        return value

    def stop(self, unit, timeout):
        self.command("systemctl", "stop", unit, timeout=timeout)
        if self.state(unit) != "inactive":
            raise Error("processing service did not stop")
        if unit.endswith(".service"):
            result = self.command("systemctl", "show", unit, "--property=Result", "--property=ExecMainStatus", timeout=5)
            values = dict(line.split("=", 1) for line in result.splitlines() if "=" in line)
            if values.get("Result") != "success" or values.get("ExecMainStatus") != "0":
                raise Error("processing service stopped uncleanly")

    def start(self, unit, timeout):
        self.command("systemctl", "start", unit, timeout=timeout)
        if self.state(unit) != "active":
            raise Error("processing service restoration unconfirmed")


def _identity(pid):
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = text.rsplit(")", 1)[1].split()
    if fields[0] in ("Z", "X"):
        raise ProcessLookupError("process is no longer running")
    return fields[19]  # Linux field 22, process start ticks.


class Processes:
    def identity(self, pid):
        return _identity(pid)

    def alive(self, receipt):
        try:
            return self.identity(receipt["pid"]) == receipt["start_identity"]
        except (OSError, KeyError, ValueError):
            return False

    def launch(self, plan_file, role):
        plan = _load_plan(plan_file)
        argv = [sys.executable, "-m", "edge.detection.run_packet_recovery_pair",
                "--internal-" + role, "--plan-file", str(plan_file)]
        if role == "worker":
            argv += ["--worker-token", _journal(plan)["worker_token"]]
        return subprocess.Popen(argv,
                                cwd=plan["repository_root"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    def terminate(self, process, force=False):
        os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)


def _paths(plan):
    group = _safe_path(Path(plan["artifact_dir"]) / ("manager-" + plan["manager_id"]))
    return group, group / "journal.json", Path(plan["database_path"] + ".packet-pair-manager.lock")


def _load_plan(path):
    plan = _load_json(path)
    if plan.get("plan_schema_version") != SCHEMA or str(uuid.UUID(plan["manager_id"])) != plan["manager_id"]:
        raise Error("invalid manager plan")
    if set(plan["budgets"]) != set(BUDGETS) or any(type(value) is not int or not 1 <= value <= 900 for value in plan["budgets"].values()):
        raise Error("invalid manager time budget")
    _, signed = pair._load_pair(_safe_path(plan["pair_plan_file"]))
    database = core.require_plan_database_path(signed, _safe_path(plan["database_path"]))
    if signed["plan_sha256"] != plan["pair_plan_sha256"] or signed["repository_root"] != plan["repository_root"]:
        raise Error("pair approval changed")
    if (plan.get("units") != list(UNITS) or plan.get("timeout_scope") != "whole_rule_then_if_pair_worker"
            or plan.get("source_session_id") != signed["current_session_id"]
            or plan.get("target_session_id") != signed["target_session_id"]
            or plan.get("boot_id") != signed["runtime"]["boot_id"]):
        raise Error("manager scope binding changed")
    pair._require_configured_locks(signed, database)
    root = _safe_path(plan["repository_root"])
    group, journal, command_lock = _paths(plan)
    core.validate_generated_paths(repository_root=root, artifact_dir=_safe_path(plan["artifact_dir"]),
                                  result_path=journal, lock_paths=(command_lock,))
    return plan


def _reconcile(plan):
    """Validate complete DB audits and original CAS, never trust child output."""
    _, signed = pair._load_pair(_safe_path(plan["pair_plan_file"]))
    database = core.require_plan_database_path(signed, plan["database_path"])
    pair._same_boot(signed, pair._runtime_observation())
    if core.inspect_repository_state(signed["repository_root"]) != signed["repository_state"]:
        raise Error("repository changed")
    group = pair._group(signed, plan["artifact_dir"])
    if group.exists():
        pair._intent(signed, group)
    with closing(pair._read_db(database)) as db:
        states, checkpoints, _ = pair._states(db, signed, group)
    return states, checkpoints


def create_plan(*, pair_plan_file, db_path, artifact_dir, plan_output, budgets=None, system=None):
    system = system or Services()
    source, signed = pair._load_pair(_safe_path(pair_plan_file))
    database = core.require_plan_database_path(signed, _safe_path(db_path))
    root = _safe_path(signed["repository_root"])
    artifacts, output = _safe_path(artifact_dir), _safe_path(plan_output)
    core.validate_generated_paths(repository_root=root, artifact_dir=artifacts, plan_output=output)
    if output.exists():
        raise Error("manager plan output must be new")
    plan = {"plan_schema_version": SCHEMA, "manager_id": str(uuid.uuid4()),
            "pair_plan_file": str(source), "pair_plan_sha256": signed["plan_sha256"],
            "database_path": str(database), "repository_root": str(root), "artifact_dir": str(artifacts),
            "source_session_id": signed["current_session_id"], "target_session_id": signed["target_session_id"],
            "boot_id": signed["runtime"]["boot_id"], "budgets": dict(BUDGETS if budgets is None else budgets),
            "timeout_scope": "whole_rule_then_if_pair_worker", "units": list(UNITS),
            "observed_services": {unit: system.state(unit) for unit in UNITS},
            "can_execute": signed["can_execute"] and not pair._group(signed, artifacts).exists(),
            "blocking_reasons": ["LEGACY_PAIR_GROUP_WITHOUT_MANAGER_ORIGINAL_STATE"] if pair._group(signed, artifacts).exists() else []}
    if set(plan["budgets"]) != set(BUDGETS) or any(type(value) is not int or not 1 <= value <= 900 for value in plan["budgets"].values()):
        raise Error("invalid manager time budget")
    _save(output, plan)
    return _load_plan(output)


def _journal(plan, required=True):
    _, path, _ = _paths(plan)
    if not path.exists():
        if required:
            raise Error("manager original service journal missing")
        return None
    journal = _load_json(path)
    if journal.get("manager_id") != plan["manager_id"] or journal.get("approval_sha256") != plan["plan_sha256"]:
        raise Error("manager journal approval mismatch")
    if set(journal.get("original", {})) != set(UNITS) or any(value not in ("active", "inactive") for value in journal["original"].values()):
        raise Error("original service state unconfirmed")
    return journal


def _receipt(plan, role):
    path = _paths(plan)[0] / (role + ".json")
    if not path.exists():
        return None
    receipt = _load_json(path)
    if receipt.get("manager_id") != plan["manager_id"] or receipt.get("approval_sha256") != plan["plan_sha256"]:
        raise Error("process receipt approval mismatch")
    if receipt.get("role") != role:
        raise Error("process role mismatch")
    if receipt.get("attempt_id") != _journal(plan)["attempt_id"]:
        return None
    return receipt


def _record_process(plan, role, pid, processes):
    value = {"manager_id": plan["manager_id"], "approval_sha256": plan["plan_sha256"],
             "pid": pid, "start_identity": processes.identity(pid), "role": role,
             "attempt_id": _journal(plan)["attempt_id"]}
    if role == "worker":
        value["worker_token"] = _journal(plan)["worker_token"]
    _save(_paths(plan)[0] / (role + ".json"), value)


def status(*, plan_file, system=None, processes=None):
    system, processes = system or Services(), processes or Processes()
    plan = _load_plan(plan_file)
    journal = _journal(plan, required=False)
    result = {"manager_id": plan["manager_id"], "plan_sha256": plan["plan_sha256"],
              "timeout_scope": plan["timeout_scope"], "database_committed": None,
              "operation_status": "HOLD", "original_services": journal["original"] if journal else None,
              "requested_services": journal.get("requested", {}) if journal else {},
              "actual_services": {unit: system.state(unit) for unit in UNITS},
              "restoration_failures": journal.get("restoration_failures", []) if journal else [],
              "journal_phase": journal.get("phase") if journal else None,
              "last_verification": journal.get("verification") if journal else None}
    states, checkpoints = _reconcile(plan)
    result.update(children=states, checkpoints=checkpoints, database_committed=any(value == "APPLIED" for value in states.values()))
    live = {role: bool(_receipt(plan, role) and processes.alive(_receipt(plan, role))) for role in ("supervisor", "worker")}
    result["live_processes"] = live
    result["operation_status"] = ("RUNNING" if any(live.values()) else "PENDING" if not result["database_committed"]
                                  else "APPLIED_VERIFY_REQUIRED" if all(value == "APPLIED" for value in states.values()) else "PARTIAL_HOLD")
    if journal is None and pair._group(pair._load_pair(plan["pair_plan_file"])[1], plan["artifact_dir"]).exists():
        result["operation_status"] = "LEGACY_ORIGINAL_STATE_HOLD"
    return result


def apply(*, plan_file, confirm, system=None, processes=None):
    system, processes = system or Services(), processes or Processes()
    system.require_admin()
    plan = _load_plan(plan_file)
    if confirm != "APPLY-PACKET-PAIR-MANAGER:" + plan["plan_sha256"] or not plan["can_execute"]:
        raise Error("manager approval mismatch or blocked plan")
    group, journal_path, command_lock = _paths(plan)
    with core.single_instance_lock(command_lock):
        journal = _journal(plan, required=False)
        if journal:
            for role in ("supervisor", "worker"):
                receipt = _receipt(plan, role)
                if receipt and processes.alive(receipt):
                    return {"operation_status": "RUNNING", "manager_id": plan["manager_id"], "database_committed": None}
            if journal["phase"] in ("LAUNCH_REQUESTED", "WORKER_START_REQUESTED", "WORKER_RUNNING") and not journal.get("worker_reaped"):
                raise Error("unresolved supervisor launch; inspect status before retry")
        else:
            signed = pair._load_pair(plan["pair_plan_file"])[1]
            if pair._group(signed, plan["artifact_dir"]).exists():
                raise Error("legacy pair has no manager original state")
            _reconcile(plan)
            original = {unit: system.state(unit) for unit in UNITS}
            if original != plan["observed_services"]:
                raise Error("service state changed since manager approval")
            group.mkdir()
            journal = {"manager_id": plan["manager_id"], "approval_sha256": plan["plan_sha256"],
                       "original": original, "requested": {}, "actual": original.copy(),
                       "restoration_failures": [], "transitions": [], "phase": "PREPARED"}
            _save(journal_path, journal)
        _reconcile(plan)
        journal.setdefault("attempt_history", []).append({"phase": journal["phase"],
                                                         "restoration_failures": journal["restoration_failures"]})
        journal.update(phase="LAUNCH_REQUESTED", attempt_id=str(uuid.uuid4()), worker_reaped=False,
                       worker_timeout=False, restoration_failures=[])
        _save(journal_path, journal)  # Ambiguous launch is never automatically retried.
        process = processes.launch(plan_file, "supervisor")
        _record_process(plan, "supervisor", process.pid, processes)
    return {"operation_status": "RUNNING", "manager_id": plan["manager_id"], "database_committed": None}


def _transition(plan, journal, system, unit, action):
    path = _paths(plan)[1]
    journal["requested"][unit] = action
    transition = {"unit": unit, "requested": action, "actual": None}
    journal.setdefault("transitions", []).append(transition)
    _save(path, journal)
    try:
        getattr(system, action)(unit, plan["budgets"]["stop_unit_seconds" if action == "stop" else "restore_unit_seconds"])
    except BaseException as error:
        transition["error"] = type(error).__name__
        raise
    finally:
        try:
            journal["actual"][unit] = system.state(unit)
        except Exception:
            journal["actual"][unit] = "UNKNOWN"
        transition["actual"] = journal["actual"][unit]
        _save(path, journal)


def verify(*, plan_file, system=None, processes=None):
    plan = _load_plan(plan_file)
    journal = _journal(plan)
    system, processes = system or Services(), processes or Processes()
    receipt = _receipt(plan, "worker")
    if receipt and processes.alive(receipt):
        raise Error("worker still alive during verification")
    if journal.get("restoration_failures"):
        raise Error("service restoration remains unconfirmed")
    if any(system.state(unit) != "active" for unit in UNITS if journal["original"][unit] == "active"):
        raise Error("original active service restoration unconfirmed")
    return pair.status_pair(plan_file=plan["pair_plan_file"], db_path=plan["database_path"], artifact_dir=plan["artifact_dir"])


def _terminate_reap(plan, worker, processes, journal):
    try:
        processes.terminate(worker)
    except ProcessLookupError:
        pass
    try:
        worker.wait(timeout=plan["budgets"]["terminate_grace_seconds"])
    except subprocess.TimeoutExpired:
        try:
            processes.terminate(worker, force=True)
        except ProcessLookupError:
            pass
        worker.wait(timeout=plan["budgets"]["kill_reap_seconds"])
    journal["worker_reaped"] = True
    _save(_paths(plan)[1], journal)


def supervise(plan_file, *, system=None, processes=None, monotonic=None, sleep=None):
    system, processes = system or Services(), processes or Processes()
    system.require_admin()
    now, pause = monotonic or time.monotonic, sleep or time.sleep
    plan = _load_plan(plan_file)
    group, journal_path, command_lock = _paths(plan)
    with core.single_instance_lock(command_lock, wait_seconds=15):
        existing_worker = _receipt(plan, "worker")
        if existing_worker and processes.alive(existing_worker):
            raise Error("existing worker still alive")
        if isinstance(processes, Processes):
            receipt = _receipt(plan, "supervisor")
            if receipt is None or receipt["pid"] != os.getpid() or not processes.alive(receipt):
                raise Error("supervisor launch receipt unconfirmed")
        _record_process(plan, "supervisor", os.getpid(), processes)
        journal = _journal(plan)
        worker = None
        stopped, safe_restore = False, False
        try:
            _reconcile(plan)
            journal["phase"] = "STOPPING"
            _save(journal_path, journal)
            stopped = True  # A timed-out stop may already have changed a service.
            for unit in UNITS:
                if system.state(unit) == "active":
                    _transition(plan, journal, system, unit, "stop")
            states, _ = _reconcile(plan)
            if not all(value == "APPLIED" for value in states.values()):
                journal.update(phase="WORKER_START_REQUESTED", worker_reaped=False, worker_timeout=False,
                               worker_token=uuid.uuid4().hex)
                _save(journal_path, journal)
                worker = processes.launch(plan_file, "worker")
                _record_process(plan, "worker", worker.pid, processes)
                journal["phase"] = "WORKER_RUNNING"
                _save(journal_path, journal)
                try:
                    worker.wait(timeout=plan["budgets"]["pair_worker_seconds"])
                except subprocess.TimeoutExpired:
                    journal["worker_timeout"] = True
                    _save(journal_path, journal)
                    _terminate_reap(plan, worker, processes, journal)
                journal["worker_reaped"] = True
                _save(journal_path, journal)
            states, checkpoints = _reconcile(plan)
            journal.update(children=states, checkpoints=checkpoints,
                           database_committed=any(value == "APPLIED" for value in states.values()))
            safe_restore = all(value == "PENDING" for value in states.values()) or all(value == "APPLIED" for value in states.values())
            journal["phase"] = "PAIR_APPLIED" if all(value == "APPLIED" for value in states.values()) else "PARTIAL_HOLD" if not safe_restore else "PRECOMMIT_HOLD"
        except BaseException as error:
            journal.update(phase="COMMITTED_OR_UNKNOWN_HOLD", error=type(error).__name__)
            if worker is not None and not journal.get("worker_reaped"):
                try:
                    _terminate_reap(plan, worker, processes, journal)
                except Exception as reap_error:
                    journal["child_shutdown_error"] = type(reap_error).__name__
            try:
                if worker is None or journal.get("worker_reaped"):
                    states, _ = _reconcile(plan)
                    journal["children"] = states
                    safe_restore = all(value == "PENDING" for value in states.values()) or all(value == "APPLIED" for value in states.values())
            except Exception:
                safe_restore = False
        finally:
            if stopped and safe_restore:
                for unit in reversed(UNITS):
                    if journal["original"][unit] == "active":
                        try:
                            _transition(plan, journal, system, unit, "start")
                        except Exception as error:
                            journal["restoration_failures"].append({"unit": unit, "error": type(error).__name__})
            if journal["restoration_failures"]:
                journal["phase"] = "COMMITTED_OR_RESTORE_HOLD"
            _save(journal_path, journal)
        if safe_restore and not journal["restoration_failures"] and all(value == "APPLIED" for value in journal.get("children", {}).values()) and len(journal.get("children", {})) == 2:
            deadline = now() + plan["budgets"]["verify_observation_start_seconds"]
            while now() < deadline:
                try:
                    journal["verification"] = verify(plan_file=plan_file, system=system, processes=processes)
                    if journal["verification"]["operation_status"] in pair.COMPLETE_STATUSES:
                        journal["phase"] = journal["verification"]["operation_status"]
                        break
                except Exception as error:
                    journal["verification"] = {"operation_status": "HOLD", "error": type(error).__name__}
                pause(min(10, max(0, deadline - now())))
            if journal["phase"] not in pair.COMPLETE_STATUSES:
                journal["phase"] = "APPLIED_VERIFY_HOLD"
            _save(journal_path, journal)
        return journal


def worker(plan_file, worker_token):
    Services().require_admin()
    plan = _load_plan(plan_file)
    processes = Processes()
    deadline = time.monotonic() + 10
    while True:
        journal = _journal(plan)
        receipt = _receipt(plan, "worker")
        supervisor = _receipt(plan, "supervisor")
        if (journal["phase"] in ("WORKER_START_REQUESTED", "WORKER_RUNNING")
                and worker_token == journal.get("worker_token") and receipt is not None
                and receipt.get("worker_token") == worker_token and receipt["pid"] == os.getpid()
                and processes.alive(receipt) and supervisor and processes.alive(supervisor)):
            break
        if time.monotonic() >= deadline or journal["phase"] not in ("WORKER_START_REQUESTED", "WORKER_RUNNING"):
            raise Error("worker launch receipt unconfirmed")
        time.sleep(0.01)
    states, _ = _reconcile(plan)
    signed = pair._load_pair(plan["pair_plan_file"])[1]
    return pair.execute_pair(plan_file=plan["pair_plan_file"], db_path=plan["database_path"],
                             artifact_dir=plan["artifact_dir"], confirm=pair.confirmation_prefix(signed) + signed["plan_sha256"],
                             confirm_skip_processable=pair.SKIP_CONFIRM + signed["plan_sha256"] if signed["skips_processable"] else None,
                             resume=any(value == "APPLIED" for value in states.values()))
