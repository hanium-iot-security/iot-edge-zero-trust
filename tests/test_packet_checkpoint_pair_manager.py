"""Real pair audits with deterministic fake service/process lifecycle."""
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
from contextlib import contextmanager

import pytest

from edge.detection import packet_checkpoint_pair_manager as manager
from edge.detection import run_packet_recovery_pair as cli
from test_packet_checkpoint_pair_recovery import fixture as recovery_fixture, _advance, _audits, _execute


class System:
    def __init__(self, fixture):
        self.fixture = fixture
        self.states = dict.fromkeys(manager.UNITS, "active")
        self.actions = []
        self.fail_stop = self.fail_start = None
        self.admin = True

    def require_admin(self):
        if not self.admin:
            raise manager.Error("administrator required")

    def state(self, unit):
        return self.states[unit]

    def set_state(self, unit, state):
        self.states[unit] = state
        if unit in self.fixture["runtime"]["services"]:
            self.fixture["runtime"]["services"][unit] = state == "active"

    def stop(self, unit, timeout):
        self.actions.append(("stop", unit, timeout))
        self.set_state(unit, "inactive")
        if unit == self.fail_stop:
            raise subprocess.TimeoutExpired("systemctl", timeout)

    def start(self, unit, timeout):
        self.actions.append(("start", unit, timeout))
        if unit == self.fail_start:
            raise manager.Error("restore failed")
        self.set_state(unit, "active")


class Process:
    def __init__(self, owner, pid, callback=None):
        self.owner, self.pid, self.callback = owner, pid, callback
        self.waits = []
        self.executed = False
        self.returncode = None

    def wait(self, timeout):
        self.waits.append(timeout)
        if not self.executed:
            self.executed = True
            if self.callback:
                self.callback()
            if self.owner.timeout:
                raise subprocess.TimeoutExpired("pair worker", timeout)
        if self.owner.force_kill and len(self.waits) == 2:
            raise subprocess.TimeoutExpired("pair worker", timeout)
        self.owner.live.discard(self.pid)
        self.returncode = 0
        return 0

    def kill(self):
        self.owner.live.discard(self.pid)
        self.executed = True

    def communicate(self, timeout):
        self.waits.append(timeout)
        self.executed = True
        if self.owner.verifier_timeout:
            raise subprocess.TimeoutExpired("verifier", timeout)
        value = self.callback()
        if self.owner.verifier_transform:
            value = self.owner.verifier_transform(value)
        self.owner.live.discard(self.pid)
        self.returncode = 0
        return json.dumps(value).encode(), None


class Processes:
    def __init__(self, callback):
        self.callback = callback
        self.launches, self.terminations, self.live = [], [], set()
        self.timeout = self.force_kill = False
        self.verifier_timeout = False
        self.verifier_transform = None
        self.lingering_group = self.stuck_group = False
        self.system = None

    def identity(self, pid):
        return "fixture-start-" + str(pid)

    def alive(self, receipt):
        return receipt["pid"] in self.live and receipt["start_identity"] == self.identity(receipt["pid"])

    def launch(self, path, role):
        process = Process(self, 9000 + len(self.launches), self.callback if role == "worker" else None)
        self.launches.append((role, process))
        self.live.add(process.pid)
        return process

    def launch_verifier(self, path, token):
        process = Process(self, os.getpid(), lambda: manager.verifier(path, token, system=self.system, processes=self))
        self.launches.append(("verifier", process))
        self.live.add(process.pid)
        return process

    def group_gone(self, process):
        pid = process["pid"] if isinstance(process, dict) else process.pid
        return pid not in self.live and not self.lingering_group

    def wait_group(self, process, timeout):
        return self.group_gone(process)

    def terminate(self, process, force=False):
        self.terminations.append((process.pid, force))
        if force and not self.stuck_group:
            self.lingering_group = False


@pytest.fixture
def fixture(recovery_fixture):
    base = recovery_fixture
    system = System(base)
    path = base["output"].with_name("manager-plan.json")
    plan = manager.create_plan(pair_plan_file=base["output"], db_path=base["database"],
                               artifact_dir=base["artifacts"], plan_output=path, system=system)
    processes = Processes(lambda: _execute(base, resume=bool(_audits(base))))
    processes.system = system
    return dict(base=base, system=system, path=path, plan=plan, processes=processes)


def launch(fixture):
    return manager.apply(plan_file=fixture["path"], confirm="APPLY-PACKET-PAIR-MANAGER:" + fixture["plan"]["plan_sha256"],
                         system=fixture["system"], processes=fixture["processes"])


def run(fixture, monkeypatch, advance=False):
    fixture["processes"].system = fixture["system"]
    elapsed = [0]
    if advance:
        fixture["processes"].callback = lambda: (_execute(fixture["base"]), _advance(fixture["base"], 20))
    else:
        monkeypatch.setattr(manager, "verify", lambda **_: {"operation_status": "APPLIED_PENDING_PROGRESS"})

    def sleep(seconds):
        elapsed[0] += seconds
        if advance:
            _advance(fixture["base"], 20 + elapsed[0])

    return manager.supervise(fixture["path"], system=fixture["system"], processes=fixture["processes"],
                             monotonic=lambda: elapsed[0], sleep=sleep)


def test_plan_is_read_only_and_binds_whole_worker_budget(fixture):
    assert _audits(fixture["base"]) == []
    assert fixture["system"].actions == []
    assert fixture["plan"]["timeout_scope"] == "whole_rule_then_if_pair_worker"
    assert fixture["plan"]["pair_plan_sha256"] == fixture["base"]["plan"]["plan_sha256"]
    assert fixture["plan"]["budgets"]["verify_observation_start_seconds"] == 120
    assert "verify_seconds" not in fixture["plan"]["budgets"]


def test_detached_launch_journal_survives_parent_and_duplicate_is_not_started(fixture):
    launch(fixture)
    original = manager._journal(fixture["plan"])["original"]
    launch(fixture)
    assert len(fixture["processes"].launches) == 1
    assert manager._journal(fixture["plan"])["original"] == original
    assert fixture["system"].actions == []


def test_full_real_pair_restores_and_requires_actual_two_advances(fixture, monkeypatch):
    launch(fixture)
    result = run(fixture, monkeypatch, advance=True)
    assert result["phase"] == "COMPLETE"
    assert len(_audits(fixture["base"])) == 2
    assert len(fixture["base"]["locks"]) == 1
    assert all(value == "active" for value in fixture["system"].states.values())
    assert all(unit in manager.UNITS for _, unit, _ in fixture["system"].actions)


def test_partial_rule_keeps_services_stopped_and_resumes_only_if(fixture, monkeypatch):
    original = manager.core._execute_locked_recovery

    def fail_if(**kwargs):
        if kwargs["plan"]["detector_name"] == "packet_if":
            raise manager.Error("IF rejected")
        return original(**kwargs)

    monkeypatch.setattr(manager.core, "_execute_locked_recovery", fail_if)
    launch(fixture)
    first = run(fixture, monkeypatch)
    assert first["phase"] == "PARTIAL_HOLD"
    assert len(_audits(fixture["base"])) == 1
    assert not any(action == "start" for action, *_ in fixture["system"].actions)
    monkeypatch.setattr(manager.core, "_execute_locked_recovery", original)
    launch(fixture)
    second = run(fixture, monkeypatch)
    assert len(_audits(fixture["base"])) == 2
    assert second["original"] == dict.fromkeys(manager.UNITS, "active")
    assert second["phase"] == "APPLIED_VERIFY_HOLD"


def test_precommit_stop_timeout_restores_original_without_worker(fixture, monkeypatch):
    fixture["system"].fail_stop = manager.UNITS[0]
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert _audits(fixture["base"]) == []
    assert [role for role, _ in fixture["processes"].launches] == ["supervisor"]
    assert all(value == "active" for value in fixture["system"].states.values())
    assert result["requested"][manager.UNITS[0]] == "start"


def test_timeout_after_commit_terminates_reaps_then_reconciles(fixture, monkeypatch):
    fixture["processes"].timeout = fixture["processes"].force_kill = True
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert result["worker_timeout"] and result["worker_reaped"]
    assert [force for _, force in fixture["processes"].terminations] == [False, True]
    assert len(_audits(fixture["base"])) == 2
    assert result["phase"] == "APPLIED_VERIFY_HOLD"


def test_restore_failure_preserves_full_audits_and_separate_state(fixture, monkeypatch):
    fixture["system"].fail_start = manager.UNITS[1]
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert result["phase"] == "COMMITTED_OR_RESTORE_HOLD"
    assert len(_audits(fixture["base"])) == 2
    assert result["original"][manager.UNITS[1]] == "active"
    assert result["requested"][manager.UNITS[1]] == "start"
    assert result["actual"][manager.UNITS[1]] == "inactive"
    assert result["restoration_failures"][0]["unit"] == manager.UNITS[1]


def test_status_is_read_only_and_does_not_verify_or_control_services(fixture, monkeypatch):
    launch(fixture)
    journal = manager._paths(fixture["plan"])[1]
    before = journal.read_bytes()
    monkeypatch.setattr(manager.pair, "status_pair", lambda **_: pytest.fail("Status wrote progress"))
    result = manager.status(plan_file=fixture["path"], system=fixture["system"], processes=fixture["processes"])
    assert result["operation_status"] == "RUNNING"
    assert journal.read_bytes() == before
    assert fixture["system"].actions == []


def test_legacy_group_cannot_guess_original_services(fixture):
    _execute(fixture["base"])
    with pytest.raises(manager.Error, match="legacy"):
        launch(fixture)
    assert fixture["system"].actions == []


def test_admin_and_plan_tampering_reject_before_service_change(fixture):
    fixture["system"].admin = False
    with pytest.raises(manager.Error):
        launch(fixture)
    fixture["system"].admin = True
    value = json.loads(fixture["path"].read_text())
    value["budgets"]["pair_worker_seconds"] += 1
    fixture["path"].write_text(json.dumps(value))
    with pytest.raises(manager.Error):
        launch(fixture)
    assert fixture["system"].actions == []


def test_supervisor_waits_for_launcher_command_lock_release(fixture, monkeypatch):
    launch(fixture)
    acquired = []

    @contextmanager
    def lock(path, **kwargs):
        acquired.append((path, kwargs))
        yield

    monkeypatch.setattr(manager.core, "single_instance_lock", lock)
    run(fixture, monkeypatch)
    assert acquired[0][0] == manager._paths(fixture["plan"])[2]
    assert acquired[0][1] == {"wait_seconds": 15}


@pytest.mark.parametrize("phase", ["LAUNCH_REQUESTED", "WORKER_START_REQUESTED", "WORKER_RUNNING"])
def test_unresolved_launch_without_receipt_cannot_spawn_again(fixture, phase):
    launch(fixture)
    fixture["processes"].live.clear()
    journal = manager._journal(fixture["plan"])
    journal.update(phase=phase, worker_reaped=False)
    manager._save(manager._paths(fixture["plan"])[1], journal)
    with pytest.raises(manager.Error, match="unresolved"):
        launch(fixture)
    assert len(fixture["processes"].launches) == 1
    assert fixture["system"].actions == []


def test_existing_live_worker_prevents_supervisor_spawn(fixture, monkeypatch):
    launch(fixture)
    journal = manager._journal(fixture["plan"])
    journal.update(phase="WORKER_RUNNING", worker_token="fixture-token")
    manager._save(manager._paths(fixture["plan"])[1], journal)
    fixture["processes"].live.add(12345)
    manager._record_process(fixture["plan"], "worker", 12345, fixture["processes"])
    with pytest.raises(manager.Error, match="worker still alive"):
        run(fixture, monkeypatch)
    assert len(fixture["processes"].launches) == 1
    assert fixture["system"].actions == []


def test_previous_reaped_flag_resets_and_interrupt_terminates_new_child(fixture, monkeypatch):
    launch(fixture)
    first = run(fixture, monkeypatch)
    assert first["worker_reaped"]
    fixture["processes"].live.clear()
    launch(fixture)
    assert manager._journal(fixture["plan"])["worker_reaped"] is False
    # A fresh operation is not needed: full audits skip spawning. Simulate a
    # precommit prior attempt, then exercise the new child's interrupted wait.
    monkeypatch.setattr(manager, "_reconcile", lambda _: ({"packet_rule": "PENDING", "packet_if": "PENDING"}, {}))
    original_wait = Process.wait

    def interrupted(process, timeout):
        persisted = manager._journal(fixture["plan"])
        if not process.waits:
            assert persisted["worker_reaped"] is False
            process.waits.append(timeout)
            raise InterruptedError("supervisor SIGTERM")
        return original_wait(process, timeout)

    monkeypatch.setattr(Process, "wait", interrupted)
    result = run(fixture, monkeypatch)
    assert result["worker_reaped"] is True
    assert fixture["processes"].terminations[-1][1] is False
    assert all(value == "active" for value in fixture["system"].states.values())


def test_unreaped_child_never_restores_even_with_committed_audits(fixture, monkeypatch):
    def stuck(process, timeout):
        if not process.executed:
            process.executed = True
            process.callback()
        process.waits.append(timeout)
        raise subprocess.TimeoutExpired("stuck worker", timeout)

    monkeypatch.setattr(Process, "wait", stuck)
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert len(_audits(fixture["base"])) == 2
    assert result["worker_reaped"] is False
    assert result["phase"] == "COMMITTED_OR_UNKNOWN_HOLD"
    assert not any(action == "start" for action, *_ in fixture["system"].actions)
    assert all(value == "inactive" for value in fixture["system"].states.values())
    assert fixture["processes"].live


def test_child_response_loss_reconciles_actual_full_audits(fixture, monkeypatch):
    original_wait = Process.wait

    def response_lost(process, timeout):
        if not process.executed:
            process.callback()
            process.executed = True
            process.waits.append(timeout)
            raise RuntimeError("result pipe lost after commit")
        return original_wait(process, timeout)

    monkeypatch.setattr(Process, "wait", response_lost)
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert len(_audits(fixture["base"])) == 2
    assert result["worker_reaped"] is True
    assert result["phase"] == "APPLIED_VERIFY_HOLD"
    assert all(value == "active" for value in fixture["system"].states.values())


def test_original_inactive_service_stays_inactive_and_resume_keeps_original(fixture, monkeypatch):
    unit = manager.UNITS[-1]
    fixture["system"].set_state(unit, "inactive")
    fixture["path"].unlink()
    fixture["plan"] = manager.create_plan(pair_plan_file=fixture["base"]["output"], db_path=fixture["base"]["database"],
                                         artifact_dir=fixture["base"]["artifacts"], plan_output=fixture["path"], system=fixture["system"])
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert result["original"][unit] == "inactive"
    assert fixture["system"].states[unit] == "inactive"
    assert not any(action == "start" and changed == unit for action, changed, _ in fixture["system"].actions)
    fixture["processes"].live.clear()
    launch(fixture)
    assert manager._journal(fixture["plan"])["original"][unit] == "inactive"


@pytest.mark.parametrize("field,value", [("units", []), ("source_session_id", "other"),
                                        ("target_session_id", "other"), ("boot_id", "other")])
def test_resigned_manager_scope_cannot_change_pair_binding(fixture, field, value):
    approval = dict(fixture["plan"])
    approval[field] = value
    manager._save(fixture["path"], approval)
    with pytest.raises(manager.Error, match="scope binding"):
        manager._load_plan(fixture["path"])
    assert fixture["system"].actions == []


def test_internal_worker_requires_approved_phase_and_current_receipt(fixture, monkeypatch):
    launch(fixture)
    monkeypatch.setattr(manager.Services, "require_admin", lambda _: None)
    monkeypatch.setattr(manager.pair, "execute_pair", lambda **_: pytest.fail("unapproved worker executed"))
    with pytest.raises(manager.Error, match="receipt unconfirmed"):
        manager.worker(fixture["path"], "arbitrary-token")


@pytest.mark.parametrize("mode", ["live-resume", "bounded-replay"])
def test_authorized_internal_worker_executes_original_pair_with_real_audits(fixture, monkeypatch, mode):
    if mode == "bounded-replay":
        base = fixture["base"]
        with sqlite3.connect(base["database"]) as db:
            db.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                       (base["plan"]["children"][0]["plan"]["target_session"]["packet_feature_ready_through"],
                        base["plan"]["target_session_id"]))
        output = base["output"].with_name("worker-bounded-pair.json")
        signed = manager.pair.inspect_pair(db_path=base["database"], repository_root=base["root"],
                                           current_session_id=base["plan"]["current_session_id"],
                                           target_session_id=base["plan"]["target_session_id"],
                                           approved_by="admin-fixture", reason="bounded worker test",
                                           plan_output=output, mode=mode)
        assert signed["can_execute"], signed["blocking_reasons"]
        base.update(output=output, plan=signed)
        path = output.with_name("worker-bounded-manager.json")
        plan = manager.create_plan(pair_plan_file=output, db_path=base["database"],
                                   artifact_dir=base["artifacts"], plan_output=path, system=fixture["system"])
        fixture.update(path=path, plan=plan)
    launch(fixture)
    journal = manager._journal(fixture["plan"])
    journal.update(phase="WORKER_RUNNING", worker_token="approved-fixture-token")
    manager._save(manager._paths(fixture["plan"])[1], journal)
    fixture["processes"].live.add(os.getpid())
    manager._record_process(fixture["plan"], "worker", os.getpid(), fixture["processes"])
    monkeypatch.setattr(manager.Services, "require_admin", lambda _: None)
    monkeypatch.setattr(manager, "Processes", lambda: fixture["processes"])
    result = manager.worker(fixture["path"], "approved-fixture-token")
    assert result["database_committed"] is True
    assert len(_audits(fixture["base"])) == 2
    assert len(fixture["base"]["locks"]) == 1
    assert fixture["system"].actions == []


def test_verify_cannot_hide_restoration_failure_or_live_worker(fixture, monkeypatch):
    launch(fixture)
    monkeypatch.setattr(manager.pair, "status_pair", lambda **_: pytest.fail("unsafe verification reached progress writer"))
    journal = manager._journal(fixture["plan"])
    journal["restoration_failures"] = [{"unit": manager.UNITS[-1], "error": "RestoreError"}]
    manager._save(manager._paths(fixture["plan"])[1], journal)
    with pytest.raises(manager.Error, match="restoration remains"):
        manager.verify(plan_file=fixture["path"], system=fixture["system"], processes=fixture["processes"])
    journal.update(restoration_failures=[], worker_token="fixture-token")
    manager._save(manager._paths(fixture["plan"])[1], journal)
    fixture["processes"].live.add(12345)
    manager._record_process(fixture["plan"], "worker", 12345, fixture["processes"])
    with pytest.raises(manager.Error, match="worker still alive"):
        manager.verify(plan_file=fixture["path"], system=fixture["system"], processes=fixture["processes"])
    fixture["processes"].live.discard(12345)
    fixture["system"].set_state(manager.UNITS[-1], "inactive")
    result = manager.verify(plan_file=fixture["path"], system=fixture["system"], processes=fixture["processes"])
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    assert result["error"] == "PacketCheckpointRecoveryError"


def test_cli_launch_and_applied_pending_are_not_completion(fixture, monkeypatch, capsys):
    monkeypatch.setattr(manager, "apply", lambda **_: {"operation_status": "RUNNING", "database_committed": None})
    assert cli.main(["apply", "--plan-file", str(fixture["path"]), "--confirm", "test"]) == 3
    monkeypatch.setattr(manager, "verify", lambda **_: {"operation_status": "APPLIED_PENDING_PROGRESS", "database_committed": True})
    assert cli.main(["verify", "--plan-file", str(fixture["path"])]) == 3
    monkeypatch.setattr(manager, "verify", lambda **_: {"operation_status": "COMPLETE", "database_committed": True})
    assert cli.main(["verify", "--plan-file", str(fixture["path"])]) == 0
    capsys.readouterr()


@pytest.mark.skipif(os.name != "posix", reason="real Linux /proc and process group semantics")
def test_linux_deadline_forces_process_group_and_reaps_without_operational_commands(fixture):
    processes = manager.Processes()
    code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('READY',flush=True);time.sleep(60)"
    process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        processes.own(process)
        assert process.stdout.readline() == b"READY\n"
        receipt = {"pid": process.pid, "start_identity": processes.identity(process.pid)}
        assert processes.alive(receipt)
        assert not processes.alive(dict(receipt, start_identity="different-start"))
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.02)
        launch(fixture)  # Fake supervisor only; no systemctl or operational DB.
        plan = dict(fixture["plan"], budgets=dict(fixture["plan"]["budgets"], terminate_grace_seconds=1, kill_reap_seconds=1))
        journal = manager._journal(fixture["plan"])
        manager._terminate_reap(plan, process, processes, journal)
        assert journal["worker_reaped"] is True
        assert process.returncode is not None
        assert not processes.alive(receipt)
        assert fixture["system"].actions == []
    finally:
        if process.poll() is None:
            processes.terminate(process, force=True)
            process.wait(timeout=5)
        process.stdout.close()


@pytest.mark.skipif(os.name != "posix", reason="real Linux flock semantics")
def test_linux_command_lock_blocks_other_process_and_releases(tmp_path):
    lock = tmp_path / "manager.lock"
    code = ("import fcntl,sys;f=open(sys.argv[1],'a+');\n"
            "try: fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
            "except BlockingIOError: sys.exit(23)\n")
    with manager.core.single_instance_lock(lock):
        blocked = subprocess.run([sys.executable, "-c", code, str(lock)], timeout=5, capture_output=True)
        assert blocked.returncode == 23
    acquired = subprocess.run([sys.executable, "-c", code, str(lock)], timeout=5, capture_output=True)
    assert acquired.returncode == 0


def test_verifier_timeout_is_bounded_without_service_reapply(fixture, monkeypatch):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    fixture["processes"].verifier_timeout = True
    before = list(fixture["system"].actions)
    plan_bytes = fixture["path"].read_bytes()
    result = manager.verify(plan_file=fixture["path"], system=fixture["system"],
                            processes=fixture["processes"], timeout=0.01, monotonic=lambda: 0)
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    assert result["error"] == "TimeoutExpired"
    assert fixture["system"].actions == before
    assert fixture["path"].read_bytes() == plan_bytes
    assert len(_audits(fixture["base"])) == 2
    journal = manager._journal(fixture["plan"])
    assert journal["verifier_direct_reaped"] and journal["verifier_group_gone"]
    assert journal["verifier_reaped"]
    assert fixture["processes"].launches[-1][1].waits[0] <= 0.01


@pytest.mark.parametrize("field,value", [("verification_token", "old-token"),
                                        ("approval_sha256", "old-sha"),
                                        ("attempt_id", "old-attempt")])
def test_stale_verifier_response_cannot_complete(fixture, monkeypatch, field, value):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    def corrupt(response):
        response[field] = value
        response["result"]["operation_status"] = "COMPLETE"
        return response
    fixture["processes"].verifier_transform = corrupt
    result = manager.verify(plan_file=fixture["path"], system=fixture["system"], processes=fixture["processes"])
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    assert len(_audits(fixture["base"])) == 2


def test_reaped_worker_with_lingering_group_must_kill_before_restore(fixture, monkeypatch):
    fixture["processes"].lingering_group = True
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert result["worker_direct_reaped"] and result["worker_group_gone"] and result["worker_reaped"]
    assert [force for _, force in fixture["processes"].terminations] == [False, True]
    assert all(value == "active" for value in fixture["system"].states.values())


def test_uncertain_worker_group_keeps_processing_stopped(fixture, monkeypatch):
    fixture["processes"].lingering_group = fixture["processes"].stuck_group = True
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert result["worker_direct_reaped"]
    assert not result["worker_group_gone"] and not result["worker_reaped"]
    assert result["phase"] == "COMMITTED_OR_UNKNOWN_HOLD"
    assert len(_audits(fixture["base"])) == 2
    assert not any(action == "start" for action, *_ in fixture["system"].actions)


def test_expired_verification_budget_never_launches(fixture, monkeypatch):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    count = len(fixture["processes"].launches)
    result = manager.verify(plan_file=fixture["path"], processes=fixture["processes"], timeout=0)
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    assert len(fixture["processes"].launches) == count


def test_late_complete_verifier_response_is_not_accepted(fixture, monkeypatch):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    elapsed = [0]
    def late(response):
        elapsed[0] = 2
        response["result"]["operation_status"] = "COMPLETE"
        return response
    fixture["processes"].verifier_transform = late
    result = manager.verify(plan_file=fixture["path"], processes=fixture["processes"],
                            timeout=1, monotonic=lambda: elapsed[0])
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    assert manager._journal(fixture["plan"])["phase"] == "APPLIED_VERIFY_HOLD"


def test_verifier_cleanup_uncertain_blocks_next_verify_and_apply(fixture, monkeypatch):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    fixture["processes"].verifier_timeout = True
    fixture["processes"].stuck_group = fixture["processes"].lingering_group = True
    original_gone = fixture["processes"].group_gone
    fixture["processes"].group_gone = lambda process: True if isinstance(process, dict) and process["role"] != "verifier" else original_gone(process)
    result = manager.verify(plan_file=fixture["path"], processes=fixture["processes"])
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    journal = manager._journal(fixture["plan"])
    assert journal["verifier_direct_reaped"] and not journal["verifier_group_gone"]
    before = list(fixture["system"].actions)
    with pytest.raises(manager.Error, match="verifier"):
        manager.verify(plan_file=fixture["path"], processes=fixture["processes"])
    with pytest.raises(manager.Error, match="verifier"):
        launch(fixture)
    assert fixture["system"].actions == before


@pytest.mark.skipif(os.name != "posix", reason="real Linux /proc and process group semantics")
def test_linux_reaped_leader_does_not_hide_term_ignoring_descendant(fixture):
    processes = manager.Processes()
    child = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('READY',flush=True);time.sleep(60)"
    code = ("import json,subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c'," + repr(child) + "],stdout=subprocess.PIPE);"
            "p.stdout.readline();print(json.dumps({'child':p.pid}),flush=True);time.sleep(60)")
    process = processes.own(subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True))
    try:
        child_pid = json.loads(process.stdout.readline())["child"]
        launch(fixture)
        plan = dict(fixture["plan"], budgets=dict(fixture["plan"]["budgets"], terminate_grace_seconds=1, kill_reap_seconds=1))
        journal = manager._journal(fixture["plan"])
        manager._terminate_reap(plan, process, processes, journal)
        assert journal["worker_direct_reaped"] and journal["worker_group_gone"] and journal["worker_reaped"]
        assert process.returncode is not None
        assert processes.group_gone(process)
        try:
            processes.identity(child_pid)
        except (ProcessLookupError, FileNotFoundError):
            pass
        else:
            pytest.fail("descendant remains running")
        assert fixture["system"].actions == []
    finally:
        processes.terminate(process, force=True)
        process.wait(timeout=5)
        process.stdout.close()


def test_spawned_verifier_identity_failure_is_cleaned_and_held(fixture, monkeypatch):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    fixture["processes"].own = lambda _: (_ for _ in ()).throw(OSError("identity unavailable"))
    result = manager.verify(plan_file=fixture["path"], processes=fixture["processes"])
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    journal = manager._journal(fixture["plan"])
    assert journal["verifier_direct_reaped"] and not journal["verifier_group_gone"]
    assert not journal["verifier_reaped"]
    assert manager._receipt(fixture["plan"], "verifier")["ownership_unconfirmed"]
    with pytest.raises(manager.Error, match="ownership"):
        manager.verify(plan_file=fixture["path"], processes=fixture["processes"])


def test_spawned_worker_receipt_failure_never_leaks_or_restores_unknown_group(fixture, monkeypatch):
    original = manager._record_process
    def fail(plan, role, pid, processes, start_identity=None):
        if role == "worker":
            raise OSError("receipt unavailable")
        return original(plan, role, pid, processes, start_identity)
    monkeypatch.setattr(manager, "_record_process", fail)
    launch(fixture)
    result = run(fixture, monkeypatch)
    assert result["phase"] == "COMMITTED_OR_UNKNOWN_HOLD"
    assert result["worker_direct_reaped"] and not result["worker_group_gone"]
    assert not any(action == "start" for action, *_ in fixture["system"].actions)
    assert _audits(fixture["base"]) == []


@pytest.mark.skipif(os.name != "posix", reason="real Linux /proc and process group semantics")
def test_linux_fast_zombie_identity_is_owned_and_reaped(fixture):
    import time
    processes = manager.Processes()
    process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while manager._process_stat(process.pid)[0] != "Z":
            assert time.monotonic() < deadline
            time.sleep(0.01)
        processes.own(process)
        assert process.start_identity
        launch(fixture)
        journal = manager._journal(fixture["plan"])
        manager._terminate_reap(fixture["plan"], process, processes, journal)
        assert journal["worker_direct_reaped"] and journal["worker_group_gone"]
        assert process.returncode == 0
    finally:
        process.wait(timeout=5)


@pytest.mark.parametrize("field,value", [("units", []), ("source_session_id", "other"),
                                        ("target_session_id", "other"), ("boot_id", "other")])
def test_verify_keeps_full_scope_gate_before_parent_writes(fixture, monkeypatch, field, value):
    launch(fixture)
    journal_path = manager._paths(fixture["plan"])[1]
    journal_bytes = journal_path.read_bytes()
    approval = dict(fixture["plan"], **{field: value})
    manager._save(fixture["path"], approval)
    monkeypatch.setattr(manager.core, "single_instance_lock", lambda *_a, **_k: pytest.fail("unvalidated lock write"))
    monkeypatch.setattr(manager, "_save", lambda *_: pytest.fail("unvalidated manager write"))
    with pytest.raises(manager.Error, match="scope binding"):
        manager.verify(plan_file=fixture["path"], processes=fixture["processes"])
    assert journal_path.read_bytes() == journal_bytes


def test_verify_keeps_generated_path_gate_before_parent_writes(fixture, monkeypatch):
    launch(fixture)
    unapproved = fixture["base"]["root"] / "unapproved-output"
    unapproved.mkdir()
    approval = dict(fixture["plan"], artifact_dir=str(unapproved))
    manager._save(fixture["path"], approval)
    monkeypatch.setattr(manager.core, "single_instance_lock", lambda *_a, **_k: pytest.fail("unvalidated lock write"))
    monkeypatch.setattr(manager, "_save", lambda *_: pytest.fail("unvalidated manager write"))
    with pytest.raises(manager.Error, match="ignored"):
        manager.verify(plan_file=fixture["path"], processes=fixture["processes"])


@pytest.mark.parametrize("mutation", ["missing-status", "wrong-result-sha", "false-complete", "damaged-checksum"])
def test_malformed_verifier_result_is_applied_hold(fixture, monkeypatch, mutation):
    launch(fixture)
    original_verify = manager.verify
    run(fixture, monkeypatch)
    monkeypatch.setattr(manager, "verify", original_verify)
    def corrupt(response):
        if mutation == "missing-status":
            response["result"].pop("operation_status")
        elif mutation == "wrong-result-sha":
            response["result"]["plan_sha256"] = "wrong-pair"
        elif mutation == "false-complete":
            response["result"].update(operation_status="COMPLETE", database_committed=False)
        else:
            response["result"]["operation_status"] = "COMPLETE"
            return response
        return manager.core.attach_plan_sha256(response, generated_at=manager.core._utc_now())
    fixture["processes"].verifier_transform = corrupt
    before = list(fixture["system"].actions)
    result = manager.verify(plan_file=fixture["path"], processes=fixture["processes"])
    assert result["operation_status"] == "APPLIED_VERIFY_HOLD"
    assert fixture["system"].actions == before
    assert len(_audits(fixture["base"])) == 2


def test_cli_verify_installs_interrupt_cleanup_handler(fixture, monkeypatch, capsys):
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(cli, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(cli.signal, "signal", lambda number, handler: calls.append((number, handler)))
    monkeypatch.setattr(manager, "verify", lambda **_: {"operation_status": "APPLIED_VERIFY_HOLD", "database_committed": True})
    assert cli.main(["verify", "--plan-file", str(fixture["path"])]) == 3
    assert calls[0][0] == cli.signal.SIGTERM
    with pytest.raises(manager.Error, match="interrupted"):
        calls[0][1](cli.signal.SIGTERM, None)
    capsys.readouterr()


def test_internal_verifier_unblocks_inherited_handoff_signals(fixture, monkeypatch, capsys):
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(cli, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(cli.signal, "signal", lambda *_: None)
    monkeypatch.setattr(cli.signal, "SIGHUP", 1, raising=False)
    monkeypatch.setattr(cli.signal, "SIG_UNBLOCK", 1, raising=False)
    monkeypatch.setattr(cli.signal, "pthread_sigmask", lambda operation, signals: calls.append((operation, signals)), raising=False)
    monkeypatch.setattr(manager, "verifier", lambda *_: {"fresh": True})
    assert cli.main(["--internal-verifier", "--plan-file", str(fixture["path"]), "--verification-token", "fresh"]) == 0
    assert calls == [(cli.signal.SIG_UNBLOCK, {cli.signal.SIGTERM, cli.signal.SIGINT})]
    capsys.readouterr()


@pytest.mark.parametrize("comm", ["온도수집".encode("utf-8"), b"collector\xff)name"])
def test_owned_group_scan_ignores_unrelated_non_ascii_process_name(monkeypatch, comm):
    from types import SimpleNamespace
    state = ["Z"]
    def stat(pid, name, process_state, group, session, identity):
        fields = [process_state, "1", str(group), str(session)] + ["0"] * 15 + [identity]
        return str(pid).encode("ascii") + b" (" + name + b") " + " ".join(fields).encode("ascii")
    class ProcPath:
        def __init__(self, path):
            self.path = str(path)
        def iterdir(self):
            assert self.path == "/proc"
            return iter([SimpleNamespace(name="101"), SimpleNamespace(name="202")])
        def read_bytes(self):
            return (stat(101, b"owned", state[0], 101, 101, "123") if self.path == "/proc/101/stat"
                    else stat(202, comm, "S", 202, 202, "456"))
        def read_text(self, encoding):
            return self.read_bytes().decode(encoding)
    monkeypatch.setattr(manager, "Path", ProcPath)
    processes = manager.Processes()
    owned = SimpleNamespace(pid=101)
    processes.own(owned)
    assert owned.start_identity == "123"
    assert processes.group_gone(owned)
    with pytest.raises(ProcessLookupError):
        manager._identity(101)
    state[0] = "S"
    assert manager._identity(101) == "123"
    assert not processes.group_gone(owned)
