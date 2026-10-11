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
        return 0


class Processes:
    def __init__(self, callback):
        self.callback = callback
        self.launches, self.terminations, self.live = [], [], set()
        self.timeout = self.force_kill = False

    def identity(self, pid):
        return "fixture-start-" + str(pid)

    def alive(self, receipt):
        return receipt["pid"] in self.live and receipt["start_identity"] == self.identity(receipt["pid"])

    def launch(self, path, role):
        process = Process(self, 9000 + len(self.launches), self.callback if role == "worker" else None)
        self.launches.append((role, process))
        self.live.add(process.pid)
        return process

    def terminate(self, process, force=False):
        self.terminations.append((process.pid, force))


@pytest.fixture
def fixture(recovery_fixture):
    base = recovery_fixture
    system = System(base)
    path = base["output"].with_name("manager-plan.json")
    plan = manager.create_plan(pair_plan_file=base["output"], db_path=base["database"],
                               artifact_dir=base["artifacts"], plan_output=path, system=system)
    processes = Processes(lambda: _execute(base, resume=bool(_audits(base))))
    return dict(base=base, system=system, path=path, plan=plan, processes=processes)


def launch(fixture):
    return manager.apply(plan_file=fixture["path"], confirm="APPLY-PACKET-PAIR-MANAGER:" + fixture["plan"]["plan_sha256"],
                         system=fixture["system"], processes=fixture["processes"])


def run(fixture, monkeypatch, advance=False):
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
    with pytest.raises(manager.Error, match="active service restoration"):
        manager.verify(plan_file=fixture["path"], system=fixture["system"], processes=fixture["processes"])


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
