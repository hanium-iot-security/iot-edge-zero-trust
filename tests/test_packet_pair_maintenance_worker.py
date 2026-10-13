"""Real SQLite pair backups/audits; only UID and host observations are fixtures."""
from datetime import timedelta
import json
from pathlib import Path
from types import SimpleNamespace
import sqlite3

import pytest

from edge.detection import packet_pair_maintenance_worker as worker
from test_packet_checkpoint_pair_recovery import (
    fixture, replay_fixture, failed_target_replay_fixture, _inspect_failed_target, _audits,
)
from test_packet_checkpoint_recovery import (
    CURRENT_SESSION, TARGET_SESSION, CURRENT_READY_THROUGH, TARGET_FIRST,
    RUNNING_SESSION_A, _insert_capture_session, _insert_capture_segment, _db_utc,
)

pair, core = worker.pair, worker.core


@pytest.fixture
def reviewed(failed_target_replay_fixture, monkeypatch):
    f = failed_target_replay_fixture
    with sqlite3.connect(f["database"]) as db:
        source = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (CURRENT_SESSION,)).fetchone()[0]
        boundary = TARGET_FIRST - timedelta(seconds=10)
        start = CURRENT_READY_THROUGH
        while start < boundary:
            _insert_capture_segment(db, session_pk=source, capture_interface="eth-current",
                                    window_start=start, status="EMPTY")
            start += timedelta(seconds=10)
        db.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=? "
                   "WHERE detector_name IN ('packet_rule','packet_if')", (_db_utc(boundary), _db_utc(boundary)))
        db.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE id=?",
                   (_db_utc(boundary + timedelta(seconds=1)), source))
        tail = _insert_capture_segment(db, session_pk=source, capture_interface="eth-current",
                                      window_start=boundary, status="FAILED")
        db.execute("UPDATE packet_capture_segments SET file_name=NULL,captured_duration_seconds=0,error_code='LATE_CAPTURE' WHERE id=?", (tail,))
        _insert_capture_session(db, session_id=RUNNING_SESSION_A, capture_interface="eth-later",
                                first_window_start=TARGET_FIRST + timedelta(seconds=40), status="RUNNING")
    output, plan = _inspect_failed_target(f, mode=core.BOUNDED_REPLAY_MODE,
        allow_failed_current_session=True, allow_failed_target_session=True)
    assert plan["can_execute"], plan["blocking_reasons"]
    f.update(output=output, plan=plan, source_tail_id=tail)
    monkeypatch.setattr(worker, "_require_pi", lambda: None)
    monkeypatch.setattr(worker, "_require_private_directory", lambda directory: None)
    monkeypatch.setattr(worker, "_require_quiescent", lambda: None)
    request_file = f["output"].with_name("maintenance-request.json")
    request = worker.prepare(plan_file=output, request_output=request_file)
    f.update(request_file=request_file, request=request)
    with sqlite3.connect(f["database"]) as db:
        db.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                   (_db_utc(TARGET_FIRST + timedelta(seconds=50)), RUNNING_SESSION_A))
    f["runtime"]["services"] = {name: False for name in pair.SERVICES}
    return f


def _args(f):
    return dict(request_file=f["request_file"], request_sha256=f["request"]["plan_sha256"],
                artifact_dir=f["artifacts"])


def _protected(f):
    with sqlite3.connect(f["database"]) as db:
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
                for table in ("packet_capture_sessions", "packet_capture_segments", "packet_feature_logs")}


def test_fresh_paused_plan_executes_two_real_audits_and_preserves_closed_input(reviewed):
    f = reviewed
    protected = _protected(f)
    result = worker.execute(**_args(f))
    assert result["state"] == "COMMITTED_VERIFIED"
    assert result["verified_audit_count"] == 2 and result["database_committed"] is True
    assert result["rerun"] is result["runtime_complete"] is False
    plan_file = f["artifacts"] / "plan.json"
    _, paused = pair._load_pair(plan_file)
    assert paused["pair_id"] != f["plan"]["pair_id"]
    assert paused["bounded_replay"]["later_running_session"] is None
    assert paused["bounded_replay"]["input_sha256"] == f["plan"]["bounded_replay"]["input_sha256"]
    assert len(_audits(f)) == 2 and _protected(f) == protected
    assert json.loads((f["artifacts"] / "result.json").read_text()) == result
    assert worker.classify(**_args(f))["state"] == "COMMITTED_VERIFIED"
    with pytest.raises(pair.Error, match="already used"):
        worker.execute(**_args(f))
    assert len(_audits(f)) == 2


@pytest.mark.parametrize("loss_at,expected,count", [
    ("before", "NOT_COMMITTED_VERIFIED", 0),
    ("packet_rule", "PARTIAL_HOLD", 1),
    ("packet_if", "COMMITTED_VERIFIED", 2),
])
def test_response_loss_uses_durable_audits_without_retry(reviewed, monkeypatch, loss_at, expected, count):
    original = core._execute_locked_recovery
    calls = []
    def lose(**prepared):
        name = prepared["plan"]["detector_name"]
        calls.append(name)
        if loss_at == "before":
            raise pair.Error("before first write")
        result = original(**prepared)
        if name == loss_at:
            raise ConnectionError("notice lost after actual COMMIT")
        return result
    monkeypatch.setattr(core, "_execute_locked_recovery", lose)
    result = worker.execute(**_args(reviewed))
    assert result["state"] == expected and result["verified_audit_count"] == count
    assert len(_audits(reviewed)) == count
    before = list(calls)
    assert worker.classify(**_args(reviewed))["state"] == expected
    assert calls == before


@pytest.mark.parametrize("sql", [
    "UPDATE packet_feature_logs SET total_bytes=61 WHERE id=2",
    "UPDATE packet_capture_sessions SET capture_interface='changed' WHERE session_id='" + CURRENT_SESSION + "'",
    "UPDATE detector_checkpoints SET last_processed_id=999 WHERE detector_name='packet_rule'",
    "UPDATE packet_capture_segments SET error_message='changed' WHERE status='FAILED'",
])
def test_changed_reviewed_input_never_applies(reviewed, sql):
    with sqlite3.connect(reviewed["database"]) as db:
        db.execute(sql)
    result = worker.execute(**_args(reviewed))
    assert result["state"] == "UNKNOWN_HOLD" and result["database_committed"] is None
    assert _audits(reviewed) == []


def test_running_capture_rejects_before_intent_or_db_write(reviewed):
    with sqlite3.connect(reviewed["database"]) as db:
        db.execute("UPDATE packet_capture_sessions SET status='RUNNING',ended_at=NULL WHERE session_id=?", (RUNNING_SESSION_A,))
    before = _protected(reviewed)
    with pytest.raises(pair.Error, match="RUNNING"):
        worker.execute(**_args(reviewed))
    assert list(reviewed["artifacts"].iterdir()) == [] and _protected(reviewed) == before


def test_quiescence_failure_never_dispatches(reviewed, monkeypatch):
    def fail():
        raise pair.Error("writer still running")
    monkeypatch.setattr(worker, "_require_quiescent", fail)
    with pytest.raises(pair.Error, match="writer still"):
        worker.execute(**_args(reviewed))
    assert list(reviewed["artifacts"].iterdir()) == [] and _audits(reviewed) == []


def test_request_sha_rejects_self_resigned_changed_scope(reviewed):
    request = json.loads(reviewed["request_file"].read_text())
    request["scope"]["reason"] = "other approval"
    request = core.attach_plan_sha256(request, generated_at=core._utc_now())
    core._write_json_atomically(reviewed["request_file"], request)
    with pytest.raises(pair.Error, match="approved request SHA"):
        worker.execute(**_args(reviewed))
    assert _audits(reviewed) == []


def test_classify_after_death_missing_plan_is_unknown_and_readonly(reviewed):
    directory = reviewed["artifacts"]
    (directory / "worker-intent.json").write_text(json.dumps({"request_sha256": reviewed["request"]["plan_sha256"]}))
    before = reviewed["database"].read_bytes()
    result = worker.classify(**_args(reviewed))
    assert result["state"] == "UNKNOWN_HOLD" and result["database_committed"] is None
    assert reviewed["database"].read_bytes() == before
    assert sorted(path.name for path in directory.iterdir()) == ["worker-intent.json"]


@pytest.mark.parametrize("mutation", ["backup", "audit", "checkpoint"])
def test_classify_refuses_corrupt_applied_backup_and_altered_audit(reviewed, mutation):
    assert worker.execute(**_args(reviewed))["state"] == "COMMITTED_VERIFIED"
    audit = _audits(reviewed)[0]
    if mutation == "backup":
        with Path(audit["backup_path"]).open("ab") as stream:
            stream.write(b"corrupted")
    else:
        with sqlite3.connect(reviewed["database"]) as db:
            if mutation == "audit":
                db.execute("UPDATE packet_checkpoint_recoveries SET reason='changed' WHERE id=?", (audit["id"],))
            else:
                db.execute("UPDATE detector_checkpoints SET last_processed_id=999 WHERE detector_name='packet_if'")
    result = worker.classify(**_args(reviewed))
    assert result["state"] == "UNKNOWN_HOLD" and result["database_committed"] is None
    assert len(_audits(reviewed)) == 2


def test_classify_rejects_new_capture_after_restoration(reviewed):
    assert worker.execute(**_args(reviewed))["state"] == "COMMITTED_VERIFIED"
    with sqlite3.connect(reviewed["database"]) as db:
        db.execute("UPDATE packet_capture_sessions SET status='RUNNING',ended_at=NULL WHERE session_id=?", (RUNNING_SESSION_A,))
    assert worker.classify(**_args(reviewed))["state"] == "UNKNOWN_HOLD"
    assert len(_audits(reviewed)) == 2


@pytest.mark.parametrize("uid,euid", [(0, 0), (1000, 0), (1001, 1001)])
def test_worker_rejects_root_or_other_uid(monkeypatch, uid, euid):
    monkeypatch.setattr(worker, "os", SimpleNamespace(name="posix", getuid=lambda: uid, geteuid=lambda: euid))
    with pytest.raises(pair.Error, match="pi UID1000"):
        worker._require_pi()


def test_cli_classify_returns_structured_unknown_without_exitcode_inference(reviewed, capsys):
    f = reviewed
    assert worker.main(["classify", "--request-file", str(f["request_file"]), "--request-sha256",
                        f["request"]["plan_sha256"], "--artifact-dir", str(f["artifacts"])]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNKNOWN_HOLD" and result["database_committed"] is None


def test_prepare_reads_database_without_changing_rows_or_bytes(reviewed):
    f = reviewed
    output = f["request_file"].with_name("second-request.json")
    before = f["database"].read_bytes()
    # The original plan requires its original later RUNNING observation.
    with sqlite3.connect(f["database"]) as db:
        db.execute("UPDATE packet_capture_sessions SET status='RUNNING',ended_at=NULL WHERE session_id=?", (RUNNING_SESSION_A,))
    before = f["database"].read_bytes()
    request = worker.prepare(plan_file=f["output"], request_output=output)
    assert request["scope"] == f["request"]["scope"]
    assert f["database"].read_bytes() == before and _audits(f) == []


@pytest.mark.parametrize("mutation", ["runtime_config", "lock_config", "repository"])
def test_changed_runtime_contract_refuses_all_writes(reviewed, monkeypatch, mutation):
    f = reviewed
    if mutation == "runtime_config":
        f["runtime"]["required"] = []
    elif mutation == "lock_config":
        monkeypatch.setattr(pair.settings, "orchestrator_lock_path", str(f["root"] / "data" / "different.lock"))
    else:
        (f["root"] / "tracked.txt").write_text("unreviewed source")
    result = worker.execute(**_args(f))
    assert result["state"] == "UNKNOWN_HOLD" and result["database_committed"] is None
    assert _audits(f) == []


def test_prepare_rejects_processable_skip_request(reviewed):
    f = reviewed
    plan = json.loads(f["output"].read_text())
    plan["skips_processable"] = True
    plan["children"][0]["plan"]["summary"]["skips_processable_sessions"] = True
    plan["children"][0]["plan"] = core.attach_plan_sha256(plan["children"][0]["plan"], generated_at=core._utc_now())
    core._write_json_atomically(f["output"], core.attach_plan_sha256(plan, generated_at=core._utc_now()))
    with pytest.raises(pair.Error, match="without skipped"):
        worker.prepare(plan_file=f["output"], request_output=f["request_file"].with_name("skip-request.json"))
    assert _audits(f) == []


@pytest.mark.parametrize("fault", [None, "service_pid_missing", "active_timer", "pending_job", "unit_missing"])
def test_real_host_guard_handles_timer_without_mainpid_but_refuses_writers(monkeypatch, fault):
    def command(argv, **kwargs):
        if argv[1] == "list-jobs":
            return SimpleNamespace(stdout="1 unknown.service start running\n" if fault == "pending_job" else "")
        unit = argv[2]
        timer = unit.endswith(".timer")
        active = "active" if timer and fault == "active_timer" else "inactive"
        pid = "" if timer or fault == "service_pid_missing" else "MainPID=0\n"
        load = "not-found" if fault == "unit_missing" else "loaded"
        return SimpleNamespace(stdout=f"LoadState={load}\nActiveState={active}\n{pid}ControlGroup=\n")
    monkeypatch.setattr(worker.subprocess, "run", command)
    if fault is None:
        worker._require_quiescent()
    else:
        with pytest.raises(pair.Error):
            worker._require_quiescent()
