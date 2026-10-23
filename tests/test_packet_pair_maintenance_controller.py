"""Controller contracts with owned files and mocked OS/process boundaries.

No systemd unit, signal, SQLite connection, Pi or network call is real here.
The Windows loader supplies fcntl only when unavailable; native lifecycle tests
remain separate. Record permissions/fsync are outside these policy fixtures.
"""
import ast
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).parents[1] / "edge/scripts/packet_pair_maintenance_controller.py"


def observation(spec, state):
    counts = {"NOT_COMMITTED_VERIFIED": 0, "PARTIAL_HOLD": 1,
              "COMMITTED_VERIFIED": 2, "UNKNOWN_HOLD": None}
    count = counts[state]
    result = dict(state=state, request_sha256=spec["request_sha256"],
                  artifact_dir=spec["artifact_dir"], rerun=False,
                  verified_audit_count=count,
                  database_committed=None if count is None else count > 0)
    if count is not None:
        result["children"] = dict(packet_rule="APPLIED" if count else "PENDING",
                                  packet_if="APPLIED" if count == 2 else "PENDING")
    return result


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    try:
        import fcntl  # noqa: F401
    except ImportError:
        monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(
            LOCK_EX=2, LOCK_NB=4, flock=lambda *args: None))
    definition = importlib.util.spec_from_file_location("pair_controller_contract", SOURCE)
    module = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(module)
    module.BASE = tmp_path
    token = "abcdef123456"
    state = tmp_path / token
    state.mkdir()
    spec = dict(token=token, boot_id="owned-boot", controller_unit="hanium-pair-maintenance-controller-"+token+".service",
                worker_unit="hanium-pair-maintenance-job-"+token+".service",
                classifier_unit="hanium-pair-maintenance-classifier-"+token+".service",
                rescue_unit="hanium-pair-maintenance-rescue-"+token,
                request_file=str(tmp_path / "request.json"), request_sha256="a"*64,
                request_file_sha256="unused", artifact_dir=str(tmp_path / "artifacts"))
    events, calls, populated = [], [], set()
    rows = {name: dict(ActiveState="inactive", MainPID="0", ControlGroup="",
                       Result="success", ExecMainStatus="0")
            for name in (*module.ALL, spec["controller_unit"], spec["worker_unit"],
                         spec["classifier_unit"], spec["rescue_unit"]+".timer")}
    active = (module.CAPTURE, module.BROKER, "mqtt-subscriber.service",
              "detection-orchestrator.service", "mqtt-feature-builder.service",
              "firewall-worker.service", "gateway-metrics.service", "iot-edge-api.service",
              *module.TIMERS)
    for index, name in enumerate(active):
        rows[name].update(ActiveState="active", MainPID=str(100+index),
                          ControlGroup="/owned/"+name)
    for name in module.TIMERS:
        rows[name].pop("MainPID")
    original = {name: dict(rows[name]) for name in module.ALL}
    original["_first_stop"] = time.monotonic()

    def record(directory, name, value, public=False):
        events.append(("record", name))
        (directory / (name+".json")).write_text(json.dumps(value), encoding="utf-8")

    def ctl(*args, **kwargs):
        calls.append(args)
        action = next((name for name in ("start", "stop") if name in args), None)
        if action:
            for name in args[args.index(action)+1:]:
                if name in rows:
                    events.append((action, name))
                    rows[name].update(ActiveState="active" if action == "start" else "inactive",
                                      MainPID="900" if action == "start" else "0")
        return ""

    module.record = record
    real_sealed = module.sealed
    module.sealed = lambda path: Path(path)  # OS file metadata boundary.
    module.ctl = ctl
    module.show = lambda name: dict(rows[name])
    module.jobs = lambda: ""
    module.kernel_empty = lambda group: group not in populated
    module.poll = lambda predicate, deadline, reason: module.require(predicate(), reason)
    monkeypatch.setattr(module.fcntl, "flock", lambda *args: events.append(("lock", "restore")))
    record(state, "original", original)
    record(state, "controller-cgroup", dict(group="/owned/controller"))
    record(state, "worker-cgroup", dict(group="/owned/worker"))
    record(state, "pause-requested", {})
    module.claim_operation(spec)
    for name in active:
        if name != module.BROKER:
            rows[name].update(ActiveState="inactive", MainPID="0")
    rows[spec["controller_unit"]].update(ActiveState="active", MainPID="500",
                                         ControlGroup="/owned/controller")
    rows[spec["worker_unit"]].update(ActiveState="active", MainPID="501",
                                     ControlGroup="/owned/worker")
    return SimpleNamespace(m=module, state=state, spec=spec, rows=rows, original=original,
                           events=events, calls=calls, populated=populated,
                           record=record, temp=tmp_path, real_sealed=real_sealed)


def starts(fixture):
    return [name for action, name in fixture.events if action == "start"]


def clear_fixture_owner(f):
    (f.temp / "active-operation/owner.json").unlink()
    (f.temp / "active-operation").rmdir()


@pytest.mark.parametrize("state", ["NOT_COMMITTED_VERIFIED", "COMMITTED_VERIFIED"])
def test_verified_zero_or_two_restore_original_actives_only(fixture, monkeypatch, state):
    m = fixture.m
    monkeypatch.setattr(m, "classify", lambda *args: observation(fixture.spec, state))
    m.restore(fixture.spec, fixture.state, independent=False)
    expected = {name for name in m.ALL if fixture.original[name]["ActiveState"] == "active"} - {m.BROKER}
    assert set(starts(fixture)) == expected
    assert starts(fixture)[-2:] == list(m.TIMERS)
    receipt = json.loads((fixture.state / "restored.json").read_text())
    assert receipt["classification"] == state and receipt["held_processing_units"] == []
    assert receipt["recovery_complete"] is False
    assert not (fixture.temp / "active-operation").exists()
    events = list(fixture.events)
    fixture.m.restore(fixture.spec, fixture.state, independent=True)
    assert fixture.events == events  # Same-operation rescue after completion is inert.


@pytest.mark.parametrize("state", ["PARTIAL_HOLD", "UNKNOWN_HOLD", "classifier_timeout"])
def test_partial_unknown_and_failed_classifier_restore_ingress_hold_processing(fixture, monkeypatch, state):
    def classify(*args):
        if state == "classifier_timeout":
            raise TimeoutError("owned classifier deadline")
        return observation(fixture.spec, state)
    monkeypatch.setattr(fixture.m, "classify", classify)
    fixture.m.restore(fixture.spec, fixture.state, independent=False)
    assert set(starts(fixture)).isdisjoint(fixture.m.PROCESSING)
    assert {fixture.m.CAPTURE, "mqtt-subscriber.service", "iot-edge-api.service"}.issubset(starts(fixture))
    receipt = json.loads((fixture.state / "restored.json").read_text())
    assert set(receipt["held_processing_units"]) == fixture.m.PROCESSING
    assert receipt["classification"] == ("UNKNOWN_HOLD" if state == "classifier_timeout" else state)
    assert (fixture.temp / "active-operation/owner.json").exists()


@pytest.mark.parametrize("group", ["/owned/worker", "/owned/controller"])
def test_unproved_owned_teardown_prevents_every_service_resume(fixture, monkeypatch, group):
    fixture.populated.add(group)
    monkeypatch.setattr(fixture.m, "classify", lambda *args: pytest.fail("No classification before reap"))
    with pytest.raises(fixture.m.Hold):
        fixture.m.restore(fixture.spec, fixture.state, independent=group.endswith("controller"))
    assert not starts(fixture)
    assert not (fixture.state / "restored.json").exists()
    assert (fixture.temp / "active-operation/owner.json").exists()


def test_independent_cancel_controller_reap_precedes_lock_worker_and_classification(fixture, monkeypatch):
    def classify(*args):
        fixture.events.append(("classify", "actual"))
        return observation(fixture.spec, "COMMITTED_VERIFIED")
    monkeypatch.setattr(fixture.m, "classify", classify)
    fixture.m.restore(fixture.spec, fixture.state, independent=True)
    assert fixture.events.index(("record", "cancelled")) < fixture.events.index(("stop", fixture.spec["controller_unit"]))
    assert fixture.events.index(("stop", fixture.spec["controller_unit"])) < fixture.events.index(("lock", "restore"))
    assert fixture.events.index(("lock", "restore")) < fixture.events.index(("stop", fixture.spec["worker_unit"]))
    assert fixture.events.index(("stop", fixture.spec["worker_unit"])) < fixture.events.index(("classify", "actual"))
    assert fixture.events.index(("classify", "actual")) < next(i for i, item in enumerate(fixture.events) if item[0] == "start")


def classifier_transport(fixture, monkeypatch, result, status="success", code="0"):
    fixture.record(fixture.state, "worker-launch-requested", {})

    def run(command, **kwargs):
        assert command[0] == "/usr/bin/systemd-run"
        assert "--property=User=pi" in command and "--property=Group=pi" in command
        assert "classify" in command and "--property=RuntimeMaxSec=20" in command
        output = next(value.split("append:", 1)[1] for value in command if "StandardOutput=append:" in value)
        Path(output).write_text(result if isinstance(result, str) else json.dumps(result), encoding="utf-8")
        fixture.rows[fixture.spec["classifier_unit"]].update(Result=status, ExecMainStatus=code)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(fixture.m.subprocess, "run", run)


@pytest.mark.parametrize("state,status,code", [("NOT_COMMITTED_VERIFIED", "success", "0"),
    ("COMMITTED_VERIFIED", "success", "0"), ("PARTIAL_HOLD", "exit-code", "3"),
    ("UNKNOWN_HOLD", "exit-code", "3")])
def test_actual_classifier_response_preserves_complete_bound_observation(fixture, monkeypatch, state, status, code):
    result = observation(fixture.spec, state)
    classifier_transport(fixture, monkeypatch, result, status, code)
    assert fixture.m.classify(fixture.spec, fixture.state, fixture.original) == result
    assert fixture.rows[fixture.spec["classifier_unit"]]["MainPID"] == "0"


@pytest.mark.parametrize("change", ["request", "directory", "rerun", "invalid_json", "count_bool",
    "count_float", "committed_numeric", "if_without_rule", "state_count", "missing_children", "timeout_status"])
def test_exit_success_cannot_replace_bound_and_consistent_actual_audit_result(fixture, monkeypatch, change):
    result = observation(fixture.spec, "COMMITTED_VERIFIED")
    status, code = "success", "0"
    if change == "request": result["request_sha256"] = "b"*64
    elif change == "directory": result["artifact_dir"] = "unrelated"
    elif change == "rerun": result["rerun"] = True
    elif change == "invalid_json": result = "{incomplete"
    elif change == "count_bool": result = observation(fixture.spec, "PARTIAL_HOLD"); result["verified_audit_count"] = True
    elif change == "count_float": result["verified_audit_count"] = 2.0
    elif change == "committed_numeric": result["database_committed"] = 1
    elif change == "if_without_rule": result = observation(fixture.spec, "PARTIAL_HOLD"); result["children"] = dict(packet_rule="PENDING", packet_if="APPLIED")
    elif change == "state_count": result["verified_audit_count"] = 0
    elif change == "missing_children": result.pop("children")
    elif change == "timeout_status": status, code = "timeout", "0"
    classifier_transport(fixture, monkeypatch, result, status, code)
    with pytest.raises((fixture.m.Hold, ValueError)):
        fixture.m.classify(fixture.spec, fixture.state, fixture.original)
    assert not starts(fixture)
    assert fixture.rows[fixture.spec["classifier_unit"]]["MainPID"] == "0"


def test_ambiguous_success_output_falls_back_unknown_and_never_starts_processing(fixture, monkeypatch):
    result = observation(fixture.spec, "COMMITTED_VERIFIED")
    result["request_sha256"] = "wrong-request"
    classifier_transport(fixture, monkeypatch, result)
    fixture.m.restore(fixture.spec, fixture.state, independent=False)
    assert set(starts(fixture)).isdisjoint(fixture.m.PROCESSING)
    assert json.loads((fixture.state / "classification.json").read_text())["state"] == "UNKNOWN_HOLD"


def worker_setup(fixture, monkeypatch, cancelled=False):
    m = fixture.m
    launch = dict(driver_sha256=m.digest(SOURCE), boot_id="owned-boot", request_file=str(fixture.temp/"request.json"),
                  request_file_sha256="bound-request", cwd=str(m.PROJECT), command=m.worker_command(fixture.spec, "execute"))
    fixture.record(fixture.state, "launch", launch)
    fixture.record(fixture.state, "accepted", {})
    if cancelled:
        fixture.record(fixture.state, "cancelled", {})
    monkeypatch.setattr(m, "sealed", lambda path: Path(path))
    monkeypatch.setattr(m, "digest", lambda path: launch["driver_sha256"] if Path(path) == SOURCE else "bound-request")
    real_read = Path.read_text

    def read(path, *args, **kwargs):
        return "owned-boot" if path.as_posix() == "/proc/sys/kernel/random/boot_id" else real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(m.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(m.os, "getgid", lambda: 1000, raising=False)
    return launch


def test_cancelled_late_worker_never_launches_database_command(fixture, monkeypatch):
    worker_setup(fixture, monkeypatch, cancelled=True)
    monkeypatch.setattr(fixture.m.subprocess, "run", lambda *args, **kwargs: pytest.fail("No late DB worker"))
    with pytest.raises(fixture.m.Hold, match="Late cancelled"):
        fixture.m.worker(fixture.state)


def test_pi_worker_preserves_project_configuration_without_root_or_memory_db_override(fixture, monkeypatch):
    launch = worker_setup(fixture, monkeypatch)
    calls = []
    monkeypatch.setattr(fixture.m.subprocess, "run", lambda command, **kwargs:
                        calls.append((command, kwargs)) or SimpleNamespace(returncode=3))
    with pytest.raises(SystemExit) as error:
        fixture.m.worker(fixture.state)
    assert error.value.code == 3 and len(calls) == 1
    assert calls[0][0] == launch["command"]
    assert calls[0][1]["cwd"] == str(fixture.m.PROJECT)
    assert "DATABASE_URL" not in calls[0][1]["env"]
    assert all("root" not in value for value in calls[0][1]["env"].values())


def test_cancel_before_launch_never_dispatches_mutating_worker(fixture, monkeypatch):
    m = fixture.m
    clear_fixture_owner(fixture)
    state = fixture.temp / "fresh-controller-state"
    spec = fixture.spec | dict(capture_main_pid=int(fixture.original[m.CAPTURE]["MainPID"]),
        capture_main_birth="owned-birth", capture_session=dict(id=117, session_id="owned-capture",
        status="RUNNING", ended_at=None), driver_sha256=m.digest(SOURCE), boot_id="owned-boot",
        spec_file=str(fixture.temp / "spec.json"))
    for name in m.ALL:
        fixture.rows[name] = dict(fixture.original[name])
    fixture.rows[spec["controller_unit"]].update(MainPID=str(os.getpid()), ControlGroup="/owned/controller")
    real_read = Path.read_text

    def read(path, *args, **kwargs):
        return "0::/owned/controller" if path.as_posix() == "/proc/self/cgroup" else real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(m, "process_birth", lambda pid: "owned-birth")
    reads = iter([spec["capture_session"], spec["capture_session"] | dict(status="COMPLETED", ended_at="owned-end")])
    monkeypatch.setattr(m, "session_row", lambda _: next(reads))

    def terminate(original):
        fixture.rows[m.CAPTURE].update(ActiveState="inactive", MainPID="0")

    monkeypatch.setattr(m, "graceful_capture_term", terminate)
    dispatched = []

    def run(command, **kwargs):
        dispatched.append(command)
        assert "--on-active=150s" in command
        fixture.rows[spec["rescue_unit"]+".timer"]["ActiveState"] = "active"
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(m.subprocess, "run", run)
    real_poll = m.poll

    def poll(predicate, deadline, reason):
        real_poll(predicate, deadline, reason)
        if reason == "Operating writers not quiescent; recovery forbidden":
            fixture.record(state, "cancelled", {})

    monkeypatch.setattr(m, "poll", poll)
    m.execute(spec, state)
    assert len(dispatched) == 1  # Rescue timer only, no database worker.
    assert not (state / "worker-launch-requested.json").exists()
    assert json.loads((state / "classification.json").read_text())["state"] == "NOT_STARTED"


def test_timers_may_start_originally_inactive_extractor_after_validation(fixture, monkeypatch):
    monkeypatch.setattr(fixture.m, "classify", lambda *args: observation(fixture.spec, "PARTIAL_HOLD"))
    original_ctl = fixture.m.ctl

    def ctl(*args, **kwargs):
        result = original_ctl(*args, **kwargs)
        if "start" in args and fixture.m.TIMERS[0] in args:
            fixture.rows["packet-feature-extractor.service"]["ActiveState"] = "active"
        return result

    monkeypatch.setattr(fixture.m, "ctl", ctl)
    fixture.m.restore(fixture.spec, fixture.state, independent=False)
    assert (fixture.state / "restored.json").exists()
    assert "packet-feature-extractor.service" not in starts(fixture)
    assert set(starts(fixture)).isdisjoint(fixture.m.PROCESSING)


def test_controller_root_imports_no_product_database_and_session_probe_is_pi_readonly():
    tree = ast.parse(SOURCE.read_text())
    imports = {node.module if isinstance(node, ast.ImportFrom) else alias.name
               for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
               for alias in (node.names if isinstance(node, ast.Import) else [None])}
    assert not imports.intersection({"sqlite3", "sqlalchemy", "backend.app.database"})
    probe = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "PI_SESSION" for target in node.targets))
    assert "mode=ro" in probe and "PRAGMA query_only=ON" in probe and "os.getuid()==os.getgid()==1000" in probe
    session = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "session_row")
    assert "runuser" in ast.get_source_segment(SOURCE.read_text(), session)


def test_capture_preserving_restoration_controls_packet_units_only(fixture):
    spec = fixture.spec | {"allow_capture_appends": True}
    allowed = {"detection-orchestrator.service", "packet-feature-extractor.service"}
    units = fixture.m.restoration_units(fixture.original,
        observation(spec, "COMMITTED_VERIFIED"), spec=spec)
    assert set(units) <= allowed
    assert "detection-orchestrator.service" in units
    assert fixture.m.restoration_units(fixture.original,
        observation(spec, "PARTIAL_HOLD"), spec=spec) == []



@pytest.fixture
def retained(fixture, monkeypatch):
    f, m = fixture, fixture.m
    f.spec.update(allow_capture_appends=True,
        capture_main_pid=int(f.original[m.CAPTURE]["MainPID"]), capture_main_birth="owned-birth",
        capture_session=dict(id=117, session_id="owned-capture", status="RUNNING", ended_at=None,
                             first_window_start="2026-10-14T00:00:00Z"))
    for name in m.service_scope(f.spec)["retained"]:
        f.rows[name] = dict(f.original[name])
    monkeypatch.setattr(m, "process_birth", lambda pid: "owned-birth")
    monkeypatch.setattr(m, "session_row", lambda _: dict(f.spec["capture_session"]))
    f.record(f.temp / "active-operation", "owner", m.operation_owner(f.spec))
    return f


@pytest.mark.parametrize("state,independent", [("COMMITTED_VERIFIED", False),
    ("NOT_COMMITTED_VERIFIED", True), ("PARTIAL_HOLD", True), ("UNKNOWN_HOLD", False)])
def test_capture_preserving_restore_leaves_all_retained_services_untouched(retained, monkeypatch, state, independent):
    f, m = retained, retained.m
    before = {name: dict(f.rows[name]) for name in m.service_scope(f.spec)["retained"]}
    monkeypatch.setattr(m, "classify", lambda *args: observation(f.spec, state))
    m.restore(f.spec, f.state, independent=independent)
    receipt = json.loads((f.state / "restored.json").read_text())
    packet = {"detection-orchestrator.service", "packet-feature-extractor.service", "packet-feature-extractor.timer"}
    if state in ("PARTIAL_HOLD", "UNKNOWN_HOLD"):
        assert not starts(f) and set(receipt["held_processing_units"]) == packet
        assert all(m.stopped(name) for name in packet)
    else:
        assert set(starts(f)) == {"detection-orchestrator.service", "packet-feature-extractor.timer"}
        assert receipt["held_processing_units"] == []
    assert all(f.rows[name] == value for name, value in before.items())
    assert set(starts(f)).isdisjoint(before)
    assert not any(name in before for action, name in f.events if action == "stop")
    assert receipt["allow_capture_appends"] is True and receipt["recovery_complete"] is False


@pytest.mark.parametrize("change", ["pid", "birth", "session", "closed"])
def test_capture_preserving_identity_change_blocks_any_resume(retained, monkeypatch, change):
    f, m = retained, retained.m
    if change == "pid":
        f.rows[m.CAPTURE]["MainPID"] = "888"
    elif change == "birth":
        monkeypatch.setattr(m, "process_birth", lambda pid: "reused-pid")
    else:
        value = f.spec["capture_session"] | ({"first_window_start": "other"} if change == "session"
                                            else {"status": "COMPLETED", "ended_at": "later"})
        monkeypatch.setattr(m, "session_row", lambda _: value)
    monkeypatch.setattr(m, "classify", lambda *args: pytest.fail("No classification after identity failure"))
    with pytest.raises(m.Hold, match="Capture"):
        m.restore(f.spec, f.state, independent=False)
    assert not starts(f) and not (f.state / "restored.json").exists()


def test_capture_preserving_classifier_checks_capture_again_after_read(retained, monkeypatch):
    f, m = retained, retained.m
    classifier_transport(f, monkeypatch, observation(f.spec, "COMMITTED_VERIFIED"))
    run = m.subprocess.run
    def changed(command, **kwargs):
        result = run(command, **kwargs)
        f.rows[m.CAPTURE]["MainPID"] = "restarted"
        return result
    monkeypatch.setattr(m.subprocess, "run", changed)
    with pytest.raises(m.Hold, match="Capture"):
        m.classify(f.spec, f.state, f.original)
    assert not starts(f) and f.rows[f.spec["classifier_unit"]]["MainPID"] == "0"


@pytest.mark.parametrize("cancelled", [False, True])
@pytest.mark.parametrize("keep", [True, False])
def test_controller_mode_pauses_only_approved_services_and_sets_worker_priority(retained, monkeypatch, cancelled, keep):
    f, m = retained, retained.m
    clear_fixture_owner(f)
    state = f.temp / "retained-full-controller"
    spec = f.spec | dict(allow_capture_appends=keep, driver_sha256=m.digest(SOURCE), boot_id="owned-boot",
                        spec_file=str(f.temp / "spec.json"))
    for name in m.ALL:
        f.rows[name] = dict(f.original[name])
    before = {name: dict(f.rows[name]) for name in m.service_scope(spec)["retained"]}
    f.rows[spec["controller_unit"]].update(MainPID=str(os.getpid()), ControlGroup="/owned/controller")
    real_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, *args, **kwargs:
        "0::/owned/controller" if path.as_posix() == "/proc/self/cgroup" else real_read(path, *args, **kwargs))
    capture = dict(spec["capture_session"])
    monkeypatch.setattr(m, "session_row", lambda _: dict(capture))
    def terminate(*args):
        assert not keep, "Retained Capture must not receive TERM"
        f.rows[m.CAPTURE].update(ActiveState="inactive", MainPID="0")
        capture.update(status="COMPLETED", ended_at="owned-end")
    monkeypatch.setattr(m, "graceful_capture_term", terminate)
    dispatched = []
    def run(command, **kwargs):
        dispatched.append(command)
        if "--on-active=150s" in command:
            f.rows[spec["rescue_unit"]+".timer"]["ActiveState"] = "active"
        else:
            assert "--worker" in command and "--property=User=pi" in command
            f.rows[spec["worker_unit"]].update(ActiveState="active", MainPID="501",
                ControlGroup="/owned/worker", User="pi", Group="pi")
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(m.subprocess, "run", run)
    real_poll = m.poll
    def poll(predicate, deadline, reason):
        if reason == "Recovery worker exceeded90s+teardown; HOLD":
            f.rows[spec["worker_unit"]].update(ActiveState="inactive", MainPID="0")
        real_poll(predicate, deadline, reason)
        if cancelled and reason == "Operating writers not quiescent; recovery forbidden":
            f.record(state, "cancelled", {})
    monkeypatch.setattr(m, "poll", poll)
    original_classify = m.classify
    monkeypatch.setattr(m, "classify", lambda *args: original_classify(*args) if cancelled
                        else observation(spec, "COMMITTED_VERIFIED"))
    m.execute(spec, state)
    packet = {"detection-orchestrator.service", "packet-feature-extractor.service", "packet-feature-extractor.timer"}
    if keep:
        assert {name for action, name in f.events if action == "stop" and name in m.ALL} <= packet
        assert set(starts(f)) <= packet
    assert all(f.rows[name] == value for name, value in before.items())
    assert len(dispatched) == (1 if cancelled else 2)
    if not cancelled:
        priority = [value for value in dispatched[-1] if value.startswith(("--property=Nice=", "--property=IOSchedulingClass="))]
        assert priority == (["--property=Nice=10", "--property=IOSchedulingClass=idle"]
                            if keep else ["--property=Nice=0"])
        assert (state / "accepted.json").exists()
    assert (state / "worker-launch-requested.json").exists() is not cancelled
    assert (state / "capture-term.json").exists() is not keep
    assert (state / "capture-closed.json").exists() is not keep
    receipt = json.loads((state / "restored.json").read_text())
    assert receipt["classification"] == ("NOT_STARTED" if cancelled else "COMMITTED_VERIFIED")


def test_capture_preserving_unrelated_periodic_jobs_do_not_block_packet_gate(retained, monkeypatch):
    m, spec = retained.m, retained.spec
    monkeypatch.setattr(m, "jobs", lambda: "7 firewall-runtime-snapshot.service start running")
    assert m.relevant_jobs(spec) == ""
    monkeypatch.setattr(m, "jobs", lambda: "7 packet-feature-extractor.service start running")
    assert m.relevant_jobs(spec)



def test_capture_preserving_full_restore_allows_timer_to_run_previously_inactive_extractor(retained, monkeypatch):
    f, m = retained, retained.m
    monkeypatch.setattr(m, "classify", lambda *args: observation(f.spec, "COMMITTED_VERIFIED"))
    ctl = m.ctl
    def start_timer(*args, **kwargs):
        result = ctl(*args, **kwargs)
        if "start" in args and "packet-feature-extractor.timer" in args:
            f.rows["packet-feature-extractor.service"].update(ActiveState="active", MainPID="999")
        return result
    monkeypatch.setattr(m, "ctl", start_timer)
    m.restore(f.spec, f.state, independent=False)
    receipt = json.loads((f.state / "restored.json").read_text())
    assert receipt["held_processing_units"] == []
    assert "packet-feature-extractor.service" not in starts(f)
    assert f.rows["packet-feature-extractor.service"]["ActiveState"] == "active"



@pytest.mark.parametrize("case", ["retained", "fixture"])
def test_classifier_priority_is_lowered_only_while_capture_is_retained(case, request, monkeypatch):
    f = request.getfixturevalue(case)
    result = observation(f.spec, "COMMITTED_VERIFIED")
    classifier_transport(f, monkeypatch, result)
    run = f.m.subprocess.run
    commands = []
    def observed(command, **kwargs):
        commands.append(command)
        return run(command, **kwargs)
    monkeypatch.setattr(f.m.subprocess, "run", observed)
    assert f.m.classify(f.spec, f.state, f.original) == result
    assert len(commands) == 1
    priority = [value for value in commands[0] if value.startswith(("--property=Nice=", "--property=IOSchedulingClass="))]
    assert priority == (["--property=Nice=10", "--property=IOSchedulingClass=idle"] if case == "retained" else [])


def controller_run(f, monkeypatch, keep):
    """Actual execute composition; only the systemd/process boundary is modelled."""
    m = f.m
    clear_fixture_owner(f)
    state = f.temp / "fresh-execute"
    spec = f.spec | dict(allow_capture_appends=keep, driver_sha256=m.digest(SOURCE),
                        spec_file=str(f.temp / "spec.json"))
    for name in m.ALL:
        f.rows[name] = dict(f.original[name])
    f.rows[spec["controller_unit"]].update(MainPID=str(os.getpid()), ControlGroup="/owned/controller")
    real_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, *args, **kwargs:
        "0::/owned/controller" if path.as_posix() == "/proc/self/cgroup" else real_read(path, *args, **kwargs))
    capture = dict(spec["capture_session"])
    monkeypatch.setattr(m, "session_row", lambda _: dict(capture))

    def terminate(*args):
        assert not keep
        f.events.append(("term", m.CAPTURE))
        f.rows[m.CAPTURE].update(ActiveState="inactive", MainPID="0")
        capture.update(status="COMPLETED", ended_at="owned-end")

    monkeypatch.setattr(m, "graceful_capture_term", terminate)
    dispatched = []

    def run(command, **kwargs):
        dispatched.append(command)
        if "--on-active=150s" in command:
            f.rows[spec["rescue_unit"]+".timer"]["ActiveState"] = "active"
        else:
            assert "--worker" in command and "--property=User=pi" in command
            f.rows[spec["worker_unit"]].update(ActiveState="active", MainPID="501",
                ControlGroup="/owned/worker", User="pi", Group="pi")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(m.subprocess, "run", run)
    return spec, state, dispatched


def other_spec(spec):
    token = "012345abcdef"
    return {key: value.replace(spec["token"], token) if isinstance(value, str) else value
            for key, value in spec.items()}


@pytest.mark.parametrize("keep,other_keep", [(True, True), (True, False), (False, True), (False, False)])
def test_active_operation_rejects_second_token_before_any_os_action(retained, monkeypatch, keep, other_keep):
    f, m = retained, retained.m
    spec, state, dispatched = controller_run(f, monkeypatch, keep)
    real_poll = m.poll
    collisions_rejected = []

    def poll(predicate, deadline, reason):
        if reason == "Recovery worker exceeded90s+teardown; HOLD":
            assert len(dispatched) == 2 and (state / "accepted.json").exists()
            assert f.rows[spec["worker_unit"]]["ActiveState"] == "active"
            second = other_spec(spec) | dict(allow_capture_appends=other_keep)
            with monkeypatch.context() as guarded:
                guarded.setattr(m, "show", lambda *args: pytest.fail("Second token reached OS before ownership rejection"))
                guarded.setattr(m, "ctl", lambda *args, **kwargs: pytest.fail("Second token changed a service"))
                with pytest.raises(m.Hold, match="Another maintenance operation"):
                    m.execute(second, f.temp / second["token"])
            collisions_rejected.append(True)
            f.rows[spec["worker_unit"]].update(ActiveState="inactive", MainPID="0")
        real_poll(predicate, deadline, reason)

    monkeypatch.setattr(m, "poll", poll)
    monkeypatch.setattr(m, "classify", lambda *args: observation(spec, "COMMITTED_VERIFIED"))
    m.execute(spec, state)
    assert collisions_rejected == [True]  # execute records ordinary callback errors as HOLD.
    assert json.loads((state / "restored.json").read_text())["classification"] == "COMMITTED_VERIFIED"


@pytest.mark.parametrize("keep", [True, False])
@pytest.mark.parametrize("populated", [False, True])
def test_execute_worker_deadline_reaps_before_classification_and_restoration(retained, monkeypatch, keep, populated):
    f, m = retained, retained.m
    spec, state, dispatched = controller_run(f, monkeypatch, keep)
    real_poll = m.poll

    def poll(predicate, deadline, reason):
        if reason == "Recovery worker exceeded90s+teardown; HOLD":
            assert len(dispatched) == 2 and (state / "accepted.json").exists()
            assert json.loads((state / "worker-cgroup.json").read_text())["group"] == "/owned/worker"
            f.events.append(("deadline", "worker"))
            if populated:
                f.populated.add("/owned/worker")
            raise m.Hold(reason)
        real_poll(predicate, deadline, reason)

    def classify(*args):
        assert m.stopped(spec["worker_unit"], "/owned/worker")
        f.events.append(("classify", "after-deadline"))
        return observation(spec, "NOT_COMMITTED_VERIFIED")

    monkeypatch.setattr(m, "poll", poll)
    monkeypatch.setattr(m, "classify", classify)
    if populated:
        with pytest.raises(m.Hold, match="not positively terminated"):
            m.execute(spec, state)
        assert not starts(f) and not (state / "restored.json").exists()
        assert ("classify", "after-deadline") not in f.events
        assert (f.temp / "active-operation/owner.json").exists()
    else:
        m.execute(spec, state)
        reap = f.events.index(("stop", spec["worker_unit"]))
        classify_at = f.events.index(("classify", "after-deadline"))
        assert f.events.index(("deadline", "worker")) < reap < classify_at
        assert all(classify_at < i for i, (action, _) in enumerate(f.events) if action == "start")
        assert (state / "restored.json").exists()
        assert not (f.temp / "active-operation").exists()


@pytest.mark.parametrize("keep", [True, False])
def test_dead_controller_with_orphan_worker_does_not_release_ownership(retained, monkeypatch, keep):
    f, m = retained, retained.m
    f.rows[f.spec["controller_unit"]].update(ActiveState="inactive", MainPID="0")
    f.populated.add("/owned/worker")
    before = list(f.events)
    second = other_spec(f.spec) | dict(allow_capture_appends=keep)
    with pytest.raises(m.Hold, match="Another maintenance operation"):
        m.execute(second, f.temp / second["token"])
    assert f.events == before and f.rows[f.spec["worker_unit"]]["ActiveState"] == "active"
    with pytest.raises(m.Hold, match="not positively terminated"):
        m.restore(f.spec, f.state, independent=True)
    assert not starts(f) and (f.temp / "active-operation/owner.json").exists()


@pytest.mark.parametrize("change", ["boot_id", "token", "request_sha256", "database_path", "paused_units"])
def test_foreign_owner_refuses_rescue_before_any_service_action(retained, change):
    f, m = retained, retained.m
    owner = json.loads((f.temp / "active-operation/owner.json").read_text())
    owner[change] = [] if change == "paused_units" else "foreign"
    f.record(f.temp / "active-operation", "owner", owner)
    before = list(f.events)
    with pytest.raises(m.Hold, match="ownership differs"):
        m.restore(f.spec, f.state, independent=True)
    assert f.events == before and not (f.state / "cancelled.json").exists()


@pytest.mark.parametrize("result", ["PARTIAL_HOLD", "UNKNOWN_HOLD"])
def test_unresolved_hold_keeps_fence_across_idempotent_rescue(retained, monkeypatch, result):
    f, m = retained, retained.m
    monkeypatch.setattr(m, "classify", lambda *args: observation(f.spec, result))
    m.restore(f.spec, f.state, independent=True)
    m.restore(f.spec, f.state, independent=True)
    assert not starts(f) and (f.temp / "active-operation/owner.json").exists()
    second = other_spec(f.spec)
    with pytest.raises(m.Hold, match="Another maintenance operation"):
        m.execute(second, f.temp / second["token"])
    assert not starts(f)


def test_full_restore_allows_new_owner_and_old_rescuer_cannot_touch_it(retained, monkeypatch):
    f, m = retained, retained.m
    monkeypatch.setattr(m, "classify", lambda *args: observation(f.spec, "COMMITTED_VERIFIED"))
    m.restore(f.spec, f.state, independent=False)
    second = other_spec(f.spec)
    m.claim_operation(second)
    before = list(f.events)
    with pytest.raises(m.Hold, match="ownership differs"):
        m.restore(f.spec, f.state, independent=True)
    assert f.events == before
    m.require_owner(second)


def test_rescuer_rechecks_owner_after_waiting_for_restore_lock(retained, monkeypatch):
    f, m = retained, retained.m
    second = other_spec(f.spec)
    boundary = []

    def previous_owner_completed(*args):
        # Model completion between the first ownership check and lock acquisition.
        m.release_operation(f.spec)
        m.claim_operation(second)
        boundary.append(len(f.events))

    monkeypatch.setattr(m.fcntl, "flock", previous_owner_completed)
    with pytest.raises(m.Hold, match="ownership differs"):
        m.restore(f.spec, f.state, independent=True)
    assert all(action not in ("start", "stop") for action, _ in f.events[boundary[0]:])
    m.require_owner(second)


@pytest.mark.parametrize("failure", ["controller_identity", "rescue_dispatch", "fresh_identity"])
def test_failure_before_pause_releases_fence_without_shared_service_action(retained, monkeypatch, failure):
    f, m = retained, retained.m
    spec, state, _ = controller_run(f, monkeypatch, True)
    if failure == "controller_identity":
        f.rows[spec["controller_unit"]]["MainPID"] = "foreign"
    elif failure == "rescue_dispatch":
        monkeypatch.setattr(m.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("dispatch")))
    else:
        monkeypatch.setattr(m, "session_row", lambda _: spec["capture_session"] | dict(first_window_start="changed"))
    m.execute(spec, state)
    assert not any(action in ("start", "stop", "term") for action, _ in f.events)
    assert not (state / "pause-requested.json").exists()
    assert not (f.temp / "active-operation").exists()
    assert json.loads((state / "not-started.json").read_text())["service_actions"] is False
    before = list(f.events)
    m.restore(spec, state, independent=True)
    assert f.events == before


@pytest.fixture
def sealed_spec(retained, monkeypatch):
    """Actual sealed/load_spec/main guards; fake only root/boot/file ownership."""
    f, m = retained, retained.m
    frozen = f.temp / ("frozen-" + f.spec["token"])
    frozen.mkdir()
    driver, request_file, spec_file = (frozen / name for name in ("controller.py", "request.json", "spec.json"))
    driver.write_bytes(SOURCE.read_bytes())
    m.OPS = f.temp / "artifacts"
    artifacts = m.OPS / f.spec["token"]
    artifacts.mkdir(parents=True)
    capture = f.spec["capture_session"] | dict(session_id="11111111-2222-3333-4444-555555555555")
    spec = f.spec | dict(schema="packet-pair-maintenance-v1", approval_received=True,
        approval_scope="capture-retained-canonical-pair-recovery", capture_session=capture,
        capture_session_id=capture["id"], capture_session_uuid=capture["session_id"],
        preflight_observed_at=time.time(), driver_sha256=m.digest(driver),
        request_file=str(request_file), artifact_dir=str(artifacts))
    reviewed = dict(plan_sha256=spec["request_sha256"], scope=dict(allow_capture_appends=True),
                    capture_session_identity=dict(capture))

    def write():
        request_file.write_text(json.dumps(reviewed), encoding="utf-8")
        spec["request_file_sha256"] = m.digest(request_file)
        spec_file.write_text(json.dumps(spec), encoding="utf-8")

    write()
    monkeypatch.setattr(m, "__file__", str(driver))
    monkeypatch.setattr(m, "os", SimpleNamespace(name="posix", getuid=lambda: 0))
    monkeypatch.setattr(m, "sealed", f.real_sealed)
    real_read, real_stat = Path.read_text, Path.stat
    monkeypatch.setattr(Path, "read_text", lambda path, *args, **kwargs:
        spec["boot_id"] if path.as_posix() == "/proc/sys/kernel/random/boot_id" else real_read(path, *args, **kwargs))

    def metadata(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path in (driver, request_file, spec_file, artifacts):
            fields = list(result)
            fields[0] = stat.S_IFDIR | 0o700 if path == artifacts else stat.S_IFREG | 0o444
            fields[4] = 1000 if path == artifacts else 0
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", metadata)
    monkeypatch.setattr(sys, "argv", [str(driver), "--execute", "--spec", str(spec_file)])
    return SimpleNamespace(f=f, m=m, spec=spec, reviewed=reviewed, write=write, path=spec_file)


@pytest.mark.parametrize("keep", [True, False])
def test_main_accepts_consistent_sealed_capture_mode_and_identity(sealed_spec, monkeypatch, keep):
    f, m = sealed_spec, sealed_spec.m
    f.spec["allow_capture_appends"] = f.reviewed["scope"]["allow_capture_appends"] = keep
    f.spec["approval_scope"] = "capture-retained-canonical-pair-recovery" if keep else "capture-pause-canonical-pair-recovery"
    f.write()
    executed = []
    monkeypatch.setattr(m, "execute", lambda spec, state: executed.append((spec, state)))
    m.main()
    assert len(executed) == 1 and executed[0][0]["capture_session"] == f.spec["capture_session"]
    assert executed[0][1] == m.BASE / f.spec["token"]
    assert not f.f.calls


@pytest.mark.parametrize("change,reason", [("signed_mode", "Signed capture mode changed"),
    ("signed_non_bool", "Signed capture mode changed"), ("spec_non_bool", "Invalid capture mode"),
    ("retained_full_identity", "Signed retained Capture identity changed")])
def test_main_rejects_sealed_request_mismatch_before_execute_or_services(sealed_spec, monkeypatch, change, reason):
    f, m = sealed_spec, sealed_spec.m
    if change == "signed_mode":
        f.reviewed["scope"]["allow_capture_appends"] = False
    elif change == "signed_non_bool":
        f.reviewed["scope"]["allow_capture_appends"] = "true"
    elif change == "spec_non_bool":
        f.spec["allow_capture_appends"] = "true"
    else:
        f.reviewed["capture_session_identity"]["first_window_start"] = "changed-with-same-uuid"
    f.write()  # Keep file hash/source/header valid so this reaches the intended guard.
    monkeypatch.setattr(m, "execute", lambda *args: pytest.fail("Invalid sealed request reached execute"))
    with pytest.raises(m.Hold, match=reason):
        m.main()
    assert not f.f.calls


def test_atomic_owner_creation_arbitrates_simultaneous_tokens(retained):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    f, m = retained, retained.m
    clear_fixture_owner(f)
    barrier = Barrier(2)

    def claim(spec):
        barrier.wait(timeout=5)
        try:
            m.claim_operation(spec)
            return spec["token"]
        except m.Hold:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = [token for token in pool.map(claim, [f.spec, other_spec(f.spec)]) if token]
    assert len(winners) == 1
    assert json.loads((f.temp / "active-operation/owner.json").read_text())["token"] == winners[0]
    assert not f.calls
