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
    spec = dict(controller_unit="hanium-pair-maintenance-controller-"+token+".service",
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
    module.ctl = ctl
    module.show = lambda name: dict(rows[name])
    module.jobs = lambda: ""
    module.kernel_empty = lambda group: group not in populated
    module.poll = lambda predicate, deadline, reason: module.require(predicate(), reason)
    monkeypatch.setattr(module.fcntl, "flock", lambda *args: events.append(("lock", "restore")))
    record(state, "original", original)
    record(state, "controller-cgroup", dict(group="/owned/controller"))
    record(state, "worker-cgroup", dict(group="/owned/worker"))
    for name in active:
        if name != module.BROKER:
            rows[name].update(ActiveState="inactive", MainPID="0")
    rows[spec["controller_unit"]].update(ActiveState="active", MainPID="500",
                                         ControlGroup="/owned/controller")
    rows[spec["worker_unit"]].update(ActiveState="active", MainPID="501",
                                     ControlGroup="/owned/worker")
    return SimpleNamespace(m=module, state=state, spec=spec, rows=rows, original=original,
                           events=events, calls=calls, populated=populated,
                           record=record, temp=tmp_path)


def starts(fixture):
    return [name for action, name in fixture.events if action == "start"]


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


@pytest.mark.parametrize("group", ["/owned/worker", "/owned/controller"])
def test_unproved_owned_teardown_prevents_every_service_resume(fixture, monkeypatch, group):
    fixture.populated.add(group)
    monkeypatch.setattr(fixture.m, "classify", lambda *args: pytest.fail("No classification before reap"))
    with pytest.raises(fixture.m.Hold):
        fixture.m.restore(fixture.spec, fixture.state, independent=group.endswith("controller"))
    assert not starts(fixture)
    assert not (fixture.state / "restored.json").exists()


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
