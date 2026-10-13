"""One-use launcher boundaries; all OS/service/SQLite preflights are mocks."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).parents[1] / "edge/scripts/run_packet_pair_maintenance.py"
TOKEN = "abcdef123456"


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    definition = importlib.util.spec_from_file_location("maintenance_launcher_contract", SOURCE)
    m = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(m)
    project = tmp_path / "project"
    (project / "output").mkdir(parents=True)
    controller = project / "controller.py"
    controller.write_bytes(b"# reviewed controller fixture\n")
    request = dict(plan_schema_version="packet-pair-maintenance-request-v1", plan_sha256="a"*64,
                   scope=dict(repository_root=str(project), database_path=str(project / "backend/data/iot_security.db")))
    request_file = tmp_path / "reviewed-request.json"
    request_file.write_text(json.dumps(request), encoding="utf-8")
    capture = dict(id=117, session_id="00000000-0000-4000-8000-000000000117", status="RUNNING",
                   ended_at=None, first_window_start="2026-10-13T04:00:40Z")
    m.PROJECT, m.BASE, m.OPS, m.CONTROLLER = project, tmp_path / "sealed", project / "output/packet-pair-maintenance", controller
    monkeypatch.setattr(m, "os", SimpleNamespace(name="posix", getuid=lambda: 0))
    monkeypatch.setattr(m.secrets, "token_hex", lambda length: TOKEN)
    directories, seals, calls = [], [], []

    def directory(path, owner, mode, create=True):
        directories.append((path, owner, mode))
        if create:
            assert owner == 0, "root must not create/chown under the pi-writable project tree"
            path.mkdir(exist_ok=True)
        return path

    original_seal = m.seal

    def seal(path, data, mode):
        seals.append((path, data, mode))
        with path.open("xb") as stream:
            stream.write(data)

    monkeypatch.setattr(m, "directory", directory)
    monkeypatch.setattr(m, "seal", seal)
    real_read = Path.read_text

    def read(path, *args, **kwargs):
        if path.as_posix() == "/proc/sys/kernel/random/boot_id":
            return "owned-boot"
        if path.as_posix() == "/proc/123/stat":
            return "123 (capture) " + " ".join(["S"]+["0"]*18+["777"])
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    result = SimpleNamespace(capture=capture, dispatch_error=None, restoration=None)

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "/usr/sbin/runuser":
            assert command[1:6] == ["-u", "pi", "--", "/usr/bin/python3", "-I"]
            if command[-3] == m.PI_ARTIFACT:
                assert command[-2:] == [str(m.OPS), TOKEN]
                m.OPS.mkdir(exist_ok=True)
                (m.OPS / TOKEN).mkdir()
                return SimpleNamespace(stdout="", returncode=0)
            assert "mode=ro" in command[-1] and "PRAGMA query_only=ON" in command[-1]
            return SimpleNamespace(stdout=json.dumps(result.capture), returncode=0)
        if command[0] == "/usr/bin/systemctl":
            return SimpleNamespace(stdout="ActiveState=active\nMainPID=123", returncode=0)
        assert command[0] == "/usr/bin/systemd-run"
        if result.dispatch_error:
            raise result.dispatch_error
        if result.restoration is not None:
            state = m.BASE / TOKEN
            state.mkdir()
            (state / "restored.json").write_text(json.dumps(result.restoration), encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(m.subprocess, "run", run)
    arguments = dict(request_file=request_file,
        request_file_sha256=hashlib.sha256(request_file.read_bytes()).hexdigest(),
        controller_sha256=hashlib.sha256(controller.read_bytes()).hexdigest(),
        approval_reference="human operating pause approval", approve_capture_pause=True,
        wait_seconds=0)
    return SimpleNamespace(m=m, args=arguments, request=request, request_file=request_file,
                           directories=directories, seals=seals, calls=calls,
                           result=result, original_seal=original_seal, temp=tmp_path)


def dispatches(fixture):
    return [command for command, _ in fixture.calls if command[0] == "/usr/bin/systemd-run"]


def test_default_hold_does_not_read_files_probe_database_or_dispatch(fixture, monkeypatch, capsys):
    monkeypatch.setattr(fixture.m, "launch", lambda **kwargs: pytest.fail("No launch in default HOLD"))
    monkeypatch.setattr(fixture.m, "reviewed_bytes", lambda *args: pytest.fail("No source read in default HOLD"))
    assert fixture.m.main([]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "HOLD"
    assert not fixture.calls and not fixture.directories


@pytest.mark.parametrize("changes", [dict(approve_capture_pause=False), dict(approve_capture_pause=1),
    dict(approval_reference="  "), dict(request_file_sha256=""), dict(request_file_sha256="0"*64),
    dict(controller_sha256="0"*64), dict(wait_seconds=-1), dict(wait_seconds=211)])
def test_approval_or_reviewed_sha_failure_cannot_pause_or_dispatch(fixture, changes):
    with pytest.raises(RuntimeError):
        fixture.m.launch(**(fixture.args | changes))
    assert not fixture.calls and not fixture.directories and not fixture.seals


@pytest.mark.parametrize("id_value,status,ended", [(True, "RUNNING", None), (0, "RUNNING", None),
    (117, "FAILED", None), (117, "RUNNING", "2026-10-13T04:01:00Z")])
def test_fresh_capture_must_be_positive_integer_running_and_open(fixture, id_value, status, ended):
    fixture.result.capture.update(id=id_value, status=status, ended_at=ended)
    with pytest.raises(RuntimeError):
        fixture.m.launch(**fixture.args)
    assert len(fixture.calls) == 1  # pi read-only preflight, no source seal or OS pause.
    assert not dispatches(fixture) and not fixture.seals


def test_source_request_spec_modes_and_fresh_capture_process_are_bound(fixture, capsys):
    result = fixture.m.launch(**fixture.args)
    assert result["status"] == "OBSERVATION_PENDING" and result["rerun"] is False
    assert result["recovery_complete"] is False and len(dispatches(fixture)) == 1
    assert sum(command[0] == "/usr/sbin/runuser" and command[-3] == fixture.m.PI_ARTIFACT
               for command, _ in fixture.calls) == 1
    assert {path.name: mode for path, _, mode in fixture.seals} == {
        "controller.py": 0o555, "request.json": 0o444, "spec.json": 0o400}
    spec = json.loads(next(raw for path, raw, _ in fixture.seals if path.name == "spec.json"))
    assert spec["capture_session"] == fixture.result.capture
    assert spec["capture_session_id"] == 117 and spec["capture_main_pid"] == 123 and spec["capture_main_birth"] == "777"
    assert spec["boot_id"] == "owned-boot" and spec["request_sha256"] == fixture.request["plan_sha256"]
    assert spec["approval_scope"] == "capture-pause-canonical-pair-recovery"
    assert spec["driver_sha256"] == fixture.args["controller_sha256"]
    assert spec["request_file_sha256"] == fixture.args["request_file_sha256"]
    assert (Path(spec["request_file"]).parent / "spec.json") == Path(result["spec_file"])
    assert not Path(result["state_dir"]).exists()
    command = dispatches(fixture)[0]
    for value in ("--property=Type=exec", "--property=RuntimeMaxSec=145",
                  "--property=TimeoutStopSec=3", "--property=KillMode=control-group"):
        assert value in command
    assert command[-3:] == ["--execute", "--spec", result["spec_file"]]
    announced = json.loads(capsys.readouterr().out)
    assert announced["status"] == "DISPATCH_REQUESTED" and announced["token"] == TOKEN


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("owned-systemd-run", 5),
    subprocess.CalledProcessError(1, "owned-systemd-run"), OSError("dispatch response lost")])
def test_uncertain_dispatch_has_identity_and_never_redispatches(fixture, capsys, error):
    fixture.result.dispatch_error = error
    result = fixture.m.launch(**fixture.args)
    assert result["status"] == "DISPATCH_UNCONFIRMED" and result["rerun"] is False
    assert len(dispatches(fixture)) == 1
    before = json.loads(capsys.readouterr().out)
    assert before["state_dir"] == result["state_dir"] and before["spec_file"] == result["spec_file"]
    assert Path(result["spec_file"]).exists()


@pytest.mark.parametrize("previous", ["frozen", "state"])
def test_existing_token_is_not_reset_or_dispatched(fixture, previous):
    fixture.m.BASE.mkdir()
    original = fixture.m.BASE / (("frozen-" if previous == "frozen" else "")+TOKEN)
    original.mkdir()
    evidence = original / "past-evidence.json"
    evidence.write_text("preserve", encoding="utf-8")
    with pytest.raises(RuntimeError, match="One-use"):
        fixture.m.launch(**fixture.args)
    assert evidence.read_text() == "preserve" and not dispatches(fixture) and not fixture.seals


def test_returned_restoration_is_still_not_recovery_completion(fixture, capsys):
    fixture.result.restoration = dict(classification="COMMITTED_VERIFIED", recovery_complete=False,
                                      worker_quiesced=True, held_processing_units=[])
    arguments = ["--execute", "--approve-capture-pause", "--approval-reference", fixture.args["approval_reference"],
        "--request-file", str(fixture.request_file), "--request-file-sha256", fixture.args["request_file_sha256"],
        "--controller-sha256", fixture.args["controller_sha256"], "--wait-seconds", "1"]
    assert fixture.m.main(arguments) == 3
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert rows[0]["status"] == "DISPATCH_REQUESTED"
    assert rows[1]["status"] == "RESTORATION_REPORTED" and rows[1]["recovery_complete"] is False
    assert len(dispatches(fixture)) == 1


def test_seal_uses_exclusive_creation_exact_bytes_and_requested_permission(fixture, monkeypatch):
    modes = []
    monkeypatch.setattr(fixture.m, "os", SimpleNamespace(fchmod=lambda fd, mode: modes.append(mode), fsync=lambda fd: None))
    target = fixture.temp / "new-root-request.json"
    raw = b'{"reviewed":true}\n'
    fixture.original_seal(target, raw, 0o444)
    assert target.read_bytes() == raw and modes == [0o444]
    with pytest.raises(FileExistsError):
        fixture.original_seal(target, b"overwrite", 0o400)
    assert target.read_bytes() == raw and modes == [0o444]


def test_launcher_imports_no_database_and_pi_probe_is_readonly():
    tree = ast.parse(SOURCE.read_text())
    modules = {node.module if isinstance(node, ast.ImportFrom) else alias.name
               for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
               for alias in (node.names if isinstance(node, ast.Import) else [None])}
    assert not modules.intersection({"sqlite3", "sqlalchemy", "backend.app.database"})
    probe = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "PI_CAPTURE" for target in node.targets))
    assert "mode=ro" in probe and "PRAGMA query_only=ON" in probe and "os.getuid()==os.getgid()==1000" in probe
    assert "assert len(rows)==1" in probe
