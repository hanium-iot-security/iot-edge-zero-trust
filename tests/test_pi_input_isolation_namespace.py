"""Disposable namespace contract using fake OS/processes; no network execution."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "infra/scripts/validate_pi_input_isolation.py"
spec = importlib.util.spec_from_file_location("pi_input_namespace_validation", SCRIPT)
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
spec.loader.exec_module(tool)
NAMES = tool.Names("p9pi-a1b2c3d4e5", "p9cl-a1b2c3d4e5", "p9pa1b2c3d4e5", "p9ca1b2c3d4e5")


@pytest.fixture(autouse=True)
def no_real_os_execution(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("Namespace tests must never invoke a real subprocess")
    monkeypatch.setattr(tool.subprocess, "run", refused)
    monkeypatch.setattr(tool.subprocess, "Popen", refused)


class FakeRunner:
    def __init__(self, *, failure=None, collision=False, stop_failure=False, delete_failure=False,
                 cancellation=None, cancel_at=None, changed_host=False, stuck_counters=False):
        self.calls = []
        self.events = []
        self.existing = {NAMES.pi} if collision else {"existing-production-ns"}
        self.ns_ids = {"existing-production-ns": "4:90"}
        self.rules = {}
        self.failure = failure
        self.stop_failure = stop_failure
        self.delete_failure = delete_failure
        self.cancellation = cancellation
        self.cancel_at = cancel_at
        self.child = None
        self.changed_host = changed_host
        self.host_observations = 0
        self.replaced_namespace = False
        self.stuck_counters = stuck_counters

    def prerequisites(self):
        if self.failure == "prerequisites":
            raise tool.ValidationError("FIXED_BINARY_UNAVAILABLE:iptables")

    def run(self, argv, *, env=None, timeout=5):
        self.calls.append((argv.copy(), env))
        if argv[0] == tool.BASH:
            assert env == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HANIUM_FW_DRY_RUN": "1"}
            operation, source, rule_id, scope = argv[2:]
            assert source == tool.SOURCE_A
            assert rule_id == str(tool.LEGACY_ID if scope == tool.LEGACY else tool.WIDE_ID)
            args = tool.expected_rule(operation, scope)
            if self.failure == "wrapper":
                args = ["-F", "INPUT"]
            return SimpleNamespace(returncode=0, stdout="\n".join(args)+"\n")
        assert argv[0] == tool.IP
        if argv[1:4] == ["-j", "link", "show"]:
            self.host_observations += 1
            extra = [{"ifindex": 8, "ifname": "external-change"}] if self.changed_host and self.host_observations > 1 else []
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"ifindex": 1, "ifname": "lo"}]+extra))
        if argv[1:5] == ["-j", "route", "show", "table"]:
            return SimpleNamespace(returncode=0, stdout="[]")
        if argv[1:3] == ["netns", "list"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(self.existing))
        if argv[1:3] == ["netns", "add"]:
            name = argv[3]
            if name in self.existing or (self.failure == "second_namespace" and name == NAMES.client):
                return SimpleNamespace(returncode=1, stdout="")
            self.existing.add(name)
            self.ns_ids[name] = "4:101" if name == NAMES.pi else "4:102"
            if self.cancel_at == "namespace_create":
                self.cancellation.request(None, None)
            return SimpleNamespace(returncode=0, stdout="")
        if argv[1:3] == ["netns", "delete"]:
            name = argv[3]
            self.events.append(f"delete:{name}")
            assert name in (NAMES.pi, NAMES.client) and name in self.existing
            if self.delete_failure:
                return SimpleNamespace(returncode=1, stdout="")
            self.existing.remove(name)
            return SimpleNamespace(returncode=0, stdout="")
        if argv[1] == "-n":
            assert argv[2] in (NAMES.pi, NAMES.client) and argv[2] in self.existing
            if self.failure == "veth" and argv[3:5] == ["link", "add"]:
                return SimpleNamespace(returncode=1, stdout="")
            if self.failure == "address" and argv[3:5] == ["addr", "add"]:
                return SimpleNamespace(returncode=1, stdout="")
            return SimpleNamespace(returncode=0, stdout="")
        assert argv[1:3] == ["netns", "exec"]
        namespace, executable, args = argv[3], argv[4], argv[5:]
        assert namespace in self.existing
        if executable == tool.IPTABLES:
            assert namespace == NAMES.pi
            if args[0] in ("-I", "-C", "-D"):
                scope = tool.WIDE if f"hanium-firewall:{tool.WIDE_ID}" in args else tool.LEGACY
                assert args == tool.expected_rule({"-I":"insert", "-C":"check", "-D":"delete"}[args[0]], scope)
                if self.failure == "iptables" and args[0] == "-I":
                    return SimpleNamespace(returncode=2, stdout="")
                if args[0] == "-I":
                    self.rules[scope] = {"packets":5, "bytes":320} if self.stuck_counters else {"packets":0, "bytes":0}
                elif args[0] == "-D":
                    del self.rules[scope]
                else:
                    return SimpleNamespace(returncode=0 if scope in self.rules else 1, stdout="")
                return SimpleNamespace(returncode=0, stdout="")
            if args == ["-S", "INPUT"]:
                lines = ["-P INPUT ACCEPT"] + ["-A INPUT " + " ".join(tool.expected_rule("check", scope)[2:]) for scope in self.rules]
                return SimpleNamespace(returncode=0, stdout="\n".join(lines))
            assert args == ["-n", "-v", "-x", "-L", "INPUT"]
            lines = [f"{counts['packets']} {counts['bytes']} DROP all -- any any {tool.SOURCE_A} anywhere /* hanium-firewall:{tool.WIDE_ID if scope == tool.WIDE else tool.LEGACY_ID} */" for scope, counts in self.rules.items()]
            return SimpleNamespace(returncode=0, stdout="\n".join(lines))
        assert namespace == NAMES.client
        assert executable == sys.executable
        if args[1] == tool.PING_CODE:
            assert args[0] == "-c" and args[2:4] == [self.ns_ids[NAMES.client], "4:100"]
            source, probe = args[-2], "icmp"
        else:
            assert executable == sys.executable and args[0:2] == ["-c", tool.PROBE_CODE]
            assert args[2:4] == [self.ns_ids[NAMES.client], "4:100"]
            source, target, kind, port, nonce = args[-5:]
            assert target == tool.PI_ADDRESS and len(nonce) == 32
            probe = f"{kind}_{port}"
        blocked = source == tool.SOURCE_A and (tool.WIDE in self.rules or (tool.LEGACY in self.rules and probe == "tcp_1883"))
        if blocked and not self.stuck_counters:
            counts = self.rules[tool.WIDE if tool.WIDE in self.rules else tool.LEGACY]
            counts["packets"] += 1; counts["bytes"] += 64
        reachable = not blocked and self.failure != "probe"
        return SimpleNamespace(returncode=(0 if reachable else 1) if args[1] == tool.PING_CODE else 0,
                               stdout=json.dumps({"reachable":reachable}))

    def identity(self, name=None):
        if self.replaced_namespace and name == NAMES.client:
            return "4:999"
        return self.ns_ids[name] if name else "4:100"

    def start_server(self, argv):
        self.events.append("start")
        assert argv[:4] == [tool.IP,"netns","exec",NAMES.pi]
        assert argv[5:8] == ["-u","-c",tool.SERVER_CODE]
        assert argv[8:] == [self.ns_ids[NAMES.pi],"4:100",tool.PI_ADDRESS]
        self.child = SimpleNamespace(pid=4242)
        if self.cancel_at == "server_create":
            self.cancellation.request(None, None)
        return self.child

    def ready(self, child, timeout=4):
        if self.failure == "readiness":
            raise tool.ValidationError("SERVER_READINESS_TIMEOUT")

    def stop_server(self, child):
        assert child is self.child
        self.events.append("stop")
        if self.cancellation:
            self.cancellation.request(None, None)
            self.cancellation.request(None, None)
        if self.stop_failure:
            raise tool.ValidationError("SERVER_NOT_REAPED")


def test_default_and_explicit_dry_run_never_execute_os(capsys):
    for args in ([], ["--dry-run"], ["--confirm", tool.CONFIRM]):
        assert tool.main(args) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "DRY_RUN" and not report["executed"]
        assert "privileged_wrapper_protection" in report["not_verified"]
    assert tool.main(["--execute"]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "EXACT_CONFIRMATION_REQUIRED"


@pytest.mark.parametrize("confirm,platform,uid,error", [
    ("", "linux", 0, "EXACT_CONFIRMATION_REQUIRED"),
    (tool.CONFIRM.lower(), "linux", 0, "EXACT_CONFIRMATION_REQUIRED"),
    (tool.CONFIRM, "win32", 0, "LINUX_REQUIRED"),
    (tool.CONFIRM, "linux", 1000, "ROOT_REQUIRED"),
])
def test_execute_authorization_is_explicit(confirm, platform, uid, error):
    with pytest.raises(tool.ValidationError, match=error):
        tool.authorize_execute(confirm, platform=platform, euid=uid)
    tool.authorize_execute(tool.CONFIRM, platform="linux", euid=0)


def test_all_stages_and_both_exact_release_directions_preserve_control():
    runner = FakeRunner()
    report = tool.Harness(runner=runner, names=NAMES).run()
    assert report["status"] == "PASS" and report["remaining_owned_namespaces"] == []
    assert report["host_links_routes_unchanged"]
    assert report["server_reaped"] and report["server_pid"] == 4242
    stages = {stage["name"]: stage for stage in report["stages"]}
    assert set(stages) == set(tool.plan(NAMES)["stages"])
    for stage in stages.values():
        assert all(stage["probes"][tool.SOURCE_B].values())
    assert not stages["release_wide_preserve_legacy"]["probes"][tool.SOURCE_A]["tcp_1883"]
    assert stages["release_wide_preserve_legacy"]["probes"][tool.SOURCE_A]["udp_9002"]
    assert not any(stages["release_legacy_preserve_wide"]["probes"][tool.SOURCE_A].values())
    assert all(stages["restored"]["probes"][tool.SOURCE_A].values())
    assert runner.events[-3:] == ["stop", f"delete:{NAMES.client}", f"delete:{NAMES.pi}"]
    assert runner.existing == {"existing-production-ns"}


def test_every_modification_is_inside_owned_namespaces_and_no_host_iptables():
    runner = FakeRunner()
    assert tool.Harness(runner=runner, names=NAMES).run()["status"] == "PASS"
    commands = [argv for argv, env in runner.calls]
    veth = next(argv for argv in commands if "veth" in argv)
    assert veth == [tool.IP,"-n",NAMES.pi,"link","add",NAMES.pi_link,"type","veth","peer","name",NAMES.client_link,"netns",NAMES.client]
    for argv in commands:
        assert "sudo" not in argv and "-F" not in argv and "-P" not in argv
        if tool.IPTABLES in argv:
            assert argv[:5] == [tool.IP,"netns","exec",NAMES.pi,tool.IPTABLES]
        if "addr" in argv or ("link" in argv and "-j" not in argv):
            assert argv[:3] in ([tool.IP,"-n",NAMES.pi], [tool.IP,"-n",NAMES.client])
        if argv[0] == tool.IP and argv[1] == "netns" and argv[2] in ("add", "delete"):
            assert argv[3] in (NAMES.pi,NAMES.client)


@pytest.mark.parametrize("failure", ["second_namespace","veth","address","readiness","probe","iptables","wrapper"])
def test_failure_cleans_only_created_namespaces_and_own_server(failure):
    runner = FakeRunner(failure=failure)
    report = tool.Harness(runner=runner, names=NAMES).run()
    assert report["status"] == "FAIL"
    assert report["cleanup_errors"] == [] and report["remaining_owned_namespaces"] == []
    assert runner.existing == {"existing-production-ns"}
    if failure == "second_namespace":
        assert runner.events == [f"delete:{NAMES.pi}"]
    if "start" in runner.events:
        assert runner.events.index("stop") < next(index for index, event in enumerate(runner.events) if event.startswith("delete:"))


def test_existing_name_collision_is_never_deleted():
    runner = FakeRunner(collision=True)
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["error_code"] == "NAMESPACE_NAME_COLLISION"
    assert runner.events == [] and runner.existing == {NAMES.pi}


def test_missing_fixed_dependency_refuses_before_any_namespace_command():
    runner = FakeRunner(failure="prerequisites")
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["status"] == "FAIL" and report["error_code"] == "FIXED_BINARY_UNAVAILABLE:iptables"
    assert runner.calls == [] and runner.events == []


def test_previous_positive_counter_does_not_substitute_for_new_drop_observation():
    runner = FakeRunner(stuck_counters=True)
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["status"] == "FAIL" and report["error_code"] == "DROP_COUNTER_DID_NOT_ADVANCE"
    assert report["remaining_owned_namespaces"] == []


@pytest.mark.parametrize("stop_failure,delete_failure", [(True,False), (False,True)])
def test_cleanup_failure_cannot_be_pass_or_delete_unknown_live_server_namespace(stop_failure, delete_failure):
    runner = FakeRunner(stop_failure=stop_failure,delete_failure=delete_failure)
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["status"] == "FAIL" and report["cleanup_errors"]
    assert set(report["remaining_owned_namespaces"]) == {NAMES.pi,NAMES.client}
    if stop_failure:
        assert not any(event.startswith("delete:") for event in runner.events)


@pytest.mark.parametrize("cancel_at", ["namespace_create", "server_create"])
def test_signal_after_success_creation_is_recorded_then_cleaned_even_with_repeat_cleanup_signal(cancel_at):
    cancellation = tool.Cancellation()
    runner = FakeRunner(cancellation=cancellation,cancel_at=cancel_at)
    report = tool.Harness(runner=runner,names=NAMES,cancelled=lambda:cancellation.requested).run()
    assert report["status"] == "FAIL" and report["error_code"] == "CANCELLED"
    assert report["remaining_owned_namespaces"] == [] and report["cleanup_errors"] == []
    assert runner.existing == {"existing-production-ns"}
    assert f"delete:{NAMES.pi}" in runner.events
    if cancel_at == "server_create":
        assert runner.events[-3:] == ["stop",f"delete:{NAMES.client}",f"delete:{NAMES.pi}"]


def test_changed_namespace_identity_is_never_deleted_as_owned():
    runner = FakeRunner()
    harness = tool.Harness(runner=runner,names=NAMES)
    harness.create()
    runner.replaced_namespace = True
    with pytest.raises(tool.ValidationError,match="IDENTITY_CHANGED"):
        harness.namespace_command(NAMES.client,["link","set","lo","up"])
    harness.cleanup()
    assert harness.owned == [NAMES.client]
    assert f"delete:{NAMES.client}" not in runner.events
    assert harness.report["cleanup_errors"] == [f"OWNED_NAMESPACE_DELETE_FAILED:{NAMES.client}"]


def test_host_observation_change_reports_failure_without_repair():
    runner = FakeRunner(changed_host=True)
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["status"] == "FAIL" and not report["host_links_routes_unchanged"]
    assert "HOST_NETWORK_OBSERVATION_CHANGED_NO_AUTO_RESTORE" in report["cleanup_errors"]
    assert runner.existing == {"existing-production-ns"}


@pytest.mark.parametrize("program", [tool.SERVER_CODE,tool.PROBE_CODE,tool.PING_CODE])
@pytest.mark.parametrize("expected", ["1:7", "1:8"])
def test_socket_program_refuses_host_or_wrong_namespace_before_socket(monkeypatch, program, expected):
    monkeypatch.setattr(tool.os,"stat",lambda path:SimpleNamespace(st_dev=1,st_ino=7))
    monkeypatch.setattr(sys,"argv",["-c",expected,"1:7",tool.PI_ADDRESS])
    with pytest.raises(SystemExit) as error:
        exec(program,{})
    assert error.value.code == 77


def test_socket_probes_require_echo_and_correct_udp_peer():
    assert "response == message" in tool.PROBE_CODE
    assert "peer != (target, int(port))" in tool.PROBE_CODE
    assert "sock.bind((source, 0))" in tool.PROBE_CODE


@pytest.mark.parametrize("operation,worker_operation", [("check","-C"),("insert","-I"),("delete","-D")])
@pytest.mark.parametrize("scope", [tool.LEGACY,tool.WIDE])
def test_standalone_match_agrees_with_existing_worker_contract(operation, worker_operation, scope):
    from edge.trust.firewall_worker import FirewallRuleSpec, build_rule_args
    rule_id = tool.LEGACY_ID if scope == tool.LEGACY else tool.WIDE_ID
    assert tool.expected_rule(operation,scope) == build_rule_args(FirewallRuleSpec(rule_id,tool.SOURCE_A,scope),operation=worker_operation)


def test_unknown_resources_operations_and_scopes_rejected_without_os():
    runner = FakeRunner()
    harness = tool.Harness(runner=runner,names=NAMES)
    with pytest.raises(tool.ValidationError,match="UNOWNED_NAMESPACE"):
        harness.namespace_exec("existing-production-ns",tool.IPTABLES,["-F","INPUT"])
    for operation,scope in (("flush",tool.WIDE),("insert","ALL")):
        with pytest.raises(ValueError):
            tool.expected_rule(operation,scope)
    with pytest.raises(ValueError):
        tool.Names("../../host",NAMES.client,NAMES.pi_link,NAMES.client_link)
    assert runner.calls == []


def test_owned_child_is_terminated_killed_and_reaped_with_bounded_waits():
    calls = []
    class Child:
        returncode = None
        stdout = None
        def poll(self): return self.returncode
        def terminate(self): calls.append("terminate")
        def kill(self): calls.append("kill")
        def wait(self,timeout):
            calls.append(("wait",timeout))
            if calls.count(("wait",timeout)) == 1:
                raise subprocess.TimeoutExpired("fake",timeout)
            self.returncode = -9
    tool.SystemRunner().stop_server(Child())
    assert calls == ["terminate",("wait",2),"kill",("wait",2)]


def test_os_command_is_detached_from_terminal_signal_group_and_has_timeout(monkeypatch):
    calls = []
    def capture(argv,**kwargs):
        calls.append((argv,kwargs))
        return SimpleNamespace(returncode=0,stdout="")
    monkeypatch.setattr(tool.subprocess,"run",capture)
    tool.SystemRunner().run([tool.IP,"netns","list"])
    assert calls == [([tool.IP,"netns","list"], {
        "env":None,"capture_output":True,"text":True,"timeout":5,
        "check":False,"start_new_session":True,
    })]


def test_peer_namespace_inode_is_verified_before_veth_creation():
    runner = FakeRunner()
    original_identity = runner.identity
    client_reads = 0
    def changed_peer(name=None):
        nonlocal client_reads
        if name == NAMES.client:
            client_reads += 1
            if client_reads > 1:
                return "4:999"
        return original_identity(name)
    runner.identity = changed_peer
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["error_code"] == "OWNED_NAMESPACE_IDENTITY_CHANGED"
    assert not any("veth" in argv for argv,env in runner.calls)
    assert NAMES.client in report["remaining_owned_namespaces"]
    assert f"delete:{NAMES.client}" not in runner.events


def test_uncertain_namespace_creation_is_reported_not_adopted_or_deleted():
    runner = FakeRunner()
    original_run = runner.run
    def timeout_after_creation(argv,**kwargs):
        result = original_run(argv,**kwargs)
        if argv == [tool.IP,"netns","add",NAMES.client]:
            raise subprocess.TimeoutExpired(argv,5)
        return result
    runner.run = timeout_after_creation
    report = tool.Harness(runner=runner,names=NAMES).run()
    assert report["status"] == "FAIL" and report["error_code"] == "TimeoutExpired"
    assert report["unconfirmed_namespace_creations"] == [NAMES.client]
    assert f"delete:{NAMES.client}" not in runner.events
    assert runner.existing == {"existing-production-ns",NAMES.client}
