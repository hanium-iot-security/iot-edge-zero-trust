#!/usr/bin/env python3
"""Opt-in, disposable Linux namespace test; default invocation makes no OS calls.

This validates packet behavior of Wrapper dry-run matches inside newly owned
namespaces. It does not exercise privileged Wrapper installation or Worker/DB.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
from uuid import uuid4

IP = "/usr/sbin/ip"
IPTABLES = "/usr/sbin/iptables"
PING = "/usr/bin/ping"
BASH = "/bin/bash"
CONFIRM = "CREATE-DISPOSABLE-PI-INPUT-NAMESPACES"
LEGACY = "MQTT_IPV4_TCP_1883"
WIDE = "PI_INPUT_IPV4_ALL"
PI_ADDRESS = "10.253.94.1"
SOURCE_A = "10.253.94.2"
SOURCE_B = "10.253.94.3"
LEGACY_ID = 91001
WIDE_ID = 91002
TCP_PORTS = (1883, 9001, 22)
UDP_PORT = 9002
PROBES = ("tcp_1883", "tcp_9001", "tcp_22", "udp_9002", "icmp")
WRAPPER = Path(__file__).resolve().with_name("hanium-firewall-rule")

# These programs have no direct CLI entry point. Before opening a socket they
# prove that ip netns exec placed them in the parent's owned, non-host namespace.
NAMESPACE_GUARD = """
import os, sys
identity = lambda path: ':'.join(str(x) for x in (os.stat(path).st_dev, os.stat(path).st_ino))
if identity('/proc/self/ns/net') != sys.argv[1] or sys.argv[1] == sys.argv[2]:
    sys.exit(77)
"""
SERVER_CODE = NAMESPACE_GUARD + """
import socket, threading
address = sys.argv[3]
sockets = []
def tcp_server(sock):
    while True:
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(2)
            try:
                message = conn.recv(128)
                conn.sendall(message)
            except OSError:
                pass
def udp_server(sock):
    while True:
        message, peer = sock.recvfrom(128)
        sock.sendto(message, peer)
for port in (1883, 9001, 22):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port)); sock.listen(16); sockets.append(sock)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((address, 9002)); sockets.append(sock)
for sock in sockets:
    threading.Thread(target=tcp_server if sock.type == socket.SOCK_STREAM else udp_server,
                     args=(sock,), daemon=True).start()
print('READY', flush=True)
threading.Event().wait()
"""
PROBE_CODE = NAMESPACE_GUARD + """
import json, socket
source, target, kind, port, nonce = sys.argv[3:]
message = nonce.encode('ascii')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM)
sock.settimeout(0.5)
sock.bind((source, 0))
reachable = False
try:
    if kind == 'tcp':
        sock.connect((target, int(port))); sock.sendall(message)
        response = sock.recv(128)
    else:
        sock.sendto(message, (target, int(port)))
        response, peer = sock.recvfrom(128)
        if peer != (target, int(port)):
            raise RuntimeError('unexpected UDP peer')
    reachable = response == message
except (TimeoutError, ConnectionRefusedError):
    pass
finally:
    sock.close()
print(json.dumps({'reachable': reachable}))
"""
PING_CODE = NAMESPACE_GUARD + """
os.execv('/usr/bin/ping', ['/usr/bin/ping', '-n', '-c', '1', '-W', '1',
                         '-I', sys.argv[3], sys.argv[4]])
"""


class ValidationError(RuntimeError):
    pass


class Cancellation:
    """Signals set a flag; creation receipts and cleanup are never interrupted."""
    requested = False

    def request(self, signum, frame):
        self.requested = True


@dataclass(frozen=True)
class Names:
    pi: str
    client: str
    pi_link: str
    client_link: str

    @classmethod
    def fresh(cls):
        token = uuid4().hex[:10]
        return cls(f"p9pi-{token}", f"p9cl-{token}", f"p9p{token}", f"p9c{token}")

    def __post_init__(self):
        if (not re.fullmatch(r"p9pi-[a-f0-9]{10}", self.pi)
                or not re.fullmatch(r"p9cl-[a-f0-9]{10}", self.client)
                or not re.fullmatch(r"p9p[a-f0-9]{10}", self.pi_link)
                or not re.fullmatch(r"p9c[a-f0-9]{10}", self.client_link)
                or len({value[-10:] for value in (self.pi, self.client, self.pi_link, self.client_link)}) != 1):
            raise ValueError("invalid owned resource names")


def expected_rule(operation, scope):
    if operation not in ("check", "insert", "delete") or scope not in (LEGACY, WIDE):
        raise ValueError("unsupported fixed rule operation")
    rule_id = LEGACY_ID if scope == LEGACY else WIDE_ID
    match = ["-s", SOURCE_A, "-m", "comment", "--comment", f"hanium-firewall:{rule_id}", "-j", "DROP"]
    if scope == LEGACY:
        match = ["-p", "tcp", "-s", SOURCE_A, "--dport", "1883", *match[2:]]
    prefix = {"check": ["-C", "INPUT"], "insert": ["-I", "INPUT", "1"], "delete": ["-D", "INPUT"]}[operation]
    return prefix + match


def plan(names=None):
    names = names or Names.fresh()
    return {
        "schema_version": "pi-input-namespace-validation-v1", "status": "DRY_RUN",
        "executed": False, "namespaces": {"pi": names.pi, "client": names.client},
        "interfaces": {"pi": names.pi_link, "client": names.client_link},
        "addresses": {"pi": PI_ADDRESS, "isolated_a": SOURCE_A, "control_b": SOURCE_B},
        "probes": list(PROBES), "confirm_required": CONFIRM,
        "stages": ["baseline", "legacy", "wide", "release_wide_preserve_legacy",
                   "wide_again", "release_legacy_preserve_wide", "restored"],
        "not_verified": ["privileged_wrapper_protection", "sudoers", "worker_approval_and_db",
                         "physical_devices", "dhcp", "reboot", "host_input_rules"],
    }


def authorize_execute(confirm, *, platform=None, euid=None):
    if confirm != CONFIRM:
        raise ValidationError("EXACT_CONFIRMATION_REQUIRED")
    if (platform or sys.platform) != "linux":
        raise ValidationError("LINUX_REQUIRED")
    uid = euid if euid is not None else (os.geteuid() if hasattr(os, "geteuid") else -1)
    if uid != 0:
        raise ValidationError("ROOT_REQUIRED")


class SystemRunner:
    def prerequisites(self):
        for path in (IP, IPTABLES, PING, BASH, sys.executable):
            if not Path(path).is_file() or not os.access(path, os.X_OK):
                raise ValidationError(f"FIXED_BINARY_UNAVAILABLE:{Path(path).name}")
        if not WRAPPER.is_file() or WRAPPER.is_symlink():
            raise ValidationError("WRAPPER_SOURCE_UNAVAILABLE")

    def run(self, argv, *, env=None, timeout=5):
        return subprocess.run(argv, env=env, capture_output=True, text=True,
                              timeout=timeout, check=False, start_new_session=True)

    def identity(self, name=None):
        value = os.stat(f"/var/run/netns/{name}" if name else "/proc/self/ns/net")
        return f"{value.st_dev}:{value.st_ino}"

    def start_server(self, argv):
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True)

    def ready(self, child, timeout=4):
        if not select.select([child.stdout], [], [], timeout)[0]:
            raise ValidationError("SERVER_READINESS_TIMEOUT")
        if os.read(child.stdout.fileno(), 64) != b"READY\n":
            raise ValidationError("SERVER_START_FAILED")

    def stop_server(self, child):
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
        if child.poll() is None:
            raise ValidationError("SERVER_NOT_REAPED")
        if child.stdout is not None:
            child.stdout.close()


class Harness:
    def __init__(self, *, runner=None, names=None, cancelled=None):
        self.runner = runner or SystemRunner()
        self.names = names or Names.fresh()
        self.owned = []
        self.child = None
        self.host_identity = None
        self.identities = {}
        self.cancelled = cancelled or (lambda: False)
        self.report = plan(self.names)
        self.report.update(status="RUNNING", executed=True, stages=[], cleanup_errors=[], unconfirmed_namespace_creations=[])

    def command(self, argv, *, allowed=(0,), env=None, cancellable=True):
        if cancellable and self.cancelled():
            raise ValidationError("CANCELLED")
        result = self.runner.run(argv, env=env)
        if result.returncode not in allowed:
            raise ValidationError(f"COMMAND_FAILED_{result.returncode}")
        return result

    def require_owned_identity(self, name):
        if name not in self.owned or name not in self.identities:
            raise ValidationError("UNOWNED_NAMESPACE")
        if self.runner.identity(name) != self.identities[name]:
            raise ValidationError("OWNED_NAMESPACE_IDENTITY_CHANGED")

    def namespace_command(self, name, args):
        self.require_owned_identity(name)
        return self.command([IP, "-n", name, *args])

    def namespace_exec(self, name, executable, args, *, allowed=(0,)):
        self.require_owned_identity(name)
        return self.command([IP, "netns", "exec", name, executable, *args], allowed=allowed)

    def host_snapshot(self, *, cancellable=True):
        # Read only; never enumerate/flush/change host INPUT rules. Compare stable
        # link/route fields so a DHCP lifetime countdown is not a false change.
        links = json.loads(self.command([IP, "-j", "link", "show"], cancellable=cancellable).stdout)
        routes = json.loads(self.command([IP, "-j", "route", "show", "table", "all"], cancellable=cancellable).stdout)
        if not isinstance(links, list) or not isinstance(routes, list):
            raise ValidationError("HOST_SNAPSHOT_INVALID")
        link_fields = ("ifindex", "ifname", "address", "mtu", "link_type", "master")
        route_fields = ("dst", "gateway", "dev", "table", "type", "protocol", "scope", "prefsrc", "metric")
        snapshot = {"links": sorted(( {k: row[k] for k in link_fields if k in row} for row in links), key=lambda x: json.dumps(x, sort_keys=True)),
                    "routes": sorted(( {k: row[k] for k in route_fields if k in row} for row in routes), key=lambda x: json.dumps(x, sort_keys=True))}
        return hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()

    def create(self):
        existing = self.command([IP, "netns", "list"]).stdout
        if {self.names.pi, self.names.client} & {line.split()[0] for line in existing.splitlines() if line.strip()}:
            raise ValidationError("NAMESPACE_NAME_COLLISION")
        self.host_identity = self.runner.identity()
        for name in (self.names.pi, self.names.client):
            if self.cancelled():
                raise ValidationError("CANCELLED")
            print(json.dumps({"event": "NAMESPACE_CREATE_REQUESTED", "namespace": name}), file=sys.stderr, flush=True)
            try:
                # Defer cancellation through command completion and the receipt.
                # A timeout/nonzero response is ambiguous and never auto-adopted.
                self.command([IP, "netns", "add", name], cancellable=False)
            except Exception:
                self.report["unconfirmed_namespace_creations"].append(name)
                raise
            self.owned.append(name)  # Only successful creations grant deletion authority.
            print(json.dumps({"event": "OWNED_NAMESPACE_CREATED", "namespace": name}), file=sys.stderr, flush=True)
            identity = self.runner.identity(name)
            if identity == self.host_identity or identity in self.identities.values():
                raise ValidationError("NAMESPACE_IDENTITY_INVALID")
            self.identities[name] = identity
        self.require_owned_identity(self.names.client)
        self.namespace_command(self.names.pi, ["link", "add", self.names.pi_link, "type", "veth", "peer", "name", self.names.client_link, "netns", self.names.client])
        for name, link, addresses in ((self.names.pi, self.names.pi_link, [PI_ADDRESS]), (self.names.client, self.names.client_link, [SOURCE_A, SOURCE_B])):
            self.namespace_command(name, ["link", "set", "lo", "up"])
            for address in addresses:
                self.namespace_command(name, ["addr", "add", f"{address}/24", "dev", link])
            self.namespace_command(name, ["link", "set", link, "up"])
        argv = [IP, "netns", "exec", self.names.pi, sys.executable, "-u", "-c", SERVER_CODE,
                self.identities[self.names.pi], self.host_identity, PI_ADDRESS]
        self.child = self.runner.start_server(argv)
        print(json.dumps({"event": "OWNED_SERVER_STARTED", "pid": self.child.pid, "namespace": self.names.pi}), file=sys.stderr, flush=True)
        if self.cancelled():
            raise ValidationError("CANCELLED")
        self.runner.ready(self.child)

    def wrapper_match(self, operation, scope):
        rule_id = LEGACY_ID if scope == LEGACY else WIDE_ID
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HANIUM_FW_DRY_RUN": "1"}
        result = self.command([BASH, str(WRAPPER), operation, SOURCE_A, str(rule_id), scope], env=env)
        args = result.stdout.splitlines()
        if args != expected_rule(operation, scope):
            raise ValidationError("WRAPPER_DRY_RUN_MATCH_MISMATCH")
        return args

    def firewall(self, operation, scope):
        args = self.wrapper_match(operation, scope)
        return self.namespace_exec(self.names.pi, IPTABLES, args, allowed=(0, 1) if operation == "check" else (0,))

    def counters(self, scopes):
        # Count/list are also confined to the owned Pi namespace.
        rules = self.namespace_exec(self.names.pi, IPTABLES, ["-S", "INPUT"]).stdout
        ids = [int(value) for value in re.findall(r"--comment \"?hanium-firewall:(\d+)", rules)]
        expected_ids = {LEGACY_ID if scope == LEGACY else WIDE_ID for scope in scopes}
        if set(ids) != expected_ids or len(ids) != len(expected_ids) or sum(line.startswith("-A ") for line in rules.splitlines()) != len(ids):
            raise ValidationError("UNEXPECTED_NAMESPACE_RULES")
        if any(self.firewall("check", scope).returncode != 0 for scope in scopes):
            raise ValidationError("EXACT_SCOPED_RULE_MISSING")
        listing = self.namespace_exec(self.names.pi, IPTABLES, ["-n", "-v", "-x", "-L", "INPUT"]).stdout
        result = {}
        for line in listing.splitlines():
            match = re.search(r"/\* hanium-firewall:(\d+) \*/", line)
            if match:
                fields = line.split()
                if not fields[0].isdigit() or not fields[1].isdigit():
                    raise ValidationError("COUNTER_FORMAT_INVALID")
                result[int(match[1])] = {"packets": int(fields[0]), "bytes": int(fields[1])}
        if set(result) != expected_ids:
            raise ValidationError("COUNTER_RULES_MISMATCH")
        return result

    def probe(self, source, probe):
        if source not in (SOURCE_A, SOURCE_B) or probe not in PROBES:
            raise ValidationError("UNKNOWN_PROBE")
        if probe == "icmp":
            result = self.namespace_exec(self.names.client, sys.executable, ["-c", PING_CODE,
                self.identities[self.names.client], self.host_identity, source, PI_ADDRESS], allowed=(0, 1))
            return result.returncode == 0
        kind, port = probe.split("_")
        result = self.namespace_exec(self.names.client, sys.executable, ["-c", PROBE_CODE,
            self.identities[self.names.client], self.host_identity, source, PI_ADDRESS, kind, port, uuid4().hex])
        data = json.loads(result.stdout)
        if not isinstance(data, dict) or type(data.get("reachable")) is not bool:
            raise ValidationError("PROBE_RESULT_INVALID")
        return data["reachable"]

    def stage(self, name, scopes):
        before_counters = self.counters(scopes)
        observations = {}
        for source in (SOURCE_A, SOURCE_B):
            observations[source] = {}
            for probe in PROBES:
                expected = source == SOURCE_B or (WIDE not in scopes and (LEGACY not in scopes or probe != "tcp_1883"))
                actual = self.probe(source, probe)
                observations[source][probe] = actual
                if actual != expected:
                    raise ValidationError(f"PROBE_EXPECTATION_FAILED_{name}_{probe}")
        counters = self.counters(scopes)
        blocking_scope = WIDE if WIDE in scopes else LEGACY if LEGACY in scopes else None
        if blocking_scope:
            rule_id = WIDE_ID if blocking_scope == WIDE else LEGACY_ID
            if (counters[rule_id]["packets"] <= before_counters[rule_id]["packets"]
                    or counters[rule_id]["bytes"] <= before_counters[rule_id]["bytes"]):
                raise ValidationError("DROP_COUNTER_DID_NOT_ADVANCE")
        self.report["stages"].append({"name": name, "probes": observations, "rule_counters": counters})

    def cleanup(self):
        if self.child is not None:
            try:
                self.runner.stop_server(self.child)
                self.report["server_reaped"] = True
            except Exception:
                self.report["server_reaped"] = False
                self.report["cleanup_errors"].append("SERVER_TERMINATE_OR_REAP_FAILED")
                # A live/unknown child can keep a deleted namespace alive. Keep
                # its named namespace for an explicit, identifiable manual check.
                return
        for name in reversed(self.owned.copy()):
            try:
                self.require_owned_identity(name)
                self.command([IP, "netns", "delete", name], cancellable=False)
                self.owned.remove(name)
            except Exception:
                self.report["cleanup_errors"].append(f"OWNED_NAMESPACE_DELETE_FAILED:{name}")

    def run(self):
        before = None
        try:
            self.runner.prerequisites()
            before = self.host_snapshot()
            self.report["host_network_before_sha256"] = before
            self.report["wrapper_sha256"] = hashlib.sha256(WRAPPER.read_bytes()).hexdigest()
            self.create()
            self.stage("baseline", set())
            self.firewall("insert", LEGACY); self.stage("legacy", {LEGACY})
            self.firewall("insert", WIDE); self.stage("wide", {LEGACY, WIDE})
            self.firewall("delete", WIDE); self.stage("release_wide_preserve_legacy", {LEGACY})
            self.firewall("insert", WIDE); self.stage("wide_again", {LEGACY, WIDE})
            self.firewall("delete", LEGACY); self.stage("release_legacy_preserve_wide", {WIDE})
            self.firewall("delete", WIDE); self.stage("restored", set())
            if hashlib.sha256(WRAPPER.read_bytes()).hexdigest() != self.report["wrapper_sha256"]:
                raise ValidationError("WRAPPER_SOURCE_CHANGED")
            self.report["status"] = "PASS"
        except (Exception, KeyboardInterrupt) as exc:
            self.report["status"] = "FAIL"
            self.report["error_code"] = str(exc) if isinstance(exc, ValidationError) else type(exc).__name__
        finally:
            self.cleanup()
            self.report["remaining_owned_namespaces"] = self.owned.copy()
            self.report["namespace_identities"] = self.identities.copy()
            self.report["server_pid"] = self.child.pid if self.child is not None else None
            if before is not None:
                try:
                    after = self.host_snapshot(cancellable=False)
                    self.report["host_network_after_sha256"] = after
                    self.report["host_links_routes_unchanged"] = before == after
                    if before != after:
                        self.report["cleanup_errors"].append("HOST_NETWORK_OBSERVATION_CHANGED_NO_AUTO_RESTORE")
                except Exception:
                    self.report["cleanup_errors"].append("HOST_AFTER_OBSERVATION_UNAVAILABLE")
            if self.report["cleanup_errors"]:
                self.report["status"] = "FAIL"
        return self.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps(plan(), sort_keys=True, indent=2))
        return 0
    try:
        authorize_execute(args.confirm)
    except ValidationError as exc:
        print(json.dumps({"status": "REFUSED", "executed": False, "error_code": str(exc)}))
        return 2
    old_handlers = {}
    cancellation = Cancellation()
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, cancellation.request)
        report = Harness(cancelled=lambda: cancellation.requested).run()
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
