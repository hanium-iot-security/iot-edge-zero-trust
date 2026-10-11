"""root 소유 Firewall Rule Wrapper 테스트.

운영 환경에서는 이 Wrapper가 실제 Rule 규격을 조립합니다. Python의
`build_rule_args()`와 규격이 어긋나면 "적용은 됐는데 확인·삭제가 안 되는" 상태가
생기므로, 두 구현이 같은 인자를 만드는지 직접 비교합니다.

Wrapper는 `HANIUM_FW_DRY_RUN=1`에서 조립된 iptables 인자만 출력하고 실행하지 않으므로
root 권한 없이 검증할 수 있습니다.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from edge.trust.firewall_worker import (
    CHECK,
    DELETE,
    INSERT,
    FirewallRuleSpec,
    build_rule_args,
)
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL


WRAPPER = Path("infra/scripts/hanium-firewall-rule")
DEVICE_IP = "192.168.0.5"
RULE_ID = 12
_GIT_BASH = Path("C:/Program Files/Git/bin/bash.exe")
BASH = str(_GIT_BASH) if os.name == "nt" and _GIT_BASH.is_file() else shutil.which("bash")

pytestmark = pytest.mark.skipif(
    BASH is None, reason="bash가 없는 환경에서는 Wrapper를 검증할 수 없습니다"
)


def _run_wrapper(*args: str, env_overrides=None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, HANIUM_FW_DRY_RUN="1")
    env.update(HANIUM_FW_TEST_PROTECTED_FILE="", HANIUM_FW_TEST_LOCAL_IPV4="")
    env.update(env_overrides or {})
    return subprocess.run(
        # Use the executable we checked; Windows may otherwise resolve the WSL
        # launcher from System32 before the Bash selected through PATH.
        [BASH, WRAPPER.as_posix(), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _wrapper_args(*args: str) -> list[str]:
    result = _run_wrapper(*args)
    assert result.returncode == 0, result.stderr
    return result.stdout.split("\n")[:-1] if result.stdout.endswith("\n") else result.stdout.split("\n")


@pytest.mark.parametrize(
    ("wrapper_operation", "python_operation"),
    [("check", CHECK), ("insert", INSERT), ("delete", DELETE)],
)
def test_wrapper_builds_the_same_specification_as_python(wrapper_operation, python_operation):
    spec = FirewallRuleSpec(rule_id=RULE_ID, source_ip=DEVICE_IP)
    assert _wrapper_args(wrapper_operation, DEVICE_IP, str(RULE_ID)) == build_rule_args(
        spec, operation=python_operation
    )


def test_wrapper_inserts_at_the_top_of_input_chain():
    assert _wrapper_args("insert", DEVICE_IP, str(RULE_ID))[:3] == ["-I", "INPUT", "1"]


def test_wrapper_list_only_reads_input_chain():
    assert _wrapper_args("list") == ["-S", "INPUT"]


@pytest.mark.parametrize(
    "source_ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "169.254.10.20",
        "256.1.1.1",
        "192.168.0",
        "not-an-ip",
        "192.168.0.5; rm -rf /",
    ],
)
def test_wrapper_rejects_non_private_or_malformed_ip(source_ip):
    result = _run_wrapper("insert", source_ip, str(RULE_ID))
    assert result.returncode == 65
    assert "iptables" not in result.stdout


@pytest.mark.parametrize("rule_id", ["abc", "-1", "1;2", "", "0", "01", "9223372036854775808"])
def test_wrapper_rejects_invalid_rule_id(rule_id):
    result = _run_wrapper("insert", DEVICE_IP, rule_id)
    assert result.returncode == 65


@pytest.mark.parametrize(
    "args",
    [
        ("flush",),
        ("insert",),
        ("insert", DEVICE_IP),
        ("list", "extra"),
        ("-F",),
        ("insert", DEVICE_IP, "12", "--dport", "22"),
    ],
)
def test_wrapper_rejects_unsupported_invocations(args):
    result = _run_wrapper(*args)
    assert result.returncode == 64


def test_wrapper_cannot_change_chain_port_or_target():
    """호출자가 무엇을 넘기든 Chain·Port·Target은 Wrapper가 고정한다."""
    args = _wrapper_args("insert", "10.0.0.7", "99")
    assert args[1] == "INPUT"
    assert "--dport" in args and args[args.index("--dport") + 1] == "1883"
    assert args[-2:] == ["-j", "DROP"]
    assert args[args.index("--comment") + 1] == "hanium-firewall:99"


@pytest.mark.parametrize("source_ip", ["10.0.0.7", "172.16.5.9", "192.168.1.20"])
def test_wrapper_accepts_all_private_ipv4_ranges(source_ip):
    args = _wrapper_args("insert", source_ip, "1")
    assert args[args.index("-s") + 1] == source_ip


def test_wrapper_is_executable():
    assert os.access(WRAPPER, os.X_OK), "Wrapper에 실행 권한이 필요합니다"


@pytest.mark.parametrize("operation,python_operation", [("check", CHECK), ("insert", INSERT), ("delete", DELETE)])
def test_wide_scope_exact_match_has_no_protocol_or_port(operation, python_operation):
    spec = FirewallRuleSpec(RULE_ID, DEVICE_IP, PI_INPUT_IPV4_ALL)
    assert _wrapper_args(operation, DEVICE_IP, str(RULE_ID), PI_INPUT_IPV4_ALL) == build_rule_args(spec, operation=python_operation)
    assert "--dport" not in build_rule_args(spec, operation=python_operation)
    assert "-p" not in build_rule_args(spec, operation=python_operation)


@pytest.mark.parametrize("scope", ["", "ALL", "PI_INPUT_IPV6_ALL", "tcp", "pi_input_ipv4_all"])
def test_unknown_explicit_scope_is_not_legacy_fallback(scope):
    assert _run_wrapper("insert", DEVICE_IP, str(RULE_ID), scope).returncode == 64


@pytest.mark.parametrize("scope", [MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL])
def test_configured_protection_blocks_insert_but_allows_exact_cleanup(tmp_path, scope):
    config = tmp_path / "protected.txt"
    config.write_text(DEVICE_IP + "\n", encoding="utf-8")
    env = {"HANIUM_FW_TEST_PROTECTED_FILE": config.as_posix()}
    assert _run_wrapper("insert", DEVICE_IP, str(RULE_ID), scope, env_overrides=env).returncode == 65
    for operation in ("check", "delete"):
        assert _run_wrapper(operation, DEVICE_IP, str(RULE_ID), scope, env_overrides=env).returncode == 0


def test_actual_pi_address_guard_is_exercised_with_dry_run_fixture():
    env = {"HANIUM_FW_TEST_LOCAL_IPV4": DEVICE_IP + ",192.168.0.20"}
    assert _run_wrapper("insert", DEVICE_IP, str(RULE_ID), PI_INPUT_IPV4_ALL, env_overrides=env).returncode == 65
    assert _run_wrapper("delete", DEVICE_IP, str(RULE_ID), PI_INPUT_IPV4_ALL, env_overrides=env).returncode == 0


def test_production_iptables_binary_and_protect_file_are_fixed():
    source = WRAPPER.read_text(encoding="utf-8")
    assert "IPTABLES=/usr/sbin/iptables\n" in source
    assert "PROTECTED_FILE=/etc/hanium/firewall-protected-ipv4.conf\n" in source
    assert "HANIUM_FW_IPTABLES" not in source
    assert "NOSETENV:" in Path("infra/sudoers/hanium-firewall-worker").read_text(encoding="utf-8")
    assert "check_owned_path /etc/hanium" in source
    assert "local IPv4 observation failed" in source
