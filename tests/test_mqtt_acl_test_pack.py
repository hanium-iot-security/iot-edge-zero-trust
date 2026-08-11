from __future__ import annotations

import io
from contextlib import redirect_stdout

from edge.scripts.mqtt_acl_test_pack import (
    Credential,
    CheckResult,
    DENY,
    PASS,
    _credential_from_args,
    parse_args,
    print_report,
)


class TestCheckResult:
    def test_ok_when_expected_matches_observed(self) -> None:
        result = CheckResult("x", "desc", PASS, PASS, "detail")
        assert result.ok is True

    def test_not_ok_when_expected_differs_from_observed(self) -> None:
        result = CheckResult("x", "desc", DENY, PASS, "detail")
        assert result.ok is False

    def test_not_ok_when_observed_is_error(self) -> None:
        result = CheckResult("x", "desc", PASS, "ERROR", "connection failed")
        assert result.ok is False


class TestCredentialFromArgs:
    def test_explicit_arg_takes_priority_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("MQTT_ACL_TEST_ESP32_01_PASSWORD", "from_env")
        credential = _credential_from_args("esp32_01", "from_arg", "MQTT_ACL_TEST_ESP32_01_PASSWORD")
        assert credential.username == "esp32_01"
        assert credential.password == "from_arg"

    def test_falls_back_to_env_when_arg_is_none(self, monkeypatch) -> None:
        monkeypatch.setenv("MQTT_ACL_TEST_ESP32_01_PASSWORD", "from_env")
        credential = _credential_from_args("esp32_01", None, "MQTT_ACL_TEST_ESP32_01_PASSWORD")
        assert credential.password == "from_env"

    def test_empty_when_neither_arg_nor_env_present(self, monkeypatch) -> None:
        monkeypatch.delenv("MQTT_ACL_TEST_ESP32_01_PASSWORD", raising=False)
        credential = _credential_from_args("esp32_01", None, "MQTT_ACL_TEST_ESP32_01_PASSWORD")
        assert credential.password == ""


class TestParseArgs:
    def test_requires_host_and_port(self) -> None:
        args = parse_args(["--host", "192.168.0.20", "--port", "18831"])
        assert args.host == "192.168.0.20"
        assert args.port == 18831

    def test_default_usernames_match_acl_principals(self) -> None:
        args = parse_args(["--host", "h", "--port", "1"])
        assert args.esp32_01_username == "esp32_01"
        assert args.esp32_02_username == "esp32_02"
        assert args.edge_subscriber_username == "edge_subscriber"
        assert args.test_tool_username == "mqtt_test_tool"


class TestPrintReport:
    def test_returns_true_when_all_checks_pass(self) -> None:
        results = [
            CheckResult("own_topic_pass", "desc", PASS, PASS, "ok"),
            CheckResult("anonymous_deny", "desc", DENY, DENY, "ok"),
        ]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            all_ok = print_report(results)

        assert all_ok is True
        output = buffer.getvalue()
        assert "own_topic_pass" in output
        assert "MISMATCH" not in output

    def test_returns_false_when_any_check_mismatches(self) -> None:
        results = [
            CheckResult("own_topic_pass", "desc", PASS, PASS, "ok"),
            CheckResult("anonymous_deny", "desc", DENY, PASS, "허용됨"),
        ]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            all_ok = print_report(results)

        assert all_ok is False
        output = buffer.getvalue()
        assert "MISMATCH" in output
        assert "anonymous_deny" in output


def test_credential_dataclass_is_simple_value_object() -> None:
    credential = Credential(username="esp32_01", password="secret")
    assert credential.username == "esp32_01"
    assert credential.password == "secret"
