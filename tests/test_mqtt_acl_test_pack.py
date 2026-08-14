"""edge.scripts.mqtt_acl_test_pack의 순수 로직 단위 테스트.

실제 Broker 연결이 필요한 부분(check_connect_only/check_publish_delivery의
동작 자체)은 이 저장소 개발 과정에서 실제 Mosquitto Broker(apt 패키지)로
수동 검증했다 — Own Topic PASS / Cross Topic DENY / Wrong Password DENY /
Anonymous DENY / Subscriber Read PASS·Write DENY 모두 기대한 대로 동작함을
확인했다. 이 테스트 파일은 Broker 없이도 항상 실행 가능한 순수 로직(Credential
해석, 보고서 포맷, CheckResult 판정)만 검증한다.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from edge.scripts.mqtt_acl_test_pack import (
    AUTH_FAILED,
    Credential,
    CheckResult,
    DENY,
    ERROR,
    PASS,
    _credential_from_args,
    _subscribe_reason_codes_failed,
    parse_args,
    print_report,
    run_test_pack,
)


class TestCheckResult:
    def test_ok_when_expected_matches_observed(self) -> None:
        result = CheckResult("x", "desc", PASS, PASS, "detail")
        assert result.ok is True

    def test_not_ok_when_expected_differs_from_observed(self) -> None:
        result = CheckResult("x", "desc", DENY, PASS, "detail")
        assert result.ok is False

    def test_not_ok_when_observed_is_error(self) -> None:
        result = CheckResult("x", "desc", PASS, ERROR, "connection failed")
        assert result.ok is False

    def test_not_ok_when_observed_is_auth_failed(self) -> None:
        assert CheckResult("x", "desc", PASS, AUTH_FAILED, "d").ok is False
        assert CheckResult("x", "desc", DENY, AUTH_FAILED, "d").ok is False


class TestCheckPublishDelivery:
    def test_publish_failure_is_not_reported_as_acl_deny_pass(self, monkeypatch) -> None:
        import edge.scripts.mqtt_acl_test_pack as pack

        class FakePublishInfo:
            rc = pack.mqtt.MQTT_ERR_NO_CONN

        class FakePublisher:
            def loop_start(self) -> None:
                pass

            def publish(self, _topic, _payload, qos=0):
                return FakePublishInfo()

            def loop_stop(self) -> None:
                pass

            def disconnect(self) -> None:
                pass

        def fake_observe_delivery(
            _host,
            _port,
            _credential,
            _topic,
            publish_fn,
            *,
            expected_nonce,
        ) -> bool:
            publish_fn()
            return False

        monkeypatch.setattr(pack, "_build_client", lambda *_args: (FakePublisher(), object()))
        monkeypatch.setattr(pack, "_connect_and_wait", lambda *_args: True)
        monkeypatch.setattr(pack, "_observe_delivery", fake_observe_delivery)

        result = pack.check_publish_delivery(
            "cross_topic_deny",
            "cross-topic publish must be denied",
            host="localhost",
            port=1883,
            publisher_credential=Credential("esp32_01", "pw"),
            observer_credential=Credential("mqtt_test_tool", "pw"),
            publish_topic="iot/esp32_02/sensor",
            watch_topic="iot/esp32_02/sensor",
            expected=DENY,
        )

        assert result.observed == ERROR
        assert result.ok is False


class TestSubscribeReasonCodesFailed:
    class _FakeReasonCode:
        def __init__(self, is_failure: bool) -> None:
            self.is_failure = is_failure

    def test_returns_empty_when_all_succeed(self) -> None:
        codes = [self._FakeReasonCode(False), self._FakeReasonCode(False)]
        assert _subscribe_reason_codes_failed(codes) == []

    def test_returns_only_failed_codes(self) -> None:
        ok_code = self._FakeReasonCode(False)
        bad_code = self._FakeReasonCode(True)
        codes = [ok_code, bad_code]
        assert _subscribe_reason_codes_failed(codes) == [bad_code]

    def test_handles_objects_without_is_failure_attribute(self) -> None:
        # getattr(..., False) 기본값으로 방어하므로 예외 없이 성공 취급돼야 한다.
        assert _subscribe_reason_codes_failed([object()]) == []


class TestRunTestPackComposition:
    """run_test_pack이 실제 Broker 없이도 Check 구성(이름·기대값)을 검증한다.

    check_publish_delivery/check_connect_only를 Monkeypatch해 실제 네트워크
    호출 없이 어떤 Check가 어떤 인자로 구성되는지만 확인한다.
    """

    def test_includes_both_esp32_own_topic_checks(self, monkeypatch) -> None:
        import edge.scripts.mqtt_acl_test_pack as pack

        recorded_publish_calls = []
        recorded_connect_calls = []

        def fake_check_publish_delivery(name, description, **kwargs):
            recorded_publish_calls.append((name, kwargs.get("expected")))
            return CheckResult(name, description, kwargs.get("expected"), kwargs.get("expected"), "stub")

        def fake_check_connect_only(name, description, **kwargs):
            recorded_connect_calls.append((name, kwargs.get("expected")))
            return CheckResult(name, description, kwargs.get("expected"), kwargs.get("expected"), "stub")

        monkeypatch.setattr(pack, "check_publish_delivery", fake_check_publish_delivery)
        monkeypatch.setattr(pack, "check_connect_only", fake_check_connect_only)

        results = run_test_pack(
            host="localhost",
            port=1,
            esp32_01=Credential("esp32_01", "pw1"),
            esp32_02=Credential("esp32_02", "pw2"),
            edge_subscriber=Credential("edge_subscriber", "pw3"),
            test_tool=Credential("mqtt_test_tool", "pw4"),
        )

        publish_names = {name for name, _ in recorded_publish_calls}
        connect_names = {name for name, _ in recorded_connect_calls}

        # ESP32 #1뿐 아니라 #2의 Own Topic PASS도 별도로 확인해야 한다.
        assert "esp32_01_own_topic_pass" in publish_names
        assert "esp32_02_own_topic_pass" in publish_names
        assert "cross_topic_deny" in publish_names
        assert "edge_subscriber_read_pass" in publish_names
        assert "edge_subscriber_write_deny" in publish_names
        assert "wrong_password_deny" in connect_names
        assert "anonymous_deny" in connect_names
        assert len(results) == len(recorded_publish_calls) + len(recorded_connect_calls)

    def test_esp32_02_own_topic_uses_esp32_02_credential_and_own_topic(self, monkeypatch) -> None:
        import edge.scripts.mqtt_acl_test_pack as pack

        captured = {}

        def fake_check_publish_delivery(name, description, **kwargs):
            if name == "esp32_02_own_topic_pass":
                captured.update(kwargs)
            return CheckResult(name, description, kwargs.get("expected"), kwargs.get("expected"), "stub")

        def fake_check_connect_only(name, description, **kwargs):
            return CheckResult(name, description, kwargs.get("expected"), kwargs.get("expected"), "stub")

        monkeypatch.setattr(pack, "check_publish_delivery", fake_check_publish_delivery)
        monkeypatch.setattr(pack, "check_connect_only", fake_check_connect_only)

        run_test_pack(
            host="localhost",
            port=1,
            esp32_01=Credential("esp32_01", "pw1"),
            esp32_02=Credential("esp32_02", "pw2"),
            edge_subscriber=Credential("edge_subscriber", "pw3"),
            test_tool=Credential("mqtt_test_tool", "pw4"),
        )

        assert captured["publisher_credential"] == Credential("esp32_02", "pw2")
        assert captured["publish_topic"] == "iot/esp32_02/sensor"
        assert captured["watch_topic"] == "iot/esp32_02/sensor"
        assert captured["expected"] == PASS

    def test_every_observer_credential_is_exercised_by_at_least_one_pass_check(
        self, monkeypatch
    ) -> None:
        import edge.scripts.mqtt_acl_test_pack as pack

        recorded_publish_calls = []

        def fake_check_publish_delivery(name, description, **kwargs):
            recorded_publish_calls.append(kwargs)
            return CheckResult(name, description, kwargs.get("expected"), kwargs.get("expected"), "stub")

        def fake_check_connect_only(name, description, **kwargs):
            return CheckResult(name, description, kwargs.get("expected"), kwargs.get("expected"), "stub")

        monkeypatch.setattr(pack, "check_publish_delivery", fake_check_publish_delivery)
        monkeypatch.setattr(pack, "check_connect_only", fake_check_connect_only)

        edge_subscriber = Credential("edge_subscriber", "pw3")
        test_tool = Credential("mqtt_test_tool", "pw4")

        run_test_pack(
            host="localhost",
            port=1,
            esp32_01=Credential("esp32_01", "pw1"),
            esp32_02=Credential("esp32_02", "pw2"),
            edge_subscriber=edge_subscriber,
            test_tool=test_tool,
        )

        observer_credentials_used = {call["observer_credential"] for call in recorded_publish_calls}
        assert edge_subscriber in observer_credentials_used
        assert test_tool in observer_credentials_used

        for observer in (edge_subscriber, test_tool):
            pass_checks_for_observer = [
                call
                for call in recorded_publish_calls
                if call["observer_credential"] == observer and call["expected"] == PASS
            ]
            assert pass_checks_for_observer, (
                f"{observer.username}이(가) Observer로 쓰이는 PASS 기대 Check가 "
                "없습니다 — 이 Credential의 실제 Read 권한이 검증되지 않습니다."
            )


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
