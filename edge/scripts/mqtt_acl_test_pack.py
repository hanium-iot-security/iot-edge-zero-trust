"""Mosquitto 허용/거부 Test Pack.

Own Topic PASS / Anonymous DENY / Cross Topic DENY / Wrong Password DENY를
실제 Broker에 대해 확인한다. `infra/mosquitto/mosquitto-strict.conf`로 띄운
Strict Test Listener(전환 기간, 별도 Port) 또는 인증·ACL이 이미 강제된 운영 Broker 모두에 사용할 수 있다.

이 스크립트는 Broker의 ACL DENY를 "Publish가 실제로 전달되지 않음"으로 판정한다.
QoS 0 PUBLISH는 성공 여부를 Client가 직접 알 수 없으므로(Broker가 조용히 버림),
넓은 권한을 가진 Observer(공식 MQTT Scenario/Test Tool Credential, `iot/#` Read/Write 허용)로 대상 Topic을 Subscribe해두고
실제 수신 여부로 PASS/DENY를 판정한다.

실행 예시:
  python -m edge.scripts.mqtt_acl_test_pack \\
      --host 192.168.0.20 --port 18831 \\
      --esp32-01-password '...' --esp32-02-password '...' \\
      --edge-subscriber-password '...' --test-tool-password '...'

Credential 값은 명령행 인자 또는 환경 변수로 전달한다(우선순위: 인자 > 환경변수).
이 스크립트나 Repository에는 실제 비밀번호를 저장하지 않는다.

  MQTT_ACL_TEST_ESP32_01_PASSWORD
  MQTT_ACL_TEST_ESP32_02_PASSWORD
  MQTT_ACL_TEST_EDGE_SUBSCRIBER_PASSWORD
  MQTT_ACL_TEST_TEST_TOOL_PASSWORD

종료 코드: 모든 Check가 기대한 결과와 일치하면 0, 하나라도 어긋나면 1을 반환한다.
이 Exit Code로 배포 파이프라인·Runbook의 Gate로 사용할 수 있다.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import sys
import threading
import time
from typing import Callable

import paho.mqtt.client as mqtt


DEFAULT_TIMEOUT_SECONDS = 3.0
CONNECT_WAIT_SECONDS = 3.0

PASS = "PASS"
DENY = "DENY"


@dataclass(frozen=True)
class Credential:
    username: str
    password: str


@dataclass(frozen=True)
class CheckResult:
    name: str
    description: str
    expected: str
    observed: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.expected == self.observed


class _ConnectOutcome:
    """CONNECT 결과를 Thread 간에 안전하게 전달하는 작은 상자."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.reason_code: int | None = None


def _build_client(
    client_id: str,
    credential: Credential | None,
) -> tuple[mqtt.Client, _ConnectOutcome]:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    outcome = _ConnectOutcome()

    def on_connect(_client, _userdata, _flags, reason_code, _properties) -> None:
        outcome.reason_code = int(reason_code.value)
        outcome.event.set()

    client.on_connect = on_connect
    if credential is not None and credential.username:
        client.username_pw_set(credential.username, credential.password or None)
    return client, outcome


def _connect_and_wait(
    client: mqtt.Client,
    outcome: _ConnectOutcome,
    host: str,
    port: int,
) -> bool:
    """CONNECT를 시도하고 성공 여부(Broker가 연결을 수락했는지)를 반환한다."""
    try:
        client.connect(host, port, keepalive=10)
    except (ConnectionRefusedError, OSError) as exc:
        # Broker 자체가 열려 있지 않거나 네트워크가 닿지 않는 경우.
        outcome.reason_code = None
        raise RuntimeError(f"Broker 연결 실패(TCP): {exc}") from exc

    client.loop_start()
    connected = outcome.event.wait(CONNECT_WAIT_SECONDS)
    if not connected:
        client.loop_stop()
        raise RuntimeError("CONNACK을 시간 내에 받지 못했습니다(Broker 응답 없음)")
    return outcome.reason_code == 0


def _observe_delivery(
    host: str,
    port: int,
    observer_credential: Credential,
    topic: str,
    publish_fn: Callable[[], None],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> bool:
    """Observer로 topic을 Subscribe해두고, publish_fn 실행 후 실제 수신 여부를 반환한다."""
    received = threading.Event()

    observer, observer_outcome = _build_client("acl_test_observer", observer_credential)

    def on_message(_client, _userdata, _message) -> None:
        received.set()

    observer.on_message = on_message

    subscribed = threading.Event()

    def on_subscribe(_client, _userdata, _mid, _reason_codes, _properties) -> None:
        subscribed.set()

    observer.on_subscribe = on_subscribe

    if not _connect_and_wait(observer, observer_outcome, host, port):
        observer.loop_stop()
        raise RuntimeError("Observer(Test Tool) Credential로 연결하지 못했습니다")

    observer.subscribe(topic, qos=0)
    if not subscribed.wait(CONNECT_WAIT_SECONDS):
        observer.loop_stop()
        observer.disconnect()
        raise RuntimeError("Observer SUBSCRIBE 확인(SUBACK)을 받지 못했습니다")

    # Broker가 SUBSCRIBE를 실제로 반영할 시간을 약간 준다.
    time.sleep(0.3)

    publish_fn()

    delivered = received.wait(timeout_seconds)

    observer.loop_stop()
    observer.disconnect()
    return delivered


def check_connect_only(
    name: str,
    description: str,
    *,
    host: str,
    port: int,
    credential: Credential | None,
    expected: str,
) -> CheckResult:
    client, outcome = _build_client(f"acl_test_{name}", credential)
    try:
        accepted = _connect_and_wait(client, outcome, host, port)
    except RuntimeError as exc:
        return CheckResult(name, description, expected, "ERROR", str(exc))
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass

    observed = PASS if accepted else DENY
    detail = (
        f"CONNACK reason_code={outcome.reason_code}"
        if outcome.reason_code is not None
        else "CONNACK 없음"
    )
    return CheckResult(name, description, expected, observed, detail)


def check_publish_delivery(
    name: str,
    description: str,
    *,
    host: str,
    port: int,
    publisher_credential: Credential | None,
    observer_credential: Credential,
    publish_topic: str,
    watch_topic: str,
    payload: str,
    expected: str,
) -> CheckResult:
    def do_publish() -> None:
        publisher, publisher_outcome = _build_client(f"acl_test_{name}_pub", publisher_credential)
        try:
            if not _connect_and_wait(publisher, publisher_outcome, host, port):
                # 연결 자체가 거부되면 당연히 전달되지 않는다 — publish 시도하지 않는다.
                return
            publisher.loop_start()
            publisher.publish(publish_topic, payload, qos=0)
            time.sleep(0.2)
        finally:
            publisher.loop_stop()
            try:
                publisher.disconnect()
            except Exception:
                pass

    try:
        delivered = _observe_delivery(
            host, port, observer_credential, watch_topic, do_publish
        )
    except RuntimeError as exc:
        return CheckResult(name, description, expected, "ERROR", str(exc))

    observed = PASS if delivered else DENY
    detail = "Observer가 메시지를 수신함" if delivered else "Observer가 시간 내 메시지를 받지 못함"
    return CheckResult(name, description, expected, observed, detail)


def run_test_pack(
    *,
    host: str,
    port: int,
    esp32_01: Credential,
    esp32_02: Credential,
    edge_subscriber: Credential,
    test_tool: Credential,
) -> list[CheckResult]:
    results: list[CheckResult] = []

    results.append(
        check_publish_delivery(
            "own_topic_pass",
            "ESP32 #1이 자기 Topic(iot/esp32_01/sensor)에 Publish → 전달돼야 함",
            host=host,
            port=port,
            publisher_credential=esp32_01,
            observer_credential=test_tool,
            publish_topic="iot/esp32_01/sensor",
            watch_topic="iot/esp32_01/sensor",
            payload='{"device_id":"esp32_01"}',
            expected=PASS,
        )
    )

    results.append(
        check_publish_delivery(
            "cross_topic_deny",
            "ESP32 #2 Credential로 iot/esp32_01/sensor에 Publish → Broker가 거부해야 함",
            host=host,
            port=port,
            publisher_credential=esp32_02,
            observer_credential=test_tool,
            publish_topic="iot/esp32_01/sensor",
            watch_topic="iot/esp32_01/sensor",
            payload='{"device_id":"esp32_02"}',
            expected=DENY,
        )
    )

    results.append(
        check_connect_only(
            "wrong_password_deny",
            "ESP32 #1 Username + 잘못된 Password → CONNECT 자체가 거부돼야 함",
            host=host,
            port=port,
            credential=Credential(esp32_01.username, esp32_01.password + "_wrong"),
            expected=DENY,
        )
    )

    results.append(
        check_connect_only(
            "anonymous_deny",
            "Credential 없이 연결 시도 → CONNECT 자체가 거부돼야 함",
            host=host,
            port=port,
            credential=None,
            expected=DENY,
        )
    )

    results.append(
        check_publish_delivery(
            "edge_subscriber_read_pass",
            "Test Tool이 iot/esp32_01/sensor에 Publish → Edge Subscriber Credential이 수신해야 함",
            host=host,
            port=port,
            publisher_credential=test_tool,
            observer_credential=edge_subscriber,
            publish_topic="iot/esp32_01/sensor",
            watch_topic="iot/+/sensor",
            payload='{"device_id":"esp32_01"}',
            expected=PASS,
        )
    )

    results.append(
        check_publish_delivery(
            "edge_subscriber_write_deny",
            "Edge Subscriber Credential로 Publish 시도(Read-only) → Broker가 거부해야 함",
            host=host,
            port=port,
            publisher_credential=edge_subscriber,
            observer_credential=test_tool,
            publish_topic="iot/esp32_01/sensor",
            watch_topic="iot/esp32_01/sensor",
            payload='{"device_id":"esp32_01"}',
            expected=DENY,
        )
    )

    return results


def print_report(results: list[CheckResult]) -> bool:
    all_ok = True
    print(f"{'Check':<28} {'Expected':<9} {'Observed':<9} Detail")
    print("-" * 78)
    for result in results:
        status = "OK" if result.ok else "MISMATCH"
        if not result.ok:
            all_ok = False
        print(
            f"{result.name:<28} {result.expected:<9} {result.observed:<9} "
            f"[{status}] {result.detail}"
        )
    print()
    for result in results:
        print(f"- {result.name}: {result.description}")
    return all_ok


def _credential_from_args(
    username: str,
    password_arg: str | None,
    env_var: str,
) -> Credential:
    password = password_arg if password_arg is not None else os.environ.get(env_var, "")
    return Credential(username=username, password=password)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mosquitto Own Topic PASS / Cross Topic DENY / Wrong Password DENY / "
        "Anonymous DENY Test Pack"
    )
    parser.add_argument("--host", required=True, help="검증 대상 Broker Host")
    parser.add_argument("--port", type=int, required=True, help="검증 대상 Broker Port")
    parser.add_argument("--esp32-01-username", default="esp32_01")
    parser.add_argument("--esp32-01-password", default=None)
    parser.add_argument("--esp32-02-username", default="esp32_02")
    parser.add_argument("--esp32-02-password", default=None)
    parser.add_argument("--edge-subscriber-username", default="edge_subscriber")
    parser.add_argument("--edge-subscriber-password", default=None)
    parser.add_argument("--test-tool-username", default="mqtt_test_tool")
    parser.add_argument("--test-tool-password", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    esp32_01 = _credential_from_args(
        args.esp32_01_username, args.esp32_01_password, "MQTT_ACL_TEST_ESP32_01_PASSWORD"
    )
    esp32_02 = _credential_from_args(
        args.esp32_02_username, args.esp32_02_password, "MQTT_ACL_TEST_ESP32_02_PASSWORD"
    )
    edge_subscriber = _credential_from_args(
        args.edge_subscriber_username,
        args.edge_subscriber_password,
        "MQTT_ACL_TEST_EDGE_SUBSCRIBER_PASSWORD",
    )
    test_tool = _credential_from_args(
        args.test_tool_username, args.test_tool_password, "MQTT_ACL_TEST_TEST_TOOL_PASSWORD"
    )

    for credential, label in (
        (esp32_01, "--esp32-01-password"),
        (esp32_02, "--esp32-02-password"),
        (edge_subscriber, "--edge-subscriber-password"),
        (test_tool, "--test-tool-password"),
    ):
        if not credential.password:
            print(f"[경고] {label}(또는 대응 환경 변수)이 비어 있습니다. 대상 Broker가 "
                  "이미 인증을 강제한다면 이 Check들은 실패로 보고될 수 있습니다.")

    results = run_test_pack(
        host=args.host,
        port=args.port,
        esp32_01=esp32_01,
        esp32_02=esp32_02,
        edge_subscriber=edge_subscriber,
        test_tool=test_tool,
    )
    all_ok = print_report(results)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
