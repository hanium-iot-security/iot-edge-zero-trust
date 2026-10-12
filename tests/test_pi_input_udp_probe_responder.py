"""Protocol and finite-lifetime tests on loopback; no Pi or physical device."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import socket
import time

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "infra/scripts/pi_input_udp_probe_responder.py"
SPEC = importlib.util.spec_from_file_location("pi_input_udp_probe_responder", SOURCE)
responder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(responder)


@pytest.mark.parametrize("payload", [
    b"", b"P9UDP:short", b"P9UDP:" + b"x" * 33, b"P9UDP:abcdefgh\n",
    b"P9UDP:abcd\x00efgh", b"P9UDP:abcd\xffefgh", b"OTHER:abcdefgh",
    b"P9UDP:" + b"x" * 129,
])
def test_invalid_datagram_is_never_reflected(payload):
    assert responder.reply_for(payload, (responder.DEVICE_ADDRESS, responder.DEVICE_PORT)) is None


@pytest.mark.parametrize("peer", [("192.168.0.4", 42100), ("192.168.0.5", 42101),
                                  ("127.0.0.1", 42100)])
def test_response_is_limited_to_the_exact_physical_device_and_port(peer):
    assert responder.reply_for(b"P9UDP:run_0001", peer) is None


def test_valid_request_has_a_distinct_exact_nonce_response():
    assert responder.reply_for(b"P9UDP:run-1234_AB", ("192.168.0.5", 42100)) == b"P9UDP-ACK:run-1234_AB"


def test_real_socket_response_preserves_nonce_and_stops_at_budget():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
         ThreadPoolExecutor(max_workers=1) as pool:
        server.bind(("127.0.0.1", 0))
        client.bind(("127.0.0.1", 0))
        client.settimeout(1)
        events = []
        future = pool.submit(responder.serve_socket, server, expected_address="127.0.0.1",
                             expected_port=client.getsockname()[1], max_datagrams=1,
                             overall_seconds=1, idle_seconds=1, emit=events.append)
        client.sendto(b"P9UDP:baseline_01", server.getsockname())
        payload, peer = client.recvfrom(128)
        assert payload == b"P9UDP-ACK:baseline_01"
        assert peer == server.getsockname()
        report = future.result(timeout=2)
        assert report["reason"] == "datagram_budget"
        assert (report["received"], report["replied"]) == (1, 1)
        assert events[0]["nonce"] == "baseline_01"


def test_real_socket_rejects_oversize_without_a_reply():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
         ThreadPoolExecutor(max_workers=1) as pool:
        server.bind(("127.0.0.1", 0))
        client.bind(("127.0.0.1", 0))
        client.settimeout(.1)
        future = pool.submit(responder.serve_socket, server, expected_address="127.0.0.1",
                             expected_port=client.getsockname()[1], max_datagrams=1,
                             overall_seconds=1, idle_seconds=1)
        client.sendto(b"P9UDP:" + b"x" * 1024, server.getsockname())
        with pytest.raises(socket.timeout):
            client.recvfrom(128)
        assert future.result(timeout=2)["replied"] == 0


def test_idle_socket_stops_without_datagrams():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        report = responder.serve_socket(server, overall_seconds=1, idle_seconds=.03)
        assert report["reason"] == "idle_timeout"
        assert report["received"] == report["replied"] == 0


def test_incoming_datagrams_cannot_extend_the_overall_lifetime():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
         ThreadPoolExecutor(max_workers=1) as pool:
        server.bind(("127.0.0.1", 0))
        client.bind(("127.0.0.1", 0))
        client.settimeout(.3)
        future = pool.submit(responder.serve_socket, server, expected_address="127.0.0.1",
                             expected_port=client.getsockname()[1], max_datagrams=100,
                             overall_seconds=.18, idle_seconds=1)
        for _ in range(4):
            client.sendto(b"P9UDP:bounded_01", server.getsockname())
            assert client.recvfrom(128)[0] == b"P9UDP-ACK:bounded_01"
            time.sleep(.01)
        report = future.result(timeout=2)
        assert report["reason"] == "overall_timeout"
        assert report["replied"] == 4


def test_default_cli_is_a_plan_and_never_opens_a_socket(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("plan must not open a socket")
    monkeypatch.setattr(responder.socket, "socket", forbidden)
    assert responder.main([]) == 0
    assert '"executed": false' in capsys.readouterr().out


def test_serving_refuses_root_before_opening_a_socket(monkeypatch):
    monkeypatch.setattr(responder.sys, "platform", "linux")
    monkeypatch.setattr(responder.os, "geteuid", lambda: 0, raising=False)
    with pytest.raises(SystemExit) as error:
        responder.main(["--serve"])
    assert error.value.code == 2
