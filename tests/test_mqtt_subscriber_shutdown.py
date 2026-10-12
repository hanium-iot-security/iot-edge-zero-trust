"""Subscriber shutdown must drain a callback and expose receiver failures.

The loopback tests use the installed Paho client and real SQLite commits. The
small broker implements only the MQTT packets needed here; it is not Mosquitto.
Only the real SIGTERM test is POSIX-only. No running broker or device is used.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from edge.mqtt import subscriber


ROOT = Path(__file__).resolve().parents[1]
TOPIC = "iot/shutdown_test/sensor"


def _wait_until(predicate, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition did not become true before the deadline")


class _Client:
    def __init__(self, receive):
        self.receive = receive
        self.disconnected = threading.Event()
        self.worker_daemon = None

    def loop_forever(self):
        self.worker_daemon = threading.current_thread().daemon
        self.receive()

    def disconnect(self):
        self.disconnected.set()
        return subscriber.mqtt.MQTT_ERR_SUCCESS


def test_stop_waits_for_the_in_flight_callback_to_finish() -> None:
    stopping = threading.Event()
    entered = threading.Event()
    release_commit = threading.Event()
    committed = threading.Event()
    failures = []

    def receive():
        entered.set()
        assert release_commit.wait(5)
        committed.set()

    client = _Client(receive)

    def run():
        try:
            subscriber.run_mqtt_loop(client, shutdown_requested=stopping.is_set)
        except Exception as exc:
            failures.append(exc)

    caller = threading.Thread(target=run)
    caller.start()
    try:
        assert entered.wait(5)
        assert client.worker_daemon is False
        stopping.set()
        assert client.disconnected.wait(5)
        assert caller.is_alive()
        assert not committed.is_set()
    finally:
        stopping.set()
        release_commit.set()
        caller.join(5)
    assert not caller.is_alive()
    assert committed.is_set()
    assert failures == []


@pytest.mark.parametrize("failure", [RuntimeError("forced storage failure"), SystemExit(0)])
def test_callback_failure_is_propagated_to_the_main_thread(failure: BaseException) -> None:

    def receive():
        raise failure

    client = _Client(receive)
    with pytest.raises(RuntimeError, match="MQTT receiver failed") as caught:
        subscriber.run_mqtt_loop(client, shutdown_requested=lambda: False)
    assert caught.value.__cause__ is failure
    assert client.disconnected.is_set()


def test_disconnect_failure_still_joins_the_in_flight_callback() -> None:
    stopping = threading.Event()
    entered = threading.Event()
    release_commit = threading.Event()
    committed = threading.Event()
    failures = []

    def receive():
        entered.set()
        assert release_commit.wait(5)
        committed.set()

    client = _Client(receive)
    disconnect_failure = RuntimeError("forced disconnect failure")

    def disconnect():
        client.disconnected.set()
        raise disconnect_failure

    client.disconnect = disconnect

    def run():
        try:
            subscriber.run_mqtt_loop(client, shutdown_requested=stopping.is_set)
        except Exception as exc:
            failures.append(exc)

    caller = threading.Thread(target=run)
    caller.start()
    try:
        assert entered.wait(5)
        stopping.set()
        assert client.disconnected.wait(5)
        assert caller.is_alive(), "disconnect failure escaped before callback drain"
        assert not committed.is_set()
    finally:
        stopping.set()
        release_commit.set()
        caller.join(5)
    assert not caller.is_alive()
    assert client.worker_daemon is False
    assert committed.is_set()
    assert failures == [disconnect_failure]


def test_unexpected_network_loop_return_is_a_failure() -> None:
    client = _Client(lambda: None)
    with pytest.raises(RuntimeError, match="MQTT receiver failed") as caught:
        subscriber.run_mqtt_loop(client, shutdown_requested=lambda: False)
    assert "stopped unexpectedly" in str(caught.value.__cause__)
    assert client.disconnected.is_set()


def test_stop_during_connect_does_not_start_the_network_worker(monkeypatch) -> None:
    stopping = threading.Event()
    client = _Client(lambda: pytest.fail("receiver must not start after stop"))

    def connect(*_args, **_kwargs):
        stopping.set()

    client.connect = connect
    monkeypatch.setattr(subscriber.mqtt, "Client", lambda *_args: client)
    monkeypatch.setattr(subscriber, "settings", SimpleNamespace(
        mqtt_host="127.0.0.1", mqtt_port=1883, mqtt_subscribe_topic=TOPIC,
        mqtt_subscriber_username="", mqtt_subscriber_password="",
    ))
    assert subscriber._main(shutdown_requested=stopping.is_set) == 0
    assert client.disconnected.is_set()
    assert client.worker_daemon is None


def test_main_installs_stop_handlers_and_restores_previous_handlers(monkeypatch) -> None:
    previous = {signal.SIGTERM: object(), signal.SIGINT: object()}
    installed = dict(previous)
    monkeypatch.setattr(subscriber.signal, "getsignal", lambda sig: previous[sig])
    monkeypatch.setattr(subscriber.signal, "signal", lambda sig, handler: installed.__setitem__(sig, handler))

    def run(*, shutdown_requested):
        assert not shutdown_requested()
        installed[signal.SIGTERM](signal.SIGTERM, None)
        assert shutdown_requested()
        return 0

    monkeypatch.setattr(subscriber, "_main", run)
    assert subscriber.main() == 0
    assert installed == previous


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    parts = bytearray()
    while len(parts) < count:
        part = connection.recv(count - len(parts))
        if not part:
            raise EOFError("MQTT client closed its socket")
        parts.extend(part)
    return bytes(parts)


def _recv_packet(connection: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(connection, 1)[0]
    remaining, multiplier = 0, 1
    for _ in range(4):
        encoded = _recv_exact(connection, 1)[0]
        remaining += (encoded & 127) * multiplier
        if not encoded & 128:
            return header >> 4, _recv_exact(connection, remaining)
        multiplier *= 128
    raise AssertionError("invalid MQTT remaining length")


def _packet(header: int, body: bytes) -> bytes:
    remaining = len(body)
    encoded = bytearray()
    while True:
        digit = remaining % 128
        remaining //= 128
        encoded.append(digit | (128 if remaining else 0))
        if not remaining:
            break
    return bytes([header]) + bytes(encoded) + body


class _Broker:
    """One subscriber, optionally forcing one TCP reconnect/resubscription."""

    def __init__(self, *, reconnect: bool = False):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.reconnect = reconnect
        self.drop_first_connection = threading.Event()
        self.closed = threading.Event()
        self.failures = []
        self.subscriptions = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            for sequence in range(1, 3 if self.reconnect else 2):
                with self.listener.accept()[0] as connection:
                    connection.settimeout(10)
                    packet_type, _ = _recv_packet(connection)
                    assert packet_type == 1  # CONNECT
                    connection.sendall(b"\x20\x02\x00\x00")  # CONNACK accepted
                    packet_type, body = _recv_packet(connection)
                    assert packet_type == 8  # SUBSCRIBE
                    self.subscriptions.append(body[2:])
                    connection.sendall(b"\x90\x03" + body[:2] + b"\x00")
                    topic = TOPIC.encode()
                    payload = (f'{{"device_id":"shutdown_test","seq":{sequence}}}').encode()
                    connection.sendall(_packet(0x30, len(topic).to_bytes(2, "big") + topic + payload))
                    if self.reconnect and sequence == 1:
                        assert self.drop_first_connection.wait(10)
                        continue
                    while not self.closed.is_set():
                        packet_type, _ = _recv_packet(connection)
                        if packet_type == 14:  # DISCONNECT
                            break
                        if packet_type == 12:  # PINGREQ
                            connection.sendall(b"\xd0\x00")
                        else:
                            raise AssertionError(f"unexpected MQTT packet: {packet_type}")
        except (OSError, EOFError):
            # Storage-failure exits close the socket without MQTT DISCONNECT.
            pass
        except Exception as exc:
            self.failures.append(exc)
        finally:
            self.listener.close()

    def close(self):
        self.closed.set()
        self.drop_first_connection.set()
        self.listener.close()
        self.thread.join(11)
        assert not self.thread.is_alive(), "loopback broker did not stop"
        assert self.failures == []


CHILD = r"""
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from edge.mqtt import subscriber

db_path, port, mode, marker_dir = sys.argv[1:]
markers = Path(marker_dir)
subscriber.settings = SimpleNamespace(
    mqtt_host="127.0.0.1", mqtt_port=int(port), mqtt_subscribe_topic="iot/+/sensor",
    mqtt_subscriber_username="", mqtt_subscriber_password="",
)
class CommitSession(Session):
    def commit(self):
        (markers / "entered").write_text("entered")
        if mode == "failure":
            raise RuntimeError("forced storage failure")
        if mode in ("slow", "slow-failure"):
            deadline = time.monotonic() + 10
            while not (markers / "release").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("test commit barrier timed out")
                time.sleep(0.02)
        if mode == "slow-failure":
            raise RuntimeError("forced storage failure after shutdown")
        super().commit()
        (markers / "committed").write_text("committed")
engine = create_engine("sqlite:///" + db_path, connect_args={"check_same_thread": False})
subscriber.SessionLocal = sessionmaker(bind=engine, class_=CommitSession)
try:
    if mode == "reconnect":
        code = subscriber._main(shutdown_requested=lambda: (markers / "stop").exists())
    else:
        code = subscriber.main()
finally:
    engine.dispose()
raise SystemExit(code)
"""


@contextmanager
def _receiver(tmp_path: Path, *, mode: str):
    db_path = tmp_path / "subscriber.db"
    with sqlite3.connect(db_path) as db:
        db.executescript((ROOT / "db/migrations/001_init.sql").read_text(encoding="utf-8"))
        db.executescript((ROOT / "db/migrations/009_mqtt_raw_payload.sql").read_text(encoding="utf-8"))
    broker = _Broker(reconnect=mode == "reconnect")
    environment = dict(os.environ, DATABASE_URL=f"sqlite:///{db_path.as_posix()}")
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", CHILD, str(db_path), str(broker.port), mode, str(tmp_path)],
        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    try:
        yield process, broker, db_path
    finally:
        (tmp_path / "release").touch()
        (tmp_path / "stop").touch()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.communicate(timeout=5)
        broker.close()


def _rows(db_path: Path) -> list[tuple]:
    with sqlite3.connect(db_path, timeout=1) as db:
        return db.execute("SELECT payload, payload_raw FROM mqtt_logs ORDER BY id").fetchall()


@pytest.mark.skipif(os.name != "posix", reason="real SIGTERM process shutdown requires POSIX")
def test_sigterm_drains_actual_paho_callback_and_commits_sqlite(tmp_path: Path) -> None:
    with _receiver(tmp_path, mode="slow") as (process, broker, db_path):
        _wait_until(lambda: (tmp_path / "entered").exists())
        process.send_signal(signal.SIGTERM)
        time.sleep(0.1)
        process.send_signal(signal.SIGTERM)
        time.sleep(0.1)
        assert process.poll() is None, "shutdown returned before the SQLite callback drained"
        assert _rows(db_path) == []
        (tmp_path / "release").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr
        assert (tmp_path / "committed").exists()
        rows = _rows(db_path)
        assert len(rows) == 1
        assert rows[0][1] == rows[0][0].encode()
        assert '"seq":1' in rows[0][0]
        assert len(broker.subscriptions) == 1


@pytest.mark.skipif(os.name != "posix", reason="real SIGTERM process shutdown requires POSIX")
def test_sigterm_during_failed_commit_exits_nonzero_and_rolls_back(tmp_path: Path) -> None:
    with _receiver(tmp_path, mode="slow-failure") as (process, _broker, db_path):
        _wait_until(lambda: (tmp_path / "entered").exists())
        process.send_signal(signal.SIGTERM)
        time.sleep(0.2)
        assert process.poll() is None, "shutdown returned before the callback completed"
        assert _rows(db_path) == []
        (tmp_path / "release").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode != 0
        assert "forced storage failure after shutdown" in stdout + stderr
        assert "MQTT receiver failed" in stdout + stderr
        assert not (tmp_path / "committed").exists()
        assert _rows(db_path) == []


def test_actual_paho_storage_failure_exits_nonzero_without_committing(tmp_path: Path) -> None:
    with _receiver(tmp_path, mode="failure") as (process, _broker, db_path):
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode != 0
        assert "forced storage failure" in stdout + stderr
        assert "MQTT receiver failed" in stdout + stderr
        assert _rows(db_path) == []


def test_actual_paho_reconnect_resubscribes_and_saves_the_next_message(tmp_path: Path) -> None:
    with _receiver(tmp_path, mode="reconnect") as (process, broker, db_path):
        _wait_until(lambda: len(_rows(db_path)) == 1)
        broker.drop_first_connection.set()
        _wait_until(lambda: len(_rows(db_path)) == 2)
        (tmp_path / "stop").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr
        assert len(broker.subscriptions) == 2
        assert broker.subscriptions[0] == broker.subscriptions[1]
        rows = _rows(db_path)
        assert '"seq":1' in rows[0][0]
        assert '"seq":2' in rows[1][0]
        assert all(raw == payload.encode() for payload, raw in rows)
