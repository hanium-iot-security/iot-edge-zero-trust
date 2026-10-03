"""Management commands and the real Worker share policy and locking semantics.

Only temporary databases are used. The firewall execution boundary records
operations instead of invoking sudo, iptables, or a hardware service.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.tests.test_device_policy_api import (
    api_client, assert_business_error, change_policy, create_device, rows, write,
)
from backend.tests.test_device_policy_safety import _rule, _snapshot
from edge.trust import run_firewall_worker
from edge.trust.firewall_worker import CHECK, INSERT, LIST_RULES, CommandResult


class RecordingFirewallRunner:
    def __init__(self):
        self.operations = []

    def run_operation(self, operation, spec=None):
        self.operations.append((operation, spec))
        # The modeled OS has no managed rule until an insert is requested.
        return CommandResult(returncode=1 if operation == CHECK else 0)


@pytest.fixture
def worker_context(api_client, monkeypatch):
    _, db_path, clock = api_client
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}", connect_args={"check_same_thread": False},
    )
    sessions = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    runner = RecordingFirewallRunner()
    monkeypatch.setattr(run_firewall_worker, "SessionLocal", sessions)
    monkeypatch.setattr(run_firewall_worker, "_now", lambda: clock["now"])
    monkeypatch.setattr(run_firewall_worker, "WrapperIptablesRunner", lambda _policy: runner)
    try:
        yield sessions, runner
    finally:
        engine.dispose()


def _failed_isolation(db_path):
    write(db_path, "UPDATE devices SET trust_score=20, status='isolated' WHERE device_id='pico_01'")
    write(
        db_path,
        "INSERT INTO trust_score_history(device_id,analysis_window_start,analysis_window_end,"
        "previous_score,calculated_delta,capped_delta,actual_delta,new_score,"
        "representative_event_ids_json,policy_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("pico_01", "2026-10-01T23:59:40Z", "2026-10-01T23:59:50Z",
         50, -30, -30, -30, 20, "[]", "fixture-prior-isolation"),
    )
    return _rule(
        db_path, attempted=(datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(),
    )


def _reset(rule_id):
    return run_firewall_worker.main([
        "--admin-reset-failed", str(rule_id),
        "--confirm", run_firewall_worker.ADMIN_CONFIRM_TOKEN,
    ])


def _activate(client, clock):
    clock["now"] += timedelta(seconds=10)
    response = change_policy(client, state="ACTIVE")
    assert response.status_code == 201, response.text
    clock["now"] += timedelta(seconds=10)
    assert client.get("/api/devices/pico_01").json()["auto_response_eligible"] is True


@pytest.mark.parametrize("state", [
    "REGISTRATION_SCHEDULED", "PENDING", "DISABLE_SCHEDULED", "DISABLED",
])
def test_api_exclusion_denies_real_cli_reset_without_mutation(
    api_client, worker_context, monkeypatch, tmp_path, state,
):
    client, db_path, clock = api_client
    _, runner = worker_context
    create_device(client)
    if state == "PENDING":
        clock["now"] += timedelta(seconds=10)
    elif state != "REGISTRATION_SCHEDULED":
        _activate(client, clock)
    rule_id = _failed_isolation(db_path)
    if state in {"DISABLE_SCHEDULED", "DISABLED"}:
        _snapshot(monkeypatch, tmp_path)
        response = change_policy(client, expected=2, state="DISABLED")
        assert response.status_code == 201, response.text
        if state == "DISABLED":
            clock["now"] += timedelta(seconds=10)
    detail = client.get("/api/devices/pico_01").json()
    assert detail["registration_state"] == {
        "REGISTRATION_SCHEDULED": "PENDING", "PENDING": "PENDING",
        "DISABLE_SCHEDULED": "ACTIVE", "DISABLED": "DISABLED",
    }[state]
    assert detail["auto_response_eligible"] is False
    before = rows(db_path, "SELECT * FROM firewall_rules")
    before_history = rows(db_path, "SELECT * FROM trust_score_history")
    before_revisions = rows(db_path, "SELECT * FROM device_policy_revisions")

    assert _reset(rule_id) == 2

    assert rows(db_path, "SELECT * FROM firewall_rules") == before
    assert rows(db_path, "SELECT * FROM trust_score_history") == before_history
    assert rows(db_path, "SELECT * FROM device_policy_revisions") == before_revisions
    assert rows(db_path, "SELECT status,trust_score FROM devices") == [("isolated", 20)]
    assert runner.operations == []


def test_active_retry_prevents_disable_and_applies_without_recalculating_trust(
    api_client, worker_context, monkeypatch, tmp_path,
):
    client, db_path, clock = api_client
    _, runner = worker_context
    create_device(client)
    _activate(client, clock)
    rule_id = _failed_isolation(db_path)
    _snapshot(monkeypatch, tmp_path)
    before_history = rows(db_path, "SELECT * FROM trust_score_history")
    assert client.get("/api/devices/pico_01").json()["auto_response_eligible"] is True

    assert _reset(rule_id) == 0
    assert rows(db_path, "SELECT status FROM firewall_rules") == [("PENDING",)]
    assert_business_error(change_policy(client, expected=2, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")
    assert run_firewall_worker.main(["--once"]) == 0

    assert [operation for operation, _ in runner.operations] == [LIST_RULES, CHECK, INSERT]
    assert runner.operations[-1][1].rule_id == rule_id
    assert runner.operations[-1][1].source_ip == "192.168.0.6"
    assert rows(db_path, "SELECT status FROM firewall_rules") == [("APPLIED",)]
    assert rows(db_path, "SELECT * FROM trust_score_history") == before_history
    assert rows(db_path, "SELECT status,trust_score FROM devices") == [("isolated", 20)]
    assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(2,)]


def test_real_reset_holds_shared_lock_against_concurrent_api_disable(
    api_client, worker_context, monkeypatch, tmp_path,
):
    client, db_path, clock = api_client
    sessions, runner = worker_context
    create_device(client)
    _activate(client, clock)
    rule_id = _failed_isolation(db_path)
    _snapshot(monkeypatch, tmp_path)
    reset_has_lock = threading.Event()
    continue_reset = threading.Event()

    def paused_session_factory():
        # main() enters SessionLocal only after acquiring the actual shared
        # file lock. Pause before DB work so the HTTP command races that lock.
        reset_has_lock.set()
        assert continue_reset.wait(timeout=5), "Concurrent API command did not finish"
        return sessions()

    monkeypatch.setattr(run_firewall_worker, "SessionLocal", paused_session_factory)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(_reset, rule_id)
        try:
            assert reset_has_lock.wait(timeout=5), "Reset did not acquire the shared lock"
            assert_business_error(change_policy(client, expected=2, state="DISABLED"), 409, "POLICY_WRITE_BUSY")
            assert rows(db_path, "SELECT status FROM firewall_rules") == [("FAILED",)]
            assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(2,)]
        finally:
            continue_reset.set()
        assert pending.result(timeout=5) == 0

    # Once the lock is released, the committed retry still prevents disable.
    assert_business_error(change_policy(client, expected=2, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")
    assert rows(db_path, "SELECT status FROM firewall_rules") == [("PENDING",)]
    assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(2,)]
    assert rows(db_path, "SELECT status,trust_score FROM devices") == [("isolated", 20)]
    assert runner.operations == []
