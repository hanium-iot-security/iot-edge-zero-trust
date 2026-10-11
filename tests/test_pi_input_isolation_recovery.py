"""Scoped partial failure through audited exact release and baseline recovery."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from backend.app.config import settings
from edge.trust import baseline_recovery, firewall_runtime_snapshot
from edge.trust import firewall_release_repository as releases
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from edge.trust.firewall_worker import (
    INSERT, LIST_RULES, CommandResult, FirewallPolicy, FirewallRuleSpec,
    FirewallTransientError, build_rule_args, process_pending_rules,
    process_pending_release_requests,
)
from tests.test_firewall_worker import FakeIptablesRunner, _rule_key
from tests.test_pi_input_isolation_repository import NOW, DEVICE, IP, approve, environment


class ScopedRuntimeFake(FakeIptablesRunner):
    def run_operation(self, operation, spec=None):
        result = super().run_operation(operation, spec)
        if operation == LIST_RULES:
            return CommandResult(returncode=0, stdout="\n".join("-A INPUT " + rule for rule in self.installed))
        if operation == INSERT and spec.scope == PI_INPUT_IPV4_ALL:
            raise FirewallTransientError("simulated timeout after wide insert")
        return result


def test_failed_wide_residue_holds_until_exact_audited_release_and_later_snapshot(environment, tmp_path, monkeypatch):
    database, sessions, source = environment
    snapshot = tmp_path / "runtime.json"
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_path", str(snapshot))
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "worker.lock"))
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", 0)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=10)

    monkeypatch.setattr(firewall_runtime_snapshot, "datetime", Clock)
    monkeypatch.setattr(baseline_recovery, "datetime", Clock)
    wide = approve(sessions, source)["item"]["id"]
    legacy_key = _rule_key(build_rule_args(FirewallRuleSpec(source, IP, MQTT_IPV4_TCP_1883), operation=INSERT))
    runner = ScopedRuntimeFake(installed=[legacy_key])
    with sessions() as db:
        db.execute(text("UPDATE firewall_rules SET retry_count=2 WHERE id=:id"), {"id": wide})
        db.commit()
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=1))
        assert result.transient_failed == [wide]
        assert db.execute(text("SELECT status FROM firewall_rules WHERE id=:id"), {"id": wide}).scalar_one() == "FAILED"
        source_release = releases.create_release_request(db, firewall_rule_id=source, requested_by="test-admin", reason="separate legacy cleanup", requested_at=NOW + timedelta(seconds=2))
        db.commit()
        result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=3))
        assert result.succeeded == [source_release]
    observed = firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=4))
    assert observed["managed_rules"] == [{"rule_id": wide, "source_ip": IP, "scope": PI_INPUT_IPV4_ALL}]

    def preflight():
        return baseline_recovery.inspect_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts")

    report = preflight()
    assert report["active_firewall_rule_check"]["passed"]
    assert not report["can_execute"]
    assert report["runtime_firewall_check"][DEVICE]["status"] == "ACTIVE"
    with sessions() as db:
        wide_release = releases.create_release_request(db, firewall_rule_id=wide, requested_by="test-admin", reason="audited failed-wide residue cleanup", requested_at=NOW + timedelta(seconds=5))
        db.commit()
        assert not preflight()["pending_firewall_release_request_check"]["passed"]
        result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=6))
        assert result.succeeded == [wide_release]
        assert db.execute(text("SELECT status FROM firewall_rules WHERE id=:id"), {"id": wide}).scalar_one() == "REMOVED"
    assert runner.installed == []
    assert not preflight()["can_execute"]  # Old observation predates exact deletion.
    firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=7))
    assert preflight()["can_execute"]
    result = baseline_recovery.execute_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts", confirm=baseline_recovery.CONFIRMATION)
    assert result["result"] == "SUCCESS"
    with sessions() as db:
        assert db.execute(text("SELECT status,trust_score FROM devices")).one() == ("normal", 100)
        assert db.execute(text("SELECT count(*) FROM firewall_rules WHERE status='REMOVED'")).scalar_one() == 2
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests WHERE status='SUCCEEDED'")).scalar_one() == 2
