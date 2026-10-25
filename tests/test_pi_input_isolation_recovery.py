"""Scoped partial failure through audited exact release and baseline recovery."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from backend.app.config import settings
from edge.trust import baseline_recovery, firewall_runtime_snapshot
from edge.trust import firewall_release_repository as releases
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from edge.trust.firewall_worker import (
    CHECK, INSERT, LIST_RULES, CommandResult, FirewallPolicy, FirewallRuleSpec,
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
        if operation == INSERT and spec.scope == PI_INPUT_IPV4_ALL and result.returncode == 0:
            raise FirewallTransientError("simulated timeout after wide insert")
        return result


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
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
    return snapshot


@pytest.mark.parametrize("current_ip,extra_failed_ip", [(IP, None), ("192.168.0.44", None), ("192.168.0.44", "192.168.0.11")], ids=["same-ip", "registered-ip-changed", "later-historical-ip-has-residue"])
def test_failed_wide_residue_holds_until_exact_audited_release_and_later_snapshot(environment, tmp_path, snapshot, current_ip, extra_failed_ip):
    database, sessions, source = environment
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
        # Model explicit registry drift; physical DHCP changes alone do not
        # update devices.ip_address through the current registration API.
        db.execute(text("UPDATE devices SET ip_address=:ip WHERE device_id=:device"), {"ip": current_ip, "device": DEVICE})
        if extra_failed_ip:
            db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,status,last_attempted_at) VALUES (:device,:ip,'FAILED',:time)"), {"device": DEVICE, "ip": extra_failed_ip, "time": (NOW + timedelta(seconds=1)).isoformat()})
        db.commit()
    observed = firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=4))
    assert observed["managed_rules"] == [{"rule_id": wide, "source_ip": IP, "scope": PI_INPUT_IPV4_ALL}]

    def preflight():
        return baseline_recovery.inspect_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts")

    report = preflight()
    assert report["active_firewall_rule_check"]["passed"]
    assert not report["can_execute"]
    assert report["runtime_firewall_check"][DEVICE]["status"] == "ACTIVE"
    assert IP in report["runtime_firewall_check"][DEVICE]["details"]
    with pytest.raises(baseline_recovery.BaselineRecoveryHoldError, match="Runtime firewall release is not verified"):
        baseline_recovery.execute_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts", confirm=baseline_recovery.CONFIRMATION)
    with sessions() as db:
        assert db.execute(text("SELECT status,trust_score FROM devices")).one() == ("isolated", 20)
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
    if current_ip != IP:
        # A completed exact release must not bind this device to an old IP
        # forever when a different rule later uses that address.
        with sessions() as db:
            unrelated = db.execute(text("INSERT INTO firewall_rules(source_ip,status,applied_at) VALUES (:ip,'APPLIED',:time)"), {"ip": IP, "time": (NOW + timedelta(seconds=8)).isoformat()}).lastrowid
            db.commit()
        runner.installed.append(_rule_key(build_rule_args(FirewallRuleSpec(unrelated, IP, MQTT_IPV4_TCP_1883), operation=INSERT)))
        assert preflight()["can_execute"]  # Released old IP no longer extends freshness.
        firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=9))
    assert preflight()["can_execute"]
    result = baseline_recovery.execute_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts", confirm=baseline_recovery.CONFIRMATION)
    assert result["result"] == "SUCCESS"
    with sessions() as db:
        assert db.execute(text("SELECT status,trust_score FROM devices")).one() == ("normal", 100)
        assert db.execute(text("SELECT count(*) FROM firewall_rules WHERE status='REMOVED'")).scalar_one() == 2
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests WHERE status='SUCCEEDED'")).scalar_one() == 2


@pytest.fixture
def failed_wide_without_residue(environment, snapshot):
    database, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    legacy_key = _rule_key(build_rule_args(FirewallRuleSpec(source, IP, MQTT_IPV4_TCP_1883), operation=INSERT))
    runner = ScopedRuntimeFake(installed=[legacy_key], fail_operations={INSERT: 1})
    with sessions() as db:
        db.execute(text("UPDATE firewall_rules SET retry_count=2 WHERE id=:id"), {"id": wide})
        db.commit()
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=1))
        assert result.transient_failed == [wide]
        source_release = releases.create_release_request(db, firewall_rule_id=source, requested_by="test-admin", reason="separate legacy cleanup", requested_at=NOW + timedelta(seconds=2))
        db.commit()
        result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=3))
        assert result.succeeded == [source_release]
    assert runner.installed == []
    return database, sessions, wide, runner


@pytest.mark.parametrize("current_ip", [IP, "192.168.0.44"], ids=["same-ip", "registered-ip-changed"])
def test_failed_wide_without_runtime_residue_allows_recovery_after_fresh_snapshot(failed_wide_without_residue, tmp_path, snapshot, current_ip):
    database, sessions, wide, runner = failed_wide_without_residue
    with sessions() as db:
        db.execute(text("UPDATE devices SET ip_address=:ip WHERE device_id=:device"), {"ip": current_ip, "device": DEVICE})
        db.commit()

    def preflight():
        return baseline_recovery.inspect_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts")

    firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=3))
    assert not preflight()["can_execute"]  # Same-second absence is not release proof.
    firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=4))
    assert preflight()["can_execute"]
    result = baseline_recovery.execute_baseline_recovery(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts", confirm=baseline_recovery.CONFIRMATION)
    assert result["result"] == "SUCCESS"
    with sessions() as db:
        assert db.execute(text("SELECT status,trust_score FROM devices")).one() == ("normal", 100)
        assert db.execute(text("SELECT status FROM firewall_rules WHERE id=:id"), {"id": wide}).scalar_one() == "FAILED"


@pytest.mark.parametrize("entrypoint", ["preflight", "execute"])
@pytest.mark.parametrize("activity", ["apply", "failed-release"])
def test_old_ip_activity_after_snapshot_holds_recovery(failed_wide_without_residue, tmp_path, snapshot, entrypoint, activity):
    database, sessions, _, runner = failed_wide_without_residue
    with sessions() as db:
        db.execute(text("UPDATE devices SET ip_address='192.168.0.44' WHERE device_id=:device"), {"device": DEVICE})
        db.execute(text("INSERT INTO devices(device_id,ip_address,status,trust_score) VALUES ('replacement',:ip,'isolated',20)"), {"ip": IP})
        db.execute(text("""INSERT INTO device_policy_revisions
            (device_id,revision,effective_from,registration_state,policy_profile,
             expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
             packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason)
            SELECT 'replacement',revision,effective_from,registration_state,policy_profile,
                   expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
                   packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason
            FROM device_policy_revisions WHERE device_id=:device"""), {"device": DEVICE})
        other_rule = db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,status,last_attempted_at) VALUES ('replacement',:ip,:status,:time)"), {"ip": IP, "status": "PENDING" if activity == "apply" else "FAILED", "time": (NOW + timedelta(seconds=3)).isoformat()}).lastrowid
        db.commit()
    clean = firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=4))
    assert clean["managed_rules"] == []
    with sessions() as db:
        if activity == "apply":
            result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=5))
            assert result.applied == [other_rule]
            assert runner.installed == [_rule_key(build_rule_args(FirewallRuleSpec(other_rule, IP, MQTT_IPV4_TCP_1883), operation=INSERT))]
        else:
            request = releases.create_release_request(db, firewall_rule_id=other_rule, requested_by="test-admin", reason="old IP cleanup", requested_at=NOW + timedelta(seconds=4))
            db.commit()
            runner.fail_operations[CHECK] = 1
            result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(), now=NOW + timedelta(seconds=5))
            assert result.failed == [request]
            assert db.execute(text("SELECT last_attempted_at FROM firewall_rules WHERE id=:id"), {"id": other_rule}).scalar_one() == (NOW + timedelta(seconds=3)).isoformat()

    kwargs = dict(db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20}, artifact_dir=tmp_path / "artifacts")
    if entrypoint == "preflight":
        report = baseline_recovery.inspect_baseline_recovery(**kwargs)
        assert report["active_firewall_rule_check"]["passed"]
        assert not report["can_execute"]
        assert report["runtime_firewall_check"][DEVICE]["status"] == "UNAVAILABLE"
    else:
        with pytest.raises(baseline_recovery.BaselineRecoveryHoldError, match="last firewall attempt/release"):
            baseline_recovery.execute_baseline_recovery(**kwargs, confirm=baseline_recovery.CONFIRMATION)
    with sessions() as db:
        assert db.execute(text("SELECT status,trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE}).one() == ("isolated", 20)
    firewall_runtime_snapshot.capture_firewall_runtime_snapshot(runner, snapshot_path=snapshot, observed_at=NOW + timedelta(seconds=6))
    report = baseline_recovery.inspect_baseline_recovery(**kwargs)
    assert report["devices"][0]["last_firewall_activity_at"] == (NOW + timedelta(seconds=5)).isoformat()
    assert report["can_execute"] is (activity == "failed-release")
    assert report["runtime_firewall_check"][DEVICE]["status"] == ("VERIFIED_RELEASED" if activity == "failed-release" else "ACTIVE")
