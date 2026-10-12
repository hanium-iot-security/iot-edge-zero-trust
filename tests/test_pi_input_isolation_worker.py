"""Scoped Worker safety against actual migration/policy/release SQLite rows.

No sudo or OS firewall operations: FakeIptablesRunner models exact rule identity.
"""

from datetime import timedelta

import pytest
from sqlalchemy import text

from edge.trust import firewall_repository
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL, row_scope
from edge.trust.firewall_worker import (
    CHECK, DELETE, INSERT, LIST_RULES, FirewallPolicy, FirewallRuleSpec,
    FirewallValidationError, WrapperIptablesRunner, build_rule_args,
    process_pending_release_requests, process_pending_rules, reconcile, release_rule,
    validate_rule_row,
)
from tests.test_firewall_worker import FakeIptablesRunner, _rule_key
from tests.test_phase8_firewall_policy_gate import (
    DEVICE, IP, NOW, _revision, _row, _seed, environment,
)

REQUEST_ID = "fd7d2228-e71b-4cc0-bd10-948f02dbd1ce"


def _create_wide(sessions, source_id):
    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        row, created = firewall_repository.create_pending_scope_extension(
            db, source_rule_id=source_id, device_id=DEVICE, source_ip=IP,
            approved_policy_revision=1, requested_by="fixture-admin", reason="approved wider isolation",
            request_id=REQUEST_ID, scope=PI_INPUT_IPV4_ALL, now=NOW,
        )
        assert created
        db.commit()
        return row["id"]


def _key(rule_id, scope=PI_INPUT_IPV4_ALL):
    return _rule_key(build_rule_args(FirewallRuleSpec(rule_id, IP, scope), operation=INSERT))


def _release_request(db, rule_id):
    from edge.trust import firewall_release_repository
    request = firewall_release_repository.create_release_request(
        db, firewall_rule_id=rule_id, requested_by="fixture-admin",
        reason="approved exact residue cleanup", requested_at=NOW,
    )
    db.commit()
    return request


def _apply_wide(db, wide_id):
    firewall_repository.mark_applied(db, rule_id=wide_id, applied_at=NOW)
    db.commit()


def test_worker_applies_wide_without_mutating_source_or_device(environment):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    runner = FakeIptablesRunner(installed=[_key(source_id, MQTT_IPV4_TCP_1883)])
    with sessions() as db:
        source_before = _row(db, source_id)
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.applied == [wide_id]
        assert _row(db, source_id) == source_before
        assert _row(db, wide_id)["status"] == "APPLIED"
        assert db.execute(text("SELECT trust_score,status FROM devices")).one() == (20, "isolated")
        assert db.execute(text("SELECT count(*) FROM trust_score_history")).scalar_one() == 0
    assert runner.operations() == [CHECK, INSERT]
    assert "-p" not in runner.calls[-1] and "--dport" not in runner.calls[-1]
    assert set(runner.installed) == {_key(source_id, MQTT_IPV4_TCP_1883), _key(wide_id)}


def test_pending_crash_converges_without_duplicate_wide_insert(environment):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    runner = FakeIptablesRunner(installed=[_key(wide_id)])
    with sessions() as db:
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.already_present == [wide_id]
        assert _row(db, wide_id)["status"] == "APPLIED"
    assert runner.operations() == [CHECK]
    assert runner.installed == [_key(wide_id)]


@pytest.mark.parametrize("change", ["ip", "policy_revision", "device_status", "source_failed", "source_release", "wide_release"])
def test_restore_rechecks_current_approval_and_never_reinserts_changed_wide(environment, change):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    with sessions() as db:
        _apply_wide(db, wide_id)
        if change == "ip":
            db.execute(text("UPDATE devices SET ip_address='192.168.0.99'"))
        elif change == "device_status":
            db.execute(text("UPDATE devices SET status='normal'"))
        elif change == "policy_revision":
            _revision(db.connection().connection.driver_connection, 2, NOW - timedelta(seconds=10), "ACTIVE")
        elif change == "source_failed":
            db.execute(text("UPDATE firewall_rules SET status='FAILED' WHERE id=:id"), {"id": source_id})
        else:
            _release_request(db, source_id if change == "source_release" else wide_id)
        db.commit()
        before = _row(db, wide_id)
        runner = FakeIptablesRunner(installed=[_key(source_id, MQTT_IPV4_TCP_1883)])
        result = reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert wide_id not in result.restored
        assert _row(db, wide_id) == before
    assert INSERT not in runner.operations()
    assert all(f"hanium-firewall:{wide_id}" not in call for call in runner.calls)


def test_authorized_wide_restore_preserves_legacy_match(environment):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    with sessions() as db:
        _apply_wide(db, wide_id)
        runner = FakeIptablesRunner(installed=[_key(source_id, MQTT_IPV4_TCP_1883)])
        result = reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.verified == [source_id]
        assert result.restored == [wide_id]
    assert runner.calls[-1] == build_rule_args(FirewallRuleSpec(wide_id, IP, PI_INPUT_IPV4_ALL), operation=INSERT)


@pytest.mark.parametrize("residue", [False, True])
def test_failed_residue_requires_pending_audit_and_cleans_exact_wide_even_if_protected(environment, residue):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    actual = [_key(source_id, MQTT_IPV4_TCP_1883)] + ([_key(wide_id)] if residue else [])
    runner = FakeIptablesRunner(installed=actual)
    policy = FirewallPolicy(protected_ips=frozenset({IP}))
    with sessions() as db:
        db.execute(text("UPDATE firewall_rules SET status='FAILED' WHERE id=:id"), {"id": wide_id})
        db.commit()
        with pytest.raises(FirewallValidationError, match="audited pending release"):
            release_rule(db, rule_id=wide_id, runner=runner, policy=policy, now=NOW)
        assert runner.calls == []
        db.rollback()
        request_id = _release_request(db, wide_id)
        result = process_pending_release_requests(db, runner=runner, policy=policy, now=NOW)
        assert result.succeeded == [request_id]
        assert _row(db, wide_id)["status"] == "REMOVED"
        assert _row(db, source_id)["status"] == "APPLIED"
        assert db.execute(text("SELECT status FROM firewall_release_requests")).scalar_one() == "SUCCEEDED"
    assert runner.installed == [_key(source_id, MQTT_IPV4_TCP_1883)]
    assert runner.operations() == ([CHECK, DELETE, CHECK] if residue else [CHECK])


def test_duplicate_exact_residue_never_claims_release_success(environment):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    with sessions() as db:
        _apply_wide(db, wide_id)
        request_id = _release_request(db, wide_id)
        runner = FakeIptablesRunner(installed=[_key(wide_id), _key(wide_id)])
        result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.failed == [request_id]
        assert _row(db, wide_id)["status"] == "APPLIED"
        assert db.execute(text("SELECT status FROM firewall_release_requests")).scalar_one() == "FAILED"
    assert runner.installed == [_key(wide_id)]


def test_removed_wide_crash_convergence_uses_release_join_scope(environment):
    database, sessions = environment
    source_id = _seed(database, status="APPLIED")
    wide_id = _create_wide(sessions, source_id)
    with sessions() as db:
        _apply_wide(db, wide_id)
        request_id = _release_request(db, wide_id)
        firewall_repository.mark_removed(db, rule_id=wide_id, released_at=NOW)
        db.commit()
        runner = FakeIptablesRunner(installed=[_key(source_id, MQTT_IPV4_TCP_1883)])
        result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(protected_ips=frozenset({IP})), now=NOW+timedelta(seconds=10))
        assert result.already_removed == [request_id]
        assert db.execute(text("SELECT processed_at FROM firewall_release_requests")).scalar_one() == "2026-10-03T12:00:10Z"
    assert runner.calls == [build_rule_args(FirewallRuleSpec(wide_id, IP, PI_INPUT_IPV4_ALL), operation=CHECK)]


@pytest.mark.parametrize("scope", [None, "", "UNKNOWN", "PI_INPUT_IPV6_ALL"])
def test_unknown_scope_cannot_reach_matcher_or_wrapper_runner(monkeypatch, scope):
    def unexpected(*args, **kwargs):
        pytest.fail("unknown scope invoked subprocess")
    monkeypatch.setattr("edge.trust.firewall_worker.subprocess.run", unexpected)
    with pytest.raises(ValueError):
        spec = FirewallRuleSpec(1, IP, scope)
        build_rule_args(spec, operation=INSERT)
        WrapperIptablesRunner(FirewallPolicy()).run_operation(INSERT, spec)
    with pytest.raises(FirewallValidationError):
        validate_rule_row({"id":1,"source_ip":IP,"scope":scope,"protocol":"tcp","dest_port":1883,"action":"DROP"}, FirewallPolicy())
    assert row_scope({"id": 1}) == MQTT_IPV4_TCP_1883
