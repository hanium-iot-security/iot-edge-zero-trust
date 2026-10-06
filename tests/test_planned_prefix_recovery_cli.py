"""Manual prefix command sequencing on copied SQLite with fake systemd only."""
import json
import sqlite3

import pytest

from edge.maintenance import planned
from edge.maintenance import run_planned_maintenance as cli
from tests.test_planned_maintenance import NEW_BOOT, OLD_BOOT, TARGET, add_segment, add_session, protected, utc
from tests.test_planned_maintenance_cli import prepare, runner as base_runner


SUCCESSOR = "55555555-5555-4555-8555-555555555555"
THIRD = "66666666-6666-4666-8666-666666666666"
REASON = "Preserve and process the healthy first-boot prefix"


@pytest.fixture
def prefix_runner(base_runner):
    runner, system, directory = base_runner
    operation = prepare(runner)["operation"]["operation_id"]
    with sqlite3.connect(runner.database) as conn:
        target = add_session(conn, TARGET, 60, status="FAILED", gap=20)
        empty = add_segment(conn, target, 60, "EMPTY")
        conn.execute("UPDATE packet_capture_segments SET packet_count=16 WHERE id=?", (empty,))
        add_segment(conn, target, 70)
        add_segment(conn, target, 80)
        failure = conn.execute(
            "INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,"
            "window_end,status,packet_count,error_code,error_message,start_delay_seconds,captured_duration_seconds) "
            "VALUES (?,NULL,'eth0',?,?,'FAILED',NULL,'LATE_CAPTURE','uncaptured late start',1.166,0)",
            (target, utc(90), utc(100)),
        ).lastrowid
        conn.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE id=?", (utc(91), target))
        successor = add_session(conn, SUCCESSOR, 100)
        add_segment(conn, successor, 100)
    system.identity, system.elapsed = NEW_BOOT, 120
    system.services = {unit: True for unit in cli.MANAGED_SERVICES}
    system.events.clear()
    return runner, system, directory, operation, target, failure


def recover(fixture, **changes):
    runner, _, directory, operation, _, _ = fixture
    options = dict(operation_id=operation, target_session_id=TARGET, successor_session_id=SUCCESSOR,
                   approved_by="woomin", reason=REASON, artifact_dir=directory / "artifacts",
                   timeout=0, verify_timeout=0)
    options.update(changes)
    return runner.recover_prefix(**options)


def snapshot(runner):
    with sqlite3.connect(runner.database) as conn:
        return protected(conn)


def audit_count(runner):
    with sqlite3.connect(runner.database) as conn:
        return conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0]


def simulate_pipeline_drain(fixture):
    """Only fake progress observation; real pipeline processing has separate tests."""
    runner, _, _, _, target, _ = fixture
    with sqlite3.connect(runner.database) as conn:
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=?", (utc(90), utc(90)))
        for name in planned.PACKET_DETECTORS:
            direction = "AND f.direction='INBOUND'" if name == "packet_rule" else ""
            last_id = conn.execute(
                "SELECT MAX(f.id) FROM packet_feature_logs f JOIN packet_capture_segments s "
                "ON s.id=f.capture_segment_id WHERE s.capture_session_id=? " + direction, (target,)).fetchone()[0]
            conn.execute("UPDATE detector_checkpoints SET last_processed_id=? WHERE detector_name=?", (last_id, name))


def test_readonly_prefix_preview_binds_exact_sessions_and_never_stops_services(prefix_runner):
    runner, system, _, operation, _, _ = prefix_runner
    before = snapshot(runner)
    result = runner.dry_run_prefix(operation_id=operation, target_session_id=TARGET,
                                   successor_session_id=SUCCESSOR, approved_by="woomin", reason=REASON)
    assert result["target_session_id"] == TARGET
    assert result["maintenance_end"] == utc(60)
    assert result["failed_prefix_recovery"]["prefix_end"] == utc(90)
    assert snapshot(runner) == before and audit_count(runner) == 0
    assert system.events == []


def test_prefix_recovery_requires_real_admin_before_backup_or_service_changes(prefix_runner):
    runner, system, directory, _, _, _ = prefix_runner
    system.admin = False
    with pytest.raises(cli.MaintenanceHold, match="root required"):
        recover(prefix_runner)
    assert not (directory / "artifacts").exists() and audit_count(runner) == 0
    assert system.events == ["authenticate"]


@pytest.mark.parametrize("changes", [{"approved_by": "  "}, {"reason": "  "}])
def test_empty_explicit_identity_is_rejected(prefix_runner, changes):
    runner, system, _, _, _, _ = prefix_runner
    with pytest.raises(cli.MaintenanceHold, match="operator and reason"):
        recover(prefix_runner, **changes)
    assert audit_count(runner) == 0
    assert system.events == ["authenticate"]


def test_backup_failure_cannot_consume_prefix_approval_or_stop_receivers(prefix_runner):
    runner, system, _, operation, _, _ = prefix_runner
    runner.backup = lambda *_: (_ for _ in ()).throw(cli.MaintenanceHold("backup full"))
    with pytest.raises(cli.MaintenanceHold, match="backup full"):
        recover(prefix_runner)
    assert runner.status(operation)["operation"]["status"] == "READY" and audit_count(runner) == 0
    assert system.events == ["authenticate"]


def test_timeout_after_commit_preserves_data_and_restores_only_orchestrator(prefix_runner):
    runner, system, _, operation, _, _ = prefix_runner
    before = snapshot(runner)
    result = recover(prefix_runner)
    assert result["result"] == "COMMITTED_HOLD"
    assert result["verification"]["result"] == "WAIT"
    assert runner.status(operation)["operation"]["status"] == "RESUMED"
    assert audit_count(runner) == 1 and snapshot(runner) == before
    assert [event for event in system.events if isinstance(event, tuple)] == [
        ("stop", "detection-orchestrator.service"), ("start", "detection-orchestrator.service")]
    with sqlite3.connect(runner.database) as conn:
        rows = conn.execute("SELECT last_processed_id,last_completed_window_end FROM detector_checkpoints "
                            "WHERE detector_name IN ('packet_rule','packet_if')").fetchall()
    assert rows == [(2, utc(60)), (2, utc(60))]


def test_success_waits_for_real_check_contract_and_keeps_failed_tail(prefix_runner):
    runner, system, _, operation, _, failure = prefix_runner
    before = snapshot(runner)
    system.on_sleep = lambda: simulate_pipeline_drain(prefix_runner)
    result = recover(prefix_runner, verify_timeout=2)
    assert result["result"] == "PREFIX_DRAINED_RECOVERY_REQUIRED"
    assert result["verification"]["failed_segment_id"] == failure
    assert snapshot(runner) == before and audit_count(runner) == 1
    assert runner.status(operation)["operation"]["maintenance_end"] == utc(60)


@pytest.mark.parametrize("changed", ["operator", "reason", "boot", "successor"])
def test_committed_retry_identity_mismatch_never_reapplies(prefix_runner, changed):
    runner, system, _, _, _, _ = prefix_runner
    assert recover(prefix_runner)["result"] == "COMMITTED_HOLD"
    before, calls = snapshot(runner), system.events[:]
    changes = {}
    if changed == "operator":
        changes["approved_by"] = "someone-else"
    elif changed == "reason":
        changes["reason"] = "different scope"
    elif changed == "boot":
        system.identity = OLD_BOOT
    else:
        changes["successor_session_id"] = THIRD
    result = recover(prefix_runner, **changes)
    assert result["result"] in ("HOLD", "WAIT")
    assert audit_count(runner) == 1 and snapshot(runner) == before
    assert system.events == calls + ["authenticate"]


def test_same_identity_retry_only_observes_drain_and_reuses_audit(prefix_runner):
    runner, system, _, _, _, _ = prefix_runner
    first = recover(prefix_runner)
    simulate_pipeline_drain(prefix_runner)
    calls, before = system.events[:], snapshot(runner)
    second = recover(prefix_runner)
    assert second["result"] == "PREFIX_DRAINED_RECOVERY_REQUIRED" and second["reapplied"] is False
    assert first["audit"]["plan_sha256"] == second["audit"]["plan_sha256"]
    assert audit_count(runner) == 1 and snapshot(runner) == before
    assert system.events == calls + ["authenticate"]


def test_successor_race_before_apply_holds_and_restores_orchestrator(prefix_runner):
    runner, system, _, operation, _, _ = prefix_runner
    real_backup = runner.backup

    def backup(database, root):
        evidence = real_backup(database, root)
        with sqlite3.connect(database) as conn:
            conn.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE session_id=?",
                         (utc(115), SUCCESSOR))
            successor = add_session(conn, THIRD, 120)
            add_segment(conn, successor, 120)
        return evidence

    runner.backup = backup
    with pytest.raises(cli.MaintenanceHold, match="successor Session changed"):
        recover(prefix_runner)
    assert runner.status(operation)["operation"]["status"] == "READY" and audit_count(runner) == 0
    assert system.services["detection-orchestrator.service"] is True
    assert system.services[cli.CAPTURE] is True and system.services[cli.SUBSCRIBER] is True


def test_lost_committed_response_reports_hold_without_second_transition(prefix_runner, monkeypatch):
    runner, system, _, operation, _, _ = prefix_runner
    real_apply = planned.apply_prefix_recovery

    def apply_and_lose_response(conn, plan, **kwargs):
        real_apply(conn, plan, **kwargs)
        conn.commit()
        raise RuntimeError("committed response lost")

    monkeypatch.setattr(planned, "apply_prefix_recovery", apply_and_lose_response)
    result = recover(prefix_runner)
    assert result["result"] == "COMMITTED_HOLD" and "response lost" in result["reason"]
    assert runner.status(operation)["operation"]["status"] == "RESUMED" and audit_count(runner) == 1
    assert system.services["detection-orchestrator.service"] is True


def test_interrupt_after_commit_reports_consumed_hold_and_preserves_audit(prefix_runner):
    runner, system, _, operation, _, _ = prefix_runner

    def interrupted():
        raise KeyboardInterrupt("drain interrupted")

    system.on_sleep = interrupted
    result = recover(prefix_runner, verify_timeout=2)
    assert result["result"] == "COMMITTED_HOLD"
    assert "interrupted" in result["verification"]["reason"]
    assert runner.status(operation)["operation"]["status"] == "RESUMED" and audit_count(runner) == 1
    assert all(system.services.values())


def test_prefix_parser_requires_explicit_scope_and_keeps_normal_resume_defaults():
    parser = cli.build_parser()
    options = ["--operation-id", "o", "--target-session-id", "t", "--successor-session-id", "s",
               "--approved-by", "woomin", "--reason", REASON]
    prefix = parser.parse_args(["recover-prefix", *options])
    assert prefix.timeout == 30 and prefix.verify_timeout == 120
    assert parser.parse_args(["resume"]).timeout == 120
    assert parser.parse_args(["dry-run-prefix", *options]).target_session_id == "t"
    with pytest.raises(SystemExit):
        parser.parse_args(["recover-prefix", "--operation-id", "o"])
