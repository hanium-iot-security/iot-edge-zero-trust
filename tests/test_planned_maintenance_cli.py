"""Operational sequencing with real migrated SQLite and fake systemd only."""
from contextlib import contextmanager
from datetime import timedelta
import inspect
import json
from pathlib import Path
import shlex
import sqlite3
import subprocess

import pytest

from edge.maintenance import planned
from edge.maintenance import run_planned_maintenance as cli
from tests.test_planned_maintenance import (
    BASE, NEW_BOOT, OLD_BOOT, SOURCE, TARGET, add_segment, add_session,
    seed_planned_maintenance_database, utc,
)


class FakeSystem:
    def __init__(self, database):
        self.database = database
        self.services = {unit: True for unit in cli.MANAGED_SERVICES}
        self.events, self.elapsed = [], 0
        self.identity, self.time_sync, self.admin = OLD_BOOT, True, True
        self.fail_stop, self.on_sleep = None, None

    def require_admin(self):
        self.events.append("authenticate")
        if not self.admin:
            raise cli.MaintenanceHold("root required")

    def boot_id(self):
        return self.identity

    def synchronized(self):
        return self.time_sync

    def active(self, unit):
        return self.services[unit]

    def stop(self, unit):
        self.events.append(("stop", unit))
        self.services[unit] = False
        if unit == self.fail_stop:
            raise cli.MaintenanceHold("injected unclean shutdown")
        if unit == cli.CAPTURE:
            with sqlite3.connect(self.database) as conn:
                conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                             (utc(20), SOURCE))
            self.elapsed = 5

    def start(self, unit):
        self.events.append(("start", unit))
        self.services[unit] = True

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds
        if self.on_sleep:
            self.on_sleep()

    def now(self):
        return BASE + timedelta(seconds=int(15 + self.elapsed))


@pytest.fixture
def runner(tmp_path, monkeypatch):
    database = tmp_path / "iot.db"
    conn, _ = seed_planned_maintenance_database(database)
    conn.close()
    system = FakeSystem(database)
    runner = cli.MaintenanceRunner(database, tmp_path, system=system,
                                   core=planned, locks=(tmp_path / "test.lock",), now=system.now)
    monkeypatch.setattr(runner, "required_checkpoints", lambda: planned.REQUIRED_CHECKPOINTS)
    return runner, system, tmp_path


def prepare(runner):
    return runner.prepare_stop(approved_by="woomin", reason="Planned test reboot", timeout=0)


def ready_target(runner, system):
    result = prepare(runner)
    with sqlite3.connect(runner.database) as conn:
        pk = add_session(conn, TARGET, 60, gap=20)
        add_segment(conn, pk, 60)
    system.identity, system.elapsed = NEW_BOOT, 60
    system.services = {unit: True for unit in cli.MANAGED_SERVICES}
    return result["operation"]["operation_id"]


def raw_status(runner):
    with sqlite3.connect(runner.database) as conn:
        return conn.execute("SELECT status FROM planned_maintenance_operations ORDER BY rowid DESC LIMIT 1").fetchone()[0]


def test_prepare_authenticates_stops_writers_then_drains_and_seals(runner):
    instance, system, _ = runner
    result = prepare(instance)
    assert result["result"] == "READY"
    assert result["operation"]["source_final_boundary"] == utc(20)
    assert result["operation"]["approved_by"] == "root/uid=0; declared=woomin"
    assert system.events[0] == "authenticate"
    assert system.events[1:3] == [("stop", cli.CAPTURE), ("stop", cli.SUBSCRIBER)]
    assert [event[1] for event in system.events[3:]] == list(cli.STOP_AFTER_DRAIN)
    assert not any(system.services.values())
    with sqlite3.connect(instance.database) as conn:
        assert conn.execute("SELECT trust_score,status FROM devices").fetchone() == (20, "isolated")
        assert conn.execute("SELECT status FROM firewall_rules").fetchone()[0] == "APPLIED"


def test_declared_approver_does_not_authenticate_user(runner):
    instance, system, _ = runner
    system.admin = False
    with pytest.raises(cli.MaintenanceHold, match="root required"):
        prepare(instance)
    assert system.events == ["authenticate"]
    assert instance.status()["operation"] is None


def test_inactive_drain_service_fails_before_approval_or_stop(runner):
    instance, system, _ = runner
    system.services["detection-orchestrator.service"] = False
    with pytest.raises(cli.MaintenanceHold, match="drain services"):
        prepare(instance)
    assert not any(isinstance(event, tuple) for event in system.events)
    assert instance.status()["operation"] is None


def test_unclean_subscriber_cancels_before_restoring_services(runner):
    instance, system, _ = runner
    system.fail_stop = cli.SUBSCRIBER
    with pytest.raises(cli.MaintenanceHold, match="unclean"):
        prepare(instance)
    assert raw_status(instance) == "CANCELLED"
    assert all(system.services.values())
    assert system.events[-2:] == [("start", cli.SUBSCRIBER), ("start", cli.CAPTURE)]


def test_keyboard_interrupt_without_message_cancels_approval_and_restores_before_reraise(runner):
    instance, system, _ = runner
    original = system.stop

    def interrupt(unit):
        if unit == cli.SUBSCRIBER:
            system.services[unit] = False
            raise KeyboardInterrupt()
        original(unit)

    system.stop = interrupt
    with pytest.raises(KeyboardInterrupt):
        prepare(instance)
    assert raw_status(instance) == "CANCELLED"
    assert all(system.services.values())
    operation = instance.status()["operation"]
    assert "KeyboardInterrupt" in operation["cancellation_reason"]


def test_unprocessed_old_event_blocks_ready_and_restores_writers(runner):
    instance, system, _ = runner
    with sqlite3.connect(instance.database) as conn:
        conn.execute("INSERT INTO detection_events(device_id,detector_type,event_type,severity,score_delta,description,"
                     "detected_at,analysis_window_start,analysis_window_end,incident_family) "
                     "VALUES ('esp32_01','RULE','TEST','LOW',-5,'pending',?,?,?,'TEST')",
                     (utc(5), utc(0), utc(10)))
    with pytest.raises(cli.MaintenanceHold, match="drain timed out"):
        prepare(instance)
    assert raw_status(instance) == "CANCELLED"
    assert all(system.services.values())
    assert not any(event == ("stop", "detection-orchestrator.service") for event in system.events)


def test_finalize_race_after_drain_is_not_sealed(runner):
    instance, system, _ = runner
    old_stop = system.stop

    def stop(unit):
        old_stop(unit)
        if unit == "detection-orchestrator.service":
            with sqlite3.connect(instance.database) as conn:
                conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_if'",
                             (utc(10),))

    system.stop = stop
    with pytest.raises(cli.MaintenanceHold):
        prepare(instance)
    assert raw_status(instance) == "CANCELLED"
    assert all(system.services.values())


def test_backup_failure_never_consumes_approval(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    instance.backup = lambda *_: (_ for _ in ()).throw(cli.MaintenanceHold("backup full"))
    before = system.events[:]
    with pytest.raises(cli.MaintenanceHold, match="backup full"):
        instance.resume(operation_id=operation, artifact_dir=directory / "artifacts", timeout=0)
    assert raw_status(instance) == "READY"
    assert system.events == before + ["authenticate"]


def test_same_boot_time_unsynchronized_or_no_feature_waits_without_consuming(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    system.identity = OLD_BOOT
    result = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0)
    assert result["result"] == "WAIT" and "Same-boot" in result["reason"]
    system.identity, system.time_sync = NEW_BOOT, False
    result = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0)
    assert result["result"] == "WAIT" and "synchronized" in result["reason"]
    system.time_sync = True
    with sqlite3.connect(instance.database) as conn:
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id IN "
                     "(SELECT seg.id FROM packet_capture_segments seg JOIN packet_capture_sessions ses "
                     "ON ses.id=seg.capture_session_id WHERE ses.session_id=?)", (TARGET,))
    result = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0)
    assert result["result"] == "WAIT"
    assert raw_status(instance) == "READY"
    assert not (directory / "a").exists()


def test_resume_accepts_benign_append_and_backup_is_outside_write_transaction(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    actual_backup = instance.backup

    def backup(database, root):
        # A different connection can acquire its writer lock during snapshot work.
        with sqlite3.connect(database, timeout=0) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at) "
                         "VALUES ('esp32_01','iot/esp32_01','{}',2,?)", (utc(75),))
        evidence = actual_backup(database, root)
        with sqlite3.connect(database, timeout=0) as conn:
            conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at) "
                         "VALUES ('esp32_01','iot/esp32_01','{}',2,?)", (utc(76),))
        return evidence

    instance.backup = backup
    result = instance.resume(operation_id=operation, artifact_dir=directory / "artifacts",
                             timeout=0, verify_timeout=0)
    assert result["result"] == "COMMITTED_HOLD"
    assert raw_status(instance) == "RESUMED"
    with sqlite3.connect(instance.database) as conn:
        pair = conn.execute("SELECT last_processed_id,last_completed_window_end FROM detector_checkpoints "
                            "WHERE detector_name IN ('packet_rule','packet_if')").fetchall()
        assert pair == [(2, utc(60)), (2, utc(60))]
        assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 1
    retry = instance.resume(operation_id=operation, artifact_dir=directory / "never-created", timeout=0,
                            verify_timeout=0)
    assert retry["result"] == "COMMITTED_HOLD"
    assert retry["audit"]["operation_id"] == result["audit"]["operation_id"]
    assert not (directory / "never-created").exists()


def test_changed_backup_binding_blocks_apply(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    original = instance.backup

    def backup(database, root):
        evidence = original(database, root)
        with sqlite3.connect(evidence["backup_path"]) as conn:
            conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_if'",
                         (utc(10),))
        return evidence

    instance.backup = backup
    with pytest.raises(planned.PlannedMaintenanceError):
        instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0)
    assert raw_status(instance) == "READY"


def test_two_consecutive_checkpoint_advances_after_commit_pass(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    frame = 70

    def advance():
        nonlocal frame
        frame += 10
        system.elapsed += 9
        with sqlite3.connect(instance.database) as conn:
            conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?", (utc(frame),))

    system.on_sleep = advance
    result = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0,
                             verify_timeout=30)
    assert result["result"] == "RESUMED"
    assert len(result["verification"]["snapshots"]) == 2
    assert [(event[0], event[1]) for event in system.events[len(cli.MANAGED_SERVICES)+1:]
            if isinstance(event, tuple)] == [("stop", "detection-orchestrator.service"),
                                            ("start", "detection-orchestrator.service")]


def test_checkpoint_regression_or_session_change_never_reports_pass(runner):
    instance, system, _ = runner
    ready_target(instance, system)
    frame = 70

    def advance_with_regression():
        nonlocal frame
        frame += 10
        with sqlite3.connect(instance.database) as conn:
            conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?", (utc(frame),))
            conn.execute("UPDATE detector_checkpoints SET last_processed_id=0 WHERE detector_name='packet_if'")

    system.on_sleep = advance_with_regression
    result = instance.verify_progress(TARGET, planned.REQUIRED_CHECKPOINTS, timeout=3)
    assert result["result"] == "WAIT"
    with sqlite3.connect(instance.database) as conn:
        conn.execute("UPDATE packet_capture_sessions SET status='FAILED' WHERE session_id=?", (TARGET,))
    with pytest.raises(cli.MaintenanceHold, match="RUNNING"):
        instance.verify_progress(TARGET, planned.REQUIRED_CHECKPOINTS, timeout=0)


def test_readonly_preview_status_have_no_os_mutations(runner):
    instance, system, _ = runner
    ready_target(instance, system)
    system.admin = False
    before = system.events[:]
    assert instance.status()["operation"]["status"] == "READY"
    assert instance.dry_run()["can_execute"] is True
    assert system.events == before


def test_resume_stops_persistent_orchestrator_lock_owner_and_restores_on_failure(runner, monkeypatch):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    original = instance.protected

    @contextmanager
    def persistent_lock():
        assert not system.services["detection-orchestrator.service"]
        with original():
            raise cli.MaintenanceHold("simulated contended extractor lock")
            yield

    monkeypatch.setattr(instance, "protected", persistent_lock)
    with pytest.raises(cli.MaintenanceHold, match="contended"):
        instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0)
    assert system.services["detection-orchestrator.service"]
    assert system.services[cli.CAPTURE] and system.services[cli.SUBSCRIBER]
    assert raw_status(instance) == "READY"


def test_consumed_approval_after_another_boot_returns_hold_without_backup(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    first = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0,
                            verify_timeout=0)
    assert first["result"] == "COMMITTED_HOLD"
    system.identity = "55555555-5555-4555-8555-555555555555"
    result = instance.resume(operation_id=operation, artifact_dir=directory / "must-not-exist", timeout=120)
    assert result["result"] == "HOLD" and "another boot" in result["reason"]
    assert not (directory / "must-not-exist").exists()


def test_readonly_consumed_preview_validates_boot_session_and_audit(runner, monkeypatch):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0, verify_timeout=0)
    before = system.events[:]
    preview = instance.dry_run(operation)
    assert preview["result"] == "ALREADY_RESUMED" and preview["audit"]["operation_id"] == operation
    system.identity = OLD_BOOT
    assert instance.dry_run(operation)["result"] == "HOLD"
    system.identity = NEW_BOOT
    monkeypatch.setattr(planned, "get_resume_audit", lambda *_: (_ for _ in ()).throw(
        planned.PlannedMaintenanceError("audit validation failed")))
    with pytest.raises(planned.PlannedMaintenanceError, match="audit"):
        instance.dry_run(operation)
    assert system.events == before


def test_commit_response_failure_is_inspected_and_never_reapplied(runner, monkeypatch):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    original = planned.apply_resume

    def lost_response(conn, plan, **kwargs):
        original(conn, plan, **kwargs)
        conn.commit()
        raise RuntimeError("lost response after commit")

    monkeypatch.setattr(planned, "apply_resume", lost_response)
    result = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0,
                             verify_timeout=0)
    assert result["result"] == "COMMITTED_HOLD"
    assert result["audit"]["operation_id"] == operation
    assert "lost response" in result["reason"]
    assert system.services["detection-orchestrator.service"]
    with sqlite3.connect(instance.database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 1


def test_postcommit_service_restore_failure_retains_audit(runner):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    system.start = lambda _unit: (_ for _ in ()).throw(RuntimeError("start failed"))
    result = instance.resume(operation_id=operation, artifact_dir=directory / "a", timeout=0,
                             verify_timeout=0)
    assert result["result"] == "COMMITTED_HOLD" and "restoration" in result["reason"]
    assert result["audit"]["operation_id"] == operation
    assert raw_status(instance) == "RESUMED"


def test_administrator_can_cancel_incomplete_request_without_service_or_checkpoint_changes(runner):
    instance, system, _ = runner
    with cli.connection(instance.database) as conn:
        conn.execute("BEGIN IMMEDIATE")
        operation = planned.request_stop(conn, approved_by="root", reason="Incomplete test", source_session_id=SOURCE,
                                         source_boot_id=OLD_BOOT, now=system.now())
        conn.commit()
        before = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")]
    events = system.events[:]
    result = instance.cancel(operation["operation_id"], reason="Interrupted before drain; strict recovery next")
    assert result["result"] == "CANCELLED"
    assert system.events == events + ["authenticate"]
    with cli.connection(instance.database) as conn:
        assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")] == before


def test_required_stage_registry_includes_optional_required_mqtt_if_and_rejects_missing_packet(runner, monkeypatch):
    from types import SimpleNamespace
    instance, _, _ = runner
    monkeypatch.setattr(instance, "required_checkpoints", cli.MaintenanceRunner.required_checkpoints.__get__(instance))
    rows = [item for item in planned.REQUIRED_CHECKPOINTS if item[0] not in ("mqtt_feature_builder", "trust_score_v2")]

    def registry(_settings):
        stages = [SimpleNamespace(stage=SimpleNamespace(detector_name=name, source_table=source), required=True)
                  for name, source in rows]
        return SimpleNamespace(stages=stages, required_stages=stages)

    monkeypatch.setattr(cli, "load_stage_registry", registry)
    assert set(instance.required_checkpoints()) == set(planned.REQUIRED_CHECKPOINTS)
    rows.append(("mqtt_if", "feature_logs"))
    assert len(instance.required_checkpoints()) == 7
    rows.remove(("packet_if", "packet_feature_logs"))
    with pytest.raises(cli.MaintenanceHold, match="supported"):
        instance.required_checkpoints()


def test_optional_enabled_mqtt_if_rejects_shutdown_before_approval_or_service_stop(runner, monkeypatch):
    from types import SimpleNamespace
    instance, system, _ = runner
    monkeypatch.setattr(instance, "required_checkpoints", cli.MaintenanceRunner.required_checkpoints.__get__(instance))
    required = [SimpleNamespace(stage=SimpleNamespace(detector_name=name, source_table=source), required=True)
                for name, source in planned.REQUIRED_CHECKPOINTS
                if name not in ("mqtt_feature_builder", "trust_score_v2")]
    optional = SimpleNamespace(stage=SimpleNamespace(detector_name="mqtt_if", source_table="feature_logs"), required=False)
    monkeypatch.setattr(cli, "load_stage_registry", lambda _settings: SimpleNamespace(
        stages=required + [optional], required_stages=required))
    with pytest.raises(cli.MaintenanceHold, match="all enabled stages must be required"):
        prepare(instance)
    assert instance.status()["operation"] is None
    assert system.events == ["authenticate"]
    assert all(system.services.values())


def test_firewall_lock_order_is_after_coordinator_even_if_path_sorts_first(runner):
    instance, system, directory = runner
    configured = directory / ".env"
    configured.write_text(f"FIREWALL_LOCK_PATH={directory.as_posix()}/a-firewall.lock\n"
                          f"ORCHESTRATOR_LOCK_PATH={directory.as_posix()}/z-orchestrator.lock\n")
    second = cli.MaintenanceRunner(instance.database, directory, system=system, core=planned)
    assert second.locks[-1].name == "a-firewall.lock"
    assert list(second.locks).index(directory / "z-orchestrator.lock") < len(second.locks) - 1


def test_real_deployment_guard_uses_configured_database_not_supplied_override(runner, monkeypatch):
    instance, _, directory = runner
    configured = directory / ".env"
    configured.write_text(f"DATABASE_URL=sqlite:///{directory.as_posix()}/other.db\n")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(cli, "__file__", str(directory / "edge/maintenance/run_planned_maintenance.py"))
    actual = cli.MaintenanceRunner(instance.database, directory, system=cli.SystemOperations(), core=planned)
    assert actual.settings.database_url.endswith("/other.db")
    with pytest.raises(cli.MaintenanceHold, match="database path differs"):
        actual.require_deployment()


def test_real_deployment_guard_rejects_database_or_stage_shell_overrides(runner, monkeypatch):
    instance, _, directory = runner
    configured = directory / ".env"
    configured.write_text(f"DATABASE_URL=sqlite:///{instance.database.as_posix()}\n"
                          "ORCHESTRATOR_REQUIRED_STAGES=mqtt_feature_rule,mqtt_message_rule,packet_rule,packet_if\n")
    monkeypatch.setattr(cli, "__file__", str(directory / "edge/maintenance/run_planned_maintenance.py"))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///shell-override.db")
    actual = cli.MaintenanceRunner(instance.database, directory, system=cli.SystemOperations(), core=planned)
    with pytest.raises(cli.MaintenanceHold, match="DATABASE_URL override"):
        actual.require_deployment()
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{instance.database.as_posix()}")
    monkeypatch.setenv("ORCHESTRATOR_REQUIRED_STAGES", "mqtt_feature_rule,mqtt_message_rule")
    actual = cli.MaintenanceRunner(instance.database, directory, system=cli.SystemOperations(), core=planned)
    with pytest.raises(cli.MaintenanceHold, match="ORCHESTRATOR_REQUIRED_STAGES override"):
        actual.require_deployment()


def test_online_backup_checksum_integrity_and_private_unique_artifacts(runner):
    instance, _, directory = runner
    first = cli.online_backup(instance.database, directory / "backup")
    second = cli.online_backup(instance.database, directory / "backup")
    assert first["backup_path"] != second["backup_path"]
    import hashlib
    path = Path(first["backup_path"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == first["backup_sha256"]
    assert path.with_suffix(".db.sha256").read_text().split()[0] == first["backup_sha256"]
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_actual_system_authentication_and_systemctl_are_bounded(monkeypatch):
    monkeypatch.setattr(cli.os, "name", "posix")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(cli.MaintenanceHold, match="root administrator"):
        cli.SystemOperations().require_admin()
    calls = []

    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        from types import SimpleNamespace
        return SimpleNamespace(returncode=0, stdout="yes\n")

    monkeypatch.setattr(cli.subprocess, "run", command)
    assert cli.SystemOperations().synchronized()
    assert calls[0][0] == ("timedatectl", "show", "--property=NTPSynchronized", "--value")
    assert calls[0][1]["timeout"] == 10 and "shell" not in calls[0][1]


def test_boot_unit_never_powers_off_or_restarts_approval_loop():
    unit = Path("infra/systemd/planned-maintenance-resume.service").read_text()
    assert "User=root" in unit and "Restart=no" in unit
    assert "--timeout 120 --verify-timeout 120" in unit
    assert inspect.signature(cli.online_backup).parameters["timeout"].default == 600
    # The additional 240 seconds cover bounded service and lock operations.
    assert "TimeoutStartSec=1080" in unit
    assert "poweroff" not in unit and "reboot" not in unit


def test_boot_unit_git_trust_is_limited_to_the_deployed_repository():
    lines = Path("infra/systemd/planned-maintenance-resume.service").read_text().splitlines()
    root = next(line.removeprefix("WorkingDirectory=") for line in lines if line.startswith("WorkingDirectory="))
    environment = dict(line.removeprefix("Environment=").split("=", 1)
                       for line in lines if line.startswith("Environment="))
    assert environment == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": root,
    }
    assert root == "/home/pi/iot-edge-zero-trust"


def test_default_resume_artifacts_remain_ignored_after_first_backup(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / ".gitignore").write_text(Path(".gitignore").read_text())
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    default = cli.build_parser().parse_args(["resume"]).artifact_dir
    unit = Path("infra/systemd/planned-maintenance-resume.service").read_text()
    command = shlex.split(next(line.removeprefix("ExecStart=")
                              for line in unit.splitlines() if line.startswith("ExecStart=")))
    assert Path(command[command.index("--artifact-dir") + 1]) == default
    directory = cli.safety.validate_generated_path(root, default, field_name="artifact_dir")
    directory.mkdir(parents=True)
    (directory / "first-backup.db").write_bytes(b"private backup fixture")
    assert cli.safety.validate_generated_path(root, default, field_name="artifact_dir") == directory
    legacy = root / "data/recovery/planned"
    legacy.mkdir(parents=True)
    assert cli.safety.validate_generated_path(root, legacy, field_name="artifact_dir") == legacy
    unignored = root / "private-recovery"
    with pytest.raises(cli.safety.PacketCheckpointRecoveryError, match="artifact_dir must be Git-ignored"):
        cli.safety.validate_generated_path(root, unignored, field_name="artifact_dir")
