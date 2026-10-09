"""Paired recovery uses real fixture SQL/backup/audit with mocked host observations."""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import uuid

import pytest

from edge.detection import packet_checkpoint_pair_recovery as pair
from edge.detection import packet_checkpoint_recovery as core
from edge.detection import run_packet_checkpoint_pair_recovery as cli
from test_packet_checkpoint_recovery import (
    CURRENT_SESSION, TARGET_SESSION, TARGET_FIRST, CURRENT_READY_THROUGH, PROCESSABLE_SKIP_SESSION,
    _db_utc, _insert_capture_segment, _insert_capture_session, _insert_packet_if_checkpoint,
    _repository, _seed_valid_recovery_database,
)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = _repository(tmp_path)
    (root / ".git" / "info" / "exclude").write_text("data/\n", encoding="utf-8")
    database = tmp_path / "pair.db"
    with _seed_valid_recovery_database(database) as db:
        _insert_packet_if_checkpoint(db, last_processed_id=1)
        db.execute("UPDATE detector_checkpoints SET last_processed_id=1 WHERE detector_name='packet_rule'")
        db.execute("UPDATE packet_capture_sessions SET status='RUNNING',ended_at=NULL WHERE session_id=?", (TARGET_SESSION,))
        db.execute("UPDATE packet_capture_segments SET start_delay_seconds=0.1,captured_duration_seconds=9.9")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    runtime = {"boot_id": str(uuid.uuid4()), "services": {name: True for name in pair.SERVICES},
               "enabled": list(pair.DETECTORS), "required": list(pair.DETECTORS),
               "clock_synchronized": True, "capture_policy": asdict(pair.CapturePolicy())}
    clock = [TARGET_FIRST + timedelta(seconds=20)]
    locks = []

    @contextmanager
    def acquire(entries):
        locks.append(tuple(entries))
        yield

    monkeypatch.setattr(core, "_current_platform_name", lambda: "posix")
    monkeypatch.setattr(core, "acquire_recovery_locks", acquire)
    monkeypatch.setattr(pair, "_runtime_observation", lambda: json.loads(json.dumps(runtime)))
    monkeypatch.setattr(core, "_utc_now", lambda: clock[0])
    output = tmp_path / "pair-plan.json"
    plan = pair.inspect_pair(db_path=database, repository_root=root, current_session_id=CURRENT_SESSION,
                             target_session_id=TARGET_SESSION, approved_by="admin-fixture",
                             reason="approved local live resume", plan_output=output)
    assert plan["can_execute"], plan["blocking_reasons"]
    return dict(database=database, root=root, artifacts=artifacts, runtime=runtime,
                clock=clock, locks=locks, output=output, plan=plan)


def _kwargs(fixture):
    return dict(plan_file=fixture["output"], db_path=fixture["database"], artifact_dir=fixture["artifacts"])


def _execute(fixture, **kwargs):
    return pair.execute_pair(**_kwargs(fixture), confirm=pair.CONFIRM + fixture["plan"]["plan_sha256"], **kwargs)


def _audits(fixture):
    with sqlite3.connect(fixture["database"]) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM packet_checkpoint_recoveries ORDER BY id")]


def test_configured_orchestrator_lock_is_bound_and_acquired(fixture, tmp_path, monkeypatch):
    configured = tmp_path / "configured-orchestrator.lock"
    monkeypatch.setattr(pair.settings, "orchestrator_lock_path", str(configured))
    output = tmp_path / "configured-plan.json"
    plan = pair.inspect_pair(db_path=fixture["database"], repository_root=fixture["root"],
                             current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
                             approved_by="admin-fixture", reason="approved local live resume", plan_output=output)
    assert any(entry["path"] == str(configured) and "detection_orchestrator" in entry["roles"] for entry in plan["locks"])
    assert all(child["plan"]["locks"] == plan["locks"] for child in plan["children"])
    fixture.update(output=output, plan=plan)
    assert _execute(fixture)["database_committed"] is True
    assert any(entry.path == configured for entry in fixture["locks"][0])


def test_changed_lock_configuration_rejects_before_apply(fixture, tmp_path, monkeypatch):
    monkeypatch.setattr(pair.settings, "orchestrator_lock_path", str(tmp_path / "other-orchestrator.lock"))
    with pytest.raises(core.PacketCheckpointRecoveryError, match="lock configuration changed"):
        _execute(fixture)
    assert _audits(fixture) == []


def test_processable_skip_requires_parent_sha_approval(fixture, tmp_path):
    with sqlite3.connect(fixture["database"]) as db:
        start = CURRENT_READY_THROUGH + timedelta(seconds=10)
        session = _insert_capture_session(db, session_id=PROCESSABLE_SKIP_SESSION,
                                          capture_interface="eth-skipped", first_window_start=start)
        _insert_capture_segment(db, session_pk=session, capture_interface="eth-skipped",
                                window_start=start, status="PROCESSED", feature_count=1)
    output = tmp_path / "skip-plan.json"
    plan = pair.inspect_pair(db_path=fixture["database"], repository_root=fixture["root"],
                             current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
                             approved_by="admin-fixture", reason="approved local live resume", plan_output=output)
    assert plan["can_execute"] and plan["skips_processable"]
    fixture.update(output=output, plan=plan)
    for approval in (None, pair.SKIP_CONFIRM + "0" * 64):
        with pytest.raises(core.PacketCheckpointRecoveryError, match="skip approval"):
            _execute(fixture, confirm_skip_processable=approval)
    assert _audits(fixture) == []
    assert _execute(fixture, confirm_skip_processable=pair.SKIP_CONFIRM + plan["plan_sha256"])["database_committed"] is True


def _advance(fixture, seconds, *, packet_if_seconds=None, trust_seconds=None):
    """Record normal cutoff transactions, including EMPTY windows and zero Trust events."""
    end = TARGET_FIRST + timedelta(seconds=seconds)
    fixture["clock"][0] = end + timedelta(seconds=10)
    with sqlite3.connect(fixture["database"]) as db:
        db.row_factory = sqlite3.Row
        session_pk = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (TARGET_SESSION,)).fetchone()[0]
        ready = pair.repository.calculate_packet_feature_readiness(db, TARGET_SESSION).packet_feature_ready_through
        while ready < end:
            _insert_capture_segment(db, session_pk=session_pk, capture_interface="eth-target",
                                    window_start=ready, status="EMPTY")
            ready += timedelta(seconds=10)
        db.execute("UPDATE packet_capture_segments SET start_delay_seconds=0.1,captured_duration_seconds=9.9")
        for name, delta in (("packet_rule", seconds), ("packet_if", packet_if_seconds or seconds)):
            boundary = _db_utc(TARGET_FIRST + timedelta(seconds=delta))
            db.execute("UPDATE detector_checkpoints SET last_processed_id=3,last_completed_window_end=?,updated_at=? "
                       "WHERE detector_name=?", (boundary, boundary, name))
        for name, source, delta in (("trust_score_v2", "detection_events", trust_seconds or seconds),
                                    ("mqtt_feature_builder", "mqtt_logs", seconds)):
            boundary = _db_utc(TARGET_FIRST + timedelta(seconds=delta))
            db.execute("INSERT INTO detector_checkpoints (detector_name,source_table,last_processed_id,last_completed_window_end,updated_at) "
                       "VALUES (?,?,NULL,?,?) ON CONFLICT(detector_name,source_table) DO UPDATE SET "
                       "last_completed_window_end=excluded.last_completed_window_end,updated_at=excluded.updated_at",
                       (name, source, boundary, boundary))


def test_pair_uses_one_union_lock_and_distinct_durable_child_audits(fixture):
    with sqlite3.connect(fixture["database"]) as db:
        protected = {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                     for table in pair.repository.PROTECTED_TABLES}
    result = _execute(fixture)
    assert result["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert result["database_committed"] is True
    assert len(fixture["locks"]) == 1
    assert len({str(entry.path) for entry in fixture["locks"][0]}) == len(fixture["locks"][0])
    audits = _audits(fixture)
    assert [row["detector_name"] for row in audits] == list(pair.DETECTORS)
    assert [row["operation_id"] for row in audits] == [child["child_operation_id"] for child in fixture["plan"]["children"]]
    assert len({row["operation_id"] for row in audits}) == 2
    with sqlite3.connect(fixture["database"]) as db:
        assert protected == {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                             for table in pair.repository.PROTECTED_TABLES}
    # IF backup is made after Rule commit, rather than pretending the pair was atomic.
    with sqlite3.connect(audits[1]["backup_path"]) as backup:
        assert backup.execute("SELECT detector_name FROM packet_checkpoint_recoveries").fetchall() == [("packet_rule",)]
    assert pair.status_pair(**_kwargs(fixture))["operation_status"] != "COMPLETE"


def test_partial_failure_requires_resume_and_runs_only_original_pending_if(fixture, monkeypatch):
    original = core._execute_locked_recovery
    calls = []

    def fail_if(**prepared):
        name = prepared["plan"]["detector_name"]
        calls.append(name)
        if name == "packet_if":
            raise core.PacketCheckpointRecoveryError("fixture precommit failure")
        return original(**prepared)

    monkeypatch.setattr(core, "_execute_locked_recovery", fail_if)
    assert _execute(fixture)["operation_status"] == "PARTIAL_HOLD"
    assert len(_audits(fixture)) == 1
    assert _execute(fixture)["error"] == "explicit resume required"
    monkeypatch.setattr(core, "_execute_locked_recovery", original)
    assert _execute(fixture, resume=True)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert calls == ["packet_rule", "packet_if"]
    assert len(_audits(fixture)) == 2
    monkeypatch.setattr(core, "_execute_locked_recovery", lambda **prepared: pytest.fail("committed child repeated"))
    assert _execute(fixture, resume=True)["operation_status"] != "COMPLETE"
    assert len(_audits(fixture)) == 2


@pytest.mark.parametrize("lost_detector", pair.DETECTORS)
def test_child_commit_result_loss_is_audited_and_not_reapplied(fixture, monkeypatch, lost_detector):
    original = core._write_json_atomically
    operation_id = next(child["child_operation_id"] for child in fixture["plan"]["children"] if child["detector"] == lost_detector)

    def lose_result(path, payload):
        if path.name == "result.json" and path.parent.name == operation_id:
            raise OSError("response/artifact lost after commit")
        return original(path, payload)

    monkeypatch.setattr(core, "_write_json_atomically", lose_result)
    result = _execute(fixture)
    assert result["database_committed"] is True
    assert result["children"][lost_detector] == "APPLIED"
    assert result["operation_status"] in {"PARTIAL_HOLD", "HOLD"}
    count = 1 if lost_detector == "packet_rule" else 2
    assert len(_audits(fixture)) == count
    monkeypatch.setattr(core, "_write_json_atomically", original)
    result = _execute(fixture, resume=True)
    assert result["operation_status"] != "COMPLETE"
    assert len(_audits(fixture)) == 2


@pytest.mark.parametrize("mutation", ["pending_time", "pending_id", "repository", "target", "boot"])
def test_stale_plan_blocks_both_writes(fixture, mutation):
    if mutation in {"pending_time", "pending_id", "target"}:
        with sqlite3.connect(fixture["database"]) as db:
            if mutation == "pending_time":
                db.execute("UPDATE detector_checkpoints SET updated_at='2026-08-06T10:00:21Z' WHERE detector_name='packet_if'")
            elif mutation == "pending_id":
                db.execute("UPDATE detector_checkpoints SET last_processed_id=2 WHERE detector_name='packet_if'")
            else:
                db.execute("UPDATE packet_capture_sessions SET capture_interface='changed' WHERE session_id=?", (TARGET_SESSION,))
    elif mutation == "repository":
        (fixture["root"] / "tracked.txt").write_text("changed")
    else:
        fixture["runtime"]["boot_id"] = str(uuid.uuid4())
    with pytest.raises(core.PacketCheckpointRecoveryError):
        _execute(fixture)
    assert _audits(fixture) == []


def test_pending_if_keeps_original_cas_after_rule_commit(fixture, monkeypatch):
    original = core._execute_locked_recovery
    monkeypatch.setattr(core, "_execute_locked_recovery", lambda **prepared: original(**prepared)
                        if prepared["plan"]["detector_name"] == "packet_rule" else (_ for _ in ()).throw(core.PacketCheckpointRecoveryError("hold")))
    _execute(fixture)
    monkeypatch.setattr(core, "_execute_locked_recovery", original)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("UPDATE detector_checkpoints SET updated_at='2026-08-06T10:00:21Z' WHERE detector_name='packet_if'")
    with pytest.raises(core.PacketCheckpointRecoveryError, match="pending child"):
        _execute(fixture, resume=True)
    assert len(_audits(fixture)) == 1


def test_rule_checkpoint_change_between_children_prevents_if_write(fixture, monkeypatch):
    original = core._execute_locked_recovery

    def mutate_after_rule(**prepared):
        result = original(**prepared)
        if prepared["plan"]["detector_name"] == "packet_rule":
            with sqlite3.connect(fixture["database"]) as db:
                db.execute("UPDATE detector_checkpoints SET updated_at='2026-08-06T10:01:21Z' WHERE detector_name='packet_rule'")
        return result

    monkeypatch.setattr(core, "_execute_locked_recovery", mutate_after_rule)
    result = _execute(fixture)
    assert result["database_committed"] is True
    assert result["operation_status"] == "PARTIAL_HOLD"
    assert result["children"]["packet_rule"] == "COMMITTED_UNVERIFIED"
    assert len(_audits(fixture)) == 1


@pytest.mark.parametrize("field,value", [("reason", "other approval"), ("database_path", "other.db"),
                                         ("operation_id", "77777777-7777-4777-8777-777777777777"),
                                         ("backup_sha256", "0" * 64), ("plan_json", "{}"),
                                         ("updated_at_before", "2026-08-06T10:00:21Z"),
                                         ("target_capture_session_id", CURRENT_SESSION)])
def test_status_rejects_wrong_full_audit_even_when_checkpoint_matches(fixture, field, value):
    _execute(fixture)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute(f"UPDATE packet_checkpoint_recoveries SET {field}=? WHERE detector_name='packet_rule'", (value,))
    with pytest.raises(core.PacketCheckpointRecoveryError):
        pair.status_pair(**_kwargs(fixture))


def test_completion_needs_two_real_advances_and_allows_empty_trust_id(fixture):
    _execute(fixture)
    for seconds, expected in ((10, 0), (20, 1), (30, 2)):
        _advance(fixture, seconds)
        result = pair.status_pair(**_kwargs(fixture))
        assert result["progress_advances"] == expected
        assert result["operation_status"] == ("COMPLETE" if expected == 2 else "APPLIED_PENDING_PROGRESS")
    assert len(_audits(fixture)) == 2


def test_forward_time_with_unconsumed_feature_ids_is_hold(fixture):
    _execute(fixture)
    _advance(fixture, 10)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("UPDATE detector_checkpoints SET last_processed_id=1 WHERE detector_name IN ('packet_rule','packet_if')")
    with pytest.raises(core.PacketCheckpointRecoveryError, match="actual target feature IDs"):
        pair.status_pair(**_kwargs(fixture))


def test_rule_inbound_and_if_all_direction_consumption_are_distinct(fixture):
    _execute(fixture)
    with sqlite3.connect(fixture["database"]) as db:
        segment = db.execute("SELECT id FROM packet_capture_segments WHERE window_start=?", (_db_utc(TARGET_FIRST),)).fetchone()[0]
        db.execute("INSERT INTO packet_feature_logs (capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                   "VALUES (?,'10.0.0.9','OUTBOUND',?,?,1,60,60,60)",
                   (segment, _db_utc(TARGET_FIRST), _db_utc(TARGET_FIRST + timedelta(seconds=10))))
    _advance(fixture, 10)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="actual target feature IDs"):
        pair.status_pair(**_kwargs(fixture))
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("UPDATE detector_checkpoints SET last_processed_id=4 WHERE detector_name='packet_if'")
    assert pair.status_pair(**_kwargs(fixture))["operation_status"] != "COMPLETE"


@pytest.mark.parametrize("delay,duration", [(None, 9.9), (2.0, 9.9), (0.1, 2.0)])
def test_capture_quality_must_support_observed_target_processing(fixture, delay, duration):
    _execute(fixture)
    _advance(fixture, 10)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("UPDATE packet_capture_segments SET start_delay_seconds=?,captured_duration_seconds=? WHERE window_start=?",
                   (delay, duration, _db_utc(TARGET_FIRST)))
    with pytest.raises(core.PacketCheckpointRecoveryError, match="capture timing"):
        pair.status_pair(**_kwargs(fixture))


def test_pending_trust_event_blocks_completion_despite_advanced_checkpoint(fixture):
    _execute(fixture)
    _advance(fixture, 10)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("INSERT INTO detection_events (detector_type,event_type,analysis_window_end) VALUES ('rule','fixture',?)",
                   (_db_utc(TARGET_FIRST + timedelta(seconds=10)),))
    with pytest.raises(core.PacketCheckpointRecoveryError, match="unprocessed"):
        pair.status_pair(**_kwargs(fixture))


@pytest.mark.parametrize("field", ["analysis_window_end", "analysis_window_start", "detected_at"])
def test_malformed_unprocessed_trust_event_time_is_hold(fixture, field):
    _execute(fixture)
    _advance(fixture, 10)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute(f"INSERT INTO detection_events (detector_type,event_type,{field}) VALUES ('rule','fixture','garbage')")
    with pytest.raises(core.PacketCheckpointRecoveryError, match="unprocessed"):
        pair.status_pair(**_kwargs(fixture))


def test_valid_future_trust_event_does_not_block_current_cutoff(fixture):
    _execute(fixture)
    _advance(fixture, 10)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("INSERT INTO detection_events (detector_type,event_type,analysis_window_end) VALUES ('rule','fixture',?)",
                   (_db_utc(TARGET_FIRST + timedelta(seconds=20)),))
    assert pair.status_pair(**_kwargs(fixture))["operation_status"] == "APPLIED_PENDING_PROGRESS"


def test_cli_noncomplete_commit_exit_three_and_complete_exit_zero(fixture, capsys):
    common = ["--plan-file", str(fixture["output"]), "--db-path", str(fixture["database"]),
              "--artifact-dir", str(fixture["artifacts"])]
    assert cli.main(["execute", *common, "--confirm", pair.CONFIRM + fixture["plan"]["plan_sha256"]]) == 3
    assert json.loads(capsys.readouterr().out)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    for seconds, code in ((10, 3), (20, 3), (30, 0)):
        _advance(fixture, seconds)
        assert cli.main(["status", *common]) == code
        assert json.loads(capsys.readouterr().out)["operation_status"] == (
            "COMPLETE" if code == 0 else "APPLIED_PENDING_PROGRESS")


@pytest.mark.parametrize("condition", ["if_stalled", "trust_stalled", "stale", "service_inactive", "new_failed", "boot_changed", "clock_unsynchronized"])
def test_audits_and_service_activity_alone_never_complete(fixture, condition):
    _execute(fixture)
    _advance(fixture, 10)
    pair.status_pair(**_kwargs(fixture))
    _advance(fixture, 20)
    pair.status_pair(**_kwargs(fixture))
    _advance(fixture, 30, packet_if_seconds=20 if condition == "if_stalled" else None,
             trust_seconds=20 if condition in {"if_stalled", "trust_stalled"} else None)
    if condition == "stale":
        fixture["clock"][0] += timedelta(seconds=60)
    elif condition == "service_inactive":
        fixture["runtime"]["services"]["detection-orchestrator.service"] = False
    elif condition == "new_failed":
        with sqlite3.connect(fixture["database"]) as db:
            db.row_factory = sqlite3.Row
            pk = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (TARGET_SESSION,)).fetchone()[0]
            _insert_capture_segment(db, session_pk=pk, capture_interface="eth-target",
                                    window_start=TARGET_FIRST + timedelta(seconds=30), status="FAILED", error_code="fixture")
    elif condition == "boot_changed":
        fixture["runtime"]["boot_id"] = str(uuid.uuid4())
    elif condition == "clock_unsynchronized":
        fixture["runtime"]["clock_synchronized"] = False
    if condition in {"new_failed", "boot_changed"}:
        with pytest.raises(core.PacketCheckpointRecoveryError):
            pair.status_pair(**_kwargs(fixture))
    else:
        assert pair.status_pair(**_kwargs(fixture))["operation_status"] != "COMPLETE"


@pytest.mark.parametrize("mutation", ["same_boundary_time", "same_boundary_id", "retreat", "wrong_owner", "beyond_ready"])
def test_checkpoint_motion_requires_normal_target_evidence(fixture, mutation):
    _execute(fixture)
    _advance(fixture, 10)
    pair.status_pair(**_kwargs(fixture))
    with sqlite3.connect(fixture["database"]) as db:
        if mutation == "same_boundary_time":
            db.execute("UPDATE detector_checkpoints SET updated_at='2026-08-06T10:01:11Z' WHERE detector_name='packet_rule'")
        elif mutation == "same_boundary_id":
            db.execute("UPDATE detector_checkpoints SET last_processed_id=4 WHERE detector_name='trust_score_v2'")
        elif mutation == "retreat":
            db.execute("UPDATE detector_checkpoints SET last_completed_window_end='2026-08-06T10:01:00Z' WHERE detector_name='packet_rule'")
        elif mutation == "wrong_owner":
            db.execute("UPDATE detector_checkpoints SET last_processed_id=999 WHERE detector_name='packet_rule'")
        else:
            db.execute("UPDATE detector_checkpoints SET last_completed_window_end='2026-08-06T10:01:30Z',updated_at='2026-08-06T10:01:30Z' WHERE detector_name='packet_rule'")
    with pytest.raises(core.PacketCheckpointRecoveryError):
        pair.status_pair(**_kwargs(fixture))


def test_cli_pair_result_loss_preserves_committed_hold_exit_three(fixture, monkeypatch, capsys):
    original = core._write_json_atomically

    def fail_pair_result(path, payload):
        if path.name == "result.json" and path.parent.name.startswith("attempt-"):
            raise OSError("pair response lost")
        return original(path, payload)

    monkeypatch.setattr(core, "_write_json_atomically", fail_pair_result)
    args = ["execute", "--plan-file", str(fixture["output"]), "--db-path", str(fixture["database"]),
            "--artifact-dir", str(fixture["artifacts"]), "--confirm", pair.CONFIRM + fixture["plan"]["plan_sha256"]]
    assert cli.main(args) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["database_committed"] is True
    assert result["operation_status"] == "HOLD"
    assert set(result["children"].values()) == {"COMMITTED_UNVERIFIED"}
    monkeypatch.setattr(core, "_write_json_atomically", original)
    assert _execute(fixture, resume=True)["operation_status"] != "COMPLETE"
    assert len(_audits(fixture)) == 2


def test_pair_execution_remains_posix_only(fixture, monkeypatch):
    monkeypatch.setattr(core, "_current_platform_name", lambda: "nt")
    with pytest.raises(core.PacketCheckpointRecoveryError, match="POSIX"):
        _execute(fixture)
    assert _audits(fixture) == []
