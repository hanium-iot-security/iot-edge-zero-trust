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
    _repository, _seed_valid_recovery_database, _add_uncaptured_failed_tail,
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



def _inspect_fixture(fixture, *, allow_failed_current_session=False):
    output = fixture["output"].with_name("pair-plan-" + str(uuid.uuid4()) + ".json")
    plan = pair.inspect_pair(db_path=fixture["database"], repository_root=fixture["root"],
                             current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
                             approved_by="admin-fixture", reason="approved local live resume",
                             plan_output=output, allow_failed_current_session=allow_failed_current_session)
    return output, plan


def _use_failed_tail(fixture):
    with sqlite3.connect(fixture["database"]) as db:
        db.row_factory = sqlite3.Row
        fixture["tail_id"] = _add_uncaptured_failed_tail(db)
    output, plan = _inspect_fixture(fixture, allow_failed_current_session=True)
    assert plan["can_execute"], plan["blocking_reasons"]
    fixture.update(output=output, plan=plan)


def _resign(plan, fixture):
    signed = core.attach_plan_sha256(plan, generated_at=fixture["clock"][0])
    core._write_json_atomically(fixture["output"], signed)
    return signed


def _kwargs(fixture):
    return dict(plan_file=fixture["output"], db_path=fixture["database"], artifact_dir=fixture["artifacts"])


def _execute(fixture, **kwargs):
    return pair.execute_pair(**_kwargs(fixture), confirm=pair.confirmation_prefix(fixture["plan"]) + fixture["plan"]["plan_sha256"], **kwargs)


def _audits(fixture):
    with sqlite3.connect(fixture["database"]) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM packet_checkpoint_recoveries ORDER BY id")]


def test_readonly_verification_preserves_database_bytes(fixture):
    before = fixture["database"].read_bytes()
    checked = pair.verify_database_readonly(fixture["database"])
    assert checked.integrity_check == "ok"
    assert checked.foreign_key_violations == ()
    assert fixture["database"].read_bytes() == before


def test_readonly_verification_connection_cannot_update(fixture, monkeypatch):
    original = pair._read_db
    checked = []

    def read_db(database):
        db = original(database)
        assert db.in_transaction
        assert db.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("UPDATE devices SET trust_score=0")
        checked.append(db)
        return db

    monkeypatch.setattr(pair, "_read_db", read_db)
    assert pair.verify_database_readonly(fixture["database"]).integrity_check == "ok"
    assert len(checked) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        checked[0].execute("SELECT 1")


def test_status_rejects_backup_changed_during_readonly_verification(fixture, monkeypatch):
    _execute(fixture)
    original = pair.verify_database_readonly

    def changed(database):
        result = original(database)
        if Path(database) != fixture["database"]:
            with Path(database).open("ab") as stream:
                stream.write(b"changed-after-readonly-check")
        return result

    monkeypatch.setattr(pair, "verify_database_readonly", changed)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="backup changed during verification"):
        pair.status_pair(plan_file=fixture["output"], db_path=fixture["database"], artifact_dir=fixture["artifacts"])


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
        db.execute("UPDATE packet_capture_segments SET start_delay_seconds=0.1,captured_duration_seconds=9.9 WHERE status<>'FAILED'")
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


@pytest.mark.parametrize("failed_tail", [False, True])
def test_partial_failure_requires_resume_and_runs_only_original_pending_if(fixture, monkeypatch, failed_tail):
    if failed_tail:
        _use_failed_tail(fixture)
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
@pytest.mark.parametrize("failed_tail", [False, True])
def test_child_commit_result_loss_is_audited_and_not_reapplied(fixture, monkeypatch, lost_detector, failed_tail):
    if failed_tail:
        _use_failed_tail(fixture)
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


@pytest.mark.parametrize("failed_tail", [False, True])
def test_pending_if_keeps_original_cas_after_rule_commit(fixture, monkeypatch, failed_tail):
    if failed_tail:
        _use_failed_tail(fixture)
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


def test_failed_source_default_is_blocked_and_completed_default_remains_approved(fixture):
    assert fixture["plan"]["allow_failed_current_session"] is False
    assert all(child["plan"]["allow_failed_current_session"] is False for child in fixture["plan"]["children"])
    with sqlite3.connect(fixture["database"]) as db:
        db.row_factory = sqlite3.Row
        _add_uncaptured_failed_tail(db)
    output, plan = _inspect_fixture(fixture)
    assert not plan["can_execute"]
    assert all(name + ":CURRENT_SESSION_NOT_COMPLETED" in plan["blocking_reasons"] for name in pair.DETECTORS)
    fixture.update(output=output, plan=plan)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="blocked plan"):
        _execute(fixture)
    assert _audits(fixture) == []


def test_failed_opt_in_does_not_relax_completed_source_contract(fixture):
    _, plan = _inspect_fixture(fixture, allow_failed_current_session=True)
    assert not plan["can_execute"]
    assert all(name + ":FAILED_TAIL_RESUME_REQUIRES_FAILED_SOURCE_AND_LIVE_MODE" in plan["blocking_reasons"]
               for name in pair.DETECTORS)


def test_failed_pair_delegates_guard_and_exact_confirmation_and_preserves_source(fixture, monkeypatch):
    build = core.build_recovery_plan
    calls = []

    def build_child(db, **kwargs):
        calls.append((kwargs["detector_name"], kwargs["allow_failed_current_session"]))
        return build(db, **kwargs)

    monkeypatch.setattr(core, "build_recovery_plan", build_child)
    _use_failed_tail(fixture)
    assert calls == [(name, True) for name in pair.DETECTORS]
    assert fixture["plan"]["allow_failed_current_session"] is True
    tails = [child["plan"]["failed_current_tail"] for child in fixture["plan"]["children"]]
    assert tails[0] == tails[1] and tails[0]["segment_id"] == fixture["tail_id"]
    assert all("UNCAPTURED_FAILED_TAIL_SKIP" in child["plan"]["summary"]["warning_codes"]
               for child in fixture["plan"]["children"])
    with sqlite3.connect(fixture["database"]) as db:
        protected = {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                     for table in pair.repository.PROTECTED_TABLES}
    prepare = core._prepare_recovery_execution
    confirmations = []

    def prepare_child(**kwargs):
        confirmations.append(kwargs["confirm"])
        return prepare(**kwargs)

    monkeypatch.setattr(core, "_prepare_recovery_execution", prepare_child)
    assert _execute(fixture)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert confirmations == [core.FAILED_TAIL_RESUME_CONFIRMATION] * 2
    assert len(fixture["locks"]) == 1
    for audit, child in zip(_audits(fixture), fixture["plan"]["children"]):
        signed = json.loads(audit["plan_json"])
        assert signed == child["plan"] and signed["allow_failed_current_session"] is True
        assert signed["failed_current_tail"]["feature_count"] == 0
        assert audit["last_processed_id_before"] == audit["last_processed_id_after"] == 1
    with sqlite3.connect(fixture["database"]) as db:
        assert protected == {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                             for table in pair.repository.PROTECTED_TABLES}
    for seconds, expected in ((10, 0), (20, 1), (30, 2)):
        _advance(fixture, seconds)
        result = pair.status_pair(**_kwargs(fixture))
        assert result["progress_advances"] == expected
        assert result["operation_status"] == ("COMPLETE" if expected == 2 else "APPLIED_PENDING_PROGRESS")


@pytest.mark.parametrize("mutation", ["missing_pcap_name", "captured", "packets", "features", "capture_started",
                                      "extractor_error", "ended_outside", "extra_tail", "not_at_ready",
                                      "ready_prefix_gap", "target_failed"])
def test_failed_tail_pair_reuses_core_rejection_of_unsafe_or_processable_input(fixture, mutation):
    _use_failed_tail(fixture)
    with sqlite3.connect(fixture["database"]) as db:
        db.row_factory = sqlite3.Row
        tail = fixture["tail_id"]
        # Only this temporary fixture permits corrupt persisted LATE_CAPTURE rows,
        # so inspection must reject them independently of the schema CHECK.
        if mutation in {"missing_pcap_name", "captured", "capture_started"}:
            db.execute("PRAGMA ignore_check_constraints=ON")
        if mutation == "missing_pcap_name":
            # A recorded file name still indicates captured input even if that PCAP is now missing.
            db.execute("UPDATE packet_capture_segments SET file_name='missing.pcap' WHERE id=?", (tail,))
        elif mutation == "captured":
            db.execute("UPDATE packet_capture_segments SET captured_duration_seconds=0.1 WHERE id=?", (tail,))
        elif mutation == "packets":
            db.execute("UPDATE packet_capture_segments SET packet_count=1 WHERE id=?", (tail,))
        elif mutation == "features":
            db.execute("INSERT INTO packet_feature_logs (capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                       "SELECT id,'10.0.0.1','INBOUND',window_start,window_end,1,60,60,60 FROM packet_capture_segments WHERE id=?", (tail,))
        elif mutation == "capture_started":
            db.execute("UPDATE packet_capture_segments SET actual_capture_started_at=window_start WHERE id=?", (tail,))
        elif mutation == "extractor_error":
            db.execute("UPDATE packet_capture_segments SET error_code='EXTRACTOR_ERROR' WHERE id=?", (tail,))
        elif mutation == "ended_outside":
            db.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE session_id=?", (_db_utc(TARGET_FIRST), CURRENT_SESSION))
        elif mutation == "extra_tail":
            session = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (CURRENT_SESSION,)).fetchone()[0]
            _insert_capture_segment(db, session_pk=session, capture_interface="eth-current",
                                    window_start=CURRENT_READY_THROUGH + timedelta(seconds=10), status="FAILED")
        elif mutation == "not_at_ready":
            db.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_if'",
                       (_db_utc(CURRENT_READY_THROUGH - timedelta(seconds=10)),))
        elif mutation == "ready_prefix_gap":
            db.execute("UPDATE packet_capture_segments SET status='READY' WHERE window_end=? AND capture_session_id="
                       "(SELECT id FROM packet_capture_sessions WHERE session_id=?)", (_db_utc(CURRENT_READY_THROUGH), CURRENT_SESSION))
        else:
            target = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (TARGET_SESSION,)).fetchone()[0]
            _insert_capture_segment(db, session_pk=target, capture_interface="eth-target",
                                    window_start=TARGET_FIRST + timedelta(seconds=20), status="FAILED")
    output, plan = _inspect_fixture(fixture, allow_failed_current_session=True)
    assert not plan["can_execute"] and plan["blocking_reasons"]
    fixture.update(output=output, plan=plan)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="blocked plan"):
        _execute(fixture)
    assert _audits(fixture) == []


def test_failed_tail_changed_after_plan_blocks_both_writes(fixture):
    _use_failed_tail(fixture)
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("UPDATE packet_capture_segments SET packet_count=1 WHERE id=?", (fixture["tail_id"],))
    with pytest.raises(core.PacketCheckpointRecoveryError, match="canonical plan changed"):
        _execute(fixture)
    assert _audits(fixture) == []


@pytest.mark.parametrize("value", [1, "true", None])
def test_failed_opt_in_requires_real_boolean_before_plan_write(fixture, value):
    with pytest.raises(core.PacketCheckpointRecoveryError, match="must be boolean"):
        _inspect_fixture(fixture, allow_failed_current_session=value)
    assert _audits(fixture) == []


@pytest.mark.parametrize("mutation", ["parent_false", "parent_integer", "child_false", "child_integer", "child_hash"])
def test_failed_pair_rejects_opt_in_binding_mutation_even_with_parent_resigned(fixture, mutation):
    _use_failed_tail(fixture)
    plan = json.loads(json.dumps(fixture["plan"]))
    if mutation.startswith("parent_"):
        plan["allow_failed_current_session"] = False if mutation == "parent_false" else 1
    else:
        child = plan["children"][1]
        child["plan"]["allow_failed_current_session"] = False if mutation in {"child_false", "child_hash"} else 1
        if mutation != "child_hash":
            child["plan"] = core.attach_plan_sha256(child["plan"], generated_at=fixture["clock"][0])
    fixture["plan"] = _resign(plan, fixture)
    with pytest.raises(core.PacketCheckpointRecoveryError):
        _execute(fixture)
    assert _audits(fixture) == []


@pytest.mark.parametrize("command", ["execute", "resume", "status"])
def test_failed_opt_in_is_not_an_execution_or_status_override(fixture, command):
    common = ["--plan-file", str(fixture["output"]), "--db-path", str(fixture["database"]),
              "--artifact-dir", str(fixture["artifacts"])]
    if command != "status":
        common += ["--confirm", pair.CONFIRM + fixture["plan"]["plan_sha256"]]
    with pytest.raises(SystemExit) as error:
        cli.main([command, *common, "--allow-failed-current-session"])
    assert error.value.code == 2 and _audits(fixture) == []


def test_failed_tail_cli_opt_in_is_written_to_original_approval(fixture, capsys):
    _use_failed_tail(fixture)
    output = fixture["output"].with_name("cli-failed-plan.json")
    args = ["dry-run", "--db-path", str(fixture["database"]), "--repository-root", str(fixture["root"]),
            "--current-session-id", CURRENT_SESSION, "--target-session-id", TARGET_SESSION,
            "--approved-by", "admin-fixture", "--reason", "reviewed failed capture opportunity",
            "--plan-output", str(output)]
    assert cli.main([*args, "--allow-failed-current-session"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert pair._load_pair(output)[1] == plan
    assert plan["allow_failed_current_session"] is True
    assert all(child["plan"]["allow_failed_current_session"] is True for child in plan["children"])
    assert _audits(fixture) == []


def test_failed_opt_in_change_after_partial_commit_is_rejected_by_original_intent(fixture, monkeypatch):
    _use_failed_tail(fixture)
    original = core._execute_locked_recovery
    monkeypatch.setattr(core, "_execute_locked_recovery", lambda **kwargs: original(**kwargs)
                        if kwargs["plan"]["detector_name"] == "packet_rule" else (_ for _ in ()).throw(pair.Error("IF hold")))
    assert _execute(fixture)["operation_status"] == "PARTIAL_HOLD"
    plan = json.loads(json.dumps(fixture["plan"]))
    plan["allow_failed_current_session"] = False
    for child in plan["children"]:
        child["plan"]["allow_failed_current_session"] = False
        child["plan"] = core.attach_plan_sha256(child["plan"], generated_at=fixture["clock"][0])
    fixture["plan"] = _resign(plan, fixture)
    for call in (lambda: _execute(fixture, resume=True), lambda: pair.status_pair(**_kwargs(fixture))):
        with pytest.raises(core.PacketCheckpointRecoveryError, match="intent missing or changed"):
            call()
    assert len(_audits(fixture)) == 1


def test_failed_audit_opt_in_cannot_be_changed_to_reuse_applied_child(fixture):
    _use_failed_tail(fixture)
    _execute(fixture)
    with sqlite3.connect(fixture["database"]) as db:
        signed = json.loads(db.execute("SELECT plan_json FROM packet_checkpoint_recoveries WHERE detector_name='packet_rule'").fetchone()[0])
        signed["allow_failed_current_session"] = False
        db.execute("UPDATE packet_checkpoint_recoveries SET plan_json=? WHERE detector_name='packet_rule'", (json.dumps(signed),))
    with pytest.raises(core.PacketCheckpointRecoveryError, match="audit does not match"):
        pair.status_pair(**_kwargs(fixture))
    assert len(_audits(fixture)) == 2


def test_pre_opt_in_pair_plan_remains_valid_for_completed_source(fixture):
    plan = json.loads(json.dumps(fixture["plan"]))
    plan.pop("allow_failed_current_session")
    fixture["plan"] = _resign(plan, fixture)
    assert _execute(fixture)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert len(_audits(fixture)) == 2


def test_failed_opt_in_manager_plan_keeps_pair_sha_binding_and_original_budgets(fixture):
    from edge.detection import packet_checkpoint_pair_manager as manager
    from test_packet_checkpoint_pair_manager import System

    _use_failed_tail(fixture)
    system = System(fixture)
    output = fixture["output"].with_name("failed-manager-plan.json")
    plan = manager.create_plan(pair_plan_file=fixture["output"], db_path=fixture["database"],
                               artifact_dir=fixture["artifacts"], plan_output=output, system=system)
    assert plan["can_execute"] and plan["pair_plan_sha256"] == fixture["plan"]["plan_sha256"]
    assert plan["budgets"] == manager.BUDGETS
    assert plan["source_session_id"] == CURRENT_SESSION and plan["target_session_id"] == TARGET_SESSION
    assert system.actions == [] and _audits(fixture) == []
    changed = json.loads(json.dumps(fixture["plan"]))
    changed["reason"] = "new approval"
    for child in changed["children"]:
        child["plan"]["reason"] = changed["reason"]
        child["plan"] = core.attach_plan_sha256(child["plan"], generated_at=fixture["clock"][0])
    _resign(changed, fixture)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="pair approval changed"):
        manager._load_plan(output)


def test_failed_tail_manager_preserves_source_and_completes_only_after_real_target_advances(fixture, monkeypatch):
    from edge.detection import packet_checkpoint_pair_manager as manager
    from test_packet_checkpoint_pair_manager import System, Processes, launch, run

    _use_failed_tail(fixture)
    with sqlite3.connect(fixture["database"]) as db:
        source = db.execute("SELECT * FROM packet_capture_sessions WHERE session_id=?", (CURRENT_SESSION,)).fetchone()
        tail = db.execute("SELECT * FROM packet_capture_segments WHERE id=?", (fixture["tail_id"],)).fetchone()
    system = System(fixture)
    path = fixture["output"].with_name("complete-failed-manager-plan.json")
    plan = manager.create_plan(pair_plan_file=fixture["output"], db_path=fixture["database"],
                               artifact_dir=fixture["artifacts"], plan_output=path, system=system)
    processes = Processes(lambda: _execute(fixture, resume=bool(_audits(fixture))))
    wrapped = dict(base=fixture, system=system, path=path, plan=plan, processes=processes)
    assert launch(wrapped)["operation_status"] == "RUNNING"
    result = run(wrapped, monkeypatch, advance=True)
    assert result["phase"] == "COMPLETE" and len(_audits(fixture)) == 2
    assert all(value == "active" for value in system.states.values())
    assert all(unit in manager.UNITS for _, unit, _ in system.actions)
    with sqlite3.connect(fixture["database"]) as db:
        assert db.execute("SELECT * FROM packet_capture_sessions WHERE session_id=?", (CURRENT_SESSION,)).fetchone() == source
        assert db.execute("SELECT * FROM packet_capture_segments WHERE id=?", (fixture["tail_id"],)).fetchone() == tail


@pytest.fixture
def replay_fixture(fixture):
    with sqlite3.connect(fixture["database"]) as db:
        db.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                   (_db_utc(TARGET_FIRST + timedelta(seconds=20)), TARGET_SESSION))
    output = fixture["output"].with_name("bounded-replay-plan.json")
    plan = pair.inspect_pair(db_path=fixture["database"], repository_root=fixture["root"],
                             current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
                             approved_by="admin-fixture", reason="approved preserved replay",
                             plan_output=output, mode=core.BOUNDED_REPLAY_MODE)
    assert plan["can_execute"], plan["blocking_reasons"]
    fixture.update(output=output, plan=plan)
    fixture["clock"][0] = TARGET_FIRST + timedelta(days=2)
    return fixture


def _finish_replay(fixture, *, trust_pending=False):
    end = fixture["plan"]["bounded_replay"]["replay_end"]
    with sqlite3.connect(fixture["database"]) as db:
        for name in pair.DETECTORS:
            maximum = db.execute(
                "SELECT MAX(f.id) FROM packet_feature_logs f JOIN packet_capture_segments g ON g.id=f.capture_segment_id "
                "JOIN packet_capture_sessions s ON s.id=g.capture_session_id WHERE s.session_id=? "
                "AND (?='packet_if' OR f.direction='INBOUND')", (TARGET_SESSION, name)).fetchone()[0]
            db.execute("UPDATE detector_checkpoints SET last_processed_id=?,last_completed_window_end=?,updated_at=? "
                       "WHERE detector_name=?", (maximum, end, end, name))
        for name, source in (("trust_score_v2", "detection_events"), ("mqtt_feature_builder", "mqtt_logs")):
            boundary = fixture["plan"]["boundary"] if name == "trust_score_v2" and trust_pending else end
            db.execute("INSERT INTO detector_checkpoints(detector_name,source_table,last_processed_id,last_completed_window_end,updated_at) "
                       "VALUES(?,?,NULL,?,?) ON CONFLICT(detector_name,source_table) DO UPDATE SET "
                       "last_completed_window_end=excluded.last_completed_window_end,updated_at=excluded.updated_at",
                       (name, source, boundary, boundary))


def test_bounded_replay_requires_actual_end_and_trust_without_live_freshness(replay_fixture):
    f = replay_fixture
    assert _execute(f)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert pair.status_pair(**_kwargs(f))["operation_status"] != "REPLAY_COMPLETE"
    _finish_replay(f, trust_pending=True)
    assert pair.status_pair(**_kwargs(f))["operation_status"] == "APPLIED_PENDING_PROGRESS"
    _finish_replay(f)
    result = pair.status_pair(**_kwargs(f))
    assert result["operation_status"] == "REPLAY_COMPLETE"
    assert result["live_recovery_complete"] is False
    assert result["progress_advances"] == 0
    assert result["replay_end"] == _db_utc(TARGET_FIRST + timedelta(seconds=20))
    assert len(_audits(f)) == 2
    assert _execute(f, resume=True)["operation_status"] == "REPLAY_COMPLETE"
    assert len(_audits(f)) == 2


def test_bounded_replay_does_not_accept_live_confirmation(replay_fixture):
    f = replay_fixture
    with pytest.raises(core.PacketCheckpointRecoveryError, match="approval mismatch"):
        pair.execute_pair(**_kwargs(f), confirm=pair.CONFIRM + f["plan"]["plan_sha256"])
    assert _audits(f) == []


def test_bounded_replay_partial_resume_only_applies_pending_if(replay_fixture, monkeypatch):
    f = replay_fixture
    original = core._execute_locked_recovery
    calls = []
    def fail_if(**prepared):
        calls.append(prepared["plan"]["detector_name"])
        if calls[-1] == "packet_if":
            raise core.PacketCheckpointRecoveryError("fixture IF failure")
        return original(**prepared)
    monkeypatch.setattr(core, "_execute_locked_recovery", fail_if)
    assert _execute(f)["operation_status"] == "PARTIAL_HOLD"
    assert len(_audits(f)) == 1
    monkeypatch.setattr(core, "_execute_locked_recovery", original)
    assert _execute(f, resume=True)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert len(_audits(f)) == 2
    _finish_replay(f)
    assert pair.status_pair(**_kwargs(f))["operation_status"] == "REPLAY_COMPLETE"


@pytest.mark.parametrize("sql", [
    "UPDATE packet_feature_logs SET total_bytes=61 WHERE id=2",
    "UPDATE packet_capture_segments SET captured_duration_seconds=9.8 WHERE id=3",
    "UPDATE packet_capture_sessions SET ended_at='2026-08-06T10:01:30Z' WHERE status='COMPLETED' AND capture_interface='eth-target'",
])
def test_bounded_replay_rejects_closed_input_mutation_after_audit(replay_fixture, sql):
    f = replay_fixture
    _execute(f)
    _finish_replay(f)
    with sqlite3.connect(f["database"]) as db:
        db.execute(sql)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="bounded replay target or fixed input changed"):
        pair.status_pair(**_kwargs(f))


def test_bounded_replay_terminal_requires_required_mqtt_cutoffs(replay_fixture):
    f = replay_fixture
    f["runtime"]["enabled"].extend(["mqtt_feature_rule", "mqtt_message_rule"])
    f["runtime"]["required"].extend(["mqtt_feature_rule", "mqtt_message_rule"])
    output = f["output"].with_name("bounded-replay-mqtt.json")
    plan = pair.inspect_pair(db_path=f["database"], repository_root=f["root"],
                             current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
                             approved_by="admin-fixture", reason="approved preserved replay",
                             plan_output=output, mode=core.BOUNDED_REPLAY_MODE)
    f.update(output=output, plan=plan)
    _execute(f)
    _finish_replay(f)
    assert pair.status_pair(**_kwargs(f))["operation_status"] != "REPLAY_COMPLETE"
    with sqlite3.connect(f["database"]) as db:
        for name, source in (("mqtt_feature_rule", "feature_logs"), ("mqtt_message_rule", "mqtt_logs")):
            db.execute("INSERT INTO detector_checkpoints VALUES(?,?,NULL,?,?)",
                       (name, source, plan["bounded_replay"]["replay_end"], plan["bounded_replay"]["replay_end"]))
    assert pair.status_pair(**_kwargs(f))["operation_status"] == "REPLAY_COMPLETE"


def test_cli_bounded_replay_terminal_is_success(replay_fixture, capsys):
    f = replay_fixture
    _execute(f)
    _finish_replay(f)
    assert cli.main(["status", "--plan-file", str(f["output"]), "--db-path", str(f["database"]),
                     "--artifact-dir", str(f["artifacts"])]) == 0
    assert json.loads(capsys.readouterr().out)["operation_status"] == "REPLAY_COMPLETE"



def _close_target_with_uncaptured_tail(fixture):
    replay_end = TARGET_FIRST + timedelta(seconds=20)
    with sqlite3.connect(fixture["database"]) as db:
        session_pk = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (TARGET_SESSION,)).fetchone()[0]
        db.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE id=?",
                   (_db_utc(replay_end + timedelta(seconds=1)), session_pk))
        tail_id = _insert_capture_segment(db, session_pk=session_pk, capture_interface="eth-target",
                                          window_start=replay_end, status="FAILED")
        db.execute("UPDATE packet_capture_segments SET file_name=NULL,captured_duration_seconds=0,error_code='LATE_CAPTURE' WHERE id=?",
                   (tail_id,))
    fixture["target_tail_id"] = tail_id
    return tail_id


def _inspect_failed_target(fixture, **options):
    output = fixture["output"].with_name("failed-target-plan-" + str(uuid.uuid4()) + ".json")
    plan = pair.inspect_pair(db_path=fixture["database"], repository_root=fixture["root"],
                             current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
                             approved_by="admin-fixture", reason="process preserved prefix; do not skip target tail",
                             plan_output=output, **options)
    return output, plan


@pytest.fixture
def failed_target_replay_fixture(replay_fixture):
    f = replay_fixture
    _close_target_with_uncaptured_tail(f)
    output, plan = _inspect_failed_target(f, mode=core.BOUNDED_REPLAY_MODE, allow_failed_target_session=True)
    assert plan["can_execute"], plan["blocking_reasons"]
    f.update(output=output, plan=plan)
    return f


def test_failed_target_prefix_requires_separate_explicit_bounded_opt_in(replay_fixture):
    f = replay_fixture
    _close_target_with_uncaptured_tail(f)
    for options in ({}, {"mode": core.BOUNDED_REPLAY_MODE}, {"allow_failed_target_session": True}):
        _, rejected = _inspect_failed_target(f, **options)
        assert rejected["can_execute"] is False
        assert rejected["blocking_reasons"]
    output, plan = _inspect_failed_target(f, mode=core.BOUNDED_REPLAY_MODE, allow_failed_target_session=True)
    assert plan["can_execute"] is True and plan["allow_failed_current_session"] is False
    assert plan["failed_target_tail"]["segment_id"] == f["target_tail_id"]
    assert plan["bounded_replay"]["replay_end"] == _db_utc(TARGET_FIRST + timedelta(seconds=20))
    assert plan["bounded_replay"]["segment_count"] == 2
    assert plan["bounded_replay"]["total_segment_count"] == 3
    assert all(c["plan"]["allow_failed_target_session"] is True and
               c["plan"]["failed_target_tail"] == plan["failed_target_tail"] for c in plan["children"])
    assert pair._load_pair(output)[1] == plan
    assert _audits(f) == []


def test_failed_target_replay_finishes_only_actual_preserved_prefix_and_keeps_tail(failed_target_replay_fixture):
    f = failed_target_replay_fixture
    with sqlite3.connect(f["database"]) as db:
        original = db.execute("SELECT * FROM packet_capture_sessions WHERE session_id=?", (TARGET_SESSION,)).fetchone()
        tail = db.execute("SELECT * FROM packet_capture_segments WHERE id=?", (f["target_tail_id"],)).fetchone()
    assert _execute(f)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert pair.status_pair(**_kwargs(f))["operation_status"] != "REPLAY_COMPLETE"
    _finish_replay(f, trust_pending=True)
    assert pair.status_pair(**_kwargs(f))["operation_status"] != "REPLAY_COMPLETE"
    _finish_replay(f)
    complete = pair.status_pair(**_kwargs(f))
    assert complete["operation_status"] == "REPLAY_COMPLETE" and complete["live_recovery_complete"] is False
    assert complete["replay_end"] == f["plan"]["failed_target_tail"]["window_start"]
    assert len(_audits(f)) == 2
    assert all(json.loads(audit["plan_json"])["allow_failed_target_session"] is True for audit in _audits(f))
    assert _execute(f, resume=True)["operation_status"] == "REPLAY_COMPLETE"
    assert len(_audits(f)) == 2
    with sqlite3.connect(f["database"]) as db:
        assert db.execute("SELECT * FROM packet_capture_sessions WHERE session_id=?", (TARGET_SESSION,)).fetchone() == original
        assert db.execute("SELECT * FROM packet_capture_segments WHERE id=?", (f["target_tail_id"],)).fetchone() == tail


def test_failed_target_partial_response_loss_resumes_only_missing_if(failed_target_replay_fixture, monkeypatch):
    f = failed_target_replay_fixture
    original = core._execute_locked_recovery
    calls = []
    def lose_response(**prepared):
        name = prepared["plan"]["detector_name"]
        calls.append(name)
        result = original(**prepared)
        if name == "packet_rule":
            raise RuntimeError("response lost after real Rule COMMIT")
        return result
    monkeypatch.setattr(core, "_execute_locked_recovery", lose_response)
    assert _execute(f)["operation_status"] == "PARTIAL_HOLD"
    assert len(_audits(f)) == 1 and calls == ["packet_rule"]
    assert _execute(f, resume=True)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert calls == ["packet_rule", "packet_if"] and len(_audits(f)) == 2
    _finish_replay(f)
    assert pair.status_pair(**_kwargs(f))["operation_status"] == "REPLAY_COMPLETE"


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_failed_target_approval_requires_literal_boolean(replay_fixture, value):
    with pytest.raises(core.PacketCheckpointRecoveryError, match="failed-target-session approval must be boolean"):
        _inspect_failed_target(replay_fixture, mode=core.BOUNDED_REPLAY_MODE, allow_failed_target_session=value)


@pytest.mark.parametrize("mutation", ["parent_flag", "child_flag", "parent_tail", "child_tail"])
def test_failed_target_parent_child_approval_and_tail_are_sha_bound(failed_target_replay_fixture, mutation):
    f = failed_target_replay_fixture
    plan = json.loads(json.dumps(f["plan"]))
    if mutation == "parent_flag":
        plan["allow_failed_target_session"] = False
    elif mutation == "child_flag":
        plan["children"][0]["plan"]["allow_failed_target_session"] = False
    elif mutation == "parent_tail":
        plan["failed_target_tail"]["segment_id"] += 1
    else:
        plan["children"][0]["plan"]["failed_target_tail"]["segment_id"] += 1
    for child in plan["children"]:
        child["plan"] = core.attach_plan_sha256(child["plan"], generated_at=f["clock"][0])
    f["plan"] = _resign(plan, f)
    with pytest.raises(core.PacketCheckpointRecoveryError, match="contract mismatch|tail binding mismatch"):
        _execute(f)
    assert _audits(f) == []


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("mutation", ["prefix", "tail", "closed_end"])
def test_failed_target_prefix_and_exact_tail_cannot_change(failed_target_replay_fixture, phase, mutation):
    f = failed_target_replay_fixture
    if phase == "after":
        _execute(f)
        _finish_replay(f)
    with sqlite3.connect(f["database"]) as db:
        if mutation == "prefix":
            db.execute("UPDATE packet_feature_logs SET total_bytes=total_bytes+1 WHERE capture_segment_id IN "
                       "(SELECT id FROM packet_capture_segments WHERE capture_session_id=(SELECT id FROM packet_capture_sessions WHERE session_id=?))",
                       (TARGET_SESSION,))
        elif mutation == "tail":
            db.execute("UPDATE packet_capture_segments SET error_message='changed exact tail' WHERE id=?", (f["target_tail_id"],))
        else:
            db.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE session_id=?",
                       (_db_utc(TARGET_FIRST + timedelta(seconds=22)), TARGET_SESSION))
    with pytest.raises(core.PacketCheckpointRecoveryError, match="bounded replay target or fixed input changed"):
        pair.status_pair(**_kwargs(f)) if phase == "after" else _execute(f)
    assert len(_audits(f)) == (2 if phase == "after" else 0)


def test_cli_failed_target_opt_in_is_separate_and_terminal_status_succeeds(replay_fixture, capsys):
    f = replay_fixture
    _close_target_with_uncaptured_tail(f)
    output = f["output"].with_name("cli-failed-target-prefix.json")
    args = ["dry-run", "--db-path", str(f["database"]), "--repository-root", str(f["root"]),
            "--current-session-id", CURRENT_SESSION, "--target-session-id", TARGET_SESSION,
            "--approved-by", "admin-fixture", "--reason", "preserve normal prefix",
            "--plan-output", str(output), "--mode", core.BOUNDED_REPLAY_MODE, "--allow-failed-target-session"]
    assert cli.main(args) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["allow_failed_target_session"] is True and plan["allow_failed_current_session"] is False
    f.update(output=output, plan=plan)
    _execute(f)
    _finish_replay(f)
    assert cli.main(["status", "--plan-file", str(output), "--db-path", str(f["database"]),
                     "--artifact-dir", str(f["artifacts"])]) == 0
    assert json.loads(capsys.readouterr().out)["operation_status"] == "REPLAY_COMPLETE"



def test_failed_target_prefix_does_not_authorize_follow_on_source_tail_skip(failed_target_replay_fixture):
    f = failed_target_replay_fixture
    _execute(f)
    _finish_replay(f)
    next_session = str(uuid.uuid4())
    next_start = TARGET_FIRST + timedelta(seconds=30)
    with sqlite3.connect(f["database"]) as db:
        session_pk = _insert_capture_session(db, session_id=next_session, capture_interface="eth-target",
                                             first_window_start=next_start, status="RUNNING")
        _insert_capture_segment(db, session_pk=session_pk, capture_interface="eth-target",
                                window_start=next_start, status="EMPTY")
        db.execute("UPDATE packet_capture_segments SET start_delay_seconds=0.1,captured_duration_seconds=9.9 WHERE id=?",
                   (db.execute("SELECT MAX(id) FROM packet_capture_segments").fetchone()[0],))
    options = dict(db_path=f["database"], repository_root=f["root"], current_session_id=TARGET_SESSION,
                   target_session_id=next_session, approved_by="admin-fixture", reason="separately inspect source loss")
    blocked = pair.inspect_pair(**options, plan_output=f["output"].with_name("unapproved-follow-on.json"))
    assert blocked["can_execute"] is False and blocked["allow_failed_current_session"] is False
    approved = pair.inspect_pair(**options, allow_failed_current_session=True,
                                 plan_output=f["output"].with_name("separately-approved-follow-on.json"))
    assert approved["can_execute"], approved["blocking_reasons"]
    assert approved["allow_failed_target_session"] is False
    assert all(c["plan"]["failed_current_tail"]["segment_id"] == f["target_tail_id"] for c in approved["children"])
    assert len(_audits(f)) == 2


def test_failed_source_and_target_prefix_approvals_are_independent(replay_fixture):
    f = replay_fixture
    _close_target_with_uncaptured_tail(f)
    with sqlite3.connect(f["database"]) as db:
        source_pk = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (CURRENT_SESSION,)).fetchone()[0]
        ready = CURRENT_READY_THROUGH
        tail_start = TARGET_FIRST - timedelta(seconds=10)
        while ready < tail_start:
            _insert_capture_segment(db, session_pk=source_pk, capture_interface="eth-current",
                                    window_start=ready, status="EMPTY")
            ready += timedelta(seconds=10)
        db.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=? WHERE detector_name IN ('packet_rule','packet_if')",
                   (_db_utc(tail_start), _db_utc(tail_start)))
        db.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE id=?",
                   (_db_utc(tail_start + timedelta(seconds=1)), source_pk))
        source_tail = _insert_capture_segment(db, session_pk=source_pk, capture_interface="eth-current",
                                             window_start=tail_start, status="FAILED")
        db.execute("UPDATE packet_capture_segments SET file_name=NULL,captured_duration_seconds=0,error_code='LATE_CAPTURE' WHERE id=?",
                   (source_tail,))
    _, blocked = _inspect_failed_target(f, mode=core.BOUNDED_REPLAY_MODE, allow_failed_target_session=True)
    assert blocked["can_execute"] is False
    output, approved = _inspect_failed_target(f, mode=core.BOUNDED_REPLAY_MODE,
                                             allow_failed_target_session=True, allow_failed_current_session=True)
    assert approved["can_execute"], approved["blocking_reasons"]
    for child in approved["children"]:
        signed = child["plan"]
        assert signed["failed_current_tail"]["segment_id"] == source_tail
        assert signed["failed_target_tail"]["segment_id"] == f["target_tail_id"]
        assert core.recovery_execute_confirmation(signed) == core.FAILED_TARGET_PREFIX_BOUNDED_REPLAY_CONFIRMATION
    f.update(output=output, plan=approved)
    assert _execute(f)["operation_status"] == "APPLIED_PENDING_PROGRESS" and len(_audits(f)) == 2


def test_existing_default_bounded_pair_without_new_optional_fields_remains_executable(replay_fixture):
    f = replay_fixture
    plan = json.loads(json.dumps(f["plan"]))
    plan.pop("allow_failed_target_session")
    plan.pop("failed_target_tail", None)
    for child in plan["children"]:
        child["plan"].pop("allow_failed_target_session")
        child["plan"].pop("failed_target_tail")
        child["plan"] = core.attach_plan_sha256(child["plan"], generated_at=f["clock"][0])
    f["plan"] = _resign(plan, f)
    assert pair._load_pair(f["output"])[1] == f["plan"]
    assert _execute(f)["operation_status"] == "APPLIED_PENDING_PROGRESS"
    _finish_replay(f)
    assert pair.status_pair(**_kwargs(f))["operation_status"] == "REPLAY_COMPLETE"
