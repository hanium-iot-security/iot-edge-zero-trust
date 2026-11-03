"""Native two-failure proof and read-only confirmed-tail drain coverage."""
import json
from pathlib import Path
import shutil
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from edge.maintenance import planned
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
from tests.test_planned_maintenance import (
    NEW_BOOT, TARGET, add_segment, add_session, db as maintenance_db,
    protected, transaction, utc,
)
from tests.test_planned_prefix_recovery import (
    SUCCESSOR, THIRD, advance_for_drain, checkpoint_rows, late_tail, prefix_db,
)
from tests.test_planned_maintenance_processing import prepared as pipeline_db
from tests.test_planned_maintenance_cli import runner as base_runner
from tests.test_planned_prefix_recovery_cli import prefix_runner, recover as recover_command

FOURTH = "77777777-7777-4777-8777-777777777777"


@pytest.fixture
def chain_db(prefix_db):
    conn, directory, operation, ids = prefix_db
    ids = dict(ids)
    ids["intermediate"] = ids["successor"]
    conn.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE id=?",
                 (utc(131), ids["intermediate"]))
    conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (ids["successor_segment"],))
    conn.execute("UPDATE packet_capture_segments SET status='EMPTY' WHERE id=?", (ids["successor_segment"],))
    ids["intermediate_empty"] = ids["successor_segment"]
    ids["intermediate_normal"] = [add_segment(conn, ids["intermediate"], start) for start in (110, 120)]
    ids["intermediate_failure"] = late_tail(conn, ids["intermediate"], 130)
    ids["final"] = add_session(conn, THIRD, 140)
    ids["final_empty"] = add_segment(conn, ids["final"], 140, "EMPTY")
    ids["final_normal"] = add_segment(conn, ids["final"], 150)
    conn.commit()
    return conn, directory, operation, ids


def inspect(conn, operation, **changes):
    options = dict(target_session_id=TARGET, successor_session_id=THIRD,
                   approved_by="woomin", reason="Preserve both healthy prefixes and both uninspected tails",
                   current_boot_id=NEW_BOOT, time_synchronized=True, now=utc(180))
    options.update(changes)
    return planned.inspect_prefix_recovery(conn, operation["operation_id"], **options)


def apply(conn, plan, directory):
    with transaction(conn):
        return planned.apply_prefix_recovery(conn, plan, now=utc(185),
                                             backup_path=str((directory / "chain.backup.db").resolve()),
                                             backup_sha256="a" * 64)


def test_two_failed_prefixes_bind_both_tails_and_start_at_first_target(chain_db):
    conn, directory, operation, ids = chain_db
    before, cps = protected(conn), checkpoint_rows(conn)
    plan = inspect(conn, operation)
    proof = plan["failed_prefix_recovery"]
    child, = proof["intermediate_proofs"]
    assert child["target_snapshot"]["session"]["session_id"] == SUCCESSOR
    assert child["target_snapshot"]["prefix_segment_count"] == 3
    assert child["target_snapshot"]["feature_count"] == 2
    assert child["target_snapshot"]["prefix_segment_sha256"]
    assert child["target_snapshot"]["feature_sha256"]
    assert child["failure"]["id"] == ids["intermediate_failure"]
    assert child["prefix_end"] == utc(130)
    assert child["successor_session_id"] == THIRD
    assert len(proof["chain_adjacency"]) == 2
    assert proof["failure"]["id"] == ids["failed"]
    assert proof["prefix_end"] == utc(90)
    assert proof["successor_session_id"] == THIRD
    assert proof["successor_evidence"]["segment"]["id"] == ids["final_normal"]
    assert [row["id"] for row in proof["successor_evidence"]["empty_prefix"]] == [ids["final_empty"]]
    assert plan["maintenance_end"] == utc(60)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    changes = conn.total_changes
    audit = apply(conn, plan, directory)
    assert conn.total_changes - changes == 4
    assert protected(conn) == before
    for old, current in zip(cps, checkpoint_rows(conn)):
        assert current[2] == old[2]  # No healthy source ID was consumed or skipped.
        assert current[3] == (utc(60) if current[0] in planned.PACKET_DETECTORS else old[3])
    assert audit["maintenance_end"] == utc(60)
    assert planned.approved_intervals(conn)[0]["window_end"] == utc(60)
    assert planned.get_resume_audit(conn, operation["operation_id"])["plan_sha256"] == plan["plan_sha256"]
    assert apply(conn, plan, directory) == audit
    assert protected(conn) == before


def record_tail(conn, start):
    """The native confirmed-gap writer consumes a simulated completed prefix."""
    path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    try:
        with Session(engine) as db:
            result = advance_confirmed_packet_gap(
                db, range_start=planned.parse_db_utc(utc(start)),
                cutoff=planned.parse_db_utc(utc(start + 20)))
            assert result is not None
            db.commit()
    finally:
        engine.dispose()


def confirm_chain(conn):
    for start in (90, 130):
        advance_for_drain(conn, start)
        record_tail(conn, start)
    advance_for_drain(conn, 140)


def drain(conn, operation):
    return planned.check_prefix_drain(conn, operation["operation_id"])


def test_chain_reader_checks_each_prefix_boundary_and_keeps_original_plan(chain_db):
    conn, directory, operation, ids = chain_db
    plan = inspect(conn, operation)
    audit = apply(conn, plan, directory)
    assert drain(conn, operation)["result"] == "WAIT"
    advance_for_drain(conn, 90)
    first = drain(conn, operation)
    assert first["result"] == "PREFIX_DRAINED_RECOVERY_REQUIRED"
    assert first["prefix_end"] == utc(90)
    record_tail(conn, 90)
    for end in (100, 110, 120):
        advance_for_drain(conn, end)
        assert drain(conn, operation)["result"] == "WAIT"
    advance_for_drain(conn, 130)
    middle = drain(conn, operation)
    assert middle["result"] == "PREFIX_DRAINED_RECOVERY_REQUIRED"
    assert middle["prefix_end"] == utc(130)
    assert middle["failed_segment_id"] == ids["intermediate_failure"]
    assert middle["pending_tail"]["source_session_id"] == SUCCESSOR
    assert len(middle["confirmed_tails"]) == 1
    record_tail(conn, 130)
    assert drain(conn, operation)["result"] == "WAIT"  # MQTT/Trust still at 130.
    advance_for_drain(conn, 140)
    before = protected(conn), checkpoint_rows(conn), conn.total_changes
    for _ in range(3):
        result = drain(conn, operation)
        assert result["result"] == "PREFIX_DRAINED_CONFIRMED_GAP"
        assert result["prefix_ends"] == [utc(90), utc(130)]
        assert [(tail["window_start"], tail["window_end"], tail["status"])
                for tail in result["confirmed_tails"]] == [
                    (utc(90), utc(100), "UNINSPECTED"), (utc(130), utc(140), "UNINSPECTED")]
        assert [tail["successor_session_id"] for tail in result["confirmed_tails"]] == [SUCCESSOR, THIRD]
        assert "gap_status" not in result and "gap_end" not in result
        assert planned.get_resume_audit(conn, operation["operation_id"]) == audit
        assert apply(conn, plan, directory) == audit
    assert (protected(conn), checkpoint_rows(conn), conn.total_changes) == before
    assert conn.execute("SELECT plan_json,plan_sha256 FROM planned_maintenance_resumes").fetchone()[:] == (
        audit["plan_json"], plan["plan_sha256"])
    assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 1


@pytest.mark.parametrize("end", [60, 90, 100, 120, 130, 140])
def test_chain_reader_rejects_unequal_packet_boundaries_even_while_other_stages_lag(chain_db, end):
    conn, directory, operation, _ = chain_db
    apply(conn, inspect(conn, operation), directory)
    confirm_chain(conn)
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=? "
                 "WHERE detector_name='packet_rule'", (utc(end), utc(end)))
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=? "
                 "WHERE detector_name='packet_if'", (utc(end + 10), utc(end + 10)))
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? "
                 "WHERE source_table!='packet_feature_logs'", (utc(20),))
    conn.commit()
    before = conn.total_changes
    with pytest.raises(planned.PlannedMaintenanceError):
        drain(conn, operation)
    assert conn.total_changes == before


@pytest.mark.parametrize("detector", ["mqtt_message", "mqtt_rule", "trust"])
def test_chain_reader_waits_for_mqtt_and_trust_after_both_tails(chain_db, detector):
    conn, directory, operation, _ = chain_db
    apply(conn, inspect(conn, operation), directory)
    confirm_chain(conn)
    # Fixture names are read from the native profile instead of inventing stages.
    candidates = [row["detector_name"] for row in conn.execute("SELECT * FROM detector_checkpoints")
                  if (row["source_table"] == "mqtt_logs" if detector == "mqtt_message" else
                      row["source_table"] == "feature_logs" if detector == "mqtt_rule" else
                      row["source_table"] == "detection_events")]
    assert candidates
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name=?",
                 (utc(130), candidates[0]))
    conn.commit()
    before = conn.total_changes
    assert drain(conn, operation)["result"] == "WAIT"
    assert conn.total_changes == before


def corrupt_tail(conn, start, change):
    """Corrupt only a disposable fixture, restoring the exact immutable trigger."""
    audit = dict(conn.execute("SELECT * FROM packet_detection_gaps WHERE window_start=?", (utc(start),)).fetchone())
    trigger_name = "packet_detection_gaps_no_delete" if change == "missing" else "packet_detection_gaps_no_update"
    trigger = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (trigger_name,)).fetchone()[0]
    conn.execute(f"DROP TRIGGER {trigger_name}")
    if change == "missing":
        conn.execute("DELETE FROM packet_detection_gaps WHERE id=?", (audit["id"],))
    else:
        evidence = json.loads(audit["evidence_json"])
        if change in ("source", "target"):
            evidence[change]["session_id"] = THIRD if change == "source" or start == 90 else TARGET
            audit[change + "_session_id"] = evidence[change]["session_id"]
        elif change == "failure":
            evidence["source_last_segment"]["error_message"] = "changed tail"
        elif change == "first_segment":
            evidence["target_first_segment"]["id"] += 1
        elif change in ("rule_id", "if_id", "missing_id"):
            name = "packet_rule" if change == "rule_id" else "packet_if"
            cp = next(row for row in evidence["checkpoints_before"] if row["detector_name"] == name)
            if change == "missing_id":
                cp.pop("last_processed_id")
            else:
                cp["last_processed_id"] = 2
        elif change == "missing_pair":
            evidence["checkpoints_before"].pop()
        elif change == "boundary":
            evidence["checkpoints_before"][0]["last_completed_window_end"] = utc(start - 10)
        elif change == "reason":
            audit["reason"] = evidence["reason"] = "RECORDED_CAPTURE_GAP"
        elif change == "window":
            audit["window_end"] = evidence["window_end"] = utc(start + 20)
        audit["evidence_json"] = "{" if change == "json" else json.dumps(evidence)
        audit["plan_sha256"] = "0" * 64 if change == "digest" else planned._digest(evidence)
        conn.execute("UPDATE packet_detection_gaps SET source_session_id=:source_session_id,target_session_id=:target_session_id,"
                     "window_end=:window_end,reason=:reason,evidence_json=:evidence_json,plan_sha256=:plan_sha256 WHERE id=:id", audit)
    conn.execute(trigger)
    conn.commit()


@pytest.mark.parametrize("start", [90, 130])
@pytest.mark.parametrize("change", ["missing", "digest", "json", "source", "target", "failure", "first_segment",
                                   "rule_id", "if_id", "missing_id", "missing_pair", "boundary", "reason", "window"])
def test_every_crossed_tail_needs_exact_audit_even_when_mqtt_trust_lag(chain_db, start, change):
    conn, directory, operation, _ = chain_db
    apply(conn, inspect(conn, operation), directory)
    confirm_chain(conn)
    corrupt_tail(conn, start, change)
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? "
                 "WHERE source_table!='packet_feature_logs'", (utc(20),))
    conn.commit()
    before = conn.total_changes
    with pytest.raises(planned.PlannedMaintenanceError):
        drain(conn, operation)
    assert conn.total_changes == before


@pytest.mark.parametrize("middle_input", ["outbound", "empty"])
def test_middle_without_inbound_carries_forward_rule_id_from_first_prefix(chain_db, middle_input):
    conn, directory, operation, ids = chain_db
    if middle_input == "outbound":
        conn.execute("UPDATE packet_feature_logs SET direction='OUTBOUND' WHERE capture_segment_id IN (?,?)",
                     ids["intermediate_normal"])
    else:
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id IN (?,?)", ids["intermediate_normal"])
        conn.execute("UPDATE packet_capture_segments SET status='EMPTY' WHERE id IN (?,?)", ids["intermediate_normal"])
    conn.commit()
    plan = inspect(conn, operation)
    apply(conn, plan, directory)
    confirm_chain(conn)
    audits = [json.loads(row[0]) for row in conn.execute("SELECT evidence_json FROM packet_detection_gaps ORDER BY id")]
    rule_ids = [next(row["last_processed_id"] for row in evidence["checkpoints_before"]
                     if row["detector_name"] == "packet_rule") for evidence in audits]
    assert rule_ids[0] == rule_ids[1] > plan["checkpoints"]["packet_rule"]["before"]["last_processed_id"]
    if middle_input == "empty":
        if_ids = [next(row["last_processed_id"] for row in evidence["checkpoints_before"]
                       if row["detector_name"] == "packet_if") for evidence in audits]
        assert if_ids[0] == if_ids[1]
    assert drain(conn, operation)["result"] == "PREFIX_DRAINED_CONFIRMED_GAP"


@pytest.mark.parametrize("end", [100, 110, 130])
@pytest.mark.parametrize("change", ["missing", "if_id"])
def test_first_crossed_tail_is_required_while_middle_prefix_is_pending(chain_db, end, change):
    conn, directory, operation, _ = chain_db
    apply(conn, inspect(conn, operation), directory)
    advance_for_drain(conn, 90)
    record_tail(conn, 90)
    advance_for_drain(conn, end)
    corrupt_tail(conn, 90, change)
    before = conn.total_changes
    with pytest.raises(planned.PlannedMaintenanceError):
        drain(conn, operation)
    assert conn.total_changes == before


@pytest.mark.parametrize("start", [90, 130])
def test_exact_prefix_boundary_requires_its_own_consumed_ids(chain_db, start):
    conn, directory, operation, _ = chain_db
    apply(conn, inspect(conn, operation), directory)
    advance_for_drain(conn, 90)
    if start == 130:
        record_tail(conn, 90)
        advance_for_drain(conn, 130)
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=2 WHERE detector_name='packet_if'")
    conn.commit()
    with pytest.raises(planned.PlannedMaintenanceError):
        drain(conn, operation)


@pytest.mark.parametrize("start", [60, 100])
def test_native_schema_rejects_foreign_feature_fractional_prefix_overlap(chain_db, start):
    conn, _, operation, ids = chain_db
    fractional_end = utc(start).replace("Z", ".000001Z")
    assert conn.execute("SELECT unixepoch(?)=unixepoch(?)", (fractional_end, utc(start))).fetchone()[0] == 1
    before = protected(conn)
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        conn.execute("UPDATE packet_feature_logs SET window_start=?,window_end=? WHERE capture_segment_id=?",
                     (utc(start - 10), fractional_end, ids["final_normal"]))
    conn.rollback()
    assert protected(conn) == before
    assert inspect(conn, operation)["failed_prefix_recovery"]["prefix_end"] == utc(90)


@pytest.fixture
def chain_before_013(tmp_path, monkeypatch, request):
    from tests import test_planned_maintenance as maintenance
    old = tmp_path / "through-012"
    old.mkdir()
    for source in MIGRATIONS_DIR.glob("*.sql"):
        if int(source.name.split("_", 1)[0]) <= 12:
            shutil.copyfile(source, old / source.name)
    monkeypatch.setattr(maintenance, "MIGRATIONS_DIR", old)
    return request.getfixturevalue("chain_db")


def test_old_chain_seals_survive_real_migration_and_both_confirmed_tails(chain_before_013):
    conn, directory, operation, ids = chain_before_013
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 12
    plan = inspect(conn, operation)
    audit = apply(conn, plan, directory)
    result = apply_migrations(directory / "iot.db", MIGRATIONS_DIR)
    assert result.applied_versions == list(range(13, 20))
    assert planned.get_resume_audit(conn, operation["operation_id"]) == audit
    confirm_chain(conn)
    before = conn.total_changes
    assert drain(conn, operation)["result"] == "PREFIX_DRAINED_CONFIRMED_GAP"
    assert apply(conn, plan, directory) == audit
    assert conn.total_changes == before
    assert conn.execute("SELECT plan_json,plan_sha256 FROM planned_maintenance_resumes").fetchone()[:] == (
        audit["plan_json"], plan["plan_sha256"])
    conn.execute("UPDATE packet_feature_logs SET broker_target_ip='192.0.2.3',broker_target_port=1883,"
                 "broker_target_syn_count=0 WHERE capture_segment_id=?", (ids["intermediate_normal"][0],))
    conn.commit()
    with pytest.raises(planned.PlannedMaintenanceError):
        drain(conn, operation)


@pytest.mark.parametrize("field", ["intermediate_proofs", "chain_adjacency"])
def test_whole_stored_plan_is_validated_before_projecting_tail_pairs(chain_db, monkeypatch, field):
    from edge.maintenance import prefix_recovery
    conn, directory, operation, _ = chain_db
    apply(conn, inspect(conn, operation), directory)
    confirm_chain(conn)
    audit = dict(conn.execute("SELECT * FROM planned_maintenance_resumes").fetchone())
    plan = json.loads(audit["plan_json"])
    del plan["failed_prefix_recovery"][field]
    triggers = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                            "AND tbl_name='planned_maintenance_resumes'").fetchall()
    for name, _ in triggers:
        conn.execute(f"DROP TRIGGER {name}")
    conn.execute("UPDATE planned_maintenance_resumes SET plan_json=?", (json.dumps(plan),))
    for _, sql in triggers:
        conn.execute(sql)
    conn.commit()
    def unexpected_projection(*args):
        pytest.fail("Pair projection ran before full stored audit validation")
    monkeypatch.setattr(prefix_recovery, "_check_chain_drain", unexpected_projection)
    before = conn.total_changes
    with pytest.raises(planned.PlannedMaintenanceError):
        drain(conn, operation)
    assert conn.total_changes == before


@pytest.mark.parametrize("finish_first_call", [False, True])
def test_chain_command_accepts_both_tail_result_and_never_reapplies(prefix_runner, finish_first_call):
    runner, system, directory, operation, _, _ = prefix_runner
    with sqlite3.connect(runner.database) as conn:
        middle = conn.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (SUCCESSOR,)).fetchone()[0]
        conn.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE id=?", (utc(131), middle))
        for start in (110, 120):
            add_segment(conn, middle, start)
        late_tail(conn, middle, 130)
        final = add_session(conn, THIRD, 140)
        add_segment(conn, final, 140)
    system.elapsed = 170
    def catch_up():
        with sqlite3.connect(runner.database) as conn:
            conn.row_factory = sqlite3.Row
            confirm_chain(conn)
    if finish_first_call:
        system.on_sleep = catch_up
    first = recover_command(prefix_runner, successor_session_id=THIRD, verify_timeout=2 if finish_first_call else 0)
    assert first["result"] == ("PREFIX_DRAINED_CONFIRMED_GAP" if finish_first_call else "COMMITTED_HOLD")
    if not finish_first_call:
        catch_up()
    calls = system.events[:]
    with sqlite3.connect(runner.database) as conn:
        before = protected(conn)
    second = recover_command(prefix_runner, successor_session_id=THIRD)
    assert second["result"] == "PREFIX_DRAINED_CONFIRMED_GAP" and second["reapplied"] is False
    assert len(second["verification"]["confirmed_tails"]) == 2
    assert first["audit"]["plan_sha256"] == second["audit"]["plan_sha256"]
    assert system.events == calls + ["authenticate"]
    with sqlite3.connect(runner.database) as conn:
        assert protected(conn) == before
        assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 1


def test_chain_drain_still_stops_at_first_tail(chain_db):
    conn, directory, operation, ids = chain_db
    originals = protected(conn)
    apply(conn, inspect(conn, operation), directory)
    assert planned.check_prefix_drain(conn, operation["operation_id"])["result"] == "WAIT"
    advance_for_drain(conn)
    before = checkpoint_rows(conn), conn.total_changes
    result = planned.check_prefix_drain(conn, operation["operation_id"])
    assert result["prefix_end"] == utc(90) and result["failed_segment_id"] == ids["failed"]
    assert result["successor_session_id"] == THIRD
    assert (checkpoint_rows(conn), conn.total_changes) == before and protected(conn) == originals


@pytest.mark.parametrize("change", [
    "healthy_intermediate", "running_intermediate", "unclosed_intermediate", "missing_prefix",
    "prefix_gap", "prefix_overlap", "prefix_late", "failure_ambiguity", "tail_packet", "tail_feature",
    "foreign_feature_overlap", "foreign_segment_overlap", "adjacency_gap", "adjacency_overlap",
    "started_before_previous_end", "started_after_boundary", "interface", "final_completed", "final_not_latest",
    "final_empty_only", "final_ready", "final_zero_feature", "third_failed_session",
])
def test_nonexact_chain_holds_without_any_mutation(chain_db, change):
    conn, _, operation, ids = chain_db
    middle, first, tail = ids["intermediate"], ids["intermediate_empty"], ids["intermediate_failure"]
    if change in ("healthy_intermediate", "running_intermediate", "unclosed_intermediate"):
        status = "COMPLETED" if change == "healthy_intermediate" else "RUNNING" if change == "running_intermediate" else "FAILED"
        conn.execute("UPDATE packet_capture_sessions SET status=?,ended_at=? WHERE id=?",
                     (status, None if change == "unclosed_intermediate" else utc(131), middle))
    elif change == "missing_prefix":
        conn.execute("DELETE FROM packet_capture_segments WHERE id=?", (first,))
    elif change == "prefix_gap":
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (ids["intermediate_normal"][0],))
        conn.execute("DELETE FROM packet_capture_segments WHERE id=?", (ids["intermediate_normal"][0],))
    elif change == "prefix_overlap":
        conn.execute("UPDATE packet_capture_segments SET window_start=?,window_end=? WHERE id=?", (utc(105), utc(115), first))
    elif change == "prefix_late":
        conn.execute("UPDATE packet_capture_segments SET start_delay_seconds=1.2 WHERE id=?", (first,))
    elif change == "failure_ambiguity":
        conn.execute("UPDATE packet_capture_segments SET status='FAILED',error_code='PARTIAL_CAPTURE' WHERE id=?", (first,))
    elif change == "tail_packet":
        conn.execute("UPDATE packet_capture_segments SET packet_count=1 WHERE id=?", (tail,))
    elif change == "tail_feature":
        conn.execute("UPDATE packet_feature_logs SET capture_segment_id=?,window_start=?,window_end=? WHERE capture_segment_id=?",
                     (tail, utc(130), utc(140), ids["intermediate_normal"][0]))
    elif change == "foreign_feature_overlap":
        conn.execute("UPDATE packet_feature_logs SET window_start=?,window_end=? WHERE capture_segment_id=?",
                     (utc(110), utc(120), ids["final_normal"]))
    elif change == "foreign_segment_overlap":
        conn.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,"
                     "status,packet_count,start_delay_seconds,captured_duration_seconds) VALUES (?,'foreign.pcap','wlan0',?,?,"
                     "'EMPTY',0,0,10)", (ids["final"], utc(110), utc(120)))
    elif change in ("adjacency_gap", "adjacency_overlap", "started_before_previous_end", "started_after_boundary", "interface"):
        field, value = {"adjacency_gap": ("first_window_start", utc(110)),
                        "adjacency_overlap": ("first_window_start", utc(90)),
                        "started_before_previous_end": ("started_at", utc(90)),
                        "started_after_boundary": ("started_at", utc(101)),
                        "interface": ("capture_interface", "wlan0")}[change]
        conn.execute(f"UPDATE packet_capture_sessions SET {field}=? WHERE id=?", (value, middle))
    elif change == "final_completed":
        conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE id=?", (utc(160), ids["final"]))
    elif change == "final_not_latest":
        add_session(conn, FOURTH, 170, status="COMPLETED")
    elif change in ("final_empty_only", "final_ready"):
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (ids["final_normal"],))
        conn.execute("UPDATE packet_capture_segments SET status=? WHERE id=?",
                     ("EMPTY" if change == "final_empty_only" else "READY", ids["final_normal"]))
    elif change == "final_zero_feature":
        conn.execute("UPDATE packet_feature_logs SET packet_count=0 WHERE capture_segment_id=?", (ids["final_normal"],))
    elif change == "third_failed_session":
        conn.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE id=?", (utc(161), ids["final"]))
        late_tail(conn, ids["final"], 160)
        later = add_session(conn, FOURTH, 170)
        add_segment(conn, later, 170)
    conn.commit()
    before, cps, changes = protected(conn), checkpoint_rows(conn), conn.total_changes
    with pytest.raises(planned.PlannedMaintenanceError):
        inspect(conn, operation, successor_session_id=FOURTH if change == "third_failed_session" else THIRD)
    assert protected(conn) == before and checkpoint_rows(conn) == cps and conn.total_changes == changes
    assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("change", ["feature", "segment", "failure", "session", "adjacency"])
def test_intermediate_changes_are_detected_before_apply_and_after_resume(chain_db, committed, change):
    conn, directory, operation, ids = chain_db
    plan = inspect(conn, operation)
    if committed:
        apply(conn, plan, directory)
    if change == "feature":
        conn.execute("UPDATE packet_feature_logs SET total_bytes=total_bytes+1 WHERE capture_segment_id=?",
                     (ids["intermediate_normal"][0],))
    elif change in ("segment", "failure"):
        segment = ids["intermediate_empty"] if change == "segment" else ids["intermediate_failure"]
        conn.execute("UPDATE packet_capture_segments SET error_message='evidence changed' WHERE id=?", (segment,))
    else:
        field, value = ("started_at", utc(99)) if change == "adjacency" else ("capture_gap_start", utc(90))
        conn.execute(f"UPDATE packet_capture_sessions SET {field}=? WHERE id=?", (value, ids["intermediate"]))
    conn.commit()
    before, cps = protected(conn), checkpoint_rows(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        if committed:
            planned.get_resume_audit(conn, operation["operation_id"])
        else:
            apply(conn, plan, directory)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    if committed:
        with pytest.raises(planned.PlannedMaintenanceError):
            planned.approved_intervals(conn)
    else:
        assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


def test_audit_survives_final_appends_completion_and_a_later_running_session(chain_db):
    conn, directory, operation, ids = chain_db
    plan = inspect(conn, operation)
    add_segment(conn, ids["final"], 160)
    conn.commit()
    assert inspect(conn, operation)["plan_sha256"] == plan["plan_sha256"]
    audit = apply(conn, plan, directory)
    add_segment(conn, ids["final"], 170, "EMPTY")
    conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE id=?", (utc(180), ids["final"]))
    later = add_session(conn, FOURTH, 180)
    add_segment(conn, later, 180)
    conn.commit()
    assert planned.get_resume_audit(conn, operation["operation_id"]) == audit
    assert planned.approved_intervals(conn)[0]["window_end"] == utc(60)
    confirm_chain(conn)
    advance_for_drain(conn, 190)
    before = conn.total_changes
    assert drain(conn, operation)["result"] == "PREFIX_DRAINED_CONFIRMED_GAP"
    assert planned.get_resume_audit(conn, operation["operation_id"]) == audit
    assert conn.total_changes == before


@pytest.mark.parametrize("which", ["target", "intermediate", "ready"])
def test_each_feature_seal_uses_deployed_migration_compatibility(chain_db, which):
    from edge.packet.feature_evidence import MIGRATION_013_FIELDS
    from edge.maintenance.prefix_recovery import validate_prefix_audit
    conn, _, operation, ids = chain_db
    plan = inspect(conn, operation)
    proof = plan["failed_prefix_recovery"]
    if which == "ready":
        snapshot, key = proof["successor_evidence"], "features_sha256"
        rows = planned._rows(conn, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id",
                             {"id": ids["final_normal"]})
    else:
        snapshot = proof["target_snapshot"] if which == "target" else proof["intermediate_proofs"][0]["target_snapshot"]
        key = "feature_sha256"
        rows = planned._rows(conn, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s "
                             "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id ORDER BY f.id",
                             {"id": snapshot["session"]["id"]})
    snapshot[key] = planned._digest([{key: value for key, value in row.items() if key not in MIGRATION_013_FIELDS} for row in rows])
    validate_prefix_audit(conn, operation, plan)
    conn.execute("UPDATE packet_feature_logs SET broker_target_ip='192.0.2.3',broker_target_port=1883,"
                 "broker_target_syn_count=0 WHERE id=?", (rows[0]["id"],))
    conn.commit()
    with pytest.raises(planned.PlannedMaintenanceError):
        validate_prefix_audit(conn, operation, plan)


def test_real_pipeline_consumes_each_prefix_and_records_two_exact_uninspected_tails(pipeline_db, monkeypatch):
    from contextlib import closing
    from datetime import timedelta
    import sqlite3
    from uuid import uuid4
    from edge.detection.packet_rule_detector import PacketRuleDetectorStage
    from edge.detection.mqtt_adapters import MqttFeatureRuleStage, MqttMessageRuleStage
    from edge.features.collect_feature_logs import produce_mqtt_features_until
    from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
    from edge.orchestration import run_detection_orchestrator as orchestrator
    from edge.orchestration.stage_registry import StageRegistry, ConfiguredStage
    from edge.packet.capture_policy import CapturePolicy
    from tests.test_planned_maintenance_processing import (
        BASE, insert, packet, messages, utc as stamp, real_packet_if_with_normal_predictions,
    )

    path, factory, operation = pipeline_db
    target, middle, final, boot = (str(uuid4()) for _ in range(4))
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        last_features, tails = [], []
        for identity, start, status, end in ((target, 30, "FAILED", 61), (middle, 70, "FAILED", 101),
                                             (final, 110, "RUNNING", None)):
            session = insert(conn, "packet_capture_sessions", session_id=identity, capture_interface="eth0",
                             started_at=stamp(start - 5), first_window_start=stamp(start), status=status,
                             ended_at=stamp(end) if end else None,
                             capture_gap_start=stamp(10) if identity == target else None,
                             capture_gap_end=stamp(30) if identity == target else None)
            insert(conn, "packet_capture_segments", capture_session_id=session, file_name=f"empty-{start}.pcap",
                   capture_interface="eth0", window_start=stamp(start), window_end=stamp(start + 10),
                   status="EMPTY", packet_count=16, start_delay_seconds=0, captured_duration_seconds=10)
            last_feature = packet(conn, session, start + 10)
            if status == "FAILED":
                last_feature = packet(conn, session, start + 20)
                tails.append(late_tail(conn, session, start + 30, stamp))
            last_features.append(last_feature)
        for start in range(10, 130, 10):
            messages(conn, start, malformed=start < 30)
        conn.commit()
        tables = ("devices", "device_policy_revisions", "mqtt_logs", "packet_capture_sessions",
                  "packet_capture_segments", "packet_feature_logs")
        originals = {table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in tables}
        plan = planned.inspect_prefix_recovery(conn, operation, target_session_id=target, successor_session_id=final,
                                               approved_by="woomin", reason="Keep both healthy prefixes and uninspected tails",
                                               current_boot_id=boot, time_synchronized=True, now=stamp(135))
        assert plan["maintenance_end"] == stamp(30)
        with transaction(conn):
            planned.apply_prefix_recovery(conn, plan, now=stamp(135),
                                           backup_path=str(path.with_suffix(".backup.db")), backup_sha256="a" * 64)
    with factory.begin() as db:
        produced = produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=130))
        assert produced.created_feature_count == 10
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    ai, predicted = real_packet_if_with_normal_predictions()
    stages = (MqttFeatureRuleStage(), MqttMessageRuleStage(),
              PacketFeatureReadyStage(PacketRuleDetectorStage(capture_policy=CapturePolicy())), PacketFeatureReadyStage(ai))
    registry = StageRegistry(tuple(ConfiguredStage(stage.detector_name, stage, True) for stage in stages))
    observed = []
    for boundary in (30, 60, 70, 100, 110, 130):
        outcome = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
        assert outcome.status == orchestrator.CYCLE_COMPLETED
        assert outcome.cutoff == BASE + timedelta(seconds=boundary)
        with closing(sqlite3.connect(path)) as conn:
            conn.row_factory = sqlite3.Row
            observed.append(conn.execute("SELECT last_processed_id FROM detector_checkpoints WHERE detector_name='packet_if'").fetchone()[0])
            before = conn.total_changes
            expected = ("WAIT" if boundary in (30, 70) else
                        "PREFIX_DRAINED_RECOVERY_REQUIRED" if boundary in (60, 100) else
                        "PREFIX_DRAINED_CONFIRMED_GAP")
            result = planned.check_prefix_drain(conn, operation)
            assert result["result"] == expected
            assert conn.total_changes == before
            assert planned.get_resume_audit(conn, operation)["plan_sha256"] == plan["plan_sha256"]
    assert observed[1:] == [last_features[0], last_features[0], last_features[1], last_features[1], last_features[2]]
    assert len(predicted) == 5 and all(row["packet_count"] == 2 for row in predicted)
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        gaps = [tuple(row) for row in conn.execute("SELECT status,reason,window_start,window_end FROM packet_detection_gaps ORDER BY id")]
        assert gaps == [("UNINSPECTED", "LATE_CAPTURE", stamp(60), stamp(70)),
                        ("UNINSPECTED", "LATE_CAPTURE", stamp(100), stamp(110))]
        assert [tuple(row) for row in conn.execute("SELECT status,error_code FROM packet_capture_segments WHERE id IN (?,?) ORDER BY id", tails)] == [("FAILED", "LATE_CAPTURE")] * 2
        for table, rows in originals.items():
            assert [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")] == rows
        assert conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0] == 0
        assert planned.get_resume_audit(conn, operation)["plan_sha256"] == plan["plan_sha256"]
        assert planned.approved_intervals(conn)[0]["window_end"] == stamp(30)
