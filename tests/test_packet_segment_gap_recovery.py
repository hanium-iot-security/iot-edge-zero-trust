"""Evidence, transaction and repeated-gap tests using the real migrated schema."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.packet.segment_gap_recovery import (
    SegmentGapRecoveryError, apply_segment_gap_plan, approved_segment_gap,
    build_segment_gap_plan, canonical_plan_sha256, resolve_segment_gap_transition,
    verify_segment_gap_plan,
)


CAPTURE_UUID = "11111111-1111-4111-8111-111111111111"
BASE = datetime(2026, 10, 4, 3, 37, 10, tzinfo=timezone.utc)


def utc(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_segment_gap_database(path: Path) -> dict:
    """Reusable CLI/runtime fixture: two failures separated by healthy backlog."""
    path = Path(path).resolve()
    apply_migrations(path, MIGRATIONS_DIR)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("INSERT INTO devices(device_id,ip_address) VALUES ('esp32_01','192.168.0.4')")
    cursor = conn.execute("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status) "
                          "VALUES (?,'eth0',?,?,'RUNNING')", (CAPTURE_UUID, utc(0), utc(0)))
    session_pk = cursor.lastrowid
    segment_ids = []
    for index, state in enumerate(("PROCESSED", "FAILED", "PROCESSED", "EMPTY", "FAILED", "PROCESSED")):
        filename = f"failed-{1 if index == 1 else 2}.pcap" if state == "FAILED" else f"normal-{index}.pcap"
        cursor = conn.execute(
            "INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status,packet_count,error_code,error_message) "
            "VALUES (?,?,'eth0',?,?,?,2,?,?)",
            (session_pk, filename, utc(index * 10), utc((index + 1) * 10), state,
             "PARTIAL_CAPTURE" if state == "FAILED" else None,
             "tcpdump reported packet loss; excluded from READY (kernel=56, interface=0)" if state == "FAILED" else None),
        )
        segment_id = cursor.lastrowid
        segment_ids.append(segment_id)
        if state == "PROCESSED":
            conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,device_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                         "VALUES (?,'esp32_01','192.168.0.4','INBOUND',?,?,2,100,50,50)",
                         (segment_id, utc(index * 10), utc((index + 1) * 10)))
    for detector in ("packet_rule", "packet_if"):
        conn.execute("INSERT INTO detector_checkpoints VALUES (?,'packet_feature_logs',1,?,?)",
                     (detector, utc(10), utc(10)))
    conn.execute("INSERT INTO detector_checkpoints VALUES ('trust_score_v2','detection_events',0,?,?)", (utc(10), utc(10)))
    conn.commit()
    conn.close()
    return {"database_path": path, "capture_session_id": CAPTURE_UUID,
            "failed_segment_id": segment_ids[1], "first_failed_segment_id": segment_ids[1],
            "second_failed_segment_id": segment_ids[4], "segment_ids": segment_ids,
            "pcap_filename": "failed-1.pcap", "window_start": utc(10), "window_end": utc(20)}


def open_database(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def plan_kwargs(seed, directory, *, second=False):
    return {"capture_session_id": seed["capture_session_id"],
            "failed_segment_id": seed["second_failed_segment_id"] if second else seed["failed_segment_id"],
            "approved_by": "woomin", "reason": "Explicit operator approval of one failed capture Window",
            "repository_commit": "a" * 40, "database_path": str(seed["database_path"]),
            "backup_path": str((directory / "backup.db").resolve()),
            "preserved_pcap_path": str((directory / ("failed-2.pcap" if second else "failed-1.pcap")).resolve()),
            "pcap_sha256": "b" * 64}


@pytest.fixture
def evidence(tmp_path):
    seed = seed_segment_gap_database(tmp_path / "iot.db")
    conn = open_database(seed["database_path"])
    yield seed, conn, plan_kwargs(seed, tmp_path)
    conn.close()


def protected(conn):
    return {table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]
            for table in ("devices", "detection_events", "trust_score_history", "isolation_history",
                          "firewall_rules", "firewall_release_requests", "packet_capture_sessions",
                          "packet_capture_segments", "packet_feature_logs")}


def apply(conn, plan):
    conn.execute("BEGIN IMMEDIATE")
    result = apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
    conn.commit()
    return result


def test_one_gap_changes_only_two_checkpoints_and_one_audit(evidence):
    seed, conn, kwargs = evidence
    before = protected(conn)
    unrelated = dict(conn.execute("SELECT * FROM detector_checkpoints WHERE detector_name='trust_score_v2'").fetchone())
    plan = build_segment_gap_plan(conn, **kwargs)
    assert not conn.in_transaction
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    audit = apply(conn, plan)
    assert protected(conn) == before
    assert dict(conn.execute("SELECT * FROM detector_checkpoints WHERE detector_name='trust_score_v2'").fetchone()) == unrelated
    assert audit["window_end"] == utc(20)
    checkpoints = [dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints WHERE source_table='packet_feature_logs'")]
    assert {row["last_processed_id"] for row in checkpoints} == {1}
    assert {row["last_completed_window_end"] for row in checkpoints} == {utc(20)}
    segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (seed["failed_segment_id"],)).fetchone())
    assert approved_segment_gap(conn, segment)["operation_id"] == audit["operation_id"]
    assert resolve_segment_gap_transition(conn, BASE + timedelta(seconds=20), checkpoints)["operation_id"] == audit["operation_id"]


def test_cli_extra_binding_fields_are_verified_and_preserved(evidence):
    _, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    plan.update(repository_state={"head": "a" * 40}, repository_root=str(Path(kwargs["database_path"]).parent))
    plan["plan_sha256"] = canonical_plan_sha256(plan)
    verify_segment_gap_plan(plan)
    audit = apply(conn, plan)
    assert json.loads(audit["plan_json"])["repository_state"] == {"head": "a" * 40}


@pytest.mark.parametrize("field,value", [("approved_by", "attacker"), ("pcap_sha256", "d" * 64),
                                         ("repository_commit", "d" * 40), ("window_end", utc(30))])
def test_plan_tampering_rejected_before_mutation(evidence, field, value):
    _, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    before = protected(conn)
    plan[field] = value
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(SegmentGapRecoveryError, match="SHA256"):
        apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
    assert protected(conn) == before
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    conn.rollback()


@pytest.mark.parametrize("change", ["checkpoint", "failed", "following"])
def test_evidence_changed_after_plan_holds(evidence, change):
    seed, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    if change == "checkpoint":
        conn.execute("UPDATE detector_checkpoints SET updated_at=? WHERE detector_name='packet_if'", (utc(0),))
    elif change == "failed":
        conn.execute("UPDATE packet_capture_segments SET error_message='changed' WHERE id=?", (seed["failed_segment_id"],))
    else:
        conn.execute("UPDATE packet_capture_segments SET status='READY' WHERE id=?", (seed["segment_ids"][2],))
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(SegmentGapRecoveryError):
        apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    conn.rollback()


def test_feature_attached_to_healthy_segment_inside_failed_window_rejects(evidence):
    seed, conn, kwargs = evidence
    conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                 "VALUES (?,'192.168.0.9','INBOUND',?,?,1,10,10,10)",
                 (seed["segment_ids"][0], utc(10), utc(20)))
    conn.commit()
    with pytest.raises(SegmentGapRecoveryError, match="Packet Features"):
        build_segment_gap_plan(conn, **kwargs)


def test_other_capture_session_overlapping_failure_rejects(evidence):
    _, conn, kwargs = evidence
    conn.execute("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status) "
                 "VALUES ('22222222-2222-4222-8222-222222222222','eth1',?,?,'COMPLETED')", (utc(10), utc(10)))
    session_pk = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status) "
                 "VALUES (?,'overlap.pcap','eth1',?,?,'EMPTY')", (session_pk, utc(10), utc(20)))
    conn.commit()
    with pytest.raises(SegmentGapRecoveryError, match="overlaps"):
        build_segment_gap_plan(conn, **kwargs)


def test_failure_during_second_checkpoint_update_rolls_back_first(evidence):
    _, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    pair_before = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")]
    conn.execute("CREATE TRIGGER reject_second BEFORE UPDATE ON detector_checkpoints WHEN NEW.detector_name='packet_if' "
                 "BEGIN SELECT RAISE(ABORT,'injected second update failure'); END")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
    assert conn.in_transaction
    assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")] == pair_before
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    conn.commit()


def test_outer_rollback_removes_both_checkpoints_and_audit(evidence):
    _, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    conn.execute("BEGIN IMMEDIATE")
    apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
    conn.rollback()
    assert {row[0] for row in conn.execute("SELECT last_completed_window_end FROM detector_checkpoints")} == {utc(10)}
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0


def test_duplicate_window_is_not_reapplied(evidence):
    _, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    apply(conn, plan)
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(SegmentGapRecoveryError, match="already has"):
        apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 1


def test_second_gap_requires_consuming_healthy_backlog_and_keeps_first_audit(evidence, tmp_path):
    seed, conn, kwargs = evidence
    before = protected(conn)
    apply(conn, build_segment_gap_plan(conn, **kwargs))
    second = plan_kwargs(seed, tmp_path, second=True)
    with pytest.raises(SegmentGapRecoveryError, match="Checkpoint transition"):
        build_segment_gap_plan(conn, **second)
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=2,last_completed_window_end=?,updated_at=? "
                 "WHERE source_table='packet_feature_logs'", (utc(40), utc(40)))
    conn.commit()
    audit = apply(conn, build_segment_gap_plan(conn, **second))
    assert audit["window_end"] == utc(50)
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 2
    assert protected(conn) == before


@pytest.mark.parametrize("tamper", ["audit_sha", "audit_field", "failed_row", "audit_json", "checkpoint_rewind",
                                  "checkpoint_id", "checkpoint_updated_at"])
def test_runtime_validation_fails_closed_after_tampering(evidence, tamper):
    seed, conn, kwargs = evidence
    apply(conn, build_segment_gap_plan(conn, **kwargs))
    if tamper == "audit_sha":
        conn.execute("UPDATE packet_segment_gap_recoveries SET plan_sha256=?", ("d" * 64,))
    elif tamper == "audit_field":
        conn.execute("UPDATE packet_segment_gap_recoveries SET approved_by='changed'")
    elif tamper == "failed_row":
        conn.execute("UPDATE packet_capture_segments SET updated_at='changed' WHERE id=?", (seed["failed_segment_id"],))
    elif tamper == "audit_json":
        conn.execute("UPDATE packet_segment_gap_recoveries SET plan_json='{}'")
    elif tamper == "checkpoint_rewind":
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_if'", (utc(10),))
    elif tamper == "checkpoint_id":
        conn.execute("UPDATE detector_checkpoints SET last_processed_id=2 WHERE detector_name='packet_if'")
    else:
        conn.execute("UPDATE detector_checkpoints SET updated_at='changed' WHERE detector_name='packet_if'")
    conn.commit()
    segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (seed["failed_segment_id"],)).fetchone())
    assert approved_segment_gap(conn, segment) is None


def test_transition_requires_both_preserved_ids_while_readiness_allows_later_progress(evidence):
    seed, conn, kwargs = evidence
    apply(conn, build_segment_gap_plan(conn, **kwargs))
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=2,last_completed_window_end=?,updated_at=? "
                 "WHERE source_table='packet_feature_logs'", (utc(30), utc(30)))
    conn.commit()
    segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (seed["failed_segment_id"],)).fetchone())
    assert approved_segment_gap(conn, {**segment, "feature_count": 0}) is not None
    pair = [dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints WHERE source_table='packet_feature_logs'")]
    assert resolve_segment_gap_transition(conn, BASE + timedelta(seconds=30), pair) is None
    engine = create_engine("sqlite:///" + str(seed["database_path"]))
    with Session(engine) as db:
        assert approved_segment_gap(db, segment) is not None
    engine.dispose()


def test_missing_008_is_unapproved_not_an_exception(evidence):
    seed, conn, _ = evidence
    segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (seed["failed_segment_id"],)).fetchone())
    conn.execute("DROP TABLE packet_segment_gap_recoveries")
    conn.commit()
    assert approved_segment_gap(conn, segment) is None


def test_apply_requires_caller_transaction(evidence):
    _, conn, kwargs = evidence
    plan = build_segment_gap_plan(conn, **kwargs)
    with pytest.raises(SegmentGapRecoveryError, match="caller"):
        apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)


def _consume_two_approved_gaps_and_close(seed, conn, kwargs, tmp_path):
    apply(conn, build_segment_gap_plan(conn, **kwargs))
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=2,last_completed_window_end=?,updated_at=? "
                 "WHERE source_table='packet_feature_logs'", (utc(40), utc(40)))
    conn.commit()
    apply(conn, build_segment_gap_plan(conn, **plan_kwargs(seed, tmp_path, second=True)))
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=3,last_completed_window_end=?,updated_at=? "
                 "WHERE source_table='packet_feature_logs'", (utc(60), utc(60)))
    conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                 (utc(60), seed["capture_session_id"]))
    conn.commit()


def test_old_recovery_readiness_matches_runtime_after_two_audited_gaps_and_shutdown(evidence, tmp_path):
    from edge.detection.packet_checkpoint_recovery_repository import calculate_packet_feature_readiness
    from edge.packet.capture_session_repository import get_packet_feature_ready_through

    seed, conn, kwargs = evidence
    failed_before = [dict(row) for row in conn.execute("SELECT * FROM packet_capture_segments WHERE status='FAILED' ORDER BY id")]
    _consume_two_approved_gaps_and_close(seed, conn, kwargs, tmp_path)
    old_ready = calculate_packet_feature_readiness(conn, seed["capture_session_id"])
    engine = create_engine("sqlite:///" + str(seed["database_path"]))
    with Session(engine) as db:
        runtime_ready = get_packet_feature_ready_through(db, session_id=seed["capture_session_id"])
    engine.dispose()
    assert old_ready.packet_feature_ready_through == runtime_ready.packet_feature_ready_through == BASE + timedelta(seconds=60)
    assert old_ready.full_ready
    assert old_ready.blocking_reasons == old_ready.live_resume_blocking_reasons == ()
    assert [dict(row) for row in conn.execute("SELECT * FROM packet_capture_segments WHERE status='FAILED' ORDER BY id")] == failed_before


def test_old_live_resume_accepts_closed_audited_source_without_losing_ready_through(evidence, tmp_path):
    from edge.detection.packet_checkpoint_recovery import build_recovery_plan, LIVE_RESUME_MODE

    seed, conn, kwargs = evidence
    _consume_two_approved_gaps_and_close(seed, conn, kwargs, tmp_path)
    target = "22222222-2222-4222-8222-222222222222"
    cursor = conn.execute("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status) "
                          "VALUES (?,'eth0',?,?,'RUNNING')", (target, utc(70), utc(70)))
    cursor = conn.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status) "
                          "VALUES (?,'new-running.pcap','eth0',?,?,'EMPTY')", (cursor.lastrowid, utc(70), utc(80)))
    conn.commit()
    for detector in ("packet_rule", "packet_if"):
        plan = build_recovery_plan(
            conn, repository_state={"repository_root": str(tmp_path), "repository_commit": "a" * 40},
            database_path=seed["database_path"], detector_name=detector,
            current_session_id=seed["capture_session_id"], target_session_id=target,
            approved_by="woomin", reason="Approved rejoin after source audit consumption", lock_entries=(),
            mode=LIVE_RESUME_MODE,
        )
        assert "CURRENT_CHECKPOINT_NOT_AT_READY_THROUGH" not in plan["blocking_reasons"]
        assert plan["can_execute"]
        assert plan["current_session"]["packet_feature_ready_through"] == utc(60)
        assert plan["checkpoint"]["after"]["last_completed_window_end"] == utc(70)


@pytest.mark.parametrize("tamper", ["unapproved", "plan", "failed_snapshot", "rewound_checkpoint", "bad_feature"])
def test_old_recovery_still_blocks_unapproved_or_changed_gap(evidence, tmp_path, tamper):
    from edge.detection.packet_checkpoint_recovery_repository import calculate_packet_feature_readiness

    seed, conn, kwargs = evidence
    if tamper != "unapproved":
        _consume_two_approved_gaps_and_close(seed, conn, kwargs, tmp_path)
        if tamper == "plan":
            conn.execute("UPDATE packet_segment_gap_recoveries SET plan_json='{}' WHERE failed_segment_id=?",
                         (seed["first_failed_segment_id"],))
        elif tamper == "failed_snapshot":
            conn.execute("UPDATE packet_capture_segments SET error_message='changed' WHERE id=?", (seed["first_failed_segment_id"],))
        elif tamper == "rewound_checkpoint":
            conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_if'", (utc(10),))
        else:
            conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                         "VALUES (?,'192.168.0.9','INBOUND',?,?,1,10,10,10)",
                         (seed["first_failed_segment_id"], utc(10), utc(20)))
        conn.commit()
    readiness = calculate_packet_feature_readiness(conn, seed["capture_session_id"])
    assert readiness.packet_feature_ready_through == BASE + timedelta(seconds=10)
    assert not readiness.full_ready
    assert "NON_TERMINAL_OR_ERROR" in readiness.blocking_reasons
    assert "FAILED_OR_EXTRACTOR_ERROR" in readiness.live_resume_blocking_reasons
