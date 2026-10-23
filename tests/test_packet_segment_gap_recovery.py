"""Evidence, transaction and repeated-gap tests using the real migrated schema."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.packet.segment_gap_recovery import (
    SegmentGapRecoveryError, apply_segment_gap_plan, approved_segment_gap,
    build_segment_gap_plan, canonical_plan_sha256, resolve_segment_gap_transition,
    verify_segment_gap_plan,
)
from edge.packet import segment_gap_recovery as recovery
from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
from edge.packet.confirmed_partial_capture import approved_partial_capture_gap
from test_confirmed_gap_runtime import _partial_files
from test_segment_gap_runtime import runtime, _segment, _time, CAPTURE_ID, format_db_utc


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


def seed_segment_gap_chain_database(path):
    seed = seed_segment_gap_database(path)
    with open_database(seed["database_path"]) as conn:
        conn.execute("UPDATE packet_capture_segments SET file_name='normal-4.pcap' WHERE id=?", (seed["segment_ids"][4],))
        for index in (1, 2, 3):
            segment_id = seed["segment_ids"][index]
            conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (segment_id,))
            conn.execute("UPDATE packet_capture_segments SET status='FAILED',error_code='PARTIAL_CAPTURE',"
                         "error_message=?,file_name=? WHERE id=?",
                         (f"kernel packet loss {index}", f"failed-{index}.pcap", segment_id))
        conn.execute("UPDATE packet_capture_segments SET status='EMPTY',error_code=NULL,error_message=NULL "
                     "WHERE id=?", (seed["segment_ids"][4],))
        conn.commit()
    seed["failed_segment_ids"] = seed["segment_ids"][1:4]
    return seed


def chain_kwargs(seed, directory):
    return {"capture_session_id": seed["capture_session_id"],
            "failed_segment_ids": seed["failed_segment_ids"],
            "approved_by": "woomin", "reason": "Approved exact three-window kernel loss",
            "repository_commit": "a" * 40, "database_path": str(seed["database_path"]),
            "backup_path": str((directory / "chain-backup.db").resolve()),
            "preserved_pcaps": [{"path": str((directory / f"failed-{index}.pcap").resolve()),
                                 "sha256": str(index) * 64} for index in (1, 2, 3)]}


@pytest.fixture
def chain_evidence(tmp_path):
    seed = seed_segment_gap_chain_database(tmp_path / "chain.db")
    conn = open_database(seed["database_path"])
    yield seed, conn, chain_kwargs(seed, tmp_path)
    conn.close()


def test_chain_atomic_audits_preserve_capture_features_trust_and_source_ids(chain_evidence):
    seed, conn, kwargs = chain_evidence
    before = protected(conn)
    plan = recovery.build_segment_gap_chain_plan(conn, **kwargs)
    assert plan["schema_version"] == "packet-segment-gap-recovery-v2"
    assert plan["coverage"] == "UNINSPECTED"
    assert [entry["failed_segment_id"] for entry in plan["failed_segments"]] == seed["failed_segment_ids"]
    assert (plan["window_start"], plan["window_end"]) == (utc(10), utc(40))
    result = apply(conn, plan)
    assert len(result["audits"]) == 3
    audits = [dict(row) for row in conn.execute("SELECT * FROM packet_segment_gap_recoveries ORDER BY window_start")]
    assert len({row["operation_id"] for row in audits}) == 3
    assert all(json.loads(row["plan_json"]) == plan for row in audits)
    assert [(row["window_start"], row["window_end"]) for row in audits] == [(utc(n), utc(n+10)) for n in (10,20,30)]
    assert protected(conn) == before
    pair = [dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints WHERE source_table='packet_feature_logs'")]
    assert {row["last_processed_id"] for row in pair} == {1}
    assert {row["last_completed_window_end"] for row in pair} == {utc(40)}
    for segment_id in seed["failed_segment_ids"]:
        segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (segment_id,)).fetchone())
        assert approved_segment_gap(conn, segment) is not None
    assert resolve_segment_gap_transition(conn, BASE + timedelta(seconds=40), pair) is not None
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(SegmentGapRecoveryError):
        apply_segment_gap_plan(conn, plan, backup_sha256="c"*64)
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 3


@pytest.mark.parametrize("change", ["missing", "duplicate", "reversed", "different_session", "hole", "feature", "overlap", "following"])
def test_chain_exact_approved_range_rejects_unbound_evidence(chain_evidence, change):
    seed, conn, kwargs = chain_evidence
    if change == "missing":
        kwargs["failed_segment_ids"] = kwargs["failed_segment_ids"][:2]
        kwargs["preserved_pcaps"] = kwargs["preserved_pcaps"][:2]
    elif change == "duplicate":
        kwargs["failed_segment_ids"][1] = kwargs["failed_segment_ids"][0]
    elif change == "reversed":
        kwargs["failed_segment_ids"].reverse()
        kwargs["preserved_pcaps"].reverse()
    elif change == "different_session":
        conn.execute("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status) "
                     "VALUES ('22222222-2222-4222-8222-222222222222','eth0',?,?,'COMPLETED')", (utc(0), utc(0)))
        other = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("UPDATE packet_capture_segments SET capture_session_id=? WHERE id=?", (other, seed["failed_segment_ids"][1]))
    elif change == "hole":
        conn.execute("UPDATE packet_capture_segments SET window_start=?,window_end=? WHERE id=?", (utc(70),utc(80),seed["failed_segment_ids"][1]))
    elif change == "feature":
        conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                     "VALUES (?,'192.0.2.9','INBOUND',?,?,1,10,10,10)", (seed["failed_segment_ids"][1],utc(20),utc(30)))
    elif change == "overlap":
        conn.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status) "
                     "VALUES (?,'overlap.pcap','eth1',?,?,'EMPTY')", (1,utc(20),utc(30)))
    else:
        conn.execute("UPDATE packet_capture_segments SET status='READY' WHERE id=?", (seed["segment_ids"][4],))
    conn.commit()
    with pytest.raises(SegmentGapRecoveryError):
        recovery.build_segment_gap_chain_plan(conn, **kwargs)
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0


@pytest.mark.parametrize("tamper", ["missing_audit", "different_operation", "different_backup", "different_plan", "changed_failed", "checkpoint_id"])
def test_chain_every_audit_required_even_after_later_progress(chain_evidence, tamper):
    seed, conn, kwargs = chain_evidence
    apply(conn, recovery.build_segment_gap_chain_plan(conn, **kwargs))
    middle = seed["failed_segment_ids"][1]
    if tamper == "missing_audit":
        conn.execute("DELETE FROM packet_segment_gap_recoveries WHERE failed_segment_id=?", (middle,))
    elif tamper == "different_operation":
        conn.execute("UPDATE packet_segment_gap_recoveries SET operation_id='22222222-2222-4222-8222-222222222222' WHERE failed_segment_id=?", (middle,))
    elif tamper == "different_backup":
        conn.execute("UPDATE packet_segment_gap_recoveries SET backup_sha256=? WHERE failed_segment_id=?", ("d"*64,middle))
    elif tamper == "different_plan":
        conn.execute("UPDATE packet_segment_gap_recoveries SET plan_json='{}' WHERE failed_segment_id=?", (middle,))
    elif tamper == "changed_failed":
        conn.execute("UPDATE packet_capture_segments SET error_message='replaced original' WHERE id=?", (middle,))
    else:
        conn.execute("UPDATE detector_checkpoints SET last_processed_id=999 WHERE detector_name='packet_if'")
    conn.commit()
    for segment_id in seed["failed_segment_ids"]:
        segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (segment_id,)).fetchone())
        assert approved_segment_gap(conn, segment) is None
    if tamper != "checkpoint_id":
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=?,last_processed_id=3 WHERE source_table='packet_feature_logs'", (utc(60),utc(60)))
        conn.commit()
        for segment_id in seed["failed_segment_ids"]:
            segment = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (segment_id,)).fetchone())
            assert approved_segment_gap(conn, segment) is None


def test_chain_middle_audit_failure_rolls_back_all_rows_and_both_checkpoints(chain_evidence):
    _, conn, kwargs = chain_evidence
    plan = recovery.build_segment_gap_chain_plan(conn, **kwargs)
    before = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")]
    middle = plan["failed_segments"][1]["failed_segment_id"]
    conn.execute(f"CREATE TRIGGER reject_middle_audit BEFORE INSERT ON packet_segment_gap_recoveries WHEN NEW.failed_segment_id={middle} BEGIN SELECT RAISE(ABORT,'injected chain audit failure'); END")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        apply_segment_gap_plan(conn, plan, backup_sha256="c"*64)
    assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")] == before
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    conn.commit()


@pytest.mark.parametrize("source_path", ["/srv/capture-evidence/backup.db", "C:/review/backup.db"])
def test_chain_source_host_absolute_evidence_readable_locally(chain_evidence, source_path):
    _, conn, kwargs = chain_evidence
    kwargs["backup_path"] = source_path
    plan = recovery.build_segment_gap_chain_plan(conn, **kwargs)
    assert len(apply(conn, plan)["audits"]) == 3


@pytest.mark.parametrize("change", ["checkpoint", "failed", "sha", "coverage", "count_one", "count_four", "relative_backup"])
def test_chain_plan_changes_and_limits_hold_before_mutation(chain_evidence, change):
    seed, conn, kwargs = chain_evidence
    if change in ("count_one", "count_four", "relative_backup"):
        if change == "count_one":
            kwargs["failed_segment_ids"] = kwargs["failed_segment_ids"][:1]
            kwargs["preserved_pcaps"] = kwargs["preserved_pcaps"][:1]
        elif change == "count_four":
            kwargs["failed_segment_ids"] += [seed["segment_ids"][4]]
            kwargs["preserved_pcaps"] += [{"path": str(Path(kwargs["backup_path"]).parent / "normal-4.pcap"), "sha256": "d"*64}]
        else:
            kwargs["backup_path"] = "relative.db"
        with pytest.raises(SegmentGapRecoveryError):
            recovery.build_segment_gap_chain_plan(conn, **kwargs)
        return
    plan = recovery.build_segment_gap_chain_plan(conn, **kwargs)
    if change == "checkpoint":
        conn.execute("UPDATE detector_checkpoints SET updated_at='changed' WHERE detector_name='packet_if'")
        conn.commit()
    elif change == "failed":
        conn.execute("UPDATE packet_capture_segments SET error_message='changed' WHERE id=?", (seed["failed_segment_ids"][1],))
        conn.commit()
    elif change == "sha":
        plan["failed_segments"][1]["pcap_sha256"] = "d"*64
    else:
        plan["coverage"] = "INSPECTED"
        plan["plan_sha256"] = canonical_plan_sha256(plan)
    before = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")]
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(SegmentGapRecoveryError):
        apply_segment_gap_plan(conn, plan, backup_sha256="c"*64)
    assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")] == before
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    conn.rollback()


def test_chain_explicit_two_window_limit_and_outer_rollback(chain_evidence):
    seed, conn, kwargs = chain_evidence
    third = seed["failed_segment_ids"][2]
    conn.execute("UPDATE packet_capture_segments SET status='EMPTY',error_code=NULL,error_message=NULL WHERE id=?", (third,))
    conn.commit()
    kwargs["failed_segment_ids"] = kwargs["failed_segment_ids"][:2]
    kwargs["preserved_pcaps"] = kwargs["preserved_pcaps"][:2]
    plan = recovery.build_segment_gap_chain_plan(conn, **kwargs)
    conn.execute("BEGIN IMMEDIATE")
    result = apply_segment_gap_plan(conn, plan, backup_sha256="c"*64)
    assert len(result["audits"]) == 2
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
    assert {row[0] for row in conn.execute("SELECT last_completed_window_end FROM detector_checkpoints")} == {utc(10)}


def test_v1_still_rejects_a_following_partial_chain(chain_evidence, tmp_path):
    seed, conn, _ = chain_evidence
    with pytest.raises(SegmentGapRecoveryError, match="healthy contiguous"):
        build_segment_gap_plan(conn, **plan_kwargs(seed, tmp_path))


@pytest.mark.parametrize("path", ["/srv/capture-evidence/backup.db", "C:/evidence/backup.db"])
def test_v1_audit_source_host_path_formats_are_readable(evidence, path):
    _, conn, kwargs = evidence
    kwargs["backup_path"] = path
    assert apply(conn, build_segment_gap_plan(conn, **kwargs))["backup_path"] == path


def _chain_segments(seed, conn):
    return [dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (segment_id,)).fetchone())
            for segment_id in seed["failed_segment_ids"]]


def test_batch_read_validates_one_chain_once_and_keeps_request_order(chain_evidence, monkeypatch):
    seed, conn, kwargs = chain_evidence
    apply(conn, recovery.build_segment_gap_chain_plan(conn, **kwargs))
    segments = _chain_segments(seed, conn)[::-1]
    visited = []
    real_check = recovery._no_gap_features_or_overlap
    def count_check(db, segment):
        visited.append(segment["id"])
        return real_check(db, segment)
    monkeypatch.setattr(recovery, "_no_gap_features_or_overlap", count_check)
    audits = recovery.approved_segment_gaps(conn, segments)
    assert [audit["failed_segment_id"] for audit in audits] == [segment["id"] for segment in segments]
    assert visited == seed["failed_segment_ids"]
    # Every read call establishes its own proof; this is no cross-call cache.
    conn.execute("DELETE FROM packet_segment_gap_recoveries WHERE failed_segment_id=?", (seed["failed_segment_ids"][1],))
    conn.commit()
    assert recovery.approved_segment_gaps(conn, segments) == [None, None, None]


@pytest.mark.parametrize("supplied", ["changed_full_snapshot", "changed_partial_snapshot"])
def test_batch_bad_supplied_chain_member_closes_whole_chain(chain_evidence, supplied):
    seed, conn, kwargs = chain_evidence
    apply(conn, recovery.build_segment_gap_chain_plan(conn, **kwargs))
    segments = _chain_segments(seed, conn)
    if supplied == "changed_full_snapshot":
        segments[1]["error_message"] = "different supplied evidence"
    else:
        segments[1] = {"id": segments[1]["id"], "status": "EMPTY", "feature_count": 0}
    assert recovery.approved_segment_gaps(conn, segments) == [None, None, None]
    assert approved_segment_gap(conn, segments[1]) is None


def test_batch_partial_reader_fields_and_v1_independence(evidence, tmp_path):
    seed, conn, kwargs = evidence
    _consume_two_approved_gaps_and_close(seed, conn, kwargs, tmp_path)
    segments = [dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (segment_id,)).fetchone())
                for segment_id in (seed["first_failed_segment_id"], seed["second_failed_segment_id"])]
    requested = [{"id": segment["id"], "status": segment["status"], "feature_count": 0} for segment in segments]
    assert all(recovery.approved_segment_gaps(conn, requested))
    conn.execute("UPDATE packet_segment_gap_recoveries SET plan_json='{}' WHERE failed_segment_id=?", (seed["first_failed_segment_id"],))
    conn.commit()
    outcomes = recovery.approved_segment_gaps(conn, requested)
    assert outcomes[0] is None and outcomes[1]["failed_segment_id"] == seed["second_failed_segment_id"]


def test_batch_partial_chain_reader_preserves_single_api_result(chain_evidence):
    seed, conn, kwargs = chain_evidence
    apply(conn, recovery.build_segment_gap_chain_plan(conn, **kwargs))
    requested = [{"id": segment_id, "status": "FAILED", "feature_count": 0} for segment_id in seed["failed_segment_ids"]]
    expected = [approved_segment_gap(conn, segment) for segment in requested]
    assert recovery.approved_segment_gaps(conn, requested) == expected


def test_batch_malformed_chain_entries_remains_fail_closed(chain_evidence):
    seed, conn, kwargs = chain_evidence
    plan = recovery.build_segment_gap_chain_plan(conn, **kwargs)
    apply(conn, plan)
    plan["failed_segments"] = None
    plan["plan_sha256"] = canonical_plan_sha256(plan)
    conn.execute("UPDATE packet_segment_gap_recoveries SET plan_json=?", (json.dumps(plan),))
    conn.commit()
    requested = _chain_segments(seed, conn)
    assert recovery.approved_segment_gaps(conn, requested) == [None, None, None]
    assert approved_segment_gap(conn, requested[0]) is None


def confirmed_prefix_manual_case(runtime, tmp_path, monkeypatch, count):
    """Real016 commit, healthy consumption, then a separately approved manual gap."""
    factory, database, source = runtime
    with factory() as db:
        _, initial_id = _segment(db, source, 0)
        earlier_id, _ = _partial_files(db, tmp_path, source, 10, monkeypatch)
        _, consumed_id = _segment(db, source, 20)
        failed = [_partial_files(db, tmp_path, source, at, monkeypatch)
                  for at in range(30, 30 + count * 10, 10)]
        _segment(db, source, 30 + count * 10)
        for detector in recovery.DETECTORS:
            db.execute(text("INSERT INTO detector_checkpoints VALUES (:name,'packet_feature_logs',:id,:at,:at)"),
                       {"name": detector, "id": initial_id, "at": format_db_utc(_time(10))})
        db.commit()
        assert advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30))
        db.commit()
    conn = open_database(database)
    try:
        earlier = dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (earlier_id,)).fetchone())
        assert approved_partial_capture_gap(conn, earlier) is not None
        assert approved_segment_gap(conn, earlier) is None
        assert {row[0] for row in conn.execute("SELECT last_processed_id FROM detector_checkpoints "
                                              "WHERE source_table='packet_feature_logs'")} == {initial_id}
        conn.execute("UPDATE detector_checkpoints SET last_processed_id=?,last_completed_window_end=?,updated_at=? "
                     "WHERE source_table='packet_feature_logs'",
                     (consumed_id, format_db_utc(_time(30)), format_db_utc(_time(30))))
        conn.commit()
        # Later loss has a preserved PCAP but no diagnostics: it needs manual approval.
        for _, path in failed:
            path.with_suffix(".pcap.capture.json").unlink()
        kwargs = dict(capture_session_id=CAPTURE_ID, approved_by="woomin", reason="Approve only the later loss",
                      repository_commit="a" * 40, database_path=str(database),
                      backup_path=str((tmp_path / "manual.backup.db").resolve()))
        if count == 1:
            builder = build_segment_gap_plan
            kwargs.update(failed_segment_id=failed[0][0], preserved_pcap_path=str(failed[0][1]), pcap_sha256="b" * 64)
        else:
            builder = recovery.build_segment_gap_chain_plan
            kwargs.update(failed_segment_ids=[item[0] for item in failed],
                          preserved_pcaps=[{"path": str(path), "sha256": "b" * 64} for _, path in failed])
        return conn, earlier, builder, kwargs
    except Exception:
        conn.close()
        raise


@pytest.mark.parametrize("count", [1, 2])
def test_manual_recovery_accepts_prior_confirmed_partial_audit(runtime, tmp_path, monkeypatch, count):
    conn, earlier, builder, kwargs = confirmed_prefix_manual_case(runtime, tmp_path, monkeypatch, count)
    try:
        before = protected(conn)
        automatic = [tuple(row) for row in conn.execute("SELECT * FROM packet_detection_gaps")]
        checkpoints = recovery._checkpoint_pair(conn)
        plan = builder(conn, **kwargs)
        assert {name: item["before"] for name, item in plan["checkpoints"].items()} == checkpoints
        assert conn.execute("SELECT COUNT(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
        apply(conn, plan)
        assert protected(conn) == before
        assert [tuple(row) for row in conn.execute("SELECT * FROM packet_detection_gaps")] == automatic
        assert recovery._checkpoint_pair(conn) == {name: item["after"] for name, item in plan["checkpoints"].items()}
        assert approved_partial_capture_gap(conn, earlier) is not None
        assert approved_segment_gap(conn, earlier) is None
        audits = [dict(row) for row in conn.execute("SELECT * FROM packet_segment_gap_recoveries")]
        assert len(audits) == count and all(row["failed_segment_id"] != earlier["id"] for row in audits)
        assert all(json.loads(row["plan_json"]) == plan for row in audits)
    finally:
        conn.close()


@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("change", ["missing_audit", "bad_digest", "changed_partial", "changed_checkpoint"])
def test_manual_recovery_rechecks_prior_confirmed_proof_before_writing(runtime, tmp_path, monkeypatch, count, change):
    conn, earlier, builder, kwargs = confirmed_prefix_manual_case(runtime, tmp_path, monkeypatch, count)
    try:
        plan = builder(conn, **kwargs)
        if change in ("missing_audit", "bad_digest"):
            trigger_name = "packet_detection_gaps_no_delete" if change == "missing_audit" else "packet_detection_gaps_no_update"
            trigger = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (trigger_name,)).fetchone()[0]
            conn.execute(f"DROP TRIGGER {trigger_name}")
            if change == "missing_audit":
                conn.execute("DELETE FROM packet_detection_gaps")
            else:
                conn.execute("UPDATE packet_detection_gaps SET plan_sha256=?", ("0" * 64,))
            conn.execute(trigger)
        elif change == "changed_partial":
            conn.execute("UPDATE packet_capture_segments SET error_message='changed' WHERE id=?", (earlier["id"],))
        else:
            conn.execute("UPDATE detector_checkpoints SET last_processed_id=999 WHERE detector_name='packet_if'")
        conn.commit()
        before = protected(conn), recovery._checkpoint_pair(conn), conn.total_changes
        if change != "changed_checkpoint":
            with pytest.raises(SegmentGapRecoveryError, match="Earlier Capture gap"):
                builder(conn, **kwargs)
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(SegmentGapRecoveryError, match="checkpoint changed|Earlier Capture gap"):
            apply_segment_gap_plan(conn, plan, backup_sha256="c" * 64)
        assert (protected(conn), recovery._checkpoint_pair(conn), conn.total_changes) == before
        assert conn.execute("SELECT COUNT(*) FROM packet_segment_gap_recoveries").fetchone()[0] == 0
        conn.rollback()
    finally:
        conn.close()
