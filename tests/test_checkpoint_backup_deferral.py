"""Real pair SQL tests: defer duplicate work, retain every fresh mutation guard."""
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import sqlite3

import pytest

from edge.detection import packet_checkpoint_pair_recovery as pair
from edge.detection import packet_checkpoint_recovery as core
from edge.scripts import phase4_cutover_storage as storage
from test_packet_checkpoint_pair_recovery import fixture as paired_fixture,_use_failed_tail,_audits
from test_packet_checkpoint_recovery import (
    CURRENT_SESSION, TARGET_SESSION, RUNNING_SESSION_A, RUNNING_SESSION_B,
    TARGET_FIRST, TARGET_READY_THROUGH, _db_utc, _insert_capture_session,
    _insert_capture_segment, _insert_feature_for_existing_segment,
)


@pytest.fixture
def operation(paired_fixture):
    _use_failed_tail(paired_fixture)
    return paired_fixture


def execute(operation):
    return pair.execute_pair(plan_file=operation["output"],db_path=operation["database"],
        artifact_dir=operation["artifacts"],confirm=pair.confirmation_prefix(operation["plan"])+operation["plan"]["plan_sha256"])


def checkpoint(operation,name):
    with sqlite3.connect(operation["database"]) as db:
        db.row_factory=sqlite3.Row
        return dict(db.execute("SELECT * FROM detector_checkpoints WHERE detector_name=? AND source_table='packet_feature_logs'",(name,)).fetchone())


def test_each_leg_keeps_two_hashes_and_one_fresh_full_backup_check_before_mutation(operation,monkeypatch):
    events=[];original_checks=storage._database_checks;original_hash=storage.file_sha256
    original_core_hash=core.file_sha256;original_update=pair.repository.update_checkpoint_conditionally
    def checks(path):
        if Path(path).name=="database.backup.db":events.append((str(path),"full_check"))
        return original_checks(path)
    def creator_hash(path):
        if Path(path).name=="database.backup.db":events.append((str(path),"creator_hash"))
        return original_hash(path)
    def core_hash(path):
        if Path(path).name=="database.backup.db":events.append((str(path),"fresh_hash"))
        return original_core_hash(path)
    def update(db,**kwargs):
        name=kwargs["before"]["detector_name"]
        backup=next(path for path,event in events if name in Path(path).parts)
        assert [event for path,event in events if path==backup]==["creator_hash","fresh_hash","full_check"]
        assert db.in_transaction
        return original_update(db,**kwargs)
    monkeypatch.setattr(storage,"_database_checks",checks)
    monkeypatch.setattr(storage,"file_sha256",creator_hash)
    monkeypatch.setattr(core,"file_sha256",core_hash)
    monkeypatch.setattr(pair.repository,"update_checkpoint_conditionally",update)
    result=execute(operation)
    assert result["operation_status"]=="APPLIED_PENDING_PROGRESS" and len(_audits(operation))==2
    assert len([event for path,event in events if event=="full_check"])==2


@pytest.mark.parametrize("leg",pair.DETECTORS)
@pytest.mark.parametrize("corruption",["sha_after_creator","integrity_before_creator_hash","fk_before_creator_hash"])
def test_core_fresh_backup_guards_reject_actual_corruption_on_either_leg(operation,monkeypatch,leg,corruption):
    original_hash=storage.file_sha256;original_backup=core.create_sqlite_backup
    before=checkpoint(operation,leg);changed=[]
    def creator_hash(path):
        if Path(path).name=="database.backup.db" and leg in Path(path).parts and not changed:
            changed.append(str(path))
            if corruption=="integrity_before_creator_hash":
                with Path(path).open("r+b") as file:file.write(b"Broken SQLite header")
            elif corruption=="fk_before_creator_hash":
                with sqlite3.connect(path) as bad:
                    bad.execute("PRAGMA foreign_keys=OFF")
                    bad.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
                        "VALUES(999999,'10.0.0.9','INBOUND','2026-08-06T10:00:00Z','2026-08-06T10:00:10Z',1,60,60,60)")
                    bad.commit();bad.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    assert bad.execute("PRAGMA foreign_key_check").fetchall()
        return original_hash(path)
    def backup(source,destination,**kwargs):
        assert kwargs=={"verify":False}
        artifact=original_backup(source,destination,**kwargs)
        assert artifact.integrity_check=="NOT_CHECKED"
        if leg in Path(destination).parts and corruption=="sha_after_creator":
            with Path(destination).open("ab") as stream:stream.write(b"changed after creator hash")
            changed.append(str(destination))
        # Even an apparent good report cannot replace checking the actual file.
        return replace(artifact,integrity_check="ok",foreign_key_violations=())
    monkeypatch.setattr(storage,"file_sha256",creator_hash)
    monkeypatch.setattr(core,"create_sqlite_backup",backup)
    result=execute(operation)
    assert changed and result["operation_status"]==("HOLD" if leg=="packet_rule" else "PARTIAL_HOLD")
    assert len(_audits(operation))==(0 if leg=="packet_rule" else 1)
    assert checkpoint(operation,leg)==before


@pytest.mark.parametrize("leg",pair.DETECTORS)
def test_deferral_keeps_actual_data_version_outside_commit_guard(operation,monkeypatch,leg):
    original=core.create_sqlite_backup;before=checkpoint(operation,leg)
    def racing(source,destination,**kwargs):
        artifact=original(source,destination,**kwargs)
        if leg in Path(destination).parts:
            with sqlite3.connect(source) as outside:
                outside.execute("UPDATE packet_capture_sessions SET updated_at='2026-08-06T10:02:30Z' WHERE session_id=?",
                    (operation["plan"]["target_session_id"],))
                assert outside.total_changes==1
        return artifact
    monkeypatch.setattr(core,"create_sqlite_backup",racing)
    result=execute(operation)
    assert result["operation_status"]==("HOLD" if leg=="packet_rule" else "PARTIAL_HOLD")
    assert len(_audits(operation))==(0 if leg=="packet_rule" else 1) and checkpoint(operation,leg)==before


@pytest.mark.parametrize("leg",pair.DETECTORS)
def test_deferral_keeps_conditional_update_and_rolls_back_failed_cas(operation,monkeypatch,leg):
    original=pair.repository.update_checkpoint_conditionally;before=checkpoint(operation,leg)
    def changed(db,**kwargs):
        if kwargs["before"]["detector_name"]==leg:
            db.execute("UPDATE detector_checkpoints SET updated_at='2026-08-06T10:00:21Z' WHERE detector_name=? AND source_table='packet_feature_logs'",(leg,))
            assert original(db,**kwargs)==0
            return 0
        return original(db,**kwargs)
    monkeypatch.setattr(pair.repository,"update_checkpoint_conditionally",changed)
    result=execute(operation)
    assert result["operation_status"]==("HOLD" if leg=="packet_rule" else "PARTIAL_HOLD")
    assert len(_audits(operation))==(0 if leg=="packet_rule" else 1) and checkpoint(operation,leg)==before


@pytest.fixture(params=[core.LIVE_RESUME_MODE, core.BOUNDED_REPLAY_MODE])
def append_operation(paired_fixture, request):
    operation = paired_fixture
    mode = request.param
    with sqlite3.connect(operation["database"]) as db:
        if mode == core.BOUNDED_REPLAY_MODE:
            db.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                       (_db_utc(TARGET_READY_THROUGH), TARGET_SESSION))
            active_pk = _insert_capture_session(
                db, session_id=RUNNING_SESSION_A, capture_interface="eth-live",
                first_window_start=TARGET_READY_THROUGH, status="RUNNING")
            _insert_capture_segment(db, session_pk=active_pk, capture_interface="eth-live",
                                    window_start=TARGET_READY_THROUGH, status="READY")
        else:
            active_pk = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?",
                                   (TARGET_SESSION,)).fetchone()[0]
        db.execute("INSERT INTO detector_checkpoints(detector_name,source_table,last_processed_id,last_completed_window_end,updated_at) "
                   "VALUES('mqtt_feature_builder','mqtt_logs',NULL,?,?)",
                   (_db_utc(TARGET_FIRST), _db_utc(TARGET_FIRST)))
    output = operation["output"].with_name("append-opt-in-plan.json")
    plan = pair.inspect_pair(
        db_path=operation["database"], repository_root=operation["root"],
        current_session_id=CURRENT_SESSION, target_session_id=TARGET_SESSION,
        approved_by="admin-fixture", reason="allow collection while recovering fixed inputs",
        plan_output=output, mode=mode, allow_capture_appends=True)
    assert plan["can_execute"], plan["blocking_reasons"]
    assert plan["allow_capture_appends"] is True
    assert all(child["plan"]["allow_capture_appends"] is True for child in plan["children"])
    operation.update(output=output, plan=plan, active_pk=active_pk)
    return operation


def _append_segment(db, operation, *, gap=False, failed=False, feature=False):
    session = db.execute("SELECT * FROM packet_capture_sessions WHERE id=?",
                         (operation["active_pk"],)).fetchone()
    end = db.execute("SELECT MAX(window_end) FROM packet_capture_segments WHERE capture_session_id=?",
                     (session["id"],)).fetchone()[0]
    start = core.parse_db_utc(end) + timedelta(seconds=10 if gap else 0)
    segment = _insert_capture_segment(
        db, session_pk=session["id"], capture_interface=session["capture_interface"],
        window_start=start, status="FAILED" if failed else "PROCESSED" if feature else "READY",
        error_code="CAPTURE_FAILED" if failed else None, feature_count=int(feature))
    db.execute("UPDATE packet_capture_segments SET start_delay_seconds=0.1,captured_duration_seconds=9.9 WHERE id=?",
               (segment,))
    return segment


def _mqtt_commit(db):
    db.execute("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at) "
               "VALUES('device-live','sensor/live','{}',2,?)", (_db_utc(TARGET_READY_THROUGH),))
    message_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO feature_logs(device_id,window_start,window_end,publish_count) "
               "VALUES('device-live',?,?,1)", (_db_utc(TARGET_FIRST), _db_utc(TARGET_FIRST + timedelta(seconds=10))))
    db.execute("UPDATE detector_checkpoints SET last_processed_id=?,last_completed_window_end=?,updated_at=? "
               "WHERE detector_name='mqtt_feature_builder' AND source_table='mqtt_logs'",
               (message_id, _db_utc(TARGET_FIRST + timedelta(seconds=10)), _db_utc(TARGET_FIRST + timedelta(seconds=10))))


def _race_at(operation, monkeypatch, timing, mutation, *, leg="packet_rule"):
    """Commit from another actual SQLite connection at either guarded boundary."""
    real_connect = sqlite3.connect
    real_backup = core.create_sqlite_backup
    active_leg = [None]
    fired = []

    def commit():
        if fired or active_leg[0] != leg:
            return
        with real_connect(operation["database"]) as writer:
            writer.row_factory = sqlite3.Row
            writer.execute("PRAGMA foreign_keys=ON")
            mutation(writer)
        fired.append(leg)

    def backup(source, destination, **kwargs):
        active_leg[0] = next(name for name in pair.DETECTORS if name in Path(destination).parts)
        if timing == "during_backup":
            commit()
        return real_backup(source, destination, **kwargs)

    class BeginRaceConnection:
        def __init__(self, connection):
            object.__setattr__(self, "_connection", connection)

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def __setattr__(self, name, value):
            setattr(self._connection, name, value)

        def __enter__(self):
            self._connection.__enter__()
            return self

        def __exit__(self, *args):
            return self._connection.__exit__(*args)

        def execute(self, sql, *args):
            if timing == "before_begin" and sql.strip().upper() == "BEGIN IMMEDIATE":
                commit()
            return self._connection.execute(sql, *args)

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        if kwargs.get("isolation_level", "default") is None and Path(args[0]) == operation["database"]:
            return BeginRaceConnection(connection)
        return connection

    monkeypatch.setattr(core, "create_sqlite_backup", backup)
    monkeypatch.setattr(core.sqlite3, "connect", connect)
    return fired


@pytest.mark.parametrize("timing", ["during_backup", "before_begin"])
@pytest.mark.parametrize("capture_append", [False, True], ids=["mqtt_only", "capture_and_mqtt"])
def test_signed_append_opt_in_allows_real_collection_commits(append_operation, monkeypatch, timing, capture_append):
    operation = append_operation
    def mutation(db):
        if capture_append:
            _append_segment(db, operation)
        _mqtt_commit(db)
    fired = _race_at(operation, monkeypatch, timing, mutation)
    result = execute(operation)
    assert fired == ["packet_rule"]
    assert result["operation_status"] == "APPLIED_PENDING_PROGRESS"
    assert len(_audits(operation)) == 2
    for name in pair.DETECTORS:
        expected = next(child["plan"]["checkpoint"]["after"] for child in operation["plan"]["children"] if child["detector"] == name)
        actual = checkpoint(operation, name)
        assert actual["last_processed_id"] == expected["last_processed_id"]
        assert actual["last_completed_window_end"] == expected["last_completed_window_end"]
    with sqlite3.connect(operation["database"]) as db:
        assert db.execute("SELECT COUNT(*) FROM mqtt_logs WHERE device_id='device-live'").fetchone()[0] == 1
        assert db.execute("SELECT last_processed_id FROM detector_checkpoints WHERE detector_name='mqtt_feature_builder'").fetchone()[0] is not None


def _unsafe_mutation(db, operation, change):
    if change in {"source_segment", "target_segment", "source_feature", "target_feature", "source_identity", "target_identity"}:
        source = change.startswith("source")
        session_id = CURRENT_SESSION if source else TARGET_SESSION
        session_pk = db.execute("SELECT id FROM packet_capture_sessions WHERE session_id=?", (session_id,)).fetchone()[0]
        if change.endswith("segment"):
            db.execute("UPDATE packet_capture_segments SET packet_count=777 WHERE id=(SELECT MIN(id) FROM packet_capture_segments WHERE capture_session_id=?)", (session_pk,))
        elif change.endswith("feature"):
            # Mutate the last row so a prefix-only or first-row comparison cannot pass.
            db.execute("UPDATE packet_feature_logs SET total_bytes=777 WHERE id=(SELECT MAX(f.id) FROM packet_feature_logs f JOIN packet_capture_segments g ON g.id=f.capture_segment_id WHERE g.capture_session_id=?)", (session_pk,))
        else:
            db.execute("UPDATE packet_capture_sessions SET capture_interface='changed' WHERE id=?", (session_pk,))
    elif change == "packet_checkpoint":
        db.execute("UPDATE detector_checkpoints SET updated_at='2026-08-06T10:00:21Z' WHERE detector_name='packet_if'")
    elif change == "audit":
        assert db.execute("UPDATE packet_checkpoint_recoveries SET reason='changed after baseline' WHERE detector_name='packet_rule'").rowcount == 1
    elif change == "new_session":
        _insert_capture_session(db, session_id=RUNNING_SESSION_B, capture_interface="eth-other",
                                first_window_start=TARGET_READY_THROUGH + timedelta(minutes=1), status="RUNNING")
    elif change == "new_feature_existing_segment":
        segment = db.execute("SELECT MIN(id) FROM packet_capture_segments WHERE capture_session_id=(SELECT id FROM packet_capture_sessions WHERE session_id=?)", (TARGET_SESSION,)).fetchone()[0]
        _insert_feature_for_existing_segment(db, segment)
    elif change == "existing_segment_failure":
        db.execute("UPDATE packet_capture_segments SET status='FAILED',error_code='CAPTURE_FAILED' WHERE id=(SELECT MAX(id) FROM packet_capture_segments WHERE capture_session_id=?)", (operation["active_pk"],))
    else:
        assert change in {"new_failed", "new_processed_feature", "discontinuous_suffix"}
        _append_segment(db, operation, failed=change == "new_failed", feature=change == "new_processed_feature", gap=change == "discontinuous_suffix")


@pytest.mark.parametrize("timing", ["during_backup", "before_begin"])
@pytest.mark.parametrize("change", [
    "source_segment", "target_segment", "source_feature", "target_feature",
    "source_identity", "target_identity", "packet_checkpoint", "audit",
    "new_failed", "new_session", "new_processed_feature", "new_feature_existing_segment",
    "existing_segment_failure", "discontinuous_suffix",
])
def test_signed_append_opt_in_rejects_changes_outside_normal_suffix(append_operation, monkeypatch, timing, change):
    operation = append_operation
    leg = "packet_if" if change == "audit" else "packet_rule"
    before = checkpoint(operation, leg)
    fired = _race_at(operation, monkeypatch, timing,
                     lambda db: _unsafe_mutation(db, operation, change), leg=leg)
    result = execute(operation)
    assert fired == [leg]
    assert result["operation_status"] == ("PARTIAL_HOLD" if leg == "packet_if" else "HOLD")
    audits = _audits(operation)
    assert len(audits) == (1 if leg == "packet_if" else 0)
    assert not any(audit["detector_name"] == leg for audit in audits)
    assert checkpoint(operation, leg) == before


@pytest.mark.parametrize("change", ["delete", "replace_file"])
def test_append_captured_in_backup_is_frozen_before_transaction(append_operation, monkeypatch, change):
    operation = append_operation
    real_backup = core.create_sqlite_backup
    real_connect = sqlite3.connect
    appended = []
    before = checkpoint(operation, "packet_rule")

    def append_before_backup(source, destination, **kwargs):
        if "packet_rule" in Path(destination).parts and not appended:
            with real_connect(source) as writer:
                writer.row_factory = sqlite3.Row
                appended.append(_append_segment(writer, operation))
        return real_backup(source, destination, **kwargs)

    def mutate_after_backup(db):
        assert len(appended) == 1
        if change == "delete":
            assert db.execute("DELETE FROM packet_capture_segments WHERE id=?", (appended[0],)).rowcount == 1
        else:
            assert db.execute("UPDATE packet_capture_segments SET file_name='replaced-after-backup.pcap' WHERE id=?", (appended[0],)).rowcount == 1

    monkeypatch.setattr(core, "create_sqlite_backup", append_before_backup)
    fired = _race_at(operation, monkeypatch, "before_begin", mutate_after_backup)
    result = execute(operation)
    assert fired == ["packet_rule"]
    assert result["operation_status"] == "HOLD"
    assert _audits(operation) == []
    assert checkpoint(operation, "packet_rule") == before
