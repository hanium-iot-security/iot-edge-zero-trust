"""Real pair SQL tests: defer duplicate work, retain every fresh mutation guard."""
from dataclasses import replace
from pathlib import Path
import sqlite3

import pytest

from edge.detection import packet_checkpoint_pair_recovery as pair
from edge.detection import packet_checkpoint_recovery as core
from edge.scripts import phase4_cutover_storage as storage
from test_packet_checkpoint_pair_recovery import fixture as paired_fixture,_use_failed_tail,_audits


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
