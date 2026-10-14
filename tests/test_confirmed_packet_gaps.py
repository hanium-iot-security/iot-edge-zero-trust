"""Confirmed loss may advance only packet checkpoints, with a durable audit."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import apply_migrations, MIGRATIONS_DIR
from edge.packet.confirmed_gaps import advance_confirmed_packet_gap, resolve_confirmed_packet_gap

BASE = datetime(2026, 10, 14, tzinfo=timezone.utc)
SOURCE = '11111111-1111-4111-8111-111111111111'
TARGET = '22222222-2222-4222-8222-222222222222'

def utc(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')

def segment(db, session, start, status='EMPTY', interface='eth0'):
    failed = status == 'FAILED'
    return db.execute(text('INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status,error_code,captured_duration_seconds) VALUES (:session,:file,:interface,:start,:end,:status,:error,:duration)'),
        dict(session=session, file=None if failed else f'{session}-{interface}-{start}.pcap', interface=interface, start=utc(start), end=utc(start+10), status=status, error='LATE_CAPTURE' if failed else None, duration=0 if failed else 10)).lastrowid

@pytest.fixture
def db(tmp_path):
    path = tmp_path / 'confirmed.db'
    apply_migrations(path, MIGRATIONS_DIR)
    engine = create_engine(f'sqlite:///{path.as_posix()}')
    with Session(engine) as session:
        session.execute(text('INSERT INTO packet_capture_sessions(id,session_id,capture_interface,started_at,first_window_start,ended_at,status) VALUES (1,:source,\'eth0\',:start,:start,:end,\'COMPLETED\')'), dict(source=SOURCE,start=utc(0),end=utc(12)))
        session.execute(text('INSERT INTO packet_capture_sessions(id,session_id,capture_interface,started_at,first_window_start,capture_gap_start,capture_gap_end,status) VALUES (2,:target,\'eth0\',:start,:start,:gap,:start,\'RUNNING\')'),dict(target=TARGET,start=utc(30),gap=utc(10)))
        segment(session, 1, 0)
        segment(session, 2, 30)
        for name in ('packet_rule','packet_if'):
            session.execute(text('INSERT INTO detector_checkpoints VALUES (:name,\'packet_feature_logs\',0,:end,:end)'),dict(name=name,end=utc(10)))
        session.execute(text('INSERT INTO detector_checkpoints VALUES (\'trust_score_v2\',\'detection_events\',0,:end,:end)'),dict(end=utc(10)))
        session.commit()
        yield session
    engine.dispose()

def advance(db, start=10, cutoff=40):
    return advance_confirmed_packet_gap(db, range_start=BASE+timedelta(seconds=start),cutoff=BASE+timedelta(seconds=cutoff))

def pair(db):
    return [dict(row) for row in db.execute(text("SELECT * FROM detector_checkpoints WHERE source_table='packet_feature_logs' ORDER BY detector_name")).mappings()]

def resolve(db):
    return resolve_confirmed_packet_gap(db,range_start=BASE+timedelta(seconds=10),boundary=BASE+timedelta(seconds=30),checkpoint_rows=pair(db))

def test_recorded_gap_is_atomic_uninspected_and_preserves_trust(db):
    result = advance(db)
    assert result['target_session_id'] == TARGET
    assert result['window_start'] == utc(10)
    assert result['window_end'] == utc(30)
    assert all(r['last_completed_window_end'] == utc(30) and r['last_processed_id'] == 0 for r in pair(db))
    assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints WHERE detector_name='trust_score_v2'")).scalar_one() == utc(10)
    row = dict(db.execute(text('SELECT * FROM packet_detection_gaps')).mappings().one())
    assert row['status'] == 'UNINSPECTED'
    assert row['reason'] == 'RECORDED_CAPTURE_GAP'
    assert resolve(db)['plan_sha256'] == result['plan_sha256']
    db.rollback()
    assert all(r['last_completed_window_end'] == utc(10) for r in pair(db))
    assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 0

@pytest.mark.parametrize('mutation', [
    "UPDATE packet_capture_segments SET status='READY' WHERE capture_session_id=1",
    "UPDATE detector_checkpoints SET last_completed_window_end='2026-10-14T00:00:00Z' WHERE detector_name='packet_if'",
    "UPDATE packet_capture_sessions SET capture_gap_start=NULL WHERE id=2",
    "UPDATE packet_capture_segments SET status='READY' WHERE capture_session_id=2",
    "UPDATE packet_capture_sessions SET capture_interface='wlan0' WHERE id=2",
    "UPDATE packet_capture_sessions SET status='RUNNING' WHERE id=1",
])
def test_unconfirmed_or_pending_input_does_not_advance(db,mutation):
    db.execute(text(mutation))
    db.commit()
    before = pair(db)
    assert advance(db) is None
    assert pair(db) == before

def test_other_interface_overlap_also_blocks(db):
    segment(db, 1, 10, interface='wlan0')
    db.commit()
    assert advance(db) is None

def test_late_terminal_adjacent_without_gap_metadata(db):
    db.execute(text("UPDATE packet_capture_sessions SET status='FAILED' WHERE id=1"))
    segment(db,1,10,'FAILED')
    db.execute(text('UPDATE packet_capture_sessions SET first_window_start=:end,capture_gap_start=NULL,capture_gap_end=NULL WHERE id=2'),dict(end=utc(20)))
    db.execute(text('UPDATE packet_capture_segments SET window_start=:start,window_end=:end WHERE capture_session_id=2'),dict(start=utc(20),end=utc(30)))
    db.commit()
    result = advance(db)
    assert result['window_end'] == utc(20)
    assert db.execute(text('SELECT reason FROM packet_detection_gaps')).scalar_one() == 'LATE_CAPTURE'
    assert db.execute(text('SELECT status FROM packet_capture_segments WHERE window_start=:start'),dict(start=utc(10))).scalar_one() == 'FAILED'

def test_resolver_survives_target_lifecycle_and_restart(db):
    result = advance(db)
    db.commit()
    assert advance(db) is None
    db.execute(text("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=:end WHERE id=2"),dict(end=utc(60)))
    segment(db,2,40)
    db.commit()
    assert resolve(db)['plan_sha256'] == result['plan_sha256']
    assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 1
    segment(db,1,10,interface='wlan0')
    db.commit()
    assert resolve(db) is None

def test_audit_cannot_be_changed_or_deleted(db):
    advance(db)
    db.commit()
    with pytest.raises(Exception, match='immutable'):
        db.execute(text("UPDATE packet_detection_gaps SET reason='changed'"))
    db.rollback()
    with pytest.raises(Exception, match='immutable'):
        db.execute(text('DELETE FROM packet_detection_gaps'))
    db.rollback()

def test_missing_migration_is_explicit(db):
    db.execute(text('DROP TABLE packet_detection_gaps'))
    db.commit()
    with pytest.raises(ValueError, match='016'):
        advance(db)

def test_late_capture_with_additional_recorded_gap(db):
    db.execute(text("UPDATE packet_capture_sessions SET status='FAILED' WHERE id=1"))
    segment(db, 1, 10, 'FAILED')
    db.execute(text('UPDATE packet_capture_sessions SET capture_gap_start=:end WHERE id=2'),dict(end=utc(20)))
    db.commit()
    assert advance(db)['window_end'] == utc(30)


def test_pending_target_or_cutoff_before_first_completed_window_blocks(db):
    assert advance(db, cutoff=30) is None
    db.rollback()
    db.execute(text('DELETE FROM packet_capture_segments WHERE capture_session_id=2'))
    db.commit()
    assert advance(db) is None


def test_feature_in_gap_is_not_skipped(db):
    source_segment = db.execute(text('SELECT id FROM packet_capture_segments WHERE capture_session_id=1')).scalar_one()
    db.execute(text("UPDATE packet_capture_segments SET status='PROCESSED' WHERE id=:id"), {'id': source_segment})
    db.execute(text("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (:id,'192.0.2.1','INBOUND',:start,:end,1,1,1,1)"), {'id': source_segment,'start':utc(0),'end':utc(10)})
    db.execute(text('UPDATE packet_feature_logs SET window_start=:start,window_end=:end'),{'start':utc(10),'end':utc(20)})
    db.commit()
    assert advance(db) is None


def test_second_checkpoint_failure_rolls_back_first_and_audit(db):
    db.execute(text("CREATE TRIGGER reject_rule_checkpoint BEFORE UPDATE ON detector_checkpoints WHEN NEW.detector_name='packet_rule' BEGIN SELECT RAISE(ABORT,'injected second checkpoint failure'); END"))
    db.commit()
    with pytest.raises(Exception, match='injected second checkpoint failure'):
        advance(db)
    db.rollback()
    assert all(row['last_completed_window_end'] == utc(10) for row in pair(db))
    assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 0


def test_empty_intermediate_session_is_not_bypassed(db):
    db.execute(text('UPDATE packet_capture_sessions SET id=3 WHERE id=2'))
    db.execute(text('UPDATE packet_capture_segments SET capture_session_id=3 WHERE capture_session_id=2'))
    db.execute(text("INSERT INTO packet_capture_sessions(id,session_id,capture_interface,started_at,status) VALUES (2,'33333333-3333-4333-8333-333333333333','eth0',:start,'FAILED')"), {'start':utc(20)})
    db.commit()
    assert advance(db) is None


def test_resolver_rejects_changed_source_or_checkpoint_provenance(db):
    advance(db)
    db.commit()
    db.execute(text("UPDATE detector_checkpoints SET last_processed_id=5 WHERE detector_name='packet_if'"))
    db.commit()
    assert resolve(db) is None
    db.execute(text("UPDATE detector_checkpoints SET last_processed_id=0 WHERE detector_name='packet_if'"))
    db.execute(text('UPDATE packet_capture_sessions SET capture_gap_start=:start WHERE id=2'),{'start':utc(0)})
    db.commit()
    assert resolve(db) is None


def test_no_packet_checkpoint_or_unrelated_future_capture_changes_audit(db):
    advance(db)
    db.commit()
    db.execute(text("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status) VALUES ('33333333-3333-4333-8333-333333333333','eth0',:start,:start,'RUNNING')"),{'start':utc(70)})
    db.commit()
    assert resolve(db) is not None
    db.execute(text("DELETE FROM detector_checkpoints WHERE detector_name='packet_if'"))
    db.commit()
    assert resolve(db) is None


def test_detector_specific_ids_are_preserved_at_shared_boundary(db):
    db.execute(text("UPDATE detector_checkpoints SET last_processed_id=17 WHERE detector_name='packet_rule'"))
    db.execute(text("UPDATE detector_checkpoints SET last_processed_id=18 WHERE detector_name='packet_if'"))
    db.commit()
    assert advance(db) is not None
    assert {row['detector_name']: row['last_processed_id'] for row in pair(db)} == {'packet_rule': 17, 'packet_if': 18}
    assert resolve(db) is not None


def test_normal_unprocessed_window_before_gap_is_not_skipped(db):
    db.execute(text('UPDATE packet_capture_sessions SET capture_gap_start=:end WHERE id=2'), {'end':utc(20)})
    segment(db,1,10)
    db.commit()
    assert advance(db) is None


def test_segment_interface_inconsistent_with_session_blocks(db):
    db.execute(text("UPDATE packet_capture_segments SET capture_interface='wlan0' WHERE capture_session_id=2"))
    db.commit()
    assert advance(db) is None
