"""Confirmed loss does not hide the next real Packet event from Trust."""

import pytest
from sqlalchemy import text

from edge.orchestration import run_detection_orchestrator as orchestrator
from edge.packet import capture_session_repository as captures
from test_segment_gap_runtime import (
    runtime, _time, _segment, _registry, _checkpoint, CAPTURE_ID, DEVICE_ID,
    format_db_utc, run_producer_cycle, CYCLE_COMPLETED,
    PACKET_RULE, PACKET_IF, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE,
)

NEXT = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


def _chain(runtime, tmp_path, *, attack=False, late=False):
    factory, _, source = runtime
    with factory() as db:
        _, initial_feature = _segment(db, source, 0)
        if late:
            captures.insert_late_capture_segment(
                db, capture_session_pk=source, capture_interface="eth0",
                window_start=_time(10), window_end=_time(20),
                error_message="capture did not start", start_delay_seconds=2.5,
            )
        captures.close_session(db, source, _time(12 if late else 10),
                               "FAILED" if late else "COMPLETED")
        next_start = 20 if late else 30
        target = captures.create_session(db, session_id=NEXT, capture_interface="eth0",
                                         started_at=_time(next_start - 2))
        captures.set_first_window_start(db, target, _time(next_start))
        if not late:
            captures.record_capture_gap(db, target, _time(10), _time(next_start))
        segment, last_feature = _segment(db, target, next_start)
        # The fixture helper normally names its original capture UUID.
        db.execute(text("UPDATE packet_capture_segments SET file_name=replace(file_name,:old,:new) WHERE id=:id"),
                   {"old": CAPTURE_ID, "new": NEXT, "id": segment})
        if attack:
            db.execute(text("UPDATE packet_feature_logs SET packet_count=201, total_bytes=2010 WHERE id=:id"),
                       {"id": last_feature})
        for seconds in range(0, next_start + 10, 10):
            db.execute(text("INSERT INTO mqtt_logs (device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) "
                            "VALUES (:device,:topic,'{}',2,:at,1,1)"),
                       {"device": DEVICE_ID, "topic": f"iot/{DEVICE_ID}/sensor", "at": format_db_utc(_time(seconds + 1))})
        db.commit()
    run_producer_cycle(session_factory=factory, now=_time(next_start + 11))
    registry = _registry(tmp_path)
    first = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert first.status == CYCLE_COMPLETED and first.cutoff == _time(10)
    return registry, next_start, initial_feature, last_feature


@pytest.mark.parametrize("late", [False, True])
def test_confirmed_gap_then_real_attack_is_scored(runtime, tmp_path, monkeypatch, late):
    registry, next_start, initial_feature, last_feature = _chain(runtime, tmp_path, attack=True, late=late)
    factory, _, _ = runtime
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    catchup = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED
    assert catchup.range_start == _time(10) and catchup.cutoff == _time(next_start)
    assert all(item.detector_name not in (PACKET_RULE, PACKET_IF) for item in catchup.stage_results)
    with factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE_ID}).scalar_one() == 100
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == initial_feature
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(next_start + 10)
    with factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE_ID}).scalar_one() < 100
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE applied_to_score=1")).scalar_one() > 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == last_feature
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(next_start + 10))
        if late:
            assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments WHERE status='FAILED' AND error_code='LATE_CAPTURE'")).scalar_one() == 1


def test_policy_disabled_keeps_existing_hold(runtime, tmp_path, monkeypatch):
    registry, _, _, _ = _chain(runtime, tmp_path)
    factory, _, _ = runtime
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": False}))
    result = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert result.status != CYCLE_COMPLETED
    with factory() as db:
        assert _checkpoint(db, PACKET_RULE)["last_completed_window_end"] == format_db_utc(_time(10))


def test_committed_gap_catches_up_after_restart_with_policy_disabled(runtime, tmp_path, monkeypatch):
    from edge.packet.confirmed_gaps import advance_confirmed_packet_gap

    registry, next_start, initial_feature, last_feature = _chain(runtime, tmp_path, attack=True)
    factory, _, _ = runtime
    # Persist only the atomic Packet transition, as if the process died immediately after commit.
    with factory() as db:
        assert advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(next_start + 10))
        db.commit()
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(10))
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": False}))
    catchup = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == _time(next_start)
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(next_start + 10)
    with factory() as db:
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device": DEVICE_ID}).scalar_one() < 100
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE applied_to_score=1")).scalar_one() > 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == last_feature
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(next_start + 10))

def _partial_files(db, tmp_path, source, start, monkeypatch):
    import json
    import struct
    from backend.app import config
    from edge.packet.pcap_naming import build_pcap_filename
    name = build_pcap_filename(session_id=CAPTURE_ID, interface="eth0", window_start=_time(start), window_end=_time(start+10), tmp=False)
    path = tmp_path / name
    path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    metadata = dict(schema_version="packet-capture-diagnostics-v1", session_id=CAPTURE_ID,
        capture_interface="eth0", window_start=_time(start).isoformat(), window_end=_time(start+10).isoformat(),
        pcap_file_name=name, expected_pcap_file_name=name, success=False, error_code="PARTIAL_CAPTURE",
        file_validation_error=None, completed_full_window=True, terminated_cleanly=True, exit_code=-15,
        stderr_complete=True, packets_captured=0, packets_received=1, packets_dropped=1,
        packets_dropped_by_interface=None, drop_status="observed_loss")
    path.with_suffix(".pcap.capture.json").write_text(json.dumps(metadata), encoding="utf-8")
    sid, _ = _segment(db, source, start, status="FAILED")
    db.execute(text("UPDATE packet_capture_segments SET captured_duration_seconds=9.8 WHERE id=:id"), {"id":sid})
    monkeypatch.setattr(config, "settings", config.settings.model_copy(update={"pcap_failed_dir":str(tmp_path)}))
    return sid, path


@pytest.mark.parametrize("count", [1, 3, 4])
@pytest.mark.parametrize("source_status", ["RUNNING", "FAILED", "COMPLETED"])
def test_confirmed_partial_chain_keeps_failed_and_scores_healthy_tail(runtime, tmp_path, monkeypatch, count, source_status):
    factory, _, source = runtime
    tail_start = 10 + count * 10
    with factory() as db:
        _, initial = _segment(db, source, 0)
        failed = [_partial_files(db, tmp_path, source, at, monkeypatch)[0] for at in range(10, tail_start, 10)]
        _, tail = _segment(db, source, tail_start)
        db.execute(text("UPDATE packet_feature_logs SET packet_count=201,total_bytes=2010 WHERE id=:id"), {"id":tail})
        if source_status != "RUNNING":
            captures.close_session(db, source, _time(tail_start+10), source_status)
        for seconds in range(0, tail_start+10, 10):
            db.execute(text("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) VALUES (:device,:topic,'{}',2,:at,1,1)"), {"device":DEVICE_ID,"topic":f"iot/{DEVICE_ID}/sensor","at":format_db_utc(_time(seconds+1))})
        db.commit()
    run_producer_cycle(session_factory=factory, now=_time(tail_start+11))
    registry = _registry(tmp_path)
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(update={"packet_confirmed_gap_policy_enabled":True}))
    first = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert first.status == CYCLE_COMPLETED and first.cutoff == _time(10)
    catchup = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == _time(tail_start)
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(tail_start+10)
    with factory() as db:
        import json
        audit = db.execute(text("SELECT * FROM packet_detection_gaps")).mappings().one()
        evidence = json.loads(audit["evidence_json"])
        assert audit["reason"] == "RECORDED_CAPTURE_GAP"
        assert evidence["loss_kind"] == "PARTIAL_CAPTURE"
        assert len(evidence["failed_segments"]) == count
        assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments WHERE status='FAILED' AND error_code='PARTIAL_CAPTURE'")).scalar_one() == count
        assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs WHERE capture_segment_id IN (SELECT id FROM packet_capture_segments WHERE status='FAILED')")).scalar_one() == 0
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"), {"device":DEVICE_ID}).scalar_one() < 100
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        assert _checkpoint(db, PACKET_RULE)["last_processed_id"] == tail
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(tail_start+10))

def _partial_case(runtime, tmp_path, monkeypatch, count=1):
    factory, _, source = runtime
    tail_start = 10 + count*10
    with factory() as db:
        _, initial = _segment(db, source, 0)
        files = [_partial_files(db, tmp_path, source, at, monkeypatch) for at in range(10, tail_start, 10)]
        _, tail = _segment(db, source, tail_start)
        for at in range(0, tail_start+10, 10):
            db.execute(text("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) VALUES (:device,:topic,'{}',2,:at,1,1)"), {"device":DEVICE_ID,"topic":f"iot/{DEVICE_ID}/sensor","at":format_db_utc(_time(at+1))})
        db.commit()
    run_producer_cycle(session_factory=factory, now=_time(tail_start+11))
    registry = _registry(tmp_path)
    assert orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry).cutoff == _time(10)
    return registry, files, initial, tail


@pytest.mark.parametrize("mutation", ["missing_pcap", "missing_diagnostics", "malformed_pcap", "diagnostic_identity",
    "diagnostic_unknown", "timing_math", "feature_overlap", "subsecond_feature_overlap", "segment_overlap",
    "checkpoint_mismatch", "no_healthy", "pending_healthy", "interface", "changed_before_write"])
def test_unconfirmed_partial_never_advances(runtime, tmp_path, monkeypatch, mutation):
    from edge.packet import confirmed_gaps
    import json
    registry, files, initial, tail = _partial_case(runtime, tmp_path, monkeypatch)
    failed_id, path = files[0]
    sidecar = path.with_suffix(".pcap.capture.json")
    factory, _, source = runtime
    if mutation == "missing_pcap": path.unlink()
    elif mutation == "missing_diagnostics": sidecar.unlink()
    elif mutation == "malformed_pcap": path.write_bytes(b"invalid")
    elif mutation in ("diagnostic_identity", "diagnostic_unknown"):
        metadata = json.loads(sidecar.read_text())
        metadata["session_id" if mutation == "diagnostic_identity" else "stderr_complete"] = "wrong" if mutation == "diagnostic_identity" else False
        sidecar.write_text(json.dumps(metadata))
    with factory() as db:
        if mutation == "timing_math": db.execute(text("UPDATE packet_capture_segments SET captured_duration_seconds=3 WHERE id=:id"), {"id":failed_id})
        if mutation == "feature_overlap":
            db.execute(text("UPDATE packet_feature_logs SET window_start=:start,window_end=:end WHERE id=:id"),
                       {"start":format_db_utc(_time(10)),"end":format_db_utc(_time(20)),"id":initial})
        if mutation == "subsecond_feature_overlap":
            # Simulate a legacy/corrupt row that modern constraints reject.
            from datetime import timedelta
            db.execute(text("PRAGMA ignore_check_constraints=ON"))
            db.execute(text("UPDATE packet_feature_logs SET window_start=:start,window_end=:end WHERE id=:id"),
                       {"start":(_time(10)-timedelta(microseconds=1)).isoformat(),
                        "end":(_time(20)-timedelta(microseconds=1)).isoformat(),"id":initial})
            db.execute(text("PRAGMA ignore_check_constraints=OFF"))
        if mutation == "segment_overlap":
            _segment(db, source, 10, status="EMPTY", interface="wlan0")
        if mutation == "checkpoint_mismatch": db.execute(text("UPDATE detector_checkpoints SET last_completed_window_end=:at WHERE detector_name='packet_if'"), {"at":format_db_utc(_time(0))})
        if mutation == "no_healthy":
            db.execute(text("DELETE FROM packet_feature_logs WHERE id=:id"), {"id":tail})
            db.execute(text("DELETE FROM packet_capture_segments WHERE window_start=:at"), {"at":format_db_utc(_time(20))})
        if mutation == "pending_healthy": db.execute(text("UPDATE packet_capture_segments SET status='READY' WHERE window_start=:at"), {"at":format_db_utc(_time(20))})
        if mutation == "interface": db.execute(text("UPDATE packet_capture_segments SET capture_interface='wlan0' WHERE id=:id"), {"id":failed_id})
        db.commit()
        before = [tuple(row) for row in db.execute(text("SELECT * FROM detector_checkpoints ORDER BY detector_name"))]
        if mutation == "changed_before_write":
            original = confirmed_gaps.validate_partial_evidence
            def changed(*args, **kwargs):
                path.write_bytes(path.read_bytes()+b"change")
                return original(*args, **kwargs)
            monkeypatch.setattr(confirmed_gaps, "validate_partial_evidence", changed)
        assert confirmed_gaps.advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30)) is None
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 0
        assert [tuple(row) for row in db.execute(text("SELECT * FROM detector_checkpoints ORDER BY detector_name"))] == before
        db.rollback()


def test_partial_audit_survives_restart_policy_off_and_file_retention(runtime, tmp_path, monkeypatch):
    from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
    from edge.packet.confirmed_partial_capture import approved_partial_capture_gap
    from edge.detection.packet_checkpoint_recovery_repository import calculate_packet_feature_readiness
    import sqlite3
    registry, files, initial, tail = _partial_case(runtime, tmp_path, monkeypatch, 3)
    factory, database, source = runtime
    with factory() as db:
        result = advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(50))
        assert result
        db.commit()
        assert advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(50)) is None
        db.rollback()
    for _, path in files:
        path.unlink()
        path.with_suffix(".pcap.capture.json").unlink()
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(update={"packet_confirmed_gap_policy_enabled":False}))
    catchup = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == _time(40)
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(50)
    with factory() as db:
        captures.close_session(db, source, _time(50), "COMPLETED")
        db.commit()
        failed = dict(db.execute(text("SELECT * FROM packet_capture_segments WHERE id=:id"), {"id":files[0][0]}).mappings().one())
        assert approved_partial_capture_gap(db, failed)["id"] == 1
        assert captures.get_packet_feature_ready_through(db, session_id=CAPTURE_ID).packet_feature_ready_through == _time(50)
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        statements=[]
        connection.set_trace_callback(statements.append)
        assert calculate_packet_feature_readiness(connection, CAPTURE_ID).full_ready
        assert approved_partial_capture_gap(connection, failed)["id"] == 1
        assert all(statement.lstrip().split()[0].upper() in ("SELECT", "PRAGMA") for statement in statements)


def test_partial_then_late_then_poweroff_sessions_keep_order_and_score_attack(runtime, tmp_path, monkeypatch):
    third = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    registry, files, initial, tail = _partial_case(runtime, tmp_path, monkeypatch, 3)
    factory, _, source = runtime
    with factory() as db:
        captures.insert_late_capture_segment(db, capture_session_pk=source, capture_interface="eth0",
            window_start=_time(50), window_end=_time(60), error_message="capture missed its start", start_delay_seconds=2)
        captures.close_session(db, source, _time(52), "FAILED")
        for identity, start, end, status, gap in ((NEXT,70,80,"COMPLETED",60),(third,100,110,"RUNNING",80)):
            target = captures.create_session(db, session_id=identity, capture_interface="eth0", started_at=_time(start-2))
            captures.set_first_window_start(db, target, _time(start))
            captures.record_capture_gap(db, target, _time(gap), _time(start))
            segment, feature = _segment(db, target, start)
            db.execute(text("UPDATE packet_capture_segments SET file_name=replace(file_name,:old,:new) WHERE id=:id"), {"old":CAPTURE_ID,"new":identity,"id":segment})
            if status == "COMPLETED": captures.close_session(db, target, _time(end), status)
            else: db.execute(text("UPDATE packet_feature_logs SET packet_count=201,total_bytes=2010 WHERE id=:id"), {"id":feature})
        for at in range(50,110,10):
            db.execute(text("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) VALUES (:device,:topic,'{}',2,:at,1,1)"), {"device":DEVICE_ID,"topic":f"iot/{DEVICE_ID}/sensor","at":format_db_utc(_time(at+1))})
        db.commit()
    run_producer_cycle(session_factory=factory, now=_time(111))
    monkeypatch.setattr(orchestrator,"settings",orchestrator.settings.model_copy(update={"packet_confirmed_gap_policy_enabled":True}))
    boundaries=[]
    for _ in range(6):
        outcome=orchestrator.run_orchestration_cycle(session_factory=factory,registry=registry)
        assert outcome.status == CYCLE_COMPLETED
        boundaries.append(outcome.cutoff)
    assert boundaries == [_time(at) for at in (40,50,70,80,100,110)]
    with factory() as db:
        audits=db.execute(text("SELECT reason,window_start,window_end FROM packet_detection_gaps ORDER BY id")).all()
        assert [row[0] for row in audits] == ["RECORDED_CAPTURE_GAP","LATE_CAPTURE","RECORDED_CAPTURE_GAP"]
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"),{"device":DEVICE_ID}).scalar_one() < 100
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments WHERE status='FAILED'")).scalar_one() == 4


def test_partial_hashing_precedes_writer_and_atomic_pair_rollback(runtime, tmp_path, monkeypatch):
    from edge.packet import confirmed_partial_capture as proofs
    from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
    _, files, _, _ = _partial_case(runtime, tmp_path, monkeypatch)
    factory, _, _ = runtime
    with factory() as db:
        db.execute(text("CREATE TRIGGER reject_partial_rule BEFORE UPDATE ON detector_checkpoints WHEN NEW.detector_name='packet_rule' BEGIN SELECT RAISE(ABORT,'reject partial checkpoint'); END"))
        db.commit()
        original = proofs._file_proof
        observed=[]
        def checked(*args, **kwargs):
            observed.append(db.connection().connection.driver_connection.in_transaction)
            return original(*args, **kwargs)
        monkeypatch.setattr(proofs, "_file_proof", checked)
        with pytest.raises(Exception, match="reject partial checkpoint"):
            advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30))
        db.rollback()
        assert observed == [False,False]
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 0
        assert _checkpoint(db, PACKET_RULE)["last_completed_window_end"] == format_db_utc(_time(10))
        assert _checkpoint(db, PACKET_IF)["last_completed_window_end"] == format_db_utc(_time(10))


def test_partial_batch_validates_audit_once_per_read_and_rechecks_mutation(runtime, tmp_path, monkeypatch):
    from edge.packet import confirmed_partial_capture as proofs
    from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
    from edge.detection.packet_checkpoint_recovery_repository import calculate_packet_feature_readiness
    from edge.maintenance.planned import _approved_source_gaps
    import sqlite3
    _, files, _, _ = _partial_case(runtime, tmp_path, monkeypatch, 8)
    factory, database, _ = runtime
    with factory() as db:
        assert advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(100))
        db.commit()
    original = proofs.validate_partial_evidence
    calls=[]
    def checked(*args, **kwargs):
        calls.append(args[1]['id'])
        return original(*args, **kwargs)
    monkeypatch.setattr(proofs,'validate_partial_evidence',checked)
    with factory() as db:
        assert captures.get_packet_feature_ready_through(db,session_id=CAPTURE_ID).packet_feature_ready_through == _time(100)
        assert calls == [1]
        segments=[dict(row) for row in db.execute(text('SELECT * FROM packet_capture_segments ORDER BY id')).mappings()]
        assert len(_approved_source_gaps(db,segments)) == 8
        assert calls == [1,1]
    with sqlite3.connect(database) as connection:
        connection.row_factory=sqlite3.Row
        assert calculate_packet_feature_readiness(connection,CAPTURE_ID).live_resume_blocking_reasons == ()
        assert calls == [1,1,1]
    with factory() as db:
        db.execute(text("UPDATE packet_capture_segments SET error_message='changed' WHERE id=:id"),{'id':files[-1][0]})
        db.commit()
        assert captures.get_packet_feature_ready_through(db,session_id=CAPTURE_ID).packet_feature_ready_through == _time(10)
        assert calls == [1,1,1,1]


@pytest.mark.parametrize('count',[1,8])
def test_partial_candidate_segment_reads_are_constant_per_chain(runtime,tmp_path,monkeypatch,count):
    from edge.packet import confirmed_partial_capture as proofs
    _, _, _, _ = _partial_case(runtime,tmp_path,monkeypatch,count)
    factory, _, _ = runtime
    original=proofs.rows
    reads=[]
    def checked(db,sql,params=None):
        if 'FROM packet_capture_segments' in sql:
            reads.append(sql)
        return original(db,sql,params)
    monkeypatch.setattr(proofs,'rows',checked)
    with factory() as db:
        source,failed,healthy=proofs._candidate_rows(db,format_db_utc(_time(10)),_time(20+count*10))
        assert len(failed) == count
        assert len(reads) == 4
        assert any('capture_session_id=:id' in sql and 'ORDER BY window_start,id LIMIT 1' in sql for sql in reads)
        assert sum('unixepoch(window_end)' in sql for sql in reads) == 3


def test_partial_overlap_scan_is_bounded_with_large_future_history(runtime,tmp_path,monkeypatch):
    from edge.packet import confirmed_partial_capture as proofs
    _, files, _, _ = _partial_case(runtime,tmp_path,monkeypatch)
    factory, _, source = runtime
    with factory() as db:
        failed=[dict(db.execute(text('SELECT * FROM packet_capture_segments WHERE id=:id'),{'id':files[0][0]}).mappings().one())]
        raw=db.connection().connection.driver_connection
        def steps():
            work=[]
            raw.set_progress_handler(lambda:work.append(1) or 0,1)
            try:
                proofs._unobstructed(db,_time(10),_time(20),failed)
            finally:
                raw.set_progress_handler(None,0)
            return len(work)
        initial=steps()
        future=[{'session':source,'name':f'future-{at}.pcap','start':format_db_utc(_time(at)),
                 'end':format_db_utc(_time(at+10))} for at in range(1000,21000,10)]
        db.execute(text("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status) VALUES (:session,:name,'eth0',:start,:end,'EMPTY')"),future)
        db.commit()
        assert steps() <= initial+500
        details=db.execute(text("EXPLAIN QUERY PLAN SELECT * FROM packet_capture_segments WHERE unixepoch(window_end)>=unixepoch(:start)-1 AND unixepoch(window_end)<=unixepoch(:end)+11 AND unixepoch(window_start)<=unixepoch(:end)+1"),{'start':format_db_utc(_time(10)),'end':format_db_utc(_time(20))}).all()
        assert any('idx_packet_segments_gap_end' in row[3] and '<expr>>?' in row[3] and '<expr><?' in row[3] for row in details)


def test_partial_batch_preserves_unique_covering_audit_and_individual_row_guard(runtime,tmp_path,monkeypatch):
    from edge.packet import confirmed_partial_capture as proofs
    from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
    import json
    _,files,_,_=_partial_case(runtime,tmp_path,monkeypatch,3)
    factory,_,_=runtime
    with factory() as db:
        assert advance_confirmed_packet_gap(db,range_start=_time(10),cutoff=_time(50))
        db.commit()
        failed=[dict(row) for row in db.execute(text("SELECT * FROM packet_capture_segments WHERE status='FAILED' ORDER BY id")).mappings()]
        supplied=[dict(row) for row in failed]
        supplied[0]['error_message']='stale supplied row'
        result=proofs.approved_partial_capture_gaps(db,supplied)
        assert result[0] is None and all(item is not None for item in result[1:])
        audit=dict(db.execute(text('SELECT * FROM packet_detection_gaps')).mappings().one())
        evidence=json.loads(audit['evidence_json'])
        evidence['window_start']=format_db_utc(_time(20))
        evidence['failed_segments']=evidence['failed_segments'][1:]
        for row in evidence['checkpoints_before']:
            row['last_completed_window_end']=row['updated_at']=evidence['window_start']
        db.execute(text("INSERT INTO packet_detection_gaps(source_session_id,target_session_id,window_start,window_end,status,reason,evidence_json,plan_sha256) VALUES (:source,:source,:start,:end,'UNINSPECTED','RECORDED_CAPTURE_GAP',:evidence,:sha)"),
            {'source':CAPTURE_ID,'start':evidence['window_start'],'end':evidence['window_end'],'evidence':json.dumps(evidence),'sha':proofs.digest(evidence)})
        db.commit()
        result=proofs.approved_partial_capture_gaps(db,list(reversed(failed)))
        assert result[0] is None and result[1] is None and result[2] is not None


@pytest.mark.parametrize('reported_drops',[0,None])
def test_confirmed_early_exit_without_reported_drops_resumes_and_scores_attack(runtime,tmp_path,monkeypatch,reported_drops):
    """A verified early exit is coverage loss even without positive drop counts."""
    from datetime import timedelta
    import json
    registry,files,initial,tail=_partial_case(runtime,tmp_path,monkeypatch)
    failed_id,path=files[0]
    sidecar=path.with_suffix('.pcap.capture.json')
    diagnostics=json.loads(sidecar.read_text())
    diagnostics.update(completed_full_window=False,exit_code=0,packets_dropped=reported_drops,
        packets_dropped_by_interface=None,
        drop_status='unknown' if reported_drops is None else 'no_kernel_drops_reported')
    sidecar.write_text(json.dumps(diagnostics),encoding='utf-8')
    factory,_,source=runtime
    with factory() as db:
        db.execute(text("UPDATE packet_capture_segments SET capture_stop_requested_at=:stop,"
                        "capture_process_exited_at=:exited,captured_duration_seconds=8.8,"
                        "error_message='tcpdump exited before the window completed' WHERE id=:id"),
            {'stop':_time(19).isoformat(),'exited':(_time(19)+timedelta(milliseconds=50)).isoformat(),'id':failed_id})
        db.execute(text('UPDATE packet_feature_logs SET packet_count=201,total_bytes=2010 WHERE id=:id'),{'id':tail})
        captures.close_session(db,source,_time(30),'FAILED')
        db.commit()
        original_failed=dict(db.execute(text('SELECT * FROM packet_capture_segments WHERE id=:id'),{'id':failed_id}).mappings().one())
    monkeypatch.setattr(orchestrator,'settings',orchestrator.settings.model_copy(update={'packet_confirmed_gap_policy_enabled':True}))
    catchup=orchestrator.run_orchestration_cycle(session_factory=factory,registry=registry)
    assert catchup.status == CYCLE_COMPLETED and catchup.range_start == _time(10) and catchup.cutoff == _time(20)
    with factory() as db:
        audit=db.execute(text('SELECT * FROM packet_detection_gaps')).mappings().one()
        evidence=json.loads(audit['evidence_json'])
        assert audit['reason'] == 'RECORDED_CAPTURE_GAP' and audit['status'] == 'UNINSPECTED'
        assert evidence['version'] == 2 and evidence['loss_kind'] == 'PARTIAL_CAPTURE'
        assert evidence['failed_segments'][0]['diagnostics'] == diagnostics
        assert evidence['failed_segments'][0]['segment'] == original_failed
        for name in (PACKET_RULE,PACKET_IF):
            assert _checkpoint(db,name)['last_completed_window_end'] == format_db_utc(_time(20))
            assert _checkpoint(db,name)['last_processed_id'] == initial
        assert _checkpoint(db,TRUST_DETECTOR_NAME,TRUST_SOURCE_TABLE)['last_completed_window_end'] == format_db_utc(_time(20))
        assert db.execute(text('SELECT trust_score FROM devices WHERE device_id=:device'),{'device':DEVICE_ID}).scalar_one() == 100
    attack=orchestrator.run_orchestration_cycle(session_factory=factory,registry=registry)
    assert attack.status == CYCLE_COMPLETED and attack.range_start == _time(20) and attack.cutoff == _time(30)
    with factory() as db:
        assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 1
        assert dict(db.execute(text('SELECT * FROM packet_capture_segments WHERE id=:id'),{'id':failed_id}).mappings().one()) == original_failed
        assert db.execute(text('SELECT status FROM packet_capture_sessions WHERE id=:id'),{'id':source}).scalar_one() == 'FAILED'
        assert db.execute(text('SELECT COUNT(*) FROM packet_feature_logs WHERE capture_segment_id=:id'),{'id':failed_id}).scalar_one() == 0
        assert db.execute(text('SELECT COUNT(*) FROM detection_events WHERE applied_to_score=1')).scalar_one() > 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT'")).scalar_one() == 0
        assert db.execute(text('SELECT trust_score FROM devices WHERE device_id=:device'),{'device':DEVICE_ID}).scalar_one() < 100
        for name in (PACKET_RULE,PACKET_IF):
            assert _checkpoint(db,name)['last_processed_id'] == tail
            assert _checkpoint(db,name)['last_completed_window_end'] == format_db_utc(_time(30))
        assert _checkpoint(db,TRUST_DETECTOR_NAME,TRUST_SOURCE_TABLE)['last_completed_window_end'] == format_db_utc(_time(30))


def _warning_evidence(factory, registry):
    from dataclasses import replace
    from backend.app.config import Settings
    from edge.detection.ai_warning_aggregation import WarningPolicy
    from edge.orchestration.runtime_evidence import RuntimeEvidence

    evidence = RuntimeEvidence(factory, Settings(
        _env_file=None, orchestrator_enabled_stages=",".join(registry.enabled_names),
        orchestrator_required_stages=",".join(registry.required_names)), clock=lambda: _time(50))
    evidence.warning_policy = WarningPolicy("gap-regression", 60, 2, 0)
    for configured in registry.stages:
        evidence.register_stage(configured.name, configured.stage)
    return replace(registry, runtime_evidence=evidence)


def _observe_anomaly(db, evidence, seconds, *, detector=PACKET_IF):
    import json
    from edge.detection.ai_run_evidence import AICompletionRecord
    from edge.detection.ai_runtime_repository import store_ai_completions

    model = dict(model_version="test-v1", bundle_sha256="a" * 64,
                 device_ai_mode="OBSERVE", device_ai_revision=1)
    facts = dict(detector_name=detector, **({"model": model} if detector == PACKET_IF else model))
    db.execute(text("INSERT INTO detection_events "
                    "(device_id,detector_type,event_type,analysis_window_start,analysis_window_end,evidence_json) "
                    "VALUES (:device,'AI',:event,:start,:end,:evidence)"),
               dict(device=DEVICE_ID, event="AI_PACKET_ANOMALY" if detector == PACKET_IF else "AI_ANOMALY",
                    start=format_db_utc(_time(seconds)), end=format_db_utc(_time(seconds + 10)),
                    evidence=json.dumps(facts)))
    record = AICompletionRecord(detector, DEVICE_ID, _time(seconds), _time(seconds + 10),
                                1, 1, 0, 1, {}, "test-v1", "a" * 64, 1, "OBSERVE")
    store_ai_completions(db, [record], run_id=evidence.run_id, boot_id=evidence.boot_id,
                         observed_at=evidence.clock(), warning_policy=evidence.warning_policy)


@pytest.mark.parametrize("partial", [False, True], ids=["v1", "v2"])
def test_confirmed_gap_interrupts_packet_warning_without_fabricating_completion(runtime, tmp_path, monkeypatch, partial):
    from edge.detection.ai_runtime_repository import read_ai_completions, list_ai_warnings

    if partial:
        registry, _, _, _ = _partial_case(runtime, tmp_path, monkeypatch)
        next_start = 20
    else:
        registry, next_start, _, _ = _chain(runtime, tmp_path)
    factory, _, _ = runtime
    registry = _warning_evidence(factory, registry)
    with factory() as db, db.begin():
        _observe_anomaly(db, registry.runtime_evidence, 0)
        _observe_anomaly(db, registry.runtime_evidence, 0, detector="mqtt_if")
        before = read_ai_completions(db)
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    result = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert result.status == CYCLE_COMPLETED and result.cutoff == _time(next_start)
    with factory() as db, db.begin():
        assert read_ai_completions(db) == before
        buckets = db.execute(text("SELECT detector_name,closed,last_decision FROM ai_warning_aggregates "
                                  "ORDER BY detector_name")).all()
        _observe_anomaly(db, registry.runtime_evidence, next_start)
        assert list_ai_warnings(db)["total"] == 0
        assert buckets == [("mqtt_if", 0, "BELOW_THRESHOLD"), (PACKET_IF, 1, "INPUT_INTERRUPTED")]
        assert db.execute(text("SELECT closed,last_decision,notified_at,count FROM ai_warning_aggregates "
                               "WHERE detector_name='packet_if'")).one() == (1, "LATE_ATTACHED", None, 2)


@pytest.mark.parametrize("partial", [False, True], ids=["v1", "v2"])
def test_warning_interruption_failure_rolls_back_gap_audit_and_packet_boundaries(runtime, tmp_path, monkeypatch, partial):
    from edge.detection import ai_runtime_repository as repository

    registry, _, _, _ = (_partial_case(runtime, tmp_path, monkeypatch) if partial
                          else _chain(runtime, tmp_path))
    factory, _, _ = runtime
    registry = _warning_evidence(factory, registry)
    with factory() as db, db.begin():
        _observe_anomaly(db, registry.runtime_evidence, 0)
        before = [_checkpoint(db, detector) for detector in (PACKET_RULE, PACKET_IF)]
    original = repository.interrupt_ai_warnings

    def fail_after_interruption(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("warning persistence failed")

    monkeypatch.setattr(repository, "interrupt_ai_warnings", fail_after_interruption)
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": True}))
    with pytest.raises(RuntimeError, match="warning persistence failed"):
        orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    with factory() as db:
        assert [_checkpoint(db, detector) for detector in (PACKET_RULE, PACKET_IF)] == before
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 0
        assert db.execute(text("SELECT closed,last_decision FROM ai_warning_aggregates")).one() == (0, "BELOW_THRESHOLD")


@pytest.mark.parametrize("mode", ["OFF", "OBSERVE"])
def test_activated_ai_policy_resumes_real_input_after_committed_gap(runtime, tmp_path, monkeypatch, mode):
    from dataclasses import replace
    from importlib.metadata import version
    from ai.packet_if_artifact import packet_if_bundle_sha256
    from backend.app.config import Settings
    from edge.detection.ai_runtime_repository import read_ai_completions
    from edge.detection.packet_ai_detector import PacketIsolationForestStage
    from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
    from edge.orchestration.stage_registry import ConfiguredStage
    from edge.policy.ai_stage_activation import prepare_activation, apply_activation
    from test_predict_packet_isolation_forest import _write_artifact, _write_metadata

    registry, next_start, initial_feature, last_feature = _chain(runtime, tmp_path, attack=True)
    factory, _, _ = runtime
    directory = tmp_path / "pinned-packet"
    metadata = _write_artifact(directory)
    metadata["library_versions"].update({key: version(package) for key, package in (
        ("numpy", "numpy"), ("pandas", "pandas"),
        ("scikit_learn", "scikit-learn"), ("joblib", "joblib"))})
    _write_metadata(directory, metadata)
    configured = Settings(_env_file=None, ai_device_policy_enabled=True,
                          runtime_evidence_enabled=True, packet_confirmed_gap_policy_enabled=True,
                          trust_ai_mode="observe", packet_if_artifact_dir=str(directory),
                          packet_if_expected_model_version=metadata["model_version"],
                          packet_if_expected_bundle_sha256=packet_if_bundle_sha256(directory))
    delegate = PacketIsolationForestStage.from_settings(app_settings=configured)
    registry = replace(registry, stages=tuple(
        ConfiguredStage(PACKET_IF, PacketFeatureReadyStage(delegate), True)
        if item.name == PACKET_IF else item for item in registry.stages))
    registry = _warning_evidence(factory, registry)
    identity = dict(stage_name=PACKET_IF, model_version=delegate.artifact.model_version,
                    bundle_sha256=delegate.artifact.bundle_sha256,
                    enabled_stages=list(registry.enabled_names), required_stages=list(registry.required_names),
                    trust_ai_mode="observe")
    with factory() as db, db.begin():
        db.execute(text("INSERT INTO device_ai_policy_revisions "
                        "(device_id,revision,mode,effective_from,created_at,created_by,reason) "
                        "VALUES (:device,1,:mode,:start,:start,'test','gap integration')"),
                   dict(device=DEVICE_ID, mode=mode, start=format_db_utc(_time(0))))
        plan = prepare_activation(db, **identity, boundary=_time(10), approved_by="fixture-author",
                                  reason="synthetic gap integration", prepared_at=_time(50))
        apply_activation(db, plan, **identity, applied_at=_time(50))
    calls = []
    original_score = delegate.artifact.model.decision_function

    def score(matrix):
        calls.append(len(matrix))
        return original_score(matrix)

    monkeypatch.setattr(delegate.artifact.model, "decision_function", score)
    monkeypatch.setattr(orchestrator, "settings", configured)
    monkeypatch.setattr(orchestrator, "resolve_ai_mode", lambda: "observe")
    original_cycle = orchestrator.run_detection_cycle

    def fail_after_gap(**kwargs):
        raise RuntimeError("interrupted after gap commit")

    monkeypatch.setattr(orchestrator, "run_detection_cycle", fail_after_gap)
    with pytest.raises(RuntimeError, match="interrupted after gap commit"):
        orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    with factory() as db:
        assert read_ai_completions(db) == []
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        assert _checkpoint(db, PACKET_IF)["last_processed_id"] == initial_feature
        assert _checkpoint(db, PACKET_IF)["last_completed_window_end"] == format_db_utc(_time(next_start))
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(10))
    assert calls == []
    # A fresh process catches MQTT/Trust up from the persisted audit, even after opt-out.
    monkeypatch.setattr(orchestrator, "run_detection_cycle", original_cycle)
    monkeypatch.setattr(orchestrator, "settings", configured.model_copy(
        update={"packet_confirmed_gap_policy_enabled": False}))
    delegate.completion_sink = None  # A restarted publisher installs one fresh sink.
    registry = _warning_evidence(factory, registry)
    caught_up = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert caught_up.status == CYCLE_COMPLETED and caught_up.cutoff == _time(next_start)
    resumed = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert resumed.status == CYCLE_COMPLETED and resumed.cutoff == _time(next_start + 10)
    assert calls == ([1] if mode == "OBSERVE" else [])
    with factory() as db:
        (completion,) = read_ai_completions(db, device_id=DEVICE_ID)
        assert completion["window_start"] == format_db_utc(_time(next_start))
        assert completion["ai_mode"] == mode and completion["ai_revision"] == 1
        assert completion["inference_count"] == int(mode == "OBSERVE")
        assert _checkpoint(db, PACKET_IF)["last_processed_id"] == last_feature
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)["last_completed_window_end"] == format_db_utc(_time(next_start + 10))
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"),
                          dict(device=DEVICE_ID)).scalar_one() < 100  # Real Rule input still applies.


@pytest.mark.parametrize("change", ["checkpoint", "failed", "healthy_feature", "session", "append"])
def test_partial_proof_rechecks_real_commits_between_preparation_and_writer(runtime, tmp_path, monkeypatch, change):
    from contextlib import closing
    import sqlite3
    from edge.packet import confirmed_gaps

    _, files, _, _ = _partial_case(runtime, tmp_path, monkeypatch)
    factory, database, source = runtime
    original = confirmed_gaps.prepare_partial_capture
    committed = []

    def race(db, *args):
        proof = original(db, *args)
        assert proof is not None
        assert not db.connection().connection.driver_connection.in_transaction
        with closing(sqlite3.connect(database, timeout=0)) as writer:
            if change == "checkpoint":
                writer.execute("UPDATE detector_checkpoints SET last_processed_id=999 WHERE detector_name='packet_if'")
            elif change == "failed":
                writer.execute("UPDATE packet_capture_segments SET error_message='changed by writer' WHERE id=?", (files[0][0],))
            elif change == "healthy_feature":
                writer.execute("UPDATE packet_feature_logs SET total_bytes=total_bytes+1 WHERE window_start=?", (format_db_utc(_time(20)),))
            elif change == "session":
                writer.execute("UPDATE packet_capture_sessions SET started_at=? WHERE id=?", (format_db_utc(_time(-10)), source))
            else:
                writer.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,"
                               "window_start,window_end,status,captured_duration_seconds) "
                               "VALUES (?,'later.pcap','eth0',?,?,'EMPTY',10)",
                               (source, format_db_utc(_time(30)), format_db_utc(_time(40))))
            writer.commit()
            committed.append(tuple(writer.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")))
        return proof

    monkeypatch.setattr(confirmed_gaps, 'prepare_partial_capture', race)
    with factory() as db:
        result = confirmed_gaps.advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30))
        assert len(committed) == 1
        if change == 'append':
            assert result['window_end'] == format_db_utc(_time(20))
            db.commit()
            assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 1
        else:
            assert result is None
            db.rollback()
            assert tuple(db.execute(text('SELECT * FROM detector_checkpoints ORDER BY detector_name'))) == committed[0]
            assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 0
