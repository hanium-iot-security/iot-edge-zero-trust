"""Versioned proof of clean captures rejected by the unchanged timing policy."""
from dataclasses import asdict
from datetime import timedelta
import json
import sqlite3

import pytest
from sqlalchemy import text

from edge.packet import capture_session_repository as captures
from edge.packet import confirmed_gaps as gaps
from edge.packet import confirmed_partial_capture as proofs
from edge.packet.capture_policy import CapturePolicy
from test_confirmed_gap_runtime import _partial_case
from test_segment_gap_runtime import (
    runtime, _time, _checkpoint, format_db_utc, CAPTURE_ID, PACKET_RULE, PACKET_IF,
)


def _late_case(runtime, tmp_path, monkeypatch, *, count=1, mixed=False, delay=1.270588, policy=None):
    registry, files, initial, tail = _partial_case(runtime, tmp_path, monkeypatch, count)
    factory, _, _ = runtime
    policy = policy or CapturePolicy()
    with factory() as db:
        for index, (sid, path) in enumerate(files):
            if mixed and index == 0:
                continue
            start, end = _time(10 + index * 10), _time(20 + index * 10)
            timing = dict(actual_capture_started_at=(start + timedelta(seconds=delay)).isoformat(),
                          capture_stop_requested_at=end.isoformat(),
                          capture_process_exited_at=(end + timedelta(milliseconds=50)).isoformat(),
                          start_delay_seconds=delay, captured_duration_seconds=10 - delay)
            db.execute(text("UPDATE packet_capture_segments SET actual_capture_started_at=:actual_capture_started_at, "
                            "capture_stop_requested_at=:capture_stop_requested_at, capture_process_exited_at=:capture_process_exited_at, "
                            "start_delay_seconds=:start_delay_seconds, captured_duration_seconds=:captured_duration_seconds WHERE id=:id"),
                       dict(timing, id=sid))
            sidecar = path.with_suffix('.pcap.capture.json')
            diagnostic = json.loads(sidecar.read_text())
            reason = ('start_delay_exceeds_policy' if delay > policy.max_start_delay_seconds + policy.epsilon_seconds
                      else 'captured_duration_below_policy')
            diagnostic.update(schema_version='packet-capture-diagnostics-v2', quality_failure_reason=reason,
                              capture_policy=asdict(policy), stderr_error=None, packets_dropped=0,
                              drop_status='no_kernel_drops_reported', **timing)
            sidecar.write_text(json.dumps(diagnostic), encoding='utf-8')
        db.commit()
    return registry, files, initial, tail


def _audit(db):
    return dict(db.execute(text('SELECT * FROM packet_detection_gaps')).mappings().one())


@pytest.mark.parametrize('count,mixed', [(1, False), (3, False), (3, True)])
def test_late_partial_atomic_proof_and_retained_history(runtime, tmp_path, monkeypatch, count, mixed):
    _, files, initial, _ = _late_case(runtime, tmp_path, monkeypatch, count=count, mixed=mixed)
    factory, database, _ = runtime
    end = _time(10 + count * 10)
    with factory() as db:
        before = [dict(row) for row in db.execute(text("SELECT * FROM packet_capture_segments WHERE status='FAILED' ORDER BY id")).mappings()]
        result = gaps.advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=end + timedelta(seconds=10))
        assert result is not None
        db.commit()
        audit = _audit(db)
        evidence = json.loads(audit['evidence_json'])
        assert evidence['version'] == 3 and evidence['status'] == 'UNINSPECTED'
        assert evidence['loss_kind'] == 'PARTIAL_CAPTURE'
        assert [entry['segment'] for entry in evidence['failed_segments']] == before
        assert proofs.validate_partial_evidence(db, audit) == evidence
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)['last_completed_window_end'] == format_db_utc(end)
            assert _checkpoint(db, detector)['last_processed_id'] == initial
        assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs WHERE capture_segment_id IN (SELECT id FROM packet_capture_segments WHERE status='FAILED')")).scalar_one() == 0
    for _, path in files:
        path.unlink()
        path.with_suffix('.pcap.capture.json').unlink()
    monkeypatch.setattr(CapturePolicy, 'from_env', classmethod(lambda cls: (_ for _ in ()).throw(AssertionError('historical policy must be stored'))))
    with factory() as db:
        assert proofs.validate_partial_evidence(db, audit) == evidence
        checkpoints = gaps._pair(db)
        assert gaps.resolve_confirmed_packet_gap(db, range_start=_time(10), boundary=end, checkpoint_rows=checkpoints) == result
    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row
        assert all(proofs.approved_partial_capture_gaps(db, before))


def test_old_sidecar_and_audit_are_preserved(runtime, tmp_path, monkeypatch):
    _partial_case(runtime, tmp_path, monkeypatch)
    factory, _, _ = runtime
    with factory() as db:
        assert gaps.advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30))
        db.commit()
        audit = _audit(db)
        evidence = json.loads(audit['evidence_json'])
        assert evidence['version'] == 2
        assert evidence['failed_segments'][0]['diagnostics']['schema_version'] == 'packet-capture-diagnostics-v1'
        assert proofs.validate_partial_evidence(db, audit) == evidence
        evidence['version'] = 3
        assert proofs.validate_partial_evidence(db, dict(audit, evidence_json=json.dumps(evidence), plan_sha256=proofs.digest(evidence))) is None


def test_producer_policy_snapshot_proves_duration_rejection(runtime, tmp_path, monkeypatch):
    policy = CapturePolicy(minimum_duration_seconds=9.9)
    _late_case(runtime, tmp_path, monkeypatch, delay=.2, policy=policy)
    factory, _, _ = runtime
    with factory() as db:
        assert gaps.advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30))
        db.commit()
        audit = _audit(db)
        evidence = proofs.validate_partial_evidence(db, audit)
        assert evidence['failed_segments'][0]['diagnostics']['quality_failure_reason'] == 'captured_duration_below_policy'
        assert evidence['capture_policy']['minimum_duration_seconds'] == 9
        evidence['version'] = 2
        assert proofs.validate_partial_evidence(db, dict(audit, evidence_json=json.dumps(evidence), plan_sha256=proofs.digest(evidence))) is None


@pytest.mark.parametrize('mutation', [
    'missing_reason', 'unknown_reason', 'wrong_reason', 'wrong_schema', 'old_schema', 'missing_policy', 'policy_bool',
    'policy_version_type', 'missing_timing', 'time_mismatch', 'duration_bool', 'duration_mismatch',
    'early_exit', 'dirty_exit', 'bad_exit', 'stderr_incomplete', 'stderr_error', 'unknown_drops',
    'kernel_drop', 'interface_drop', 'drop_status', 'eligible_timing', 'stop_before_end', 'no_healthy', 'different_session',
])
def test_unproved_late_partial_never_moves_checkpoints(runtime, tmp_path, monkeypatch, mutation):
    _, files, _, _ = _late_case(runtime, tmp_path, monkeypatch)
    sid, path = files[0]
    sidecar = path.with_suffix('.pcap.capture.json')
    diagnostic = json.loads(sidecar.read_text())
    if mutation == 'missing_reason': diagnostic.pop('quality_failure_reason')
    elif mutation == 'unknown_reason': diagnostic['quality_failure_reason'] = 'late'
    elif mutation == 'wrong_reason': diagnostic['quality_failure_reason'] = 'captured_duration_below_policy'
    elif mutation == 'wrong_schema': diagnostic['schema_version'] = 'packet-capture-diagnostics-v3'
    elif mutation == 'old_schema': diagnostic['schema_version'] = 'packet-capture-diagnostics-v1'
    elif mutation == 'missing_policy': diagnostic.pop('capture_policy')
    elif mutation == 'policy_bool': diagnostic['capture_policy']['epsilon_seconds'] = False
    elif mutation == 'policy_version_type': diagnostic['capture_policy']['version'] = 1
    elif mutation == 'missing_timing': diagnostic.pop('actual_capture_started_at')
    elif mutation == 'time_mismatch': diagnostic['actual_capture_started_at'] = _time(12).isoformat()
    elif mutation == 'duration_bool': diagnostic['captured_duration_seconds'] = True
    elif mutation == 'duration_mismatch': diagnostic['captured_duration_seconds'] = 8
    elif mutation == 'early_exit': diagnostic['completed_full_window'] = False
    elif mutation == 'dirty_exit': diagnostic['terminated_cleanly'] = False
    elif mutation == 'bad_exit': diagnostic['exit_code'] = -9
    elif mutation == 'stderr_incomplete': diagnostic['stderr_complete'] = False
    elif mutation == 'stderr_error': diagnostic['stderr_error'] = 'read failed'
    elif mutation == 'unknown_drops': diagnostic['packets_dropped'] = None
    elif mutation == 'kernel_drop': diagnostic['packets_dropped'] = 1
    elif mutation == 'interface_drop': diagnostic['packets_dropped_by_interface'] = 1
    elif mutation == 'drop_status': diagnostic['drop_status'] = 'unknown'
    elif mutation == 'eligible_timing':
        diagnostic['capture_policy']['max_start_delay_seconds'] = 2
        diagnostic['capture_policy']['minimum_duration_seconds'] = 8
    elif mutation == 'stop_before_end':
        diagnostic['capture_stop_requested_at'] = _time(19).isoformat()
        diagnostic['captured_duration_seconds'] -= 1
    sidecar.write_text(json.dumps(diagnostic), encoding='utf-8')
    factory, _, _ = runtime
    with factory() as db:
        if mutation == 'no_healthy':
            db.execute(text('DELETE FROM packet_feature_logs WHERE window_start=:start'), {'start':format_db_utc(_time(20))})
            db.execute(text('DELETE FROM packet_capture_segments WHERE window_start=:start'), {'start':format_db_utc(_time(20))})
        elif mutation == 'different_session':
            other = captures.create_session(db, session_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd',
                                            capture_interface='eth0', started_at=_time(20))
            captures.set_first_window_start(db, other, _time(20))
            db.execute(text('UPDATE packet_capture_segments SET capture_session_id=:session WHERE window_start=:start'),
                       {'session':other, 'start':format_db_utc(_time(20))})
        elif mutation == 'stop_before_end':
            db.execute(text('UPDATE packet_capture_segments SET capture_stop_requested_at=:stop, captured_duration_seconds=:duration WHERE id=:id'),
                       {'stop':diagnostic['capture_stop_requested_at'], 'duration':diagnostic['captured_duration_seconds'], 'id':sid})
        db.commit()
        before = gaps._pair(db)
        assert gaps.advance_confirmed_packet_gap(db, range_start=_time(10), cutoff=_time(30)) is None
        assert gaps._pair(db) == before
        assert db.execute(text('SELECT COUNT(*) FROM packet_detection_gaps')).scalar_one() == 0
        db.rollback()
