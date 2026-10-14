"""Record proven missing capture intervals without stopping healthy live input.

The caller owns commit/rollback. Only the two packet checkpoints advance; raw
capture state and Trust are untouched. A gap is uninspected, never healthy data.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_window_boundary
from edge.packet.capture_session_repository import LATE_CAPTURE, get_packet_feature_ready_through

DETECTORS = ('packet_rule', 'packet_if')
TABLE = 'packet_detection_gaps'
SESSION_FIELDS = ('id', 'session_id', 'capture_interface', 'started_at', 'first_window_start',
                  'capture_gap_start', 'capture_gap_end')


def _rows(db, sql, params=None):
    return [dict(row) for row in db.execute(text(sql), params or {}).mappings()]


def _schema_exists(db):
    return bool(_rows(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=:name", {'name': TABLE}))


def _pair(db):
    return _rows(db, "SELECT detector_name,source_table,last_processed_id,last_completed_window_end,updated_at "
                 "FROM detector_checkpoints WHERE source_table='packet_feature_logs' "
                 "AND detector_name IN ('packet_rule','packet_if') ORDER BY detector_name")


def _complete_pair(rows, boundary):
    return (len(rows) == 2 and {row['detector_name'] for row in rows} == set(DETECTORS)
            and all(row['source_table'] == 'packet_feature_logs'
                    and row['last_completed_window_end'] == boundary for row in rows))


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _no_inputs(db, start, end, failed_id):
    params = {'start': start, 'end': end, 'failed': failed_id or -1}
    overlap = 'unixepoch(window_start)<unixepoch(:end) AND unixepoch(window_end)>unixepoch(:start)'
    return not (_rows(db, f'SELECT id FROM packet_capture_segments WHERE id<>:failed AND {overlap} LIMIT 1', params)
                or _rows(db, f'SELECT id FROM packet_feature_logs WHERE capture_segment_id=:failed OR ({overlap}) LIMIT 1', params))


def _candidate(db, start, cutoff, checkpoints):
    """Read a bounded, provable loss; pending input returns no candidate."""
    sources = _rows(db, "SELECT DISTINCT pcs.* FROM packet_capture_sessions pcs "
                    "JOIN packet_capture_segments seg ON seg.capture_session_id=pcs.id "
                    "WHERE pcs.status IN ('COMPLETED','FAILED') AND "
                    "(seg.window_end=:start OR (seg.window_start=:start AND seg.status='FAILED' "
                    "AND seg.error_code=:late))", {'start': start, 'late': LATE_CAPTURE})
    candidates = []
    for source in sources:
        segments = _rows(db, 'SELECT * FROM packet_capture_segments WHERE capture_session_id=:id '
                         'ORDER BY window_start DESC,id DESC LIMIT 1', {'id': source['id']})
        if not segments:
            continue
        last = segments[0]
        if (last['capture_interface'] != source['capture_interface']
                or source['first_window_start'] is None
                or parse_db_utc(last['window_start']) < parse_db_utc(source['first_window_start'])):
            continue
        late = last['window_start'] == start and last['status'] == 'FAILED' and last['error_code'] == LATE_CAPTURE
        if late:
            if (parse_db_utc(last['window_end']) != parse_db_utc(start) + timedelta(seconds=10)
                    or last['captured_duration_seconds'] != 0
                    or any(last[key] is not None for key in ('file_name', 'actual_capture_started_at',
                           'capture_stop_requested_at', 'capture_process_exited_at', 'packet_count'))):
                continue
        elif last['window_end'] != start or last['status'] not in ('PROCESSED', 'EMPTY') or last['error_code']:
            continue
        ready = get_packet_feature_ready_through(db, session_id=source['session_id'])
        if ready is None or ((ready.packet_feature_ready_through or ready.first_window_start) != parse_db_utc(start)):
            continue
        targets = _rows(db, 'SELECT * FROM packet_capture_sessions WHERE capture_interface=:interface AND id>:id ORDER BY id LIMIT 1',
                        {'interface': source['capture_interface'], 'id': source['id']})
        if not targets:
            continue
        target = targets[0]
        end = target['first_window_start']
        if end is None or not parse_db_utc(start) < parse_db_utc(end) <= cutoff:
            continue
        require_utc_window_boundary(parse_db_utc(end), 'target first window')
        gap_start = last['window_end']
        if end != gap_start:
            if target['capture_gap_start'] != gap_start or target['capture_gap_end'] != end:
                continue
        elif not late or (target['capture_gap_start'], target['capture_gap_end']) not in ((None, None), (gap_start, end)):
            continue
        target_ready = get_packet_feature_ready_through(db, session_id=target['session_id'])
        first_end = parse_db_utc(end) + timedelta(seconds=10)
        if (target_ready is None or target_ready.packet_feature_ready_through is None
                or target_ready.packet_feature_ready_through < first_end or first_end > cutoff):
            continue
        first = _rows(db, 'SELECT * FROM packet_capture_segments WHERE capture_session_id=:id AND window_start=:start',
                      {'id': target['id'], 'start': end})
        if (len(first) != 1 or first[0]['status'] not in ('PROCESSED', 'EMPTY')
                or first[0]['error_code'] or first[0]['capture_interface'] != target['capture_interface']):
            continue
        if not _no_inputs(db, start, end, last['id'] if late else None):
            continue
        # Reject hidden sessions within the interval, including empty sessions.
        intermediate = _rows(db, 'SELECT id FROM packet_capture_sessions WHERE id NOT IN (:source,:target) '
                             'AND capture_interface=:interface AND '
                             '((id>:source AND id<:target) OR '
                             '(unixepoch(first_window_start)>=unixepoch(:start) AND unixepoch(first_window_start)<unixepoch(:end))) LIMIT 1',
                             {'source': source['id'], 'target': target['id'], 'interface': source['capture_interface'], 'start': start, 'end': end})
        if intermediate:
            continue
        candidates.append({'version': 1, 'status': 'UNINSPECTED',
                           'reason': LATE_CAPTURE if late else 'RECORDED_CAPTURE_GAP',
                           'window_start': start, 'window_end': end,
                           'source': {key: source[key] for key in SESSION_FIELDS + ('status', 'ended_at')},
                           'target': {key: target[key] for key in SESSION_FIELDS},
                           'source_last_segment': last, 'target_first_segment': first[0],
                           'checkpoints_before': checkpoints})
    return candidates[0] if len(candidates) == 1 else None


def _transition(evidence):
    return {'target_session_id': evidence['target']['session_id'], 'plan_sha256': _digest(evidence),
            'window_start': evidence['window_start'], 'window_end': evidence['window_end']}


def advance_confirmed_packet_gap(db: Session, *, range_start: datetime, cutoff: datetime) -> dict | None:
    """Atomically record confirmed loss and advance both Packet boundaries."""
    start = format_db_utc(require_utc_window_boundary(range_start, 'range_start'))
    cutoff = require_utc_window_boundary(cutoff, 'cutoff')
    if not _schema_exists(db):
        raise ValueError('Migration 016 packet_detection_gaps is required for confirmed gap continuation.')
    # Acquire the writer before evidence reads; an existing stale snapshot fails.
    connection = db.connection()
    if not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN IMMEDIATE')
    else:
        connection.exec_driver_sql('UPDATE detector_checkpoints SET last_processed_id=last_processed_id WHERE 0')
    checkpoints = _pair(db)
    if not _complete_pair(checkpoints, start):
        return None
    evidence = _candidate(db, start, cutoff, checkpoints)
    if evidence is None:
        return None
    # Evidence was read after acquiring the writer: concurrent capture writes
    # cannot alter it before this insert and the checkpoint compare-and-swaps.
    result = _transition(evidence)
    db.execute(text('INSERT INTO packet_detection_gaps(source_session_id,target_session_id,window_start,window_end,status,reason,evidence_json,plan_sha256) '
                    'VALUES (:source,:target,:start,:end,\'UNINSPECTED\',:reason,:evidence,:digest)'),
               {'source': evidence['source']['session_id'], 'target': result['target_session_id'],
                'start': start, 'end': result['window_end'], 'reason': evidence['reason'],
                'evidence': _json(evidence), 'digest': result['plan_sha256']})
    for row in checkpoints:
        changed = db.execute(text('UPDATE detector_checkpoints SET last_completed_window_end=:end,updated_at=:end '
                                  'WHERE detector_name=:name AND source_table=\'packet_feature_logs\' '
                                  'AND last_completed_window_end=:start AND last_processed_id IS :last_id AND updated_at=:updated'),
                             {'end': result['window_end'], 'name': row['detector_name'], 'start': start,
                              'last_id': row['last_processed_id'], 'updated': row['updated_at']})
        if changed.rowcount != 1:
            raise ValueError('Packet checkpoint changed during confirmed gap transition; rollback required.')
    return result


def validated_confirmed_gap_evidence(audit) -> dict | None:
    """Validate stored digest and bindings; callers also verify source and progress."""
    try:
        evidence = json.loads(audit['evidence_json'])
        if (evidence['version'] != 1 or evidence['status'] != audit['status'] or audit['status'] != 'UNINSPECTED'
                or _digest(evidence) != audit['plan_sha256'] or evidence['reason'] != audit['reason']
                or evidence['window_start'] != audit['window_start'] or evidence['window_end'] != audit['window_end']
                or evidence['source']['session_id'] != audit['source_session_id']
                or evidence['target']['session_id'] != audit['target_session_id']):
            return None
        if not _complete_pair(evidence['checkpoints_before'], audit['window_start']):
            return None
        return evidence
    except (ValueError, TypeError, KeyError):
        return None


def resolve_confirmed_packet_gap(db: Session, *, range_start: datetime, boundary: datetime, checkpoint_rows) -> dict | None:
    """Revalidate immutable loss evidence while allowing target capture appends."""
    if not _schema_exists(db):
        return None
    start = format_db_utc(require_utc_window_boundary(range_start, 'range_start'))
    end = format_db_utc(require_utc_window_boundary(boundary, 'boundary'))
    rows = _rows(db, 'SELECT * FROM packet_detection_gaps WHERE window_start=:start AND window_end=:end', {'start': start, 'end': end})
    if len(rows) != 1:
        return None
    evidence = validated_confirmed_gap_evidence(rows[0])
    if evidence is None:
        return None
    try:
        before = evidence['checkpoints_before']
        expected = sorted([dict(row, last_completed_window_end=end, updated_at=end) for row in before], key=lambda row: row['detector_name'])
        supplied = sorted([dict(row) for row in checkpoint_rows], key=lambda row: row['detector_name'])
        if _pair(db) != expected or supplied != expected:
            return None
        # No filesystem or live-session identity dependency: only the recorded
        # source loss, first healthy target input and checkpoint provenance bind.
        current = _candidate(db, start, boundary + timedelta(seconds=10), before)
        if current != evidence:
            return None
        return _transition(evidence)
    except (ValueError, TypeError, KeyError):
        return None
