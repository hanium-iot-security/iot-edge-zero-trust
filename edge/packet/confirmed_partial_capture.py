"""Filesystem-first proof and read-only validation for confirmed partial captures.

016 records coverage loss; failed input never becomes eligible training input.
Only preparation opens files. Historical proofs survive ordinary file retention.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_window_boundary
from edge.packet.capture_policy import (
    CapturePolicy, CaptureEligibilitySegment, is_capture_eligible, compute_effective_capture_window,
)
from edge.packet.pcap_naming import build_pcap_filename

SESSION_FIELDS = ('id', 'session_id', 'capture_interface', 'started_at', 'first_window_start',
                  'capture_gap_start', 'capture_gap_end')
DIAGNOSTIC_FIELDS = ('schema_version', 'session_id', 'capture_interface', 'window_start', 'window_end',
                    'pcap_file_name', 'expected_pcap_file_name', 'success', 'error_code',
                    'file_validation_error', 'completed_full_window', 'terminated_cleanly', 'exit_code',
                    'stderr_complete', 'packets_captured', 'packets_received', 'packets_dropped',
                    'packets_dropped_by_interface', 'drop_status')
ERRORS = (ValueError, TypeError, KeyError, OSError, sqlite3.Error, SQLAlchemyError)


def rows(db, sql, params=None):
    if isinstance(db, sqlite3.Connection):
        cursor = db.execute(sql, params or {})
        return [dict(zip((item[0] for item in cursor.description), row)) for row in cursor]
    return [dict(row) for row in db.execute(text(sql), params or {}).mappings()]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _require(condition):
    if not condition:
        raise ValueError('Unconfirmed partial Capture evidence.')


def _window(value):
    parsed = require_utc_window_boundary(parse_db_utc(value), 'partial boundary')
    _require(format_db_utc(parsed) == value)
    return parsed


def _identity(path):
    value = path.lstat()
    _require(stat.S_ISREG(value.st_mode) and not path.is_symlink())
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def _file_proof(path, *, retain=False):
    before = _identity(path)
    flags = getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    value = hashlib.sha256()
    chunks = []
    with open(path, 'rb', opener=lambda name, mode: os.open(name, mode | flags)) as handle:
        current = os.fstat(handle.fileno())
        _require([current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns] == before)
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(chunk)
            if retain:
                chunks.append(chunk)
                _require(handle.tell() <= 1024 * 1024)
    _require(_identity(path) == before)
    return before, value.hexdigest(), b''.join(chunks) if retain else None


def _timing(segment):
    start, end = _window(segment['window_start']), _window(segment['window_end'])
    _require(end == start + timedelta(seconds=10))
    actual = parse_db_utc(segment['actual_capture_started_at'], allow_subseconds=True)
    stopped = parse_db_utc(segment['capture_stop_requested_at'], allow_subseconds=True)
    exited = parse_db_utc(segment['capture_process_exited_at'], allow_subseconds=True)
    delay, duration = segment['start_delay_seconds'], segment['captured_duration_seconds']
    _require(all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in (delay, duration)))
    _require(start <= actual <= stopped <= exited and delay >= 0 and 0 <= duration <= 10)
    _require(abs(delay - (actual-start).total_seconds()) <= 0.000002)
    _, _, expected = compute_effective_capture_window(window_start=start, window_end=end,
        actual_capture_started_at=actual, capture_stop_requested_at=stopped)
    _require(abs(duration - expected) <= 0.000002)
    return start, end


def _diagnostics(item, segment, source):
    start, end = _timing(segment)
    _require(item['schema_version'] == 'packet-capture-diagnostics-v1'
        and item['session_id'] == source['session_id'] and item['capture_interface'] == source['capture_interface']
        and parse_db_utc(item['window_start']) == start and parse_db_utc(item['window_end']) == end
        and item['pcap_file_name'] == item['expected_pcap_file_name'] == segment['file_name']
        and item['success'] is False and item['error_code'] == 'PARTIAL_CAPTURE'
        and item['file_validation_error'] is None and item['stderr_complete'] is True
        and isinstance(item['exit_code'], int) and not isinstance(item['exit_code'], bool))
    for key in ('packets_captured', 'packets_received', 'packets_dropped', 'packets_dropped_by_interface'):
        value = item[key]
        _require(value is None or (isinstance(value, int) and not isinstance(value, bool) and value >= 0))
    loss = any((item[key] or 0) > 0 for key in ('packets_dropped', 'packets_dropped_by_interface'))
    _require((loss and item['drop_status'] == 'observed_loss')
             or (item['completed_full_window'] is False and segment['captured_duration_seconds'] < 10))
    _require(isinstance(item['completed_full_window'], bool) and isinstance(item['terminated_cleanly'], bool))


def _healthy(db, segment, policy):
    start, end = _timing(segment)
    _require(segment['error_message'] is None and segment['file_name'])
    _require(is_capture_eligible(CaptureEligibilitySegment(segment['status'], segment['error_code'],
        segment['start_delay_seconds'], segment['captured_duration_seconds']), policy).eligible)
    features = rows(db, 'SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id', {'id':segment['id']})
    _require((segment['status'] == 'EMPTY' and not features) or (segment['status'] == 'PROCESSED' and bool(features)))
    _require(all(item['window_start'] == segment['window_start'] and item['window_end'] == segment['window_end'] for item in features))
    _unobstructed(db, start, end, [segment], features_allowed=features, require_no_features=False)
    return features


def _unobstructed(db, start, end, failed, *, features_allowed=(), require_no_features=True):
    """Indexed broad bound, then exact Python comparison (SQLite rounds fractions)."""
    params = {'start':format_db_utc(start), 'end':format_db_utc(end)}
    # Migration003 enforces ten-second Segment/Feature windows. Keep a full
    # extra second around SQLite's fractional rounding, without scanning every
    # later window through the leading window_end expression index.
    overlap = ('unixepoch(window_end)>=unixepoch(:start)-1 '
               'AND unixepoch(window_end)<=unixepoch(:end)+11 '
               'AND unixepoch(window_start)<=unixepoch(:end)+1')
    allowed = {item['id'] for item in failed}
    allowed_features = {item['id'] for item in features_allowed}
    for table in ('packet_capture_segments', 'packet_feature_logs'):
        candidates = rows(db, f'SELECT * FROM {table} WHERE {overlap}', params)
        for item in candidates:
            a = parse_db_utc(item['window_start'], allow_subseconds=True)
            b = parse_db_utc(item['window_end'], allow_subseconds=True)
            if a < end and b > start:
                _require((table == 'packet_capture_segments' and item['id'] in allowed)
                         or (table == 'packet_feature_logs' and item['id'] in allowed_features))
    if require_no_features:
        for item in failed:
            _require(not rows(db, 'SELECT id FROM packet_feature_logs WHERE capture_segment_id=:id LIMIT 1', {'id':item['id']}))


def _candidate_rows(db, start, cutoff):
    first = rows(db, "SELECT * FROM packet_capture_segments WHERE unixepoch(window_end) "
        "BETWEEN unixepoch(:start)+9 AND unixepoch(:start)+11 "
        "AND window_start=:start AND status='FAILED' AND error_code='PARTIAL_CAPTURE'", {'start':start})
    if len(first) != 1:
        return None
    source = rows(db, 'SELECT * FROM packet_capture_sessions WHERE id=:id', {'id':first[0]['capture_session_id']})
    _require(len(source) == 1 and source[0]['status'] in ('RUNNING', 'FAILED', 'COMPLETED'))
    source = source[0]
    _require(source['first_window_start'] is not None and _window(source['first_window_start']) <= _window(start))
    # The source's existing session/window index finds the first non-partial
    # successor. Read the complete global bounded interval once so duplicate
    # windows in another Session/interface remain visible while walking it.
    target = rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id "
        "AND window_start>=:start AND NOT (status='FAILED' AND error_code='PARTIAL_CAPTURE') "
        "ORDER BY window_start,id LIMIT 1", {'id':source['id'], 'start':start})
    _require(len(target) == 1 and _window(target[0]['window_end']) <= cutoff)
    bounded = rows(db, 'SELECT * FROM packet_capture_segments WHERE unixepoch(window_end) '
        'BETWEEN unixepoch(:start)-1 AND unixepoch(:end)+11 AND window_start<=:end',
        {'start':start, 'end':target[0]['window_start']})
    by_start = {}
    for item in bounded:
        by_start.setdefault(item['window_start'], []).append(item)
    failed, current, boundary = [], first[0], _window(start)
    while current['status'] == 'FAILED' and current['error_code'] == 'PARTIAL_CAPTURE':
        _require(current['capture_session_id'] == source['id'] and current['capture_interface'] == source['capture_interface'])
        a, b = _timing(current)
        _require(a == boundary)
        failed.append(current)
        boundary = b
        following = by_start.get(format_db_utc(boundary), [])
        _require(len(following) == 1)
        current = following[0]
    _require(current['capture_session_id'] == source['id'] and current['capture_interface'] == source['capture_interface']
             and _window(current['window_end']) <= cutoff)
    _unobstructed(db, _window(start), boundary, failed)
    return source, failed, current


def prepare_partial_capture(db, start, cutoff, checkpoints):
    """Hash closed failed files before the caller acquires SQLite's writer."""
    try:
        found = _candidate_rows(db, start, cutoff)
        if found is None:
            return None
        source, failed, healthy = found
        # A caller holding an earlier write transaction must not hash files
        # while Capture/Subscriber are blocked. Runtime calls this after reads.
        _require(not db.connection().connection.driver_connection.in_transaction)
        from backend.app.config import settings
        from edge.packet.capture_runtime import _pcap_file_error
        policy = CapturePolicy.from_env()
        features = _healthy(db, healthy, policy)
        directory = Path(settings.pcap_failed_dir).resolve()
        entries = []
        for segment in failed:
            expected = build_pcap_filename(session_id=source['session_id'], interface=source['capture_interface'],
                window_start=_window(segment['window_start']), window_end=_window(segment['window_end']), tmp=False)
            _require(segment['file_name'] == expected)
            path = directory / expected
            sidecar = path.with_suffix('.pcap.capture.json')
            _require(_identity(sidecar)[2] <= 1024 * 1024)
            diagnostic_identity, diagnostic_sha, content = _file_proof(sidecar, retain=True)
            raw = json.loads(content)
            metadata = {key:raw[key] for key in DIAGNOSTIC_FIELDS}
            _require(_identity(sidecar) == diagnostic_identity)
            _diagnostics(metadata, segment, source)
            identity, sha, _ = _file_proof(path)
            _require(_pcap_file_error(path) is None and _identity(path) == identity)
            entries.append({'segment':segment, 'pcap_path':str(path), 'pcap_identity':identity, 'pcap_sha256':sha,
                'diagnostics_path':str(sidecar), 'diagnostics_identity':diagnostic_identity,
                'diagnostics_sha256':diagnostic_sha, 'diagnostics':metadata})
        return {'version':2, 'status':'UNINSPECTED', 'reason':'RECORDED_CAPTURE_GAP', 'loss_kind':'PARTIAL_CAPTURE',
            'window_start':start, 'window_end':failed[-1]['window_end'],
            'source':{key:source[key] for key in SESSION_FIELDS}, 'target':{key:source[key] for key in SESSION_FIELDS},
            'failed_segments':entries, 'target_first_segment':healthy,
            'target_features_sha256':digest(features), 'target_feature_count':len(features),
            'capture_policy':asdict(policy), 'checkpoints_before':checkpoints}
    except ERRORS:
        return None


def validate_partial_evidence(db, audit, *, verify_files=False):
    """No CP/lifecycle/filesystem dependency unless explicitly preparing a write."""
    try:
        evidence = json.loads(audit['evidence_json'])
        _require(evidence['version'] == 2 and evidence['loss_kind'] == 'PARTIAL_CAPTURE'
            and evidence['status'] == audit['status'] == 'UNINSPECTED'
            and evidence['reason'] == audit['reason'] == 'RECORDED_CAPTURE_GAP'
            and digest(evidence) == audit['plan_sha256']
            and evidence['window_start'] == audit['window_start'] and evidence['window_end'] == audit['window_end']
            and evidence['source'] == evidence['target']
            and evidence['source']['session_id'] == audit['source_session_id'] == audit['target_session_id'])
        source = rows(db, 'SELECT * FROM packet_capture_sessions WHERE session_id=:id', {'id':audit['source_session_id']})
        _require(len(source) == 1 and {key:source[0][key] for key in SESSION_FIELDS} == evidence['source'])
        pair = evidence['checkpoints_before']
        _require(len(pair) == 2 and {item['detector_name'] for item in pair} == {'packet_rule', 'packet_if'}
            and all(set(item) == {'detector_name', 'source_table', 'last_processed_id',
                                 'last_completed_window_end', 'updated_at'}
                and item['source_table'] == 'packet_feature_logs'
                and item['last_completed_window_end'] == evidence['window_start']
                and isinstance(item['updated_at'], str)
                and (item['last_processed_id'] is None or (isinstance(item['last_processed_id'], int)
                    and not isinstance(item['last_processed_id'], bool) and item['last_processed_id'] >= 0))
                for item in pair))
        boundary, finish = _window(evidence['window_start']), _window(evidence['window_end'])
        failed = []
        _require(bool(evidence['failed_segments']))
        for entry in evidence['failed_segments']:
            segment = rows(db, 'SELECT * FROM packet_capture_segments WHERE id=:id', {'id':entry['segment']['id']})
            _require(len(segment) == 1 and segment[0] == entry['segment'])
            segment = segment[0]
            _require(segment['capture_session_id'] == source[0]['id'] and segment['capture_interface'] == source[0]['capture_interface']
                and segment['status'] == 'FAILED' and segment['error_code'] == 'PARTIAL_CAPTURE')
            a, b = _timing(segment)
            _require(a == boundary)
            boundary = b
            _diagnostics(entry['diagnostics'], segment, source[0])
            for key in ('pcap_sha256', 'diagnostics_sha256'):
                _require(isinstance(entry[key], str) and len(entry[key]) == 64 and all(c in '0123456789abcdef' for c in entry[key]))
            if verify_files:
                _require(_identity(Path(entry['pcap_path'])) == entry['pcap_identity']
                    and _identity(Path(entry['diagnostics_path'])) == entry['diagnostics_identity'])
            failed.append(segment)
        _require(boundary == finish)
        _unobstructed(db, _window(evidence['window_start']), finish, failed)
        healthy = rows(db, 'SELECT * FROM packet_capture_segments WHERE id=:id', {'id':evidence['target_first_segment']['id']})
        _require(len(healthy) == 1 and healthy[0] == evidence['target_first_segment']
            and healthy[0]['capture_session_id'] == source[0]['id'] and healthy[0]['capture_interface'] == source[0]['capture_interface']
            and healthy[0]['window_start'] == evidence['window_end'])
        features = _healthy(db, healthy[0], CapturePolicy(**evidence['capture_policy']))
        _require(digest(features) == evidence['target_features_sha256'] and len(features) == evidence['target_feature_count'])
        return evidence
    except ERRORS:
        return None


def approved_partial_capture_gaps(db, segments):
    """Fresh batch proofs in request order; validate each complete016 audit once.

    Nothing is cached across calls/transactions. Every requested raw row must
    still match its sealed member and have exactly one valid covering audit.
    """
    segments = list(segments)
    results = [None] * len(segments)
    if not segments:
        return results
    try:
        if not rows(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='packet_detection_gaps'"):
            return results
        first = min(_window(item['window_start']) for item in segments)
        last = max(_window(item['window_end']) for item in segments)
        candidates = rows(db, 'SELECT * FROM packet_detection_gaps WHERE source_session_id=target_session_id '
            'AND window_start<:end AND window_end>:start', {'start':format_db_utc(first), 'end':format_db_utc(last)})
        members = {}
        for audit in candidates:
            evidence = validate_partial_evidence(db, audit)
            if evidence is None:
                continue
            for entry in evidence['failed_segments']:
                members.setdefault(entry['segment']['id'], []).append((audit, entry))
        for index, segment in enumerate(segments):
            valid = members.get(segment['id'], [])
            if len(valid) == 1:
                audit, entry = valid[0]
                if not all(entry['segment'].get(key) == value for key, value in dict(segment).items()
                           if key in entry['segment']):
                    continue
                results[index] = {**audit, 'loss_kind':'PARTIAL_CAPTURE', 'pcap_sha256':entry['pcap_sha256'],
                    'diagnostics_sha256':entry['diagnostics_sha256'], 'evidence_sha256':audit['plan_sha256']}
        return results
    except ERRORS:
        return [None] * len(segments)


def approved_partial_capture_gap(db, segment):
    """Return the actual immutable016 audit plus typed per-segment SHA evidence."""
    return approved_partial_capture_gaps(db, [segment])[0]
