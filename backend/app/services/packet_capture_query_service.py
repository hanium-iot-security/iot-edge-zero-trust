"""Bounded capture observations; absent records never imply zero traffic."""

from datetime import datetime, timedelta, timezone

from backend.app.services.device_policy_service import _connection
from backend.app.services.feature_log_query_service import _normalize_optional_utc
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible
from edge.packet.pcap_naming import format_utc_iso


MAX_CAPTURE_RANGE = timedelta(hours=1)
MAX_CAPTURE_WINDOWS = 360


class CaptureSessionNotFound(ValueError):
    pass


class CaptureMetadataUnavailable(RuntimeError):
    pass


def list_capture_windows(db, *, session_id: str, from_at: datetime, to_at: datetime) -> dict:
    start = _normalize_optional_utc(from_at, "from")
    end = _normalize_optional_utc(to_at, "to")
    if start is None or end is None:
        raise ValueError("from and to are required")
    if any(value.microsecond or value.second % 10 for value in (start, end)):
        raise ValueError("from and to must be UTC 10-second boundaries")
    if not timedelta(0) <= end - start <= MAX_CAPTURE_RANGE:
        raise ValueError("capture range must be ordered and at most one hour")
    start_text, end_text = format_utc_iso(start), format_utc_iso(end)
    expected = {format_utc_iso(start + timedelta(seconds=offset))
                for offset in range(0, int((end - start).total_seconds()), 10)}
    with _connection(db, read=True) as connection:
        cursor = connection.execute("""SELECT id, status, first_window_start, ended_at
            FROM packet_capture_sessions WHERE session_id=?""", (session_id,))
        session = cursor.fetchone()
        if session is None:
            raise CaptureSessionNotFound("capture session not found")
        observed_at = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute("""SELECT s.id, s.window_start, s.window_end,
            s.status, s.error_code, s.packet_count,
            s.start_delay_seconds, s.captured_duration_seconds,
            (SELECT COUNT(*) FROM packet_feature_logs f
             WHERE f.capture_segment_id=s.id) AS feature_row_count
            FROM packet_capture_segments s
            WHERE s.capture_session_id=? AND s.window_start>=? AND s.window_end<=?
            ORDER BY s.window_start, s.id LIMIT ?""",
            (session[0], start_text, end_text, MAX_CAPTURE_WINDOWS + 1))
        names = [column[0] for column in cursor.description]
        rows = {}
        for row in cursor.fetchall():
            if row[1] not in expected or row[1] in rows:
                raise CaptureMetadataUnavailable("capture windows are inconsistent")
            rows[row[1]] = dict(zip(names, row))

    policy = CapturePolicy.from_env()
    items = []
    current = start
    while current < end:
        window_start, window_end = format_utc_iso(current), format_utc_iso(current + timedelta(seconds=10))
        row = rows.get(window_start)
        eligibility = (is_capture_eligible(CaptureEligibilitySegment(
            status=row["status"], error_code=row["error_code"],
            start_delay_seconds=row["start_delay_seconds"],
            captured_duration_seconds=row["captured_duration_seconds"],
        ), policy) if row is not None else None)
        items.append({
            "window_start": window_start, "window_end": window_end,
            "segment_id": row["id"] if row else None,
            "segment_status": row["status"] if row else None,
            "observation": ("PENDING" if row["status"] == "READY" else row["status"]) if row else "MISSING",
            "segment_error_code": row["error_code"] if row else None,
            "packet_count": row["packet_count"] if row else None,
            "feature_row_count": row["feature_row_count"] if row else None,
            "start_delay_seconds": row["start_delay_seconds"] if row else None,
            "captured_duration_seconds": row["captured_duration_seconds"] if row else None,
            "capture_eligible": eligibility.eligible if eligibility else None,
            "capture_exclusion_reason": eligibility.exclusion_reason if eligibility else None,
        })
        current += timedelta(seconds=10)
    return {"session_id": session_id, "session_status": session[1],
            "first_window_start": session[2], "ended_at": session[3],
            "observed_at": observed_at, "from": start_text, "to": end_text,
            "items": items, "total": len(items)}
