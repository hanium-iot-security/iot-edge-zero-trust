CREATE TABLE packet_detection_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_session_id TEXT NOT NULL REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
    target_session_id TEXT NOT NULL REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status = 'UNINSPECTED'),
    reason TEXT NOT NULL CHECK(reason IN ('RECORDED_CAPTURE_GAP', 'LATE_CAPTURE')),
    evidence_json TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(window_start, window_end),
    CHECK(unixepoch(window_start) IS NOT NULL AND unixepoch(window_end) > unixepoch(window_start))
);
CREATE TRIGGER packet_detection_gaps_no_update BEFORE UPDATE ON packet_detection_gaps
BEGIN SELECT RAISE(ABORT, 'packet detection gap audit is immutable'); END;
CREATE TRIGGER packet_detection_gaps_no_delete BEFORE DELETE ON packet_detection_gaps
BEGIN SELECT RAISE(ABORT, 'packet detection gap audit is immutable'); END;

-- Bound absence checks by the gap start while preserving mixed UTC text forms.
CREATE INDEX idx_packet_segments_gap_end
ON packet_capture_segments(unixepoch(window_end), unixepoch(window_start));
CREATE INDEX idx_packet_features_gap_end
ON packet_feature_logs(unixepoch(window_end), unixepoch(window_start));
