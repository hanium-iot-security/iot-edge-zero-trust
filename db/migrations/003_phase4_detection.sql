ALTER TABLE detection_events ADD COLUMN dedupe_key TEXT;

ALTER TABLE detection_events ADD COLUMN policy_version TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_events_dedupe_key
    ON detection_events(dedupe_key)
    WHERE dedupe_key IS NOT NULL;

CREATE TABLE packet_capture_segments_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER NOT NULL,
    file_name TEXT UNIQUE,
    capture_interface TEXT NOT NULL,
    window_start DATETIME NOT NULL,
    window_end DATETIME NOT NULL,
    status TEXT NOT NULL DEFAULT 'READY'
        CHECK(status IN ('READY', 'PROCESSED', 'EMPTY', 'FAILED')),
    packet_count INTEGER CHECK(packet_count IS NULL OR packet_count >= 0),
    processed_at DATETIME,
    error_code TEXT,
    error_message TEXT,
    actual_capture_started_at DATETIME,
    capture_stop_requested_at DATETIME,
    capture_process_exited_at DATETIME,
    start_delay_seconds REAL
        CHECK(start_delay_seconds IS NULL OR start_delay_seconds >= 0),
    captured_duration_seconds REAL
        CHECK(
            captured_duration_seconds IS NULL
            OR captured_duration_seconds BETWEEN 0 AND 10
        ),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (capture_session_id)
        REFERENCES packet_capture_sessions(id)
        ON DELETE RESTRICT,
    UNIQUE(capture_interface, window_start, window_end),
    CHECK(
        window_start GLOB
            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
        AND window_end GLOB
            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
        AND unixepoch(window_start) IS NOT NULL
        AND unixepoch(window_end) IS NOT NULL
        AND unixepoch(window_end) - unixepoch(window_start) = 10
    ),
    CHECK(
        status = 'FAILED'
        OR file_name IS NOT NULL
    ),
    CHECK(
        error_code IS NULL
        OR error_code != 'LATE_CAPTURE'
        OR (
            status = 'FAILED'
            AND file_name IS NULL
            AND actual_capture_started_at IS NULL
            AND capture_stop_requested_at IS NULL
            AND capture_process_exited_at IS NULL
            AND captured_duration_seconds = 0
        )
    )
);

INSERT INTO packet_capture_segments_new (
    id,
    capture_session_id,
    file_name,
    capture_interface,
    window_start,
    window_end,
    status,
    packet_count,
    processed_at,
    error_code,
    error_message,
    created_at,
    updated_at
)
SELECT
    id,
    capture_session_id,
    file_name,
    capture_interface,
    window_start,
    window_end,
    status,
    packet_count,
    processed_at,
    error_code,
    error_message,
    created_at,
    updated_at
FROM packet_capture_segments;

DROP TABLE packet_capture_segments;

ALTER TABLE packet_capture_segments_new RENAME TO packet_capture_segments;

DELETE FROM sqlite_sequence
WHERE name = 'packet_capture_segments';

INSERT INTO sqlite_sequence(name, seq)
SELECT 'packet_capture_segments', COALESCE(MAX(id), 0)
FROM packet_capture_segments;

CREATE INDEX IF NOT EXISTS idx_packet_capture_segments_session_window
    ON packet_capture_segments(capture_session_id, window_start, window_end);

CREATE INDEX IF NOT EXISTS idx_packet_capture_segments_status
    ON packet_capture_segments(status);

ALTER TABLE isolation_history ADD COLUMN trust_score_history_id INTEGER
    REFERENCES trust_score_history(id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_isolation_history_trust_score_history_id
    ON isolation_history(trust_score_history_id)
    WHERE trust_score_history_id IS NOT NULL;

ALTER TABLE firewall_rules ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0
    CHECK(retry_count >= 0);

ALTER TABLE firewall_rules ADD COLUMN last_attempted_at DATETIME;

ALTER TABLE firewall_rules ADD COLUMN next_retry_at DATETIME;
