-- Runtime evidence is additive. Writers use the detector transaction; this migration seeds nothing.
CREATE TABLE ai_runtime_snapshot (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json))
);

CREATE TABLE ai_device_completions (
    detector_name TEXT NOT NULL CHECK (detector_name IN ('mqtt_if', 'packet_if')),
    device_key TEXT NOT NULL,
    completed_window_end TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    PRIMARY KEY (detector_name, device_key)
);
CREATE INDEX idx_ai_completions_device ON ai_device_completions(device_key, detector_name);

CREATE TABLE ai_warning_keys (
    warning_key TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL CHECK (
        json_valid(policy_json)
        AND json_type(policy_json, '$.version') IS 'text'
        AND json_type(policy_json, '$.window_seconds') IS 'integer'
        AND json_extract(policy_json, '$.window_seconds') >= 10
        AND json_extract(policy_json, '$.window_seconds') % 10 = 0
        AND json_type(policy_json, '$.count_threshold') IS 'integer'
        AND json_extract(policy_json, '$.count_threshold') >= 1
        AND json_type(policy_json, '$.cooldown_seconds') IS 'integer'
        AND json_extract(policy_json, '$.cooldown_seconds') >= 0
    ),
    latest_bucket TEXT,
    last_notification TEXT
);
CREATE TABLE ai_warning_aggregates (
    id INTEGER PRIMARY KEY,
    warning_key TEXT NOT NULL REFERENCES ai_warning_keys(warning_key),
    device_id TEXT NOT NULL,
    detector_name TEXT NOT NULL CHECK (detector_name IN ('mqtt_if', 'packet_if')),
    event_type TEXT NOT NULL CHECK (event_type IN ('AI_ANOMALY', 'AI_PACKET_ANOMALY')),
    model_version TEXT NOT NULL,
    warning_policy_version TEXT NOT NULL,
    bucket_start TEXT NOT NULL,
    bucket_end TEXT NOT NULL CHECK (bucket_end > bucket_start),
    count INTEGER NOT NULL CHECK (typeof(count) = 'integer' AND count >= 0),
    first_window TEXT,
    latest_window TEXT,
    notified_at TEXT,
    suppressed_count INTEGER NOT NULL CHECK (typeof(suppressed_count) = 'integer' AND suppressed_count >= 0),
    closed INTEGER NOT NULL CHECK (closed IN (0, 1)),
    last_decision TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (warning_key, bucket_start)
);
CREATE INDEX idx_ai_warning_bucket ON ai_warning_aggregates(bucket_start, bucket_end, id);
CREATE INDEX idx_ai_warning_device_bucket ON ai_warning_aggregates(device_id, bucket_start, bucket_end, id);
CREATE INDEX idx_ai_warning_open ON ai_warning_aggregates(detector_name, device_id, bucket_start)
    WHERE closed = 0;
CREATE TABLE ai_warning_events (
    aggregate_id INTEGER NOT NULL REFERENCES ai_warning_aggregates(id),
    event_id INTEGER NOT NULL REFERENCES detection_events(id),
    window_start TEXT NOT NULL,
    PRIMARY KEY (aggregate_id, event_id)
);
-- Bound the event lookup used by a completion sink to one device and source Window.
CREATE INDEX idx_detection_events_ai_window
    ON detection_events(device_id, analysis_window_start, analysis_window_end, event_type)
    WHERE detector_type = 'AI';
