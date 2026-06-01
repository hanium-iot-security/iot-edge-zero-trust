PRAGMA journal_mode=WAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    ip_address TEXT,
    status TEXT NOT NULL DEFAULT 'normal',
    trust_score INTEGER NOT NULL DEFAULT 100,
    last_seen_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mqtt_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    topic TEXT NOT NULL,
    payload TEXT,
    payload_size INTEGER,
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_json_valid INTEGER NOT NULL DEFAULT 0,
    is_topic_valid INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS feature_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    window_start DATETIME NOT NULL,
    window_end DATETIME NOT NULL,
    publish_count INTEGER NOT NULL DEFAULT 0,
    avg_payload_size REAL,
    max_payload_size INTEGER,
    avg_message_interval REAL,
    min_message_interval REAL,
    topic_count INTEGER NOT NULL DEFAULT 0,
    abnormal_topic_count INTEGER NOT NULL DEFAULT 0,
    malformed_payload_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(device_id, window_start, window_end)
);

CREATE TABLE IF NOT EXISTS detection_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    feature_log_id INTEGER,
    mqtt_log_id INTEGER,
    detector_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    score_delta INTEGER NOT NULL DEFAULT 0,
    applied_to_score INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS isolation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'ISOLATED',
    reason TEXT,
    trust_score INTEGER,
    trigger_event_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
