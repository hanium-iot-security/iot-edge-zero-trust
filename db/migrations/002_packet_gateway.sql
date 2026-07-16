CREATE TABLE IF NOT EXISTS packet_capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE
        CHECK(
            length(session_id) = 36
            AND substr(session_id, 9, 1) = '-'
            AND substr(session_id, 14, 1) = '-'
            AND substr(session_id, 19, 1) = '-'
            AND substr(session_id, 24, 1) = '-'
            AND substr(session_id, 1, 8) NOT GLOB '*[^0-9A-Fa-f]*'
            AND substr(session_id, 10, 4) NOT GLOB '*[^0-9A-Fa-f]*'
            AND substr(session_id, 15, 4) NOT GLOB '*[^0-9A-Fa-f]*'
            AND substr(session_id, 20, 4) NOT GLOB '*[^0-9A-Fa-f]*'
            AND substr(session_id, 25, 12) NOT GLOB '*[^0-9A-Fa-f]*'
            AND substr(session_id, 15, 1) = '4'
            AND lower(substr(session_id, 20, 1)) IN ('8', '9', 'a', 'b')
        ),
    capture_interface TEXT NOT NULL,
    started_at DATETIME NOT NULL,
    first_window_start DATETIME,
    ended_at DATETIME,
    capture_gap_start DATETIME,
    capture_gap_end DATETIME,
    status TEXT NOT NULL DEFAULT 'RUNNING'
        CHECK(status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS packet_capture_segments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER NOT NULL,
    file_name TEXT NOT NULL UNIQUE,
    capture_interface TEXT NOT NULL,
    window_start DATETIME NOT NULL,
    window_end DATETIME NOT NULL,
    status TEXT NOT NULL DEFAULT 'READY'
        CHECK(status IN ('READY', 'PROCESSED', 'EMPTY', 'FAILED')),
    packet_count INTEGER CHECK(packet_count IS NULL OR packet_count >= 0),
    processed_at DATETIME,
    error_code TEXT,
    error_message TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (capture_session_id)
        REFERENCES packet_capture_sessions(id)
        ON DELETE RESTRICT,
    UNIQUE(capture_interface, window_start, window_end),
    CHECK(
        unixepoch(window_start) IS NOT NULL
        AND unixepoch(window_end) IS NOT NULL
        AND unixepoch(window_end) - unixepoch(window_start) = 10
    )
);

CREATE TABLE IF NOT EXISTS packet_feature_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_segment_id INTEGER NOT NULL,
    device_id TEXT,
    peer_ip TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('INBOUND', 'OUTBOUND')),
    window_start DATETIME NOT NULL,
    window_end DATETIME NOT NULL,
    packet_count INTEGER NOT NULL CHECK(packet_count >= 0),
    total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0),
    avg_packet_size REAL NOT NULL CHECK(avg_packet_size >= 0),
    max_packet_size INTEGER NOT NULL CHECK(max_packet_size >= 0),
    mean_inter_arrival_time REAL NOT NULL DEFAULT 0.0
        CHECK(mean_inter_arrival_time >= 0),
    distinct_dest_port_count INTEGER NOT NULL DEFAULT 0
        CHECK(distinct_dest_port_count >= 0),
    tcp_syn_count INTEGER NOT NULL DEFAULT 0 CHECK(tcp_syn_count >= 0),
    mqtt_related_packet_count INTEGER NOT NULL DEFAULT 0
        CHECK(mqtt_related_packet_count >= 0),
    non_mqtt_tcp_udp_packet_count INTEGER NOT NULL DEFAULT 0
        CHECK(non_mqtt_tcp_udp_packet_count >= 0),
    capture_scope TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (capture_segment_id)
        REFERENCES packet_capture_segments(id)
        ON DELETE RESTRICT,
    UNIQUE(capture_segment_id, peer_ip, direction),
    CHECK(
        unixepoch(window_start) IS NOT NULL
        AND unixepoch(window_end) IS NOT NULL
        AND unixepoch(window_end) - unixepoch(window_start) = 10
    )
);

CREATE TABLE IF NOT EXISTS gateway_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at DATETIME NOT NULL,
    sample_interval_seconds REAL
        CHECK(
            sample_interval_seconds IS NULL
            OR sample_interval_seconds >= 0
        ),
    cpu_percent REAL
        CHECK(cpu_percent IS NULL OR cpu_percent BETWEEN 0 AND 100),
    memory_percent REAL NOT NULL CHECK(memory_percent BETWEEN 0 AND 100),
    disk_percent REAL NOT NULL CHECK(disk_percent BETWEEN 0 AND 100),
    disk_used_mb REAL CHECK(disk_used_mb IS NULL OR disk_used_mb >= 0),
    network_rx_bytes INTEGER
        CHECK(network_rx_bytes IS NULL OR network_rx_bytes >= 0),
    network_tx_bytes INTEGER
        CHECK(network_tx_bytes IS NULL OR network_tx_bytes >= 0),
    temperature_c REAL,
    interface_metrics_json TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detector_checkpoints (
    detector_name TEXT NOT NULL,
    source_table TEXT NOT NULL,
    last_processed_id INTEGER,
    last_completed_window_end DATETIME,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (detector_name, source_table)
);

CREATE TABLE IF NOT EXISTS trust_score_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    analysis_window_start DATETIME NOT NULL,
    analysis_window_end DATETIME NOT NULL,
    previous_score INTEGER NOT NULL CHECK(previous_score BETWEEN 0 AND 100),
    calculated_delta INTEGER NOT NULL,
    capped_delta INTEGER NOT NULL,
    actual_delta INTEGER NOT NULL,
    new_score INTEGER NOT NULL CHECK(new_score BETWEEN 0 AND 100),
    representative_event_ids_json TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id)
        REFERENCES devices(device_id)
        ON DELETE RESTRICT,
    UNIQUE(device_id, analysis_window_start, analysis_window_end),
    CHECK(analysis_window_end > analysis_window_start)
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    source_ip TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK(protocol = 'tcp'),
    dest_port INTEGER NOT NULL DEFAULT 1883 CHECK(dest_port = 1883),
    action TEXT NOT NULL DEFAULT 'DROP' CHECK(action = 'DROP'),
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(status IN ('PENDING', 'APPLIED', 'FAILED', 'REMOVED')),
    reason TEXT,
    trigger_event_id INTEGER,
    applied_at DATETIME,
    released_at DATETIME,
    last_error TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id)
        REFERENCES devices(device_id)
        ON DELETE SET NULL,
    FOREIGN KEY (trigger_event_id)
        REFERENCES detection_events(id)
        ON DELETE SET NULL
);

ALTER TABLE detection_events ADD COLUMN packet_feature_log_id INTEGER
    REFERENCES packet_feature_logs(id);

ALTER TABLE detection_events ADD COLUMN analysis_window_start DATETIME;

ALTER TABLE detection_events ADD COLUMN analysis_window_end DATETIME;

ALTER TABLE detection_events ADD COLUMN incident_family TEXT;

ALTER TABLE detection_events ADD COLUMN subject_ip TEXT;

ALTER TABLE detection_events ADD COLUMN evidence_json TEXT;

ALTER TABLE detection_events ADD COLUMN evidence_schema_version INTEGER;

ALTER TABLE detection_events ADD COLUMN processed_at DATETIME;

ALTER TABLE detection_events ADD COLUMN processing_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_packet_capture_sessions_status
    ON packet_capture_sessions(status);

CREATE INDEX IF NOT EXISTS idx_packet_capture_segments_session_window
    ON packet_capture_segments(capture_session_id, window_start, window_end);

CREATE INDEX IF NOT EXISTS idx_packet_capture_segments_status
    ON packet_capture_segments(status);

CREATE INDEX IF NOT EXISTS idx_packet_feature_logs_device_window
    ON packet_feature_logs(device_id, window_start, window_end);

CREATE INDEX IF NOT EXISTS idx_packet_feature_logs_peer_window
    ON packet_feature_logs(peer_ip, window_start, window_end);

CREATE INDEX IF NOT EXISTS idx_gateway_metrics_collected_at
    ON gateway_metrics(collected_at);

CREATE INDEX IF NOT EXISTS idx_detection_events_packet_feature_log_id
    ON detection_events(packet_feature_log_id);

CREATE INDEX IF NOT EXISTS idx_detection_events_incident_family_detected_at
    ON detection_events(incident_family, detected_at);

CREATE INDEX IF NOT EXISTS idx_detection_events_subject_ip_detected_at
    ON detection_events(subject_ip, detected_at);

CREATE INDEX IF NOT EXISTS idx_trust_score_history_window
    ON trust_score_history(analysis_window_start, analysis_window_end);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_status
    ON firewall_rules(status);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_source_ip
    ON firewall_rules(source_ip);

CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_rules_active_unique
    ON firewall_rules(source_ip, protocol, dest_port)
    WHERE status IN ('PENDING', 'APPLIED');
