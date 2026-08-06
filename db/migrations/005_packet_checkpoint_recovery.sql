CREATE TABLE packet_checkpoint_recoveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    detector_name TEXT NOT NULL CHECK (detector_name IN ('packet_rule', 'packet_if')),
    source_table TEXT NOT NULL CHECK (source_table = 'packet_feature_logs'),
    current_capture_session_id TEXT NOT NULL,
    target_capture_session_id TEXT NOT NULL,
    last_processed_id_before INTEGER,
    last_processed_id_after INTEGER,
    last_completed_window_end_before TEXT NOT NULL,
    last_completed_window_end_after TEXT NOT NULL,
    updated_at_before TEXT NOT NULL,
    updated_at_after TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256) = 64),
    plan_json TEXT NOT NULL,
    skipped_session_count INTEGER NOT NULL CHECK (skipped_session_count >= 0),
    skipped_processable_session_count INTEGER NOT NULL CHECK (skipped_processable_session_count >= 0),
    approved_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    repository_commit TEXT NOT NULL CHECK (length(repository_commit) = 40),
    database_path TEXT NOT NULL,
    backup_path TEXT NOT NULL,
    backup_sha256 TEXT NOT NULL CHECK (length(backup_sha256) = 64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (last_processed_id_before IS last_processed_id_after),
    FOREIGN KEY (detector_name, source_table)
        REFERENCES detector_checkpoints(detector_name, source_table) ON DELETE RESTRICT,
    FOREIGN KEY (current_capture_session_id)
        REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_capture_session_id)
        REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX uq_packet_checkpoint_recovery_detector_target
    ON packet_checkpoint_recoveries(
        detector_name, source_table, target_capture_session_id
    );
