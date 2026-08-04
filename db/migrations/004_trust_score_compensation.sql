CREATE TABLE trust_score_compensations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE
        CHECK(length(trim(operation_id)) > 0),
    device_id TEXT NOT NULL,
    source_event_id INTEGER NOT NULL UNIQUE,
    source_trust_history_id INTEGER NOT NULL UNIQUE,
    previous_score INTEGER NOT NULL
        CHECK(previous_score BETWEEN 0 AND 100),
    compensation_delta INTEGER NOT NULL
        CHECK(compensation_delta > 0),
    new_score INTEGER NOT NULL
        CHECK(new_score BETWEEN 0 AND 100),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    approved_by TEXT NOT NULL CHECK(length(trim(approved_by)) > 0),
    backup_path TEXT NOT NULL CHECK(length(trim(backup_path)) > 0),
    backup_sha256 TEXT NOT NULL
        CHECK(
            length(backup_sha256) = 64
            AND backup_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id)
        REFERENCES devices(device_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (source_event_id)
        REFERENCES detection_events(id)
        ON DELETE RESTRICT,
    FOREIGN KEY (source_trust_history_id)
        REFERENCES trust_score_history(id)
        ON DELETE RESTRICT,
    CHECK(new_score = previous_score + compensation_delta)
);
