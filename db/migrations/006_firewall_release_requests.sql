CREATE TABLE firewall_release_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firewall_rule_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCEEDED', 'FAILED')),
    requested_by TEXT NOT NULL CHECK (length(trim(requested_by)) > 0),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    requested_at TEXT NOT NULL,
    processed_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (status != 'PENDING' OR processed_at IS NULL),
    CHECK (status != 'PENDING' OR last_error IS NULL),
    CHECK (status = 'PENDING' OR processed_at IS NOT NULL),
    CHECK (status != 'FAILED' OR length(trim(coalesce(last_error, ''))) > 0),
    CHECK (status != 'SUCCEEDED' OR last_error IS NULL),
    FOREIGN KEY (firewall_rule_id)
        REFERENCES firewall_rules(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX uq_firewall_release_requests_pending_rule
    ON firewall_release_requests(firewall_rule_id)
    WHERE status = 'PENDING';

CREATE INDEX idx_firewall_release_requests_status_requested
    ON firewall_release_requests(status, requested_at, id);
