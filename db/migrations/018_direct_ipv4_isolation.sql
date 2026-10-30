-- Keep historical MQTT parents, escalated children, and release references intact.
CREATE TABLE firewall_sequence_018 (seq INTEGER NOT NULL);
INSERT INTO firewall_sequence_018(seq)
    SELECT seq FROM sqlite_sequence WHERE name = 'firewall_rules';

CREATE TABLE firewall_rules_018 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    source_ip TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'MQTT_IPV4_TCP_1883'
        CHECK(scope IN ('MQTT_IPV4_TCP_1883', 'PI_INPUT_IPV4_ALL')),
    protocol TEXT DEFAULT 'tcp',
    dest_port INTEGER DEFAULT 1883,
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
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count >= 0),
    last_attempted_at DATETIME,
    next_retry_at DATETIME,
    source_rule_id INTEGER,
    approved_policy_revision INTEGER,
    requested_by TEXT,
    request_id TEXT UNIQUE,
    CHECK (
        (scope = 'MQTT_IPV4_TCP_1883' AND protocol IS NOT NULL AND protocol = 'tcp'
         AND dest_port IS NOT NULL AND dest_port = 1883
         AND source_rule_id IS NULL AND approved_policy_revision IS NULL AND request_id IS NULL)
        OR
        (scope = 'PI_INPUT_IPV4_ALL' AND protocol IS NULL AND dest_port IS NULL
         AND source_rule_id IS NOT NULL AND source_rule_id > 0
         AND approved_policy_revision IS NOT NULL AND approved_policy_revision > 0
         AND request_id IS NOT NULL AND length(request_id) = 36
         AND substr(request_id, 9, 1) = '-' AND substr(request_id, 14, 1) = '-'
         AND substr(request_id, 19, 1) = '-' AND substr(request_id, 24, 1) = '-'
         AND substr(request_id, 15, 1) = '4' AND substr(request_id, 20, 1) IN ('8', '9', 'a', 'b')
         AND length(replace(request_id, '-', '')) = 32
         AND replace(request_id, '-', '') NOT GLOB '*[^0-9a-f]*'
         AND length(trim(coalesce(requested_by, ''))) > 0
         AND length(trim(coalesce(reason, ''))) > 0)
        OR
        (scope = 'PI_INPUT_IPV4_ALL' AND protocol IS NULL AND dest_port IS NULL
         AND source_rule_id IS NULL
         AND device_id IS NOT NULL
         AND trigger_event_id IS NOT NULL AND typeof(trigger_event_id) = 'integer'
         AND trigger_event_id > 0
         AND requested_by IS NOT NULL AND requested_by = 'system:trust-score-v2'
         AND approved_policy_revision IS NOT NULL AND typeof(approved_policy_revision) = 'integer'
         AND approved_policy_revision > 0
         AND request_id IS NOT NULL AND length(request_id) = 36
         AND substr(request_id, 9, 1) = '-' AND substr(request_id, 14, 1) = '-'
         AND substr(request_id, 19, 1) = '-' AND substr(request_id, 24, 1) = '-'
         AND substr(request_id, 15, 1) = '4' AND substr(request_id, 20, 1) IN ('8', '9', 'a', 'b')
         AND length(replace(request_id, '-', '')) = 32
         AND replace(request_id, '-', '') NOT GLOB '*[^0-9a-f]*'
         AND length(trim(coalesce(requested_by, ''))) > 0
         AND length(trim(coalesce(reason, ''))) > 0)
    ),
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE SET NULL,
    FOREIGN KEY(trigger_event_id) REFERENCES detection_events(id) ON DELETE SET NULL,
    FOREIGN KEY(source_rule_id) REFERENCES firewall_rules(id) ON DELETE RESTRICT
);

INSERT INTO firewall_rules_018 (
    id, device_id, source_ip, scope, protocol, dest_port, action, status, reason,
    trigger_event_id, applied_at, released_at, last_error, created_at, updated_at,
    retry_count, last_attempted_at, next_retry_at, source_rule_id,
    approved_policy_revision, requested_by, request_id
)
SELECT id, device_id, source_ip, scope, protocol, dest_port, action, status, reason,
       trigger_event_id, applied_at, released_at, last_error, created_at, updated_at,
       retry_count, last_attempted_at, next_retry_at, source_rule_id,
       approved_policy_revision, requested_by, request_id
FROM firewall_rules;

DROP TABLE firewall_rules;
ALTER TABLE firewall_rules_018 RENAME TO firewall_rules;

UPDATE sqlite_sequence
SET seq = max(seq, coalesce((SELECT max(seq) FROM firewall_sequence_018), 0))
WHERE name = 'firewall_rules';
INSERT INTO sqlite_sequence(name, seq)
SELECT 'firewall_rules', max(seq) FROM firewall_sequence_018
WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'firewall_rules')
HAVING max(seq) IS NOT NULL;
DROP TABLE firewall_sequence_018;

CREATE INDEX idx_firewall_rules_status ON firewall_rules(status);
CREATE INDEX idx_firewall_rules_source_ip ON firewall_rules(source_ip);
CREATE UNIQUE INDEX idx_firewall_rules_active_unique
    ON firewall_rules(source_ip, scope) WHERE status IN ('PENDING', 'APPLIED');
