-- Visibility is administrative metadata, separate from registration and Trust.
ALTER TABLE devices ADD COLUMN hidden_at TEXT;
ALTER TABLE devices ADD COLUMN registration_instance_id TEXT;
CREATE UNIQUE INDEX uq_devices_registration_instance ON devices(registration_instance_id)
WHERE registration_instance_id IS NOT NULL;
CREATE TRIGGER devices_registration_instance_insert AFTER INSERT ON devices
WHEN NEW.registration_instance_id IS NULL
BEGIN
    UPDATE devices SET registration_instance_id = lower(hex(randomblob(16))) WHERE device_id = NEW.device_id;
END;
CREATE TRIGGER devices_registration_instance_immutable BEFORE UPDATE OF registration_instance_id ON devices
WHEN OLD.registration_instance_id IS NOT NULL AND OLD.registration_instance_id IS NOT NEW.registration_instance_id
BEGIN SELECT RAISE(ABORT, 'registration instance is immutable'); END;

CREATE TABLE device_management_audits (
    operation_id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('DELETE_UNUSED', 'HIDE', 'RESTORE')),
    requested_at TEXT NOT NULL,
    requested_by TEXT NOT NULL CHECK(length(trim(requested_by)) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 500),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json) AND json_type(payload_json) = 'object')
);
CREATE INDEX idx_device_management_audits_device ON device_management_audits(device_id, requested_at);
CREATE TRIGGER device_management_audits_no_update BEFORE UPDATE ON device_management_audits
BEGIN SELECT RAISE(ABORT, 'device management audit is immutable'); END;
CREATE TRIGGER device_management_audits_no_delete BEFORE DELETE ON device_management_audits
BEGIN SELECT RAISE(ABORT, 'device management audit cannot be deleted'); END;
CREATE TRIGGER device_management_audits_no_replace BEFORE INSERT ON device_management_audits
WHEN EXISTS (SELECT 1 FROM device_management_audits WHERE operation_id = NEW.operation_id)
BEGIN SELECT RAISE(ABORT, 'device management operation already exists'); END;

-- Shared by the command's eligibility check and the narrow deletion backstops.
-- IP evidence counts even when it was not attributed to a registered device.
CREATE VIEW device_management_history AS
SELECT d.device_id, 'MQTT_LOGS' AS source FROM devices d WHERE EXISTS (
    SELECT 1 FROM mqtt_logs h WHERE h.device_id = d.device_id
      OR (substr(h.topic, 1, length('iot/' || d.device_id || '/')) = 'iot/' || d.device_id || '/')
      OR EXISTS (
          -- Inspect every top-level candidate, including duplicate JSON keys;
          -- SQLite's first-key extraction differs from Python's last-key parse.
          SELECT 1 FROM json_each(CASE WHEN json_valid(h.payload) THEN h.payload ELSE '{}' END) candidate
          WHERE candidate.key = 'device_id' AND candidate.type = 'text'
            AND trim(candidate.value, char(9,10,11,12,13,28,29,30,31,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = d.device_id
      )
)
UNION ALL SELECT d.device_id, 'FEATURE_LOGS' FROM devices d WHERE EXISTS (SELECT 1 FROM feature_logs h WHERE h.device_id = d.device_id)
UNION ALL SELECT d.device_id, 'PACKET_FEATURE_LOGS' FROM devices d WHERE EXISTS (SELECT 1 FROM packet_feature_logs h WHERE h.device_id = d.device_id OR h.peer_ip = d.ip_address)
UNION ALL SELECT d.device_id, 'DETECTION_EVENTS' FROM devices d WHERE EXISTS (SELECT 1 FROM detection_events h WHERE h.device_id = d.device_id OR h.subject_ip = d.ip_address)
UNION ALL SELECT d.device_id, 'ISOLATION_HISTORY' FROM devices d WHERE EXISTS (SELECT 1 FROM isolation_history h WHERE h.device_id = d.device_id)
UNION ALL SELECT d.device_id, 'TRUST_SCORE_HISTORY' FROM devices d WHERE EXISTS (SELECT 1 FROM trust_score_history h WHERE h.device_id = d.device_id)
UNION ALL SELECT d.device_id, 'TRUST_SCORE_COMPENSATIONS' FROM devices d WHERE EXISTS (SELECT 1 FROM trust_score_compensations h WHERE h.device_id = d.device_id)
UNION ALL SELECT d.device_id, 'FIREWALL_RULES' FROM devices d WHERE EXISTS (SELECT 1 FROM firewall_rules h WHERE h.device_id = d.device_id OR h.source_ip = d.ip_address)
UNION ALL SELECT d.device_id, 'FIREWALL_RELEASE_REQUESTS' FROM devices d WHERE EXISTS (
    SELECT 1 FROM firewall_release_requests r JOIN firewall_rules h ON h.id = r.firewall_rule_id
    WHERE h.device_id = d.device_id OR h.source_ip = d.ip_address
)
UNION ALL SELECT d.device_id, 'DEVICE_RECOVERY_AUDITS' FROM devices d WHERE EXISTS (SELECT 1 FROM device_recovery_audits h WHERE h.device_id = d.device_id)
UNION ALL SELECT d.device_id, 'AI_DEVICE_COMPLETIONS' FROM devices d WHERE EXISTS (SELECT 1 FROM ai_device_completions h WHERE h.device_key = d.device_id)
UNION ALL SELECT d.device_id, 'AI_WARNING_AGGREGATES' FROM devices d WHERE EXISTS (SELECT 1 FROM ai_warning_aggregates h WHERE h.device_id = d.device_id)
UNION ALL SELECT d.device_id, 'AI_WARNING_KEYS' FROM devices d WHERE EXISTS (
    SELECT 1 FROM ai_warning_keys h WHERE CASE WHEN json_valid(h.warning_key)
      THEN json_extract(h.warning_key, '$[0]') = d.device_id ELSE 0 END
);

-- Revision immutability has one exception: original setup metadata whose exact
-- row identity is preserved by this transaction's durable deletion audit.
DROP TRIGGER trg_device_policy_revisions_no_delete;
CREATE TRIGGER trg_device_policy_revisions_no_delete BEFORE DELETE ON device_policy_revisions
WHEN NOT (
    OLD.revision = 1 AND OLD.registration_state = 'PENDING'
    AND (SELECT count(*) FROM device_policy_revisions WHERE device_id = OLD.device_id) = 1
    AND NOT EXISTS (SELECT 1 FROM device_management_history WHERE device_id = OLD.device_id)
    AND EXISTS (
        SELECT 1 FROM device_management_audits a JOIN devices d ON d.device_id = a.device_id
        WHERE a.device_id = OLD.device_id AND a.action = 'DELETE_UNUSED'
          AND json_extract(a.payload_json, '$.before_device.registration_instance_id') = d.registration_instance_id
          AND d.status = 'normal' AND d.trust_score = 100 AND d.last_seen_at IS NULL AND d.hidden_at IS NULL
          AND d.registration_effective_from = OLD.effective_from
          AND json_extract(a.payload_json, '$.before_device.created_at') = d.created_at
          AND json_extract(a.payload_json, '$.rule_revision.id') = OLD.id
          AND json_extract(a.payload_json, '$.rule_revision.created_at') = OLD.created_at
    )
)
BEGIN SELECT RAISE(ABORT, 'device_policy_revisions rows are immutable'); END;

DROP TRIGGER trg_device_ai_policy_revisions_no_delete;
CREATE TRIGGER trg_device_ai_policy_revisions_no_delete BEFORE DELETE ON device_ai_policy_revisions
WHEN NOT (
    OLD.revision = 1 AND OLD.mode = 'OFF' AND OLD.reason = 'default AI mode at device registration'
    AND (SELECT count(*) FROM device_ai_policy_revisions WHERE device_id = OLD.device_id) = 1
    AND NOT EXISTS (SELECT 1 FROM device_management_history WHERE device_id = OLD.device_id)
    AND EXISTS (
        SELECT 1 FROM device_management_audits a JOIN devices d ON d.device_id = a.device_id
        JOIN device_policy_revisions p ON p.device_id = d.device_id
        WHERE a.device_id = OLD.device_id AND a.action = 'DELETE_UNUSED'
          AND json_extract(a.payload_json, '$.before_device.registration_instance_id') = d.registration_instance_id
          AND d.status = 'normal' AND d.trust_score = 100 AND d.last_seen_at IS NULL AND d.hidden_at IS NULL
          AND p.revision = 1 AND p.registration_state = 'PENDING'
          AND (SELECT count(*) FROM device_policy_revisions WHERE device_id = d.device_id) = 1
          AND p.effective_from = d.registration_effective_from AND OLD.effective_from = p.effective_from
          AND OLD.created_at = p.created_at AND OLD.created_by = p.created_by
          AND json_extract(a.payload_json, '$.before_device.created_at') = d.created_at
          AND json_extract(a.payload_json, '$.ai_revision.id') = OLD.id
          AND json_extract(a.payload_json, '$.ai_revision.created_at') = OLD.created_at
    )
)
BEGIN SELECT RAISE(ABORT, 'device_ai_policy_revisions rows are immutable'); END;

CREATE TRIGGER devices_management_delete_guard BEFORE DELETE ON devices
WHEN EXISTS (SELECT 1 FROM device_management_history WHERE device_id = OLD.device_id)
  OR NOT EXISTS (
    SELECT 1 FROM device_management_audits a WHERE a.device_id = OLD.device_id AND a.action = 'DELETE_UNUSED'
      AND json_extract(a.payload_json, '$.before_device.registration_instance_id') = OLD.registration_instance_id
      AND OLD.status = 'normal' AND OLD.trust_score = 100 AND OLD.last_seen_at IS NULL AND OLD.hidden_at IS NULL
      AND OLD.registration_effective_from IS NOT NULL
      AND json_extract(a.payload_json, '$.before_device.created_at') = OLD.created_at
      AND json_extract(a.payload_json, '$.before_device.registration_effective_from') = OLD.registration_effective_from
  )
BEGIN SELECT RAISE(ABORT, 'device deletion requires an audited unused registration'); END;
