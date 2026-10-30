-- Ordinary device recovery stores its evidence in the same transaction as the
-- device reset. Full database backups remain an explicit maintenance operation.
CREATE TABLE device_recovery_audits (
    operation_id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    requested_at TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json) AND json_type(payload_json) = 'object')
);
CREATE INDEX idx_device_recovery_audits_device_time
ON device_recovery_audits(device_id, requested_at DESC);
CREATE TRIGGER device_recovery_audits_no_update BEFORE UPDATE ON device_recovery_audits
BEGIN SELECT RAISE(ABORT, 'device recovery audit is immutable'); END;
CREATE TRIGGER device_recovery_audits_no_delete BEFORE DELETE ON device_recovery_audits
BEGIN SELECT RAISE(ABORT, 'device recovery audit cannot be deleted'); END;
-- REPLACE can otherwise delete an existing row without firing DELETE triggers.
CREATE TRIGGER device_recovery_audits_no_replace BEFORE INSERT ON device_recovery_audits
WHEN EXISTS (SELECT 1 FROM device_recovery_audits WHERE operation_id = NEW.operation_id)
BEGIN SELECT RAISE(ABORT, 'device recovery operation already exists'); END;
