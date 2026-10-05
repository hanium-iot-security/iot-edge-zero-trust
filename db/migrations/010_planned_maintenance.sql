-- Planned shutdown approval is separate from strict failure recovery.
CREATE TABLE planned_maintenance_operations (
    operation_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('REQUESTED','READY','RESUMED','CANCELLED')),
    approved_by TEXT NOT NULL CHECK(length(trim(approved_by)) > 0),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    source_session_id TEXT NOT NULL REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
    source_boot_id TEXT NOT NULL,
    required_checkpoints_json TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    ready_at TEXT,
    expires_at TEXT,
    source_final_boundary TEXT,
    source_snapshot_json TEXT,
    checkpoint_snapshot_json TEXT,
    target_session_id TEXT REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
    target_boot_id TEXT,
    maintenance_start TEXT,
    maintenance_end TEXT,
    resumed_at TEXT,
    cancelled_at TEXT,
    cancellation_reason TEXT,
    CHECK(status NOT IN ('READY','RESUMED') OR (
        ready_at IS NOT NULL AND expires_at IS NOT NULL AND source_final_boundary IS NOT NULL
        AND source_snapshot_json IS NOT NULL AND checkpoint_snapshot_json IS NOT NULL
        AND maintenance_start = source_final_boundary)),
    CHECK(status != 'RESUMED' OR (
        target_session_id IS NOT NULL AND target_boot_id IS NOT NULL AND resumed_at IS NOT NULL
        AND maintenance_end IS NOT NULL AND unixepoch(maintenance_end) >= unixepoch(maintenance_start))),
    CHECK(status != 'CANCELLED' OR (cancelled_at IS NOT NULL AND length(trim(cancellation_reason)) > 0))
);
CREATE UNIQUE INDEX uq_planned_maintenance_active
    ON planned_maintenance_operations((1)) WHERE status IN ('REQUESTED','READY');
CREATE UNIQUE INDEX uq_planned_maintenance_resumed_target
    ON planned_maintenance_operations(target_session_id) WHERE status = 'RESUMED';
CREATE INDEX idx_planned_maintenance_source_seal
    ON planned_maintenance_operations(source_session_id, status);

CREATE TABLE planned_maintenance_resumes (
    operation_id TEXT PRIMARY KEY REFERENCES planned_maintenance_operations(operation_id) ON DELETE RESTRICT,
    target_session_id TEXT NOT NULL UNIQUE REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
    target_boot_id TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
    plan_json TEXT NOT NULL,
    backup_path TEXT NOT NULL,
    backup_sha256 TEXT NOT NULL CHECK(length(backup_sha256) = 64),
    resumed_at TEXT NOT NULL
);

CREATE TRIGGER trg_planned_maintenance_approval_immutable
BEFORE UPDATE ON planned_maintenance_operations
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.approved_by IS NOT OLD.approved_by
    OR NEW.reason IS NOT OLD.reason OR NEW.source_session_id IS NOT OLD.source_session_id
    OR NEW.source_boot_id IS NOT OLD.source_boot_id OR NEW.requested_at IS NOT OLD.requested_at
    OR NEW.required_checkpoints_json IS NOT OLD.required_checkpoints_json
    OR (OLD.status != 'REQUESTED' AND (
        NEW.ready_at IS NOT OLD.ready_at OR NEW.expires_at IS NOT OLD.expires_at
        OR NEW.source_final_boundary IS NOT OLD.source_final_boundary
        OR NEW.source_snapshot_json IS NOT OLD.source_snapshot_json
        OR NEW.checkpoint_snapshot_json IS NOT OLD.checkpoint_snapshot_json
        OR NEW.maintenance_start IS NOT OLD.maintenance_start))
    OR OLD.status IN ('RESUMED','CANCELLED')
    OR (OLD.status = 'REQUESTED' AND NEW.status NOT IN ('READY','CANCELLED'))
    OR (OLD.status = 'READY' AND NEW.status NOT IN ('RESUMED','CANCELLED'))
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance approval is immutable or transition invalid');
END;
CREATE TRIGGER trg_planned_maintenance_operations_no_delete
BEFORE DELETE ON planned_maintenance_operations
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance approvals cannot be deleted');
END;
CREATE TRIGGER trg_planned_maintenance_resumes_no_update
BEFORE UPDATE ON planned_maintenance_resumes
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance resume audit is immutable');
END;
CREATE TRIGGER trg_planned_maintenance_resumes_no_delete
BEFORE DELETE ON planned_maintenance_resumes
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance resume audit cannot be deleted');
END;

-- A stopped source is sealed when READY is committed. Cancellation never
-- removes an existing seal. New Sessions and live MQTT inserts remain writable.
CREATE TRIGGER trg_planned_maintenance_source_session_update
BEFORE UPDATE ON packet_capture_sessions
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o
             WHERE o.source_session_id=OLD.session_id AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Session is sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_session_delete
BEFORE DELETE ON packet_capture_sessions
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o
             WHERE o.source_session_id=OLD.session_id AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Session is sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_segment_insert
BEFORE INSERT ON packet_capture_segments
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o JOIN packet_capture_sessions s ON s.session_id=o.source_session_id
             WHERE s.id=NEW.capture_session_id AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Segments are sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_segment_update
BEFORE UPDATE ON packet_capture_segments
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o JOIN packet_capture_sessions s ON s.session_id=o.source_session_id
             WHERE s.id IN (OLD.capture_session_id,NEW.capture_session_id) AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Segments are sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_segment_delete
BEFORE DELETE ON packet_capture_segments
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o JOIN packet_capture_sessions s ON s.session_id=o.source_session_id
             WHERE s.id=OLD.capture_session_id AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Segments are sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_feature_insert
BEFORE INSERT ON packet_feature_logs
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o JOIN packet_capture_sessions s ON s.session_id=o.source_session_id
             JOIN packet_capture_segments c ON c.capture_session_id=s.id
             WHERE c.id=NEW.capture_segment_id AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Features are sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_feature_update
BEFORE UPDATE ON packet_feature_logs
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o JOIN packet_capture_sessions s ON s.session_id=o.source_session_id
             JOIN packet_capture_segments c ON c.capture_session_id=s.id
             WHERE c.id IN (OLD.capture_segment_id,NEW.capture_segment_id) AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Features are sealed');
END;
CREATE TRIGGER trg_planned_maintenance_source_feature_delete
BEFORE DELETE ON packet_feature_logs
WHEN EXISTS (SELECT 1 FROM planned_maintenance_operations o JOIN packet_capture_sessions s ON s.session_id=o.source_session_id
             JOIN packet_capture_segments c ON c.capture_session_id=s.id
             WHERE c.id=OLD.capture_segment_id AND o.source_snapshot_json IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planned maintenance source Features are sealed');
END;
