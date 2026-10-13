-- One immutable initial activation per AI Stage. Later model replacement is explicit HOLD.
CREATE TABLE ai_stage_activations (
    activation_id TEXT PRIMARY KEY NOT NULL,
    stage_name TEXT NOT NULL UNIQUE CHECK (stage_name IN ('mqtt_if','packet_if')),
    source_table TEXT NOT NULL,
    model_version TEXT NOT NULL CHECK (length(trim(model_version)) > 0),
    bundle_sha256 TEXT NOT NULL
        CHECK (length(bundle_sha256)=64 AND bundle_sha256 NOT GLOB '*[^0-9a-f]*'),
    boundary TEXT NOT NULL CHECK (
        strftime('%Y-%m-%dT%H:%M:%SZ',boundary,'+0 seconds') IS boundary
        AND boundary GLOB '*:[0-5]0Z'),
    plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256)=64),
    plan_json TEXT NOT NULL CHECK (json_valid(plan_json)),
    applied_at TEXT NOT NULL,
    CHECK ((stage_name='mqtt_if' AND source_table='feature_logs')
        OR (stage_name='packet_if' AND source_table='packet_feature_logs'))
);
CREATE TRIGGER trg_ai_stage_activations_no_update
BEFORE UPDATE ON ai_stage_activations
BEGIN
    SELECT RAISE(ABORT,'AI Stage activation is immutable');
END;
CREATE TRIGGER trg_ai_stage_activations_no_delete
BEFORE DELETE ON ai_stage_activations
BEGIN
    SELECT RAISE(ABORT,'AI Stage activation cannot be deleted');
END;
