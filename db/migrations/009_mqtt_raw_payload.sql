-- Phase 8 P8-S04 후반: MQTT 수신 원본 바이트와 UTF-8 해석 결과 보존.
--
-- 기존 payload(TEXT)는 잘못된 UTF-8 바이트를 U+FFFD로 치환한 값이라 원본과 같지 않다.
-- payload_raw는 수신한 바이트를 그대로, payload_decode_status는 엄격한 UTF-8 해석 가능 여부를
-- 기록한다. 기존 payload·payload_size·is_json_valid의 의미는 바꾸지 않는다.
-- 이 Migration 이전에 저장된 row는 원본 바이트가 없어 두 컬럼이 NULL이며 backfill하지 않는다
-- (NULL은 "알 수 없음"이고 OK를 추정해 채우지 않는다).

ALTER TABLE mqtt_logs ADD COLUMN payload_raw BLOB;

ALTER TABLE mqtt_logs ADD COLUMN payload_decode_status TEXT
    CHECK (payload_decode_status IS NULL OR payload_decode_status IN ('OK', 'INVALID_UTF8'));

-- 두 컬럼은 함께 저장하고, 원본은 BLOB이며 payload_size(원본 byte 크기)와 길이가 같아야 한다.
CREATE TRIGGER trg_mqtt_logs_raw_payload_validate_insert
BEFORE INSERT ON mqtt_logs
WHEN NEW.payload_raw IS NOT NULL OR NEW.payload_decode_status IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'mqtt_logs.payload_raw and payload_decode_status must be set together')
    WHERE NEW.payload_raw IS NULL OR NEW.payload_decode_status IS NULL;
    SELECT RAISE(ABORT, 'mqtt_logs.payload_raw must be a BLOB')
    WHERE typeof(NEW.payload_raw) <> 'blob';
    SELECT RAISE(ABORT, 'mqtt_logs.payload_size must equal the raw payload byte length')
    WHERE NEW.payload_size IS NOT length(NEW.payload_raw);
END;

-- 수신 원본은 증적이므로 저장 후 바꾸지 않는다. 원본이 없는 기존 row에 값을 채우는 것도 막는다.
CREATE TRIGGER trg_mqtt_logs_raw_payload_immutable
BEFORE UPDATE OF payload_raw, payload_decode_status, payload_size ON mqtt_logs
WHEN NEW.payload_raw IS NOT OLD.payload_raw
    OR NEW.payload_decode_status IS NOT OLD.payload_decode_status
    OR (NEW.payload_raw IS NOT NULL AND NEW.payload_size IS NOT OLD.payload_size)
BEGIN
    SELECT RAISE(ABORT, 'mqtt_logs raw payload columns are immutable');
END;
