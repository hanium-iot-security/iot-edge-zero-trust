-- Phase 8 P8-03: 기기 등록 메타데이터와 불변 정책 Revision 이력 (device-policy-v1).
--
-- devices의 Trust 필드는 변경하지 않는다. 등록 상태(PENDING/ACTIVE/DISABLED)는 Trust 상태와
-- 별개이며 device_policy_revisions에만 저장한다.
-- 기존 기기의 정책은 이 Migration이 만들지 않는다. 확인된 운영값으로 db/backfill_device_policies.py를
-- 실행하기 전까지 정책 누락 상태로 남는다.
-- DB는 형식·범위·불변성·순번·상태 전이를, 서비스(edge/policy)는 숫자 문자열/bool 같은 묵시 변환과
-- IP 대역 검증을 맡는다.

ALTER TABLE devices ADD COLUMN device_type TEXT
    CHECK (device_type IS NULL OR device_type IN ('SENSOR', 'CAMERA', 'ACTUATOR', 'OTHER'));

ALTER TABLE devices ADD COLUMN mqtt_principal TEXT
    CHECK (mqtt_principal IS NULL OR length(mqtt_principal) BETWEEN 1 AND 128);

-- 등록 효력 시작 시각(UTC, 10초 경계). 등록 시각은 기존 created_at을 그대로 사용한다.
-- NULL은 정책 도입 전부터 있던 기존 기기를 뜻한다.
ALTER TABLE devices ADD COLUMN registration_effective_from TEXT
    CHECK (
        registration_effective_from IS NULL
        OR (
            strftime('%Y-%m-%dT%H:%M:%SZ', registration_effective_from) IS registration_effective_from
            AND registration_effective_from GLOB '*:[0-5]0Z'
        )
    );

-- 기존 중복 IP가 있으면 이 Migration은 실패하고 전체 rollback된다. 자료를 임의로 바꾸지 않는다.
-- 사전 진단: edge.policy.device_policy_repository.diagnose_device_ip_conflicts
CREATE UNIQUE INDEX uq_devices_ip_address
    ON devices(ip_address)
    WHERE ip_address IS NOT NULL AND ip_address <> '';

-- IP는 정규 dotted-decimal 형태만 저장한다(앞자리 0·공백·4개 미만/초과 octet 거부).
-- octet 범위(0~255)와 사설/LAN 대역 검증은 서비스가 담당한다.
CREATE TRIGGER trg_devices_ip_shape_insert
BEFORE INSERT ON devices
WHEN NEW.ip_address IS NOT NULL AND NEW.ip_address <> ''
BEGIN
    SELECT RAISE(ABORT, 'devices.ip_address must be a canonical dotted-decimal IPv4 address')
    WHERE length(NEW.ip_address) > 15
       OR NEW.ip_address GLOB '*[^0-9.]*'
       OR NEW.ip_address NOT GLOB '*.*.*.*'
       OR NEW.ip_address GLOB '*.*.*.*.*'
       OR NEW.ip_address GLOB '.*'
       OR NEW.ip_address GLOB '*.'
       OR NEW.ip_address GLOB '*..*'
       OR NEW.ip_address GLOB '0[0-9]*'
       OR NEW.ip_address GLOB '*.0[0-9]*';
END;

CREATE TRIGGER trg_devices_ip_shape_update
BEFORE UPDATE OF ip_address ON devices
WHEN NEW.ip_address IS NOT NULL AND NEW.ip_address <> ''
BEGIN
    SELECT RAISE(ABORT, 'devices.ip_address must be a canonical dotted-decimal IPv4 address')
    WHERE length(NEW.ip_address) > 15
       OR NEW.ip_address GLOB '*[^0-9.]*'
       OR NEW.ip_address NOT GLOB '*.*.*.*'
       OR NEW.ip_address GLOB '*.*.*.*.*'
       OR NEW.ip_address GLOB '.*'
       OR NEW.ip_address GLOB '*.'
       OR NEW.ip_address GLOB '*..*'
       OR NEW.ip_address GLOB '0[0-9]*'
       OR NEW.ip_address GLOB '*.0[0-9]*';
END;

-- 등록 효력 시점은 과거 Window의 등록 집합 판정 근거이므로 한 번 정해지면 바꿀 수 없다.
-- 값이 없던 기존 기기에 처음 채우는 것만 허용한다.
-- Device ID·IP·유형·Principal의 수정 금지는 이 DB가 아니라 서비스/API 계약이 담당한다(수정 경로를
-- 제공하지 않는다). 기존 도구와 검증 시나리오가 IP를 UPDATE할 수 있으므로 DB 수준으로 막지 않는다.
-- 등록된 기기의 IP를 바꾸면 과거 Window의 IP 귀속이 달라지므로 운영에서 바꾸지 않는다.
CREATE TRIGGER trg_devices_registration_effective_from_immutable
BEFORE UPDATE OF registration_effective_from ON devices
WHEN OLD.registration_effective_from IS NOT NULL
  AND OLD.registration_effective_from IS NOT NEW.registration_effective_from
BEGIN
    SELECT RAISE(ABORT, 'devices.registration_effective_from is immutable once set');
END;

CREATE TABLE device_policy_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    revision INTEGER NOT NULL
        CHECK (typeof(revision) = 'integer' AND revision BETWEEN 1 AND 2147483647),
    effective_from TEXT NOT NULL
        CHECK (
            strftime('%Y-%m-%dT%H:%M:%SZ', effective_from) IS effective_from
            AND effective_from GLOB '*:[0-5]0Z'
        ),
    registration_state TEXT NOT NULL
        CHECK (registration_state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    policy_profile TEXT NOT NULL
        CHECK (length(policy_profile) BETWEEN 1 AND 64),
    expected_publish_interval_seconds REAL NOT NULL
        CHECK (
            typeof(expected_publish_interval_seconds) IN ('integer', 'real')
            AND expected_publish_interval_seconds > 0
            AND expected_publish_interval_seconds <= 86400
        ),
    publish_count_max INTEGER NOT NULL
        CHECK (typeof(publish_count_max) = 'integer' AND publish_count_max BETWEEN 1 AND 10000),
    payload_size_max_bytes INTEGER NOT NULL
        CHECK (
            typeof(payload_size_max_bytes) = 'integer'
            AND payload_size_max_bytes BETWEEN 1 AND 1048576
        ),
    packet_rate_max_pps REAL NOT NULL
        CHECK (
            typeof(packet_rate_max_pps) IN ('integer', 'real')
            AND packet_rate_max_pps > 0
            AND packet_rate_max_pps <= 100000
        ),
    byte_rate_max_bytes_per_second REAL NOT NULL
        CHECK (
            typeof(byte_rate_max_bytes_per_second) IN ('integer', 'real')
            AND byte_rate_max_bytes_per_second > 0
            AND byte_rate_max_bytes_per_second <= 125000000
        ),
    created_at TEXT NOT NULL
        CHECK (
            strftime('%Y-%m-%dT%H:%M:%SZ', created_at) IS created_at
            OR strftime('%Y-%m-%dT%H:%M:%fZ', created_at) IS created_at
        ),
    created_by TEXT NOT NULL CHECK (length(trim(created_by)) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 500),
    UNIQUE (device_id, revision),
    UNIQUE (device_id, effective_from),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE RESTRICT
);

-- 직접 INSERT(seed/backfill/수동 SQL)도 같은 규칙을 지키게 한다.
-- 예정 revision 중복(PENDING_REVISION_EXISTS)처럼 서버 시각이 필요한 규칙은 서비스가 검사한다.
CREATE TRIGGER trg_device_policy_revisions_validate_insert
BEFORE INSERT ON device_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'revision must be the previous revision plus one')
    WHERE NEW.revision <> COALESCE(
        (SELECT MAX(revision) FROM device_policy_revisions WHERE device_id = NEW.device_id),
        0
    ) + 1;

    SELECT RAISE(ABORT, 'effective_from must be later than every earlier revision')
    WHERE EXISTS (
        SELECT 1 FROM device_policy_revisions
        WHERE device_id = NEW.device_id AND effective_from >= NEW.effective_from
    );

    SELECT RAISE(ABORT, 'a DISABLED device cannot receive new revisions')
    WHERE EXISTS (
        SELECT 1 FROM device_policy_revisions
        WHERE device_id = NEW.device_id
          AND revision = NEW.revision - 1
          AND registration_state = 'DISABLED'
    );

    SELECT RAISE(ABORT, 'an ACTIVE device cannot return to PENDING')
    WHERE NEW.registration_state = 'PENDING'
      AND EXISTS (
        SELECT 1 FROM device_policy_revisions
        WHERE device_id = NEW.device_id
          AND revision = NEW.revision - 1
          AND registration_state = 'ACTIVE'
    );
END;

CREATE TRIGGER trg_device_policy_revisions_no_update
BEFORE UPDATE ON device_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'device_policy_revisions rows are immutable');
END;

CREATE TRIGGER trg_device_policy_revisions_no_delete
BEFORE DELETE ON device_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'device_policy_revisions rows are immutable');
END;
