-- Phase 9 P9-03: 기기별 AI 모드(OFF / OBSERVE) 불변 Revision 이력.
--
-- 등록·정책 Revision(007)과 별개의 설정이다. 기존 기기의 모드는 이 Migration이 만들지 않는다.
-- 승인 목록으로 db/backfill_device_ai_policies.py를 실행하기 전까지 기존 기기는 AI 설정 누락
-- 상태로 남고, 탐지기는 그 기기의 AI를 제외한다(OFF로 간주하지 않는다).
-- ENFORCE는 Phase 9 범위 밖이라 저장하지 않는다.
-- DB는 형식·불변성·순번을, 서비스(edge/policy)는 예정 Revision 중복·DISABLED 기기 제한처럼
-- 서버 시각이나 다른 설정이 필요한 규칙을 맡는다.

CREATE TABLE device_ai_policy_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    revision INTEGER NOT NULL
        CHECK (typeof(revision) = 'integer' AND revision BETWEEN 1 AND 2147483647),
    mode TEXT NOT NULL CHECK (mode IN ('OFF', 'OBSERVE')),
    effective_from TEXT NOT NULL
        CHECK (
            substr(effective_from, 1, 4) >= '0001'
            AND strftime('%Y-%m-%dT%H:%M:%SZ', effective_from, '+0 seconds') IS effective_from
            AND effective_from GLOB '*:[0-5]0Z'
        ),
    created_at TEXT NOT NULL
        CHECK (
            substr(created_at, 1, 4) >= '0001'
            AND (
                strftime('%Y-%m-%dT%H:%M:%SZ', created_at, '+0 seconds') IS created_at
                OR strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '+0 seconds') IS created_at
            )
        ),
    created_by TEXT NOT NULL CHECK (length(trim(created_by)) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 500),
    UNIQUE (device_id, revision),
    UNIQUE (device_id, effective_from),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE RESTRICT
);

-- 직접 INSERT(seed/backfill/수동 SQL)도 같은 순번·시간 규칙을 지키게 한다.
CREATE TRIGGER trg_device_ai_policy_revisions_validate_insert
BEFORE INSERT ON device_ai_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'revision must be the previous revision plus one')
    WHERE NEW.revision <> COALESCE(
        (SELECT MAX(revision) FROM device_ai_policy_revisions WHERE device_id = NEW.device_id),
        0
    ) + 1;

    SELECT RAISE(ABORT, 'effective_from must be later than every earlier revision')
    WHERE EXISTS (
        SELECT 1 FROM device_ai_policy_revisions
        WHERE device_id = NEW.device_id AND effective_from >= NEW.effective_from
    );
END;

CREATE TRIGGER trg_device_ai_policy_revisions_no_update
BEFORE UPDATE ON device_ai_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'device_ai_policy_revisions rows are immutable');
END;

CREATE TRIGGER trg_device_ai_policy_revisions_no_delete
BEFORE DELETE ON device_ai_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'device_ai_policy_revisions rows are immutable');
END;
