"""P9-03: 기기별 AI 모드 저장소(등록 시 OFF, 변경, 스냅샷)와 resolver 검증."""

from __future__ import annotations

import sqlite3

import pytest

from edge.policy import device_ai_policy_repository as repo
from edge.policy.device_ai_policy import AiPolicyUnavailableError, INITIAL_AI_REASON
from edge.policy.device_ai_policy_resolver import (
    AI_RESOLUTION_NOT_REGISTERED,
    AI_RESOLUTION_OK,
    AI_RESOLUTION_UNAVAILABLE,
    REASON_NO_AI_REVISION,
    REASON_NO_EFFECTIVE_AI_REVISION,
    resolve_ai_mode,
)
from edge.policy.device_policy import (
    DeviceNotFoundError,
    DevicePolicyValidationError,
    NoPolicyChangeError,
    PendingRevisionExistsError,
    PolicyWriteBusyError,
    RevisionConflictError,
    StateTransitionBlockedError,
)
from edge.policy.device_policy_repository import append_policy_revision, register_device
from tests.device_policy_support import (
    LAN_POLICY,
    POLICY,
    at,
    clock_at,
    insert_legacy_device,
    open_db,
)


@pytest.fixture
def db(tmp_path):
    connection = open_db(tmp_path)
    try:
        yield connection
    finally:
        connection.close()


def _register(db, device_id="dev_a", ip="192.168.0.10", moment=None):
    return register_device(
        db,
        device_id=device_id,
        ip_address=ip,
        device_type="SENSOR",
        mqtt_principal=device_id,
        policy=POLICY,
        reason="registration",
        created_by="admin",
        ip_policy=LAN_POLICY,
        clock=clock_at(moment or at(0)),
    )


def _append(db, mode, expected, moment, device_id="dev_a"):
    return repo.append_ai_policy_revision(
        db,
        device_id=device_id,
        expected_revision=expected,
        mode=mode,
        reason="change",
        created_by="admin",
        clock=clock_at(moment),
    )


class TestRegistration:
    def test_new_device_starts_with_off_at_its_registration_boundary(self, db) -> None:
        registered = _register(db)

        revisions = repo.list_ai_revisions(db, "dev_a")
        assert [(r.revision, r.mode) for r in revisions] == [(1, "OFF")]
        assert revisions[0].effective_from == registered.registration_effective_from
        assert revisions[0].reason == INITIAL_AI_REASON
        assert revisions[0].created_by == "admin"

    def test_registration_response_shape_is_unchanged(self, db) -> None:
        registered = _register(db)
        assert registered.revision.revision == 1 and registered.revision.registration_state == "PENDING"

    def test_failed_ai_insert_rolls_back_the_whole_registration(self, db, monkeypatch) -> None:
        def broken(*args, **kwargs):
            raise sqlite3.OperationalError("simulated failure")

        monkeypatch.setattr(repo, "insert_ai_revision", broken)
        with pytest.raises(sqlite3.OperationalError):
            _register(db)

        assert db.execute("SELECT count(*) FROM devices").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM device_policy_revisions").fetchone()[0] == 0


class TestSnapshot:
    def test_initial_wait_has_pending_and_no_current(self, db) -> None:
        _register(db)
        snapshot = repo.get_ai_policy_snapshot(db, "dev_a", server_time=at(1))

        assert snapshot.current is None
        assert snapshot.pending.revision == 1 and snapshot.latest_revision == 1

    def test_current_after_effective(self, db) -> None:
        _register(db)
        snapshot = repo.get_ai_policy_snapshot(db, "dev_a", server_time=at(20))
        assert snapshot.current.mode == "OFF" and snapshot.pending is None

    def test_unknown_device_is_not_found(self, db) -> None:
        with pytest.raises(DeviceNotFoundError):
            repo.get_ai_policy_snapshot(db, "ghost")

    def test_legacy_device_without_settings_is_unavailable_not_off(self, db) -> None:
        insert_legacy_device(db, "legacy_1", "192.168.0.31")
        db.commit()
        with pytest.raises(AiPolicyUnavailableError):
            repo.get_ai_policy_snapshot(db, "legacy_1")

    def test_damaged_stored_value_is_unavailable(self, db) -> None:
        _register(db)
        db.execute("DROP TRIGGER trg_device_ai_policy_revisions_no_update")
        db.execute("PRAGMA ignore_check_constraints = ON")
        db.execute("UPDATE device_ai_policy_revisions SET mode = 'ENFORCE'")
        with pytest.raises(AiPolicyUnavailableError):
            repo.get_ai_policy_snapshot(db, "dev_a", server_time=at(20))


class TestAppend:
    def test_adds_revision_at_next_boundary_and_keeps_old_rows(self, db) -> None:
        _register(db)
        added = _append(db, "OBSERVE", 1, at(20))  # 00:00:23 -> 다음 경계 00:00:30

        assert (added.revision, added.mode, added.effective_from) == (2, "OBSERVE", "2026-10-02T00:00:30Z")
        assert [(r.revision, r.mode) for r in repo.list_ai_revisions(db, "dev_a")] == [
            (1, "OFF"),
            (2, "OBSERVE"),
        ]

    def test_stale_expected_revision_reports_current_and_pending(self, db) -> None:
        _register(db)
        _append(db, "OBSERVE", 1, at(20))
        with pytest.raises(RevisionConflictError) as error:
            _append(db, "OFF", 1, at(21))
        assert (error.value.current_revision, error.value.pending_revision) == (1, 2)

    def test_pending_revision_blocks_a_correct_expected_revision(self, db) -> None:
        _register(db)
        _append(db, "OBSERVE", 1, at(20))
        with pytest.raises(PendingRevisionExistsError) as error:
            _append(db, "OFF", 2, at(21))
        assert error.value.pending_revision == 2

    def test_change_is_allowed_again_after_the_pending_revision_took_effect(self, db) -> None:
        _register(db)
        _append(db, "OBSERVE", 1, at(20))
        assert _append(db, "OFF", 2, at(40)).revision == 3

    def test_same_mode_is_no_change(self, db) -> None:
        _register(db)
        with pytest.raises(NoPolicyChangeError):
            _append(db, "OFF", 1, at(20))

    def test_unknown_device_and_missing_settings(self, db) -> None:
        with pytest.raises(DeviceNotFoundError):
            _append(db, "OBSERVE", 1, at(20), device_id="ghost")
        insert_legacy_device(db, "legacy_1", "192.168.0.31")
        db.commit()
        with pytest.raises(AiPolicyUnavailableError):
            _append(db, "OBSERVE", 1, at(20), device_id="legacy_1")
        assert repo.list_ai_revisions(db, "legacy_1") == []

    @pytest.mark.parametrize(
        "overrides",
        [
            {"mode": "ENFORCE"},
            {"mode": "observe"},
            {"mode": None},
            {"expected_revision": True},
            {"expected_revision": "1"},
            {"reason": " "},
            {"created_by": None},
        ],
    )
    def test_invalid_input_never_touches_the_database(self, db, overrides) -> None:
        _register(db)
        kwargs = {"device_id": "dev_a", "expected_revision": 1, "mode": "OBSERVE",
                  "reason": "x", "created_by": "admin", "clock": clock_at(at(20))}
        kwargs.update(overrides)
        with pytest.raises(DevicePolicyValidationError):
            repo.append_ai_policy_revision(db, **kwargs)
        assert len(repo.list_ai_revisions(db, "dev_a")) == 1

    def test_disabled_device_cannot_be_set_to_observe_but_can_be_set_off(self, db) -> None:
        _register(db)
        _append(db, "OBSERVE", 1, at(20))
        append_policy_revision(
            db, device_id="dev_a", expected_revision=1, registration_state="DISABLED",
            policy=POLICY, reason="disable", created_by="admin", clock=clock_at(at(40)),
        )
        # 현재 모드는 OBSERVE. OFF로 내리는 것은 허용되고 OBSERVE 유지/전환은 막힌다.
        assert _append(db, "OFF", 2, at(60)).mode == "OFF"
        with pytest.raises(StateTransitionBlockedError):
            _append(db, "OBSERVE", 3, at(80))

    def test_write_lock_contention_is_reported_as_busy(self, db, tmp_path) -> None:
        _register(db)
        other = sqlite3.connect(tmp_path / "policy.db", isolation_level=None, timeout=0)
        other.execute("BEGIN IMMEDIATE")
        try:
            db.execute("PRAGMA busy_timeout = 0")
            with pytest.raises(PolicyWriteBusyError):
                _append(db, "OBSERVE", 1, at(20))
        finally:
            other.execute("ROLLBACK")
            other.close()


class TestResolver:
    def test_mode_follows_the_window_start_not_the_processing_time(self, db) -> None:
        _register(db)  # OFF, 효력 00:00:10
        _append(db, "OBSERVE", 1, at(20))  # OBSERVE, 효력 00:00:30

        def mode(seconds):
            result = resolve_ai_mode(db, "dev_a", at(seconds))
            return result.resolution, result.mode, result.ai_policy_revision

        assert mode(2)[0] == AI_RESOLUTION_UNAVAILABLE  # 첫 효력 전
        assert mode(10) == (AI_RESOLUTION_OK, "OFF", 1)
        assert mode(26) == (AI_RESOLUTION_OK, "OFF", 1)  # 00:00:29 — 과거를 되살리지 않는다
        assert mode(27) == (AI_RESOLUTION_OK, "OBSERVE", 2)

    def test_reasons_for_unavailable_and_unregistered(self, db) -> None:
        _register(db)
        before_first = resolve_ai_mode(db, "dev_a", at(0))
        assert before_first.reason == REASON_NO_EFFECTIVE_AI_REVISION and before_first.mode is None

        insert_legacy_device(db, "legacy_1", "192.168.0.31")
        db.commit()
        legacy = resolve_ai_mode(db, "legacy_1", at(60))
        assert (legacy.resolution, legacy.reason) == (AI_RESOLUTION_UNAVAILABLE, REASON_NO_AI_REVISION)

        ghost = resolve_ai_mode(db, "ghost", at(60))
        assert ghost.resolution == AI_RESOLUTION_NOT_REGISTERED

    def test_accepts_strings_and_rejects_bad_times(self, db) -> None:
        _register(db)
        assert resolve_ai_mode(db, "dev_a", "2026-10-02T00:00:20Z").mode == "OFF"
        with pytest.raises(DevicePolicyValidationError):
            resolve_ai_mode(db, "dev_a", "not-a-time")
        with pytest.raises(DevicePolicyValidationError):
            resolve_ai_mode(db, "dev_a", 12345)  # type: ignore[arg-type]
