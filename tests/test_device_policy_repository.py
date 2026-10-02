"""기기 등록·정책 revision 저장소와 시점 resolver 검증 (V02, V03, V06, V07 일부)."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from edge.policy import device_policy_repository as repository
from edge.policy.device_policy import (
    DeviceIdConflictError,
    DeviceIpConflictError,
    DeviceNotFoundError,
    DevicePolicyError,
    DevicePolicyValidationError,
    NoPolicyChangeError,
    PendingRevisionExistsError,
    PolicyUnavailableError,
    PolicyWriteBusyError,
    RevisionConflictError,
    StateTransitionBlockedError,
)
from edge.policy.device_policy_repository import (
    append_policy_revision,
    get_latest_revision,
    get_policy_snapshot,
    list_revisions,
    register_device,
    write_transaction,
)
from edge.policy.device_policy_resolver import (
    RESOLUTION_NOT_REGISTERED,
    RESOLUTION_OK,
    RESOLUTION_POLICY_UNAVAILABLE,
    registered_device_by_ip_at,
    registered_device_ids_at,
    resolve_device_policy,
)
from tests.device_policy_support import (
    LAN_POLICY,
    POLICY,
    T0,
    at,
    clock_at,
    count,
    insert_legacy_device,
    open_db,
)


@pytest.fixture
def db(tmp_path: Path):
    connection = open_db(tmp_path)
    try:
        yield connection
    finally:
        connection.close()


def register(connection, device_id="pico_01", ip="192.168.0.6", when=T0, **overrides):
    arguments = dict(
        device_id=device_id,
        ip_address=ip,
        device_type="SENSOR",
        mqtt_principal=device_id,
        policy=POLICY,
        reason="등록 준비",
        created_by="recovery-admin",
        ip_policy=LAN_POLICY,
        clock=clock_at(when),
    )
    arguments.update(overrides)
    return register_device(connection, **arguments)


def append(connection, device_id="pico_01", *, expected, when, state="PENDING", **policy_changes):
    return append_policy_revision(
        connection,
        device_id=device_id,
        expected_revision=expected,
        registration_state=state,
        policy={**POLICY, **policy_changes},
        reason="변경",
        created_by="recovery-admin",
        clock=clock_at(when),
    )


def snapshot_of_tables(connection) -> dict[str, list]:
    return {
        table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]
        for table in ("devices", "device_policy_revisions")
    }


# ── 등록 ─────────────────────────────────────────────────────────────────────


class TestRegisterDevice:
    def test_creates_pending_device_with_revision_one_at_next_boundary(self, db) -> None:
        result = register(db)

        assert result.revision.revision == 1
        assert result.revision.registration_state == "PENDING"
        assert result.revision.effective_from == "2026-10-02T00:00:10Z"
        assert result.registration_effective_from == "2026-10-02T00:00:10Z"
        assert result.created_at == "2026-10-02T00:00:03Z"
        row = db.execute(
            "SELECT status, trust_score, last_seen_at, device_type, mqtt_principal, "
            "registration_effective_from FROM devices WHERE device_id = 'pico_01'"
        ).fetchone()
        assert tuple(row) == ("normal", 100, None, "SENSOR", "pico_01", "2026-10-02T00:00:10Z")
        assert result.revision.created_by == "recovery-admin"

    @pytest.mark.parametrize(
        ("moment", "expected"),
        [
            (datetime(2026, 10, 2, 0, 0, 9, 900000, tzinfo=timezone.utc), "2026-10-02T00:00:10Z"),
            (datetime(2026, 10, 2, 0, 0, 10, tzinfo=timezone.utc), "2026-10-02T00:00:20Z"),
        ],
    )
    def test_effective_from_is_strictly_after_server_time(self, db, moment, expected) -> None:
        # 계약 4절 예시: 00:00:09.900 → 00:00:10Z, 정확히 00:00:10Z → 00:00:20Z
        assert register(db, when=moment).revision.effective_from == expected

    def test_server_time_is_decided_inside_the_write_lock(self, db) -> None:
        observed: list[bool] = []

        def clock():
            observed.append(db.in_transaction)
            return T0

        register(db, clock=clock)

        assert observed == [True]

    def test_stored_policy_matches_the_request(self, db) -> None:
        register(db, policy={**POLICY, "publish_count_max": 20, "packet_rate_max_pps": 12})

        stored = get_latest_revision(db, "pico_01")

        assert stored is not None
        assert stored.policy.publish_count_max == 20
        assert stored.policy.packet_rate_max_pps == 12.0

    def test_duplicate_device_id_is_rejected_without_changes(self, db) -> None:
        register(db)
        before = snapshot_of_tables(db)

        with pytest.raises(DeviceIdConflictError) as caught:
            register(db, ip="192.168.0.7")

        assert caught.value.code == "DEVICE_ID_CONFLICT"
        assert snapshot_of_tables(db) == before

    def test_duplicate_ip_is_rejected_without_changes(self, db) -> None:
        register(db)
        before = snapshot_of_tables(db)

        with pytest.raises(DeviceIpConflictError) as caught:
            register(db, device_id="pico_02")

        assert caught.value.code == "DEVICE_IP_CONFLICT"
        assert snapshot_of_tables(db) == before

    def test_legacy_device_ip_also_conflicts(self, db) -> None:
        insert_legacy_device(db, "esp32_01", "192.168.0.4")

        with pytest.raises(DeviceIpConflictError):
            register(db, ip="192.168.0.4")

    @pytest.mark.parametrize(
        "overrides",
        [
            {"device_id": "bad id"},
            {"ip_address": "8.8.8.8"},
            {"ip_address": "192.168.0.1"},  # 제외 주소
            {"ip_address": "192.168.1.5"},  # LAN 밖
            {"device_type": "ROUTER"},
            {"mqtt_principal": ""},
            {"policy": {**POLICY, "publish_count_max": "15"}},
            {"policy": {**POLICY, "publish_count_max": True}},
            {"policy": {**POLICY, "packet_rate_max_pps": float("nan")}},
            {"policy": {**POLICY, "extra": 1}},
            {"reason": " "},
            {"created_by": ""},
        ],
    )
    def test_invalid_input_never_touches_the_database(self, db, overrides) -> None:
        before = snapshot_of_tables(db)
        arguments = dict(
            device_id="pico_01",
            ip_address="192.168.0.6",
            device_type="SENSOR",
            mqtt_principal="pico_01",
            policy=POLICY,
            reason="등록 준비",
            created_by="recovery-admin",
            ip_policy=LAN_POLICY,
            clock=clock_at(T0),
        )
        arguments.update(overrides)

        with pytest.raises(DevicePolicyValidationError):
            register_device(db, **arguments)

        assert snapshot_of_tables(db) == before
        assert not db.in_transaction

    def test_failure_after_device_insert_rolls_back_the_device_row(self, db, monkeypatch) -> None:
        def boom(*args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(repository, "_insert_revision", boom)

        with pytest.raises(sqlite3.OperationalError):
            register(db)

        assert count(db, "devices") == 0
        assert count(db, "device_policy_revisions") == 0
        assert not db.in_transaction

    def test_refuses_a_connection_that_already_has_a_transaction(self, db) -> None:
        db.execute("BEGIN")

        with pytest.raises(RuntimeError, match="open transaction"):
            register(db)

        db.execute("ROLLBACK")
        assert count(db, "devices") == 0


# ── revision 추가 ────────────────────────────────────────────────────────────


class TestAppendPolicyRevision:
    def test_adds_next_revision_at_next_boundary_and_keeps_old_ones_unchanged(self, db) -> None:
        register(db)
        first = list_revisions(db, "pico_01")[0]

        second = append(db, expected=1, when=at(20), publish_count_max=20)

        assert second.revision == 2
        assert second.effective_from == "2026-10-02T00:00:30Z"
        assert second.policy.publish_count_max == 20
        revisions = list_revisions(db, "pico_01")
        assert revisions[0] == first
        assert [r.revision for r in revisions] == [1, 2]

    def test_expected_revision_must_match_latest(self, db) -> None:
        register(db)

        with pytest.raises(RevisionConflictError) as caught:
            append(db, expected=2, when=at(20), publish_count_max=20)

        assert caught.value.code == "REVISION_CONFLICT"
        assert caught.value.current_revision == 1
        assert caught.value.pending_revision is None
        assert count(db, "device_policy_revisions") == 1

    def test_pending_revision_blocks_further_changes(self, db) -> None:
        register(db)
        append(db, expected=1, when=at(20), publish_count_max=20)  # revision 2 예정(00:00:30)

        with pytest.raises(PendingRevisionExistsError) as caught:
            append(db, expected=2, when=at(21), publish_count_max=25)

        assert caught.value.code == "PENDING_REVISION_EXISTS"
        assert caught.value.current_revision == 1
        assert caught.value.pending_revision == 2

    def test_stale_expected_revision_reports_both_current_and_pending(self, db) -> None:
        register(db)
        append(db, expected=1, when=at(20), publish_count_max=20)

        with pytest.raises(RevisionConflictError) as caught:
            append(db, expected=1, when=at(21), publish_count_max=25)

        assert (caught.value.current_revision, caught.value.pending_revision) == (1, 2)

    def test_change_is_allowed_again_once_the_pending_revision_took_effect(self, db) -> None:
        register(db)
        append(db, expected=1, when=at(20), publish_count_max=20)  # 효력 00:00:30

        third = append(db, expected=2, when=at(27), publish_count_max=25)  # 서버 시각 00:00:30

        assert third.revision == 3
        assert third.effective_from == "2026-10-02T00:00:40Z"

    def test_request_without_any_change_is_rejected(self, db) -> None:
        register(db)

        with pytest.raises(NoPolicyChangeError):
            append(db, expected=1, when=at(20))

        assert count(db, "device_policy_revisions") == 1

    def test_state_only_change_is_allowed(self, db) -> None:
        register(db)

        revision = append(db, expected=1, when=at(20), state="ACTIVE")

        assert revision.registration_state == "ACTIVE"

    @pytest.mark.parametrize(
        ("steps", "final_state", "allowed"),
        [
            ([], "ACTIVE", True),  # PENDING → ACTIVE
            ([], "DISABLED", True),  # PENDING → DISABLED
            (["ACTIVE"], "DISABLED", True),  # ACTIVE → DISABLED
            (["ACTIVE"], "PENDING", False),  # ACTIVE는 PENDING으로 돌아갈 수 없다
        ],
    )
    def test_state_transitions(self, db, steps, final_state, allowed) -> None:
        register(db)
        expected = 1
        moment = 20
        for state in steps:  # 각 단계의 효력이 시작된 뒤 다음 변경을 요청한다
            append(db, expected=expected, when=at(moment), state=state)
            expected += 1
            moment += 10

        if allowed:
            result = append(db, expected=expected, when=at(moment), state=final_state)
            assert result.registration_state == final_state
        else:
            with pytest.raises(StateTransitionBlockedError):
                append(db, expected=expected, when=at(moment), state=final_state)

    def test_disabled_device_accepts_no_further_revision(self, db) -> None:
        register(db)
        append(db, expected=1, when=at(20), state="DISABLED")

        for state, changes in (("DISABLED", {"publish_count_max": 30}), ("ACTIVE", {}), ("PENDING", {})):
            with pytest.raises(StateTransitionBlockedError) as caught:
                append(db, expected=2, when=at(40), state=state, **changes)
            assert caught.value.code == "STATE_TRANSITION_BLOCKED"

    def test_state_change_guard_runs_inside_the_lock_and_can_block(self, db) -> None:
        register(db)
        calls: list[tuple[str, str, str, bool]] = []

        def guard(connection, device_id, from_state, to_state):
            calls.append((device_id, from_state, to_state, connection.in_transaction))
            raise StateTransitionBlockedError("active firewall rule exists")

        with pytest.raises(StateTransitionBlockedError, match="firewall"):
            append_policy_revision(
                db,
                device_id="pico_01",
                expected_revision=1,
                registration_state="DISABLED",
                policy=POLICY,
                reason="비활성화",
                created_by="recovery-admin",
                clock=clock_at(at(20)),
                state_change_guard=guard,
            )

        assert calls == [("pico_01", "PENDING", "DISABLED", True)]
        assert count(db, "device_policy_revisions") == 1
        assert not db.in_transaction

    def test_state_change_guard_is_not_called_for_policy_only_changes(self, db) -> None:
        register(db)

        def guard(*args):
            raise AssertionError("guard must not run when the state is unchanged")

        append_policy_revision(
            db,
            device_id="pico_01",
            expected_revision=1,
            registration_state="PENDING",
            policy={**POLICY, "publish_count_max": 20},
            reason="임계값 조정",
            created_by="recovery-admin",
            clock=clock_at(at(20)),
            state_change_guard=guard,
        )

    def test_unknown_device_is_not_found(self, db) -> None:
        with pytest.raises(DeviceNotFoundError) as caught:
            append(db, "ghost", expected=1, when=at(20), publish_count_max=20)

        assert caught.value.code == "DEVICE_NOT_FOUND"

    def test_legacy_device_without_revision_is_policy_unavailable(self, db) -> None:
        insert_legacy_device(db, "esp32_01", "192.168.0.4")

        with pytest.raises(PolicyUnavailableError) as caught:
            append(db, "esp32_01", expected=1, when=at(20), publish_count_max=20)

        assert caught.value.code == "POLICY_UNAVAILABLE"
        assert count(db, "device_policy_revisions") == 0

    @pytest.mark.parametrize("expected", [0, -1, True, "1", 1.0, None])
    def test_invalid_expected_revision_is_a_validation_error(self, db, expected) -> None:
        register(db)

        with pytest.raises(DevicePolicyValidationError):
            append(db, expected=expected, when=at(20), publish_count_max=20)

        assert count(db, "device_policy_revisions") == 1

    def test_failed_append_rolls_back_completely(self, db, monkeypatch) -> None:
        register(db)
        before = snapshot_of_tables(db)

        def boom(*args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(repository, "_insert_revision", boom)
        with pytest.raises(sqlite3.OperationalError):
            append(db, expected=1, when=at(20), publish_count_max=20)

        assert snapshot_of_tables(db) == before
        assert not db.in_transaction


# ── 동시 변경 (V03) ──────────────────────────────────────────────────────────


class TestConcurrency:
    def test_same_expected_revision_from_two_connections_only_one_wins(self, tmp_path) -> None:
        path = tmp_path / "race.db"
        apply_migrations(path, MIGRATIONS_DIR)
        setup = connect_database(path)
        register(setup)
        setup.close()

        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker(publish_count: int) -> None:
            connection = connect_database(path)
            try:
                barrier.wait()
                try:
                    append(
                        connection,
                        expected=1,
                        when=at(20),
                        publish_count_max=publish_count,
                    )
                    result = "OK"
                except DevicePolicyError as exc:
                    result = exc.code
                with lock:
                    outcomes.append(result)
            finally:
                connection.close()

        threads = [threading.Thread(target=worker, args=(value,)) for value in (20, 25)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert sorted(outcomes) == ["OK", "REVISION_CONFLICT"]
        verify = connect_database(path)
        try:
            revisions = list_revisions(verify, "pico_01")
        finally:
            verify.close()
        assert [r.revision for r in revisions] == [1, 2]  # 감사 이력이 일관된다

    def test_busy_write_lock_is_reported_and_nothing_changes(self, tmp_path) -> None:
        path = tmp_path / "busy.db"
        apply_migrations(path, MIGRATIONS_DIR)
        holder = connect_database(path)
        register(holder)
        contender = connect_database(path)
        contender.execute("PRAGMA busy_timeout = 50")
        before = snapshot_of_tables(holder)
        try:
            holder.execute("BEGIN IMMEDIATE")  # 다른 연결이 쓰기 잠금을 쥔다

            with pytest.raises(PolicyWriteBusyError) as caught:
                append(contender, expected=1, when=at(20), publish_count_max=20)

            assert caught.value.code == "POLICY_WRITE_BUSY"
            assert not contender.in_transaction
            holder.execute("ROLLBACK")
            assert snapshot_of_tables(holder) == before

            # 잠금이 풀리면 같은 요청을 새로 읽고 다시 시도할 수 있다.
            assert append(contender, expected=1, when=at(20), publish_count_max=20).revision == 2
        finally:
            contender.close()
            holder.close()

    def test_write_transaction_commits_all_or_nothing(self, db) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            with write_transaction(db):
                db.execute(
                    "INSERT INTO devices (device_id, ip_address) VALUES ('dev_x', '192.168.0.60')"
                )
                raise RuntimeError("boom")

        assert count(db, "devices") == 0
        assert not db.in_transaction


# ── 조회 ─────────────────────────────────────────────────────────────────────


class TestPolicySnapshot:
    def test_initial_registration_is_pending_not_an_error(self, db) -> None:
        register(db)

        snapshot = get_policy_snapshot(db, "pico_01", server_time=T0)

        assert snapshot.latest_revision == 1
        assert snapshot.current is None
        assert snapshot.pending is not None and snapshot.pending.revision == 1
        assert snapshot.server_time == "2026-10-02T00:00:03.000Z"

    def test_after_the_boundary_the_revision_is_current(self, db) -> None:
        register(db)

        snapshot = get_policy_snapshot(db, "pico_01", server_time=at(7))  # 00:00:10

        assert snapshot.current is not None and snapshot.current.revision == 1
        assert snapshot.pending is None

    def test_current_and_pending_are_reported_together(self, db) -> None:
        register(db)
        append(db, expected=1, when=at(20), publish_count_max=20)

        snapshot = get_policy_snapshot(db, "pico_01", server_time=at(21))

        assert snapshot.current.revision == 1
        assert snapshot.pending.revision == 2
        assert snapshot.latest_revision == 2

    def test_as_dict_matches_the_contract_shape(self, db) -> None:
        register(db)

        body = get_policy_snapshot(db, "pico_01", server_time=T0).as_dict()

        assert set(body) == {"device_id", "server_time", "latest_revision", "current", "pending"}
        assert set(body["pending"]) == {
            "device_id",
            "revision",
            "effective_from",
            "registration_state",
            "policy",
            "created_at",
            "created_by",
            "reason",
        }
        assert body["pending"]["policy"] == POLICY

    def test_unknown_device_and_missing_policy(self, db) -> None:
        with pytest.raises(DeviceNotFoundError):
            get_policy_snapshot(db, "ghost")
        insert_legacy_device(db, "esp32_01", "192.168.0.4")
        with pytest.raises(PolicyUnavailableError):
            get_policy_snapshot(db, "esp32_01")


# ── 시점 resolver (V06, V07) ─────────────────────────────────────────────────


class TestResolver:
    def window(self, seconds: int) -> datetime:
        return datetime(2026, 10, 2, 0, 0, seconds, tzinfo=timezone.utc)

    def test_not_registered_before_effective_and_ok_from_the_boundary(self, db) -> None:
        register(db)  # 효력 00:00:10

        before = resolve_device_policy(db, "pico_01", self.window(0))
        exact = resolve_device_policy(db, "pico_01", self.window(10))

        assert before.resolution == RESOLUTION_NOT_REGISTERED
        assert before.policy is None
        assert exact.resolution == RESOLUTION_OK
        assert exact.device_policy_revision == 1
        assert exact.registration_state == "PENDING"
        assert exact.policy.publish_count_max == 15

    def test_unknown_device_is_not_registered(self, db) -> None:
        assert (
            resolve_device_policy(db, "ghost", self.window(10)).resolution
            == RESOLUTION_NOT_REGISTERED
        )

    def test_window_selects_the_revision_that_was_effective_then(self, db) -> None:
        register(db)
        append(db, expected=1, when=at(20), state="ACTIVE", publish_count_max=20)  # 효력 00:00:30

        old = resolve_device_policy(db, "pico_01", self.window(20))
        new = resolve_device_policy(db, "pico_01", self.window(30))

        assert (old.device_policy_revision, old.policy.publish_count_max) == (1, 15)
        assert old.registration_state == "PENDING"
        assert (new.device_policy_revision, new.policy.publish_count_max) == (2, 20)
        assert new.registration_state == "ACTIVE"

    def test_later_changes_never_rewrite_how_an_old_window_resolves(self, db) -> None:
        register(db)
        first_resolution = resolve_device_policy(db, "pico_01", self.window(10))

        append(db, expected=1, when=at(20), publish_count_max=99)

        assert resolve_device_policy(db, "pico_01", self.window(10)) == first_resolution

    def test_legacy_device_is_registered_but_policy_unavailable(self, db) -> None:
        insert_legacy_device(db, "esp32_01", "192.168.0.4")

        resolution = resolve_device_policy(db, "esp32_01", self.window(0))

        assert resolution.resolution == RESOLUTION_POLICY_UNAVAILABLE
        assert resolution.reason == "NO_POLICY_REVISION"
        assert resolution.policy is None  # 기본값으로 보정하지 않는다
        assert "esp32_01" in registered_device_ids_at(db, self.window(0))

    def test_late_registration_does_not_claim_earlier_windows(self, db) -> None:
        # V07: 신규 기기 등록 이후에도 과거 Window의 등록 집합은 그대로다.
        insert_legacy_device(db, "esp32_01", "192.168.0.4")
        register(db)  # pico_01 효력 00:00:10

        assert registered_device_ids_at(db, self.window(0)) == {"esp32_01"}
        assert registered_device_ids_at(db, self.window(10)) == {"esp32_01", "pico_01"}

    def test_ip_attribution_respects_registration_effect(self, db) -> None:
        register(db)

        assert registered_device_by_ip_at(db, "192.168.0.6", self.window(0)) is None
        assert registered_device_by_ip_at(db, "192.168.0.6", self.window(10)) == "pico_01"
        assert registered_device_by_ip_at(db, "192.168.0.99", self.window(10)) is None
        for bad in ("not-an-ip", "", None, "192.168.0.256"):
            assert registered_device_by_ip_at(db, bad, self.window(10)) is None

    @pytest.mark.parametrize(
        "window",
        [
            "2026-10-02T00:00:10Z",
            "2026-10-02 00:00:10",  # 기존 Phase 4의 naive UTC 문자열
            datetime(2026, 10, 2, 0, 0, 10),  # naive는 UTC로 해석(기존 계약)
            datetime(2026, 10, 2, 9, 0, 10, tzinfo=timezone(timedelta(hours=9))),
        ],
    )
    def test_window_input_forms_resolve_to_the_same_utc_instant(self, db, window) -> None:
        register(db)

        assert resolve_device_policy(db, "pico_01", window).resolution == RESOLUTION_OK

    def test_resolver_never_commits_or_changes_the_callers_transaction(self, db) -> None:
        register(db)
        db.execute("BEGIN")

        resolve_device_policy(db, "pico_01", self.window(10))
        registered_device_ids_at(db, self.window(10))
        registered_device_by_ip_at(db, "192.168.0.6", self.window(10))

        assert db.in_transaction
        db.execute("ROLLBACK")

    def test_returned_policy_is_an_immutable_snapshot(self, db) -> None:
        register(db)

        resolution = resolve_device_policy(db, "pico_01", self.window(10))

        with pytest.raises(FrozenInstanceError):
            resolution.policy.publish_count_max = 1  # type: ignore[misc]
