"""기존 기기 이관(backfill), seed, CLI 검증 (V04)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from db import backfill_device_policies
from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from db.seed_devices import DEFAULT_POLICY, seed_default_devices
from edge.policy import device_policy_backfill as backfill_module
from edge.policy.device_policy import (
    BackfillBlockedError,
    DeviceIpConflictError,
    DevicePolicy,
    DevicePolicyError,
    DevicePolicyValidationError,
    PendingRevisionExistsError,
)
from edge.policy.device_policy_backfill import (
    LegacyDeviceOverride,
    apply_legacy_backfill,
    parse_override,
    plan_legacy_backfill,
)
from edge.policy.device_policy_repository import append_policy_revision, list_revisions
from edge.policy.device_policy_resolver import (
    RESOLUTION_OK,
    RESOLUTION_POLICY_UNAVAILABLE,
    registered_device_ids_at,
    resolve_device_policy,
)
from tests.device_policy_support import (
    LAN_POLICY,
    POLICY,
    T0,
    clock_at,
    count,
    insert_legacy_device,
    insert_revision_raw,
    open_db,
)


EFFECTIVE = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

# 기본값(15/5120/10.0/2500.0)과 다른 "확인된 운영값". 코드 기본값으로 이관하지 않음을 보인다.
OPERATING_POLICY = {**POLICY, "publish_count_max": 12, "packet_rate_max_pps": 8.0}


def override(device_id: str, **changes) -> LegacyDeviceOverride:
    return LegacyDeviceOverride(
        device_id=device_id,
        device_type="SENSOR",
        mqtt_principal=changes.pop("mqtt_principal", device_id),
        policy=DevicePolicy(**{**OPERATING_POLICY, **changes}),
        source="baseline-manifest:test",
    )


OVERRIDES = {name: override(name) for name in ("esp32_01", "esp32_02")}


@pytest.fixture
def legacy_db(tmp_path: Path):
    connection = open_db(tmp_path)
    connection.execute(
        "INSERT INTO devices (device_id, ip_address, status, trust_score, last_seen_at) "
        "VALUES ('esp32_01', '192.168.0.4', 'normal', 100, '2026-10-01T00:00:00Z')"
    )
    connection.execute(
        "INSERT INTO devices (device_id, ip_address, status, trust_score) "
        "VALUES ('esp32_02', '192.168.0.5', 'isolated', 25)"
    )
    connection.execute(
        "INSERT INTO detection_events (device_id, detector_type, event_type, score_delta) "
        "VALUES ('esp32_02', 'RULE', 'ABNORMAL_PUBLISH_RATE', -20)"
    )
    connection.execute(
        "INSERT INTO isolation_history (device_id, action, trust_score) "
        "VALUES ('esp32_02', 'ISOLATED', 25)"
    )
    connection.execute(
        "INSERT INTO firewall_rules (device_id, source_ip, status) "
        "VALUES ('esp32_02', '192.168.0.5', 'APPLIED')"
    )
    connection.execute(
        """
        INSERT INTO trust_score_history (
            device_id, analysis_window_start, analysis_window_end, previous_score,
            calculated_delta, capped_delta, actual_delta, new_score,
            representative_event_ids_json, policy_version
        )
        VALUES ('esp32_02', '2026-09-30T00:00:00Z', '2026-09-30T00:00:10Z',
                45, -20, -20, -20, 25, '[1]', 'trust-v2')
        """
    )
    try:
        yield connection
    finally:
        connection.close()


def protected_state(connection) -> dict[str, list]:
    queries = {
        "devices": "SELECT device_id, ip_address, status, trust_score, last_seen_at, created_at "
        "FROM devices ORDER BY device_id",
        "events": "SELECT * FROM detection_events ORDER BY id",
        "isolation": "SELECT * FROM isolation_history ORDER BY id",
        "rules": "SELECT * FROM firewall_rules ORDER BY id",
        "history": "SELECT * FROM trust_score_history ORDER BY id",
    }
    return {name: [tuple(row) for row in connection.execute(sql)] for name, sql in queries.items()}


def apply(connection, overrides=OVERRIDES, **kwargs):
    arguments = dict(
        effective_from=EFFECTIVE,
        ip_policy=LAN_POLICY,
        reason="baseline-manifest test 기준 이관",
        clock=clock_at(T0),
    )
    arguments.update(kwargs)
    return apply_legacy_backfill(connection, overrides, **arguments)


# ── backfill ─────────────────────────────────────────────────────────────────


class TestBackfill:
    def test_creates_active_initial_revisions_from_the_confirmed_operating_values(
        self, legacy_db
    ) -> None:
        result = apply(legacy_db)

        assert result.created == ("esp32_01", "esp32_02")
        for device_id in result.created:
            [revision] = list_revisions(legacy_db, device_id)
            assert revision.revision == 1
            assert revision.registration_state == "ACTIVE"
            assert revision.effective_from == "2026-10-01T00:00:00Z"
            assert revision.policy.publish_count_max == 12  # 코드 기본값(15)이 아니다
            assert revision.policy.packet_rate_max_pps == 8.0
            assert revision.created_by == "backfill:baseline-manifest:test"
            assert revision.reason == "baseline-manifest test 기준 이관"
        metadata = legacy_db.execute(
            "SELECT device_type, mqtt_principal, registration_effective_from "
            "FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone()
        assert tuple(metadata) == ("SENSOR", "esp32_01", None)

    def test_trust_firewall_and_history_data_are_unchanged(self, legacy_db) -> None:
        before = protected_state(legacy_db)

        apply(legacy_db)

        assert protected_state(legacy_db) == before

    def test_isolated_device_keeps_isolated_state_and_score(self, legacy_db) -> None:
        apply(legacy_db)

        row = legacy_db.execute(
            "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_02'"
        ).fetchone()
        assert tuple(row) == ("isolated", 25)

    def test_windows_before_migration_stay_registered_but_policy_unavailable(
        self, legacy_db
    ) -> None:
        apply(legacy_db)
        before = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
        after = datetime(2026, 10, 1, 0, 0, 10, tzinfo=timezone.utc)

        # 이관 이전 Window는 기존 Identity 판정(등록됨)을 바꾸지 않고, 정책은 추정하지 않는다.
        assert {"esp32_01", "esp32_02"} <= registered_device_ids_at(legacy_db, before)
        old_window = resolve_device_policy(legacy_db, "esp32_01", before)
        assert old_window.resolution == RESOLUTION_POLICY_UNAVAILABLE
        assert old_window.reason == "NO_EFFECTIVE_REVISION_AT_WINDOW"
        new_window = resolve_device_policy(legacy_db, "esp32_01", after)
        assert new_window.resolution == RESOLUTION_OK
        assert new_window.registration_state == "ACTIVE"
        assert new_window.policy.publish_count_max == 12

    def test_unconfirmed_principal_does_not_block_and_stays_null(self, legacy_db) -> None:
        overrides = {name: override(name, mqtt_principal=None) for name in OVERRIDES}

        result = apply(legacy_db, overrides)

        assert result.created == ("esp32_01", "esp32_02")
        row = legacy_db.execute(
            "SELECT device_type, mqtt_principal FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone()
        assert tuple(row) == ("SENSOR", None)

    def test_missing_principal_keeps_an_existing_one_without_mismatch(self, legacy_db) -> None:
        legacy_db.execute(
            "UPDATE devices SET mqtt_principal = 'esp32_01_mqtt' WHERE device_id = 'esp32_01'"
        )

        apply(legacy_db, {name: override(name, mqtt_principal=None) for name in OVERRIDES})

        row = legacy_db.execute(
            "SELECT mqtt_principal FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone()
        assert row[0] == "esp32_01_mqtt"

    def test_backfilled_device_can_receive_policy_changes_afterwards(self, legacy_db) -> None:
        # 이관된 기존 ESP32가 실제 운영에서 가장 먼저 탈 경로: 정책 변경 → 상태 전환.
        apply(legacy_db)
        now = datetime(2026, 10, 2, 0, 0, 3, tzinfo=timezone.utc)

        second = append_policy_revision(
            legacy_db,
            device_id="esp32_01",
            expected_revision=1,
            registration_state="ACTIVE",
            policy={**OPERATING_POLICY, "publish_count_max": 20},
            reason="임계값 조정",
            created_by="recovery-admin",
            clock=clock_at(now),
        )
        assert second.revision == 2
        assert second.effective_from == "2026-10-02T00:00:10Z"

        # 예정 revision이 있는 동안에는 추가 변경을 거부하고, 효력 시작 후 다시 허용한다.
        with pytest.raises(PendingRevisionExistsError):
            append_policy_revision(
                legacy_db,
                device_id="esp32_01",
                expected_revision=2,
                registration_state="DISABLED",
                policy={**OPERATING_POLICY, "publish_count_max": 20},
                reason="비활성화",
                created_by="recovery-admin",
                clock=clock_at(now),
            )
        third = append_policy_revision(
            legacy_db,
            device_id="esp32_01",
            expected_revision=2,
            registration_state="DISABLED",
            policy={**OPERATING_POLICY, "publish_count_max": 20},
            reason="비활성화",
            created_by="recovery-admin",
            clock=clock_at(now + timedelta(seconds=10)),
        )
        assert third.registration_state == "DISABLED"
        # 점수·차단 상태는 정책 변경이 건드리지 않는다.
        assert tuple(
            legacy_db.execute(
                "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_02'"
            ).fetchone()
        ) == ("isolated", 25)

    def test_rerun_does_not_overwrite_existing_policies(self, legacy_db) -> None:
        apply(legacy_db)
        before = [list_revisions(legacy_db, name) for name in OVERRIDES]
        different = {name: override(name, publish_count_max=99) for name in OVERRIDES}

        result = apply(legacy_db, different)

        assert result.created == ()
        assert result.already_revised == ("esp32_01", "esp32_02")
        assert [list_revisions(legacy_db, name) for name in OVERRIDES] == before
        assert count(legacy_db, "device_policy_revisions") == 2

    def test_only_devices_without_a_revision_are_created(self, legacy_db) -> None:
        insert_revision_raw(
            legacy_db,
            device_id="esp32_01",
            registration_state="ACTIVE",
            effective_from="2026-09-01T00:00:00Z",
            publish_count_max=7,
        )

        result = apply(legacy_db, {"esp32_02": override("esp32_02")})

        assert result.created == ("esp32_02",)
        assert result.already_revised == ("esp32_01",)
        assert list_revisions(legacy_db, "esp32_01")[0].policy.publish_count_max == 7

    def test_dry_run_plans_without_writing(self, legacy_db) -> None:
        before = (protected_state(legacy_db), count(legacy_db, "device_policy_revisions"))

        plan = plan_legacy_backfill(legacy_db, OVERRIDES, ip_policy=LAN_POLICY)

        assert plan.to_create == ("esp32_01", "esp32_02")
        assert plan.problems == ()
        assert (protected_state(legacy_db), count(legacy_db, "device_policy_revisions")) == before
        assert not legacy_db.in_transaction


class TestBackfillIsBlockedAtomically:
    def test_missing_override_blocks_every_device(self, legacy_db) -> None:
        with pytest.raises(BackfillBlockedError) as caught:
            apply(legacy_db, {"esp32_01": override("esp32_01")})

        assert caught.value.code == "BACKFILL_BLOCKED"
        assert any(p.startswith("MISSING_OVERRIDE:esp32_02") for p in caught.value.problems)
        assert count(legacy_db, "device_policy_revisions") == 0
        row = legacy_db.execute(
            "SELECT device_type, mqtt_principal FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone()
        assert tuple(row) == (None, None)  # 일부 기기만 이관되지 않는다
        assert not legacy_db.in_transaction

    def test_all_problems_are_reported_together(self, legacy_db) -> None:
        insert_legacy_device(legacy_db, "dev_blank", "")
        insert_legacy_device(legacy_db, "dev_public", "8.8.8.8")
        legacy_db.execute("UPDATE devices SET device_type = 'CAMERA' WHERE device_id = 'esp32_01'")
        overrides = {
            **OVERRIDES,
            "dev_blank": override("dev_blank"),
            "dev_public": override("dev_public"),
            "ghost": override("ghost"),
        }

        with pytest.raises(BackfillBlockedError) as caught:
            apply(legacy_db, overrides)

        problems = " | ".join(caught.value.problems)
        assert "IP_MISSING:dev_blank" in problems
        assert "IP_INVALID:dev_public" in problems
        assert "UNKNOWN_OVERRIDE:ghost" in problems
        assert "METADATA_MISMATCH:esp32_01" in problems
        assert count(legacy_db, "device_policy_revisions") == 0

    @pytest.mark.parametrize("ip", ["8.8.8.8", "192.168.1.9"])
    def test_ip_outside_the_allowed_range_blocks_the_backfill(self, legacy_db, ip) -> None:
        insert_legacy_device(legacy_db, "dev_odd", ip)

        with pytest.raises(BackfillBlockedError) as caught:
            apply(legacy_db, {**OVERRIDES, "dev_odd": override("dev_odd")})

        assert any(p.startswith("IP_INVALID:dev_odd") for p in caught.value.problems)
        assert count(legacy_db, "device_policy_revisions") == 0

    def test_protected_data_guard_rolls_everything_back(self, legacy_db, monkeypatch) -> None:
        calls = {"n": 0}

        def drifting_fingerprint(connection):
            calls["n"] += 1
            return {"call": calls["n"]}

        monkeypatch.setattr(backfill_module, "_fingerprint", drifting_fingerprint)

        with pytest.raises(DevicePolicyError, match="rolled back"):
            apply(legacy_db)

        assert count(legacy_db, "device_policy_revisions") == 0
        row = legacy_db.execute(
            "SELECT device_type FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone()
        assert row[0] is None

    @pytest.mark.parametrize(
        "arguments",
        [
            {"effective_from": datetime(2026, 10, 1, 0, 0, 13, tzinfo=timezone.utc)},
            {"effective_from": datetime(2026, 10, 1, 0, 0, 0)},
            {"reason": "  "},
        ],
    )
    def test_invalid_arguments_fail_before_any_change(self, legacy_db, arguments) -> None:
        with pytest.raises(DevicePolicyValidationError):
            apply(legacy_db, **arguments)

        assert count(legacy_db, "device_policy_revisions") == 0


class TestDirectCallsAreRevalidated:
    """manifest를 거치지 않고 저장 함수를 직접 호출해도 같은 검증을 받는다."""

    @pytest.mark.parametrize(
        "policy_changes",
        [
            {"publish_count_max": True},  # bool은 정수가 아니다
            {"payload_size_max_bytes": "5120"},  # 숫자 문자열 묵시 변환 금지
            {"publish_count_max": 15.0},
            {"packet_rate_max_pps": 0},
            {"packet_rate_max_pps": 10**400},  # 매우 큰 수
        ],
    )
    def test_invalid_policy_objects_are_rejected_without_changes(
        self, legacy_db, policy_changes
    ) -> None:
        bad = {name: override(name, **policy_changes) for name in OVERRIDES}
        before = protected_state(legacy_db)

        with pytest.raises(DevicePolicyValidationError):
            apply(legacy_db, bad)
        with pytest.raises(DevicePolicyValidationError):
            plan_legacy_backfill(legacy_db, bad, ip_policy=LAN_POLICY)

        assert count(legacy_db, "device_policy_revisions") == 0
        assert protected_state(legacy_db) == before
        assert not legacy_db.in_transaction

    def test_other_fields_of_override_objects_are_validated(self, legacy_db) -> None:
        for bad in (
            LegacyDeviceOverride(
                device_id="esp32_01", device_type="ROUTER", source="x", policy=DevicePolicy(**OPERATING_POLICY)
            ),
            LegacyDeviceOverride(
                device_id="esp32_01", device_type="SENSOR", source=" ", policy=DevicePolicy(**OPERATING_POLICY)
            ),
            LegacyDeviceOverride(
                device_id="esp32_01",
                device_type="SENSOR",
                source="x",
                policy=DevicePolicy(**OPERATING_POLICY),
                mqtt_principal="bad principal",
            ),
        ):
            with pytest.raises(DevicePolicyValidationError):
                apply(legacy_db, {"esp32_01": bad, "esp32_02": override("esp32_02")})

        assert count(legacy_db, "device_policy_revisions") == 0

    def test_key_must_match_the_override_device_id(self, legacy_db) -> None:
        mismatched = {"esp32_01": override("esp32_02"), "esp32_02": override("esp32_02")}

        with pytest.raises(DevicePolicyValidationError, match="does not match"):
            apply(legacy_db, mismatched)

        assert count(legacy_db, "device_policy_revisions") == 0

    def test_non_override_values_are_rejected(self, legacy_db) -> None:
        with pytest.raises(DevicePolicyValidationError):
            apply(legacy_db, {"esp32_01": {"device_id": "esp32_01"}})  # type: ignore[dict-item]

    @pytest.mark.parametrize("overrides", [None, [], "esp32_01", 5])
    def test_overrides_must_be_a_mapping(self, legacy_db, overrides) -> None:
        with pytest.raises(DevicePolicyValidationError):
            apply(legacy_db, overrides)  # type: ignore[arg-type]
        with pytest.raises(DevicePolicyValidationError):
            plan_legacy_backfill(legacy_db, overrides, ip_policy=LAN_POLICY)  # type: ignore[arg-type]


class TestParseOverride:
    VALID = {
        "device_id": "esp32_01",
        "device_type": "SENSOR",
        "mqtt_principal": "esp32_01",
        "policy": POLICY,
        "source": "baseline-manifest:abc",
    }

    def test_valid_override(self) -> None:
        parsed = parse_override(self.VALID)

        assert parsed.device_id == "esp32_01"
        assert parsed.policy.publish_count_max == 15

    @pytest.mark.parametrize("omit", ["absent", "null"])
    def test_principal_is_optional(self, omit) -> None:
        raw = {k: v for k, v in self.VALID.items() if k != "mqtt_principal"}
        if omit == "null":
            raw["mqtt_principal"] = None

        assert parse_override(raw).mqtt_principal is None

    def test_given_principal_is_still_validated(self) -> None:
        with pytest.raises(DevicePolicyValidationError):
            parse_override({**self.VALID, "mqtt_principal": "bad principal"})

    @pytest.mark.parametrize(
        "change",
        [
            {"extra": 1},
            {"device_id": "bad id"},
            {"device_type": "ROUTER"},
            {"policy": {**POLICY, "publish_count_max": "15"}},
            {"source": ""},
        ],
    )
    def test_invalid_override_is_rejected(self, change) -> None:
        with pytest.raises(DevicePolicyValidationError):
            parse_override({**self.VALID, **change})

    def test_missing_fields_are_rejected(self) -> None:
        incomplete = dict(self.VALID)
        del incomplete["policy"]
        with pytest.raises(DevicePolicyValidationError, match="missing"):
            parse_override(incomplete)


# ── seed ─────────────────────────────────────────────────────────────────────


class TestSeed:
    def test_fresh_database_gets_active_devices_with_initial_revisions(self, tmp_path) -> None:
        connection = open_db(tmp_path)
        try:
            result = seed_default_devices(connection, clock=clock_at(T0))

            assert result.created == ("esp32_01", "esp32_02")
            assert result.missing_policy == ()
            for device_id in result.created:
                [revision] = list_revisions(connection, device_id)
                assert revision.registration_state == "ACTIVE"
                assert revision.policy == DEFAULT_POLICY
                assert revision.effective_from == "2026-10-02T00:00:00Z"
            assert DEFAULT_POLICY.publish_count_max == 15
            assert DEFAULT_POLICY.payload_size_max_bytes == 5120
            assert DEFAULT_POLICY.packet_rate_max_pps == 10.0
            assert DEFAULT_POLICY.byte_rate_max_bytes_per_second == 2500.0
            row = connection.execute(
                "SELECT ip_address, status, trust_score, device_type, mqtt_principal "
                "FROM devices WHERE device_id = 'esp32_01'"
            ).fetchone()
            # Broker Principal은 확인되지 않은 값을 지어내지 않는다.
            assert tuple(row) == ("192.168.0.4", "normal", 100, "SENSOR", None)
        finally:
            connection.close()

    def test_rerun_changes_nothing(self, tmp_path) -> None:
        connection = open_db(tmp_path)
        try:
            seed_default_devices(connection, clock=clock_at(T0))
            before = [
                tuple(row) for row in connection.execute("SELECT * FROM device_policy_revisions")
            ]

            again = seed_default_devices(connection, clock=clock_at(T0))

            assert again.created == ()
            assert again.already_present == ("esp32_01", "esp32_02")
            assert [
                tuple(row) for row in connection.execute("SELECT * FROM device_policy_revisions")
            ] == before
        finally:
            connection.close()

    def test_existing_device_without_a_revision_is_reported_not_silently_filled(
        self, tmp_path
    ) -> None:
        connection = open_db(tmp_path)
        try:
            insert_legacy_device(connection, "esp32_01", "192.168.0.4")

            result = seed_default_devices(connection, clock=clock_at(T0))

            assert result.missing_policy == ("esp32_01",)
            assert result.created == ("esp32_02",)
            assert list_revisions(connection, "esp32_01") == []
        finally:
            connection.close()

    def test_ip_taken_by_another_device_rolls_the_whole_seed_back(self, tmp_path) -> None:
        connection = open_db(tmp_path)
        try:
            insert_legacy_device(connection, "other", "192.168.0.5")  # esp32_02의 IP

            with pytest.raises(DeviceIpConflictError):
                seed_default_devices(connection, clock=clock_at(T0))

            assert count(connection, "device_policy_revisions") == 0
            assert (
                connection.execute(
                    "SELECT 1 FROM devices WHERE device_id = 'esp32_01'"
                ).fetchone()
                is None
            )
        finally:
            connection.close()


# ── CLI ──────────────────────────────────────────────────────────────────────


DROP = object()  # write_manifest에서 해당 키를 manifest에서 삭제한다


def write_manifest(path: Path, **changes) -> Path:
    manifest = {
        "schema_version": "device-policy-backfill-v1",
        "effective_from": "2026-10-01T00:00:00Z",
        "reason": "baseline-manifest test 기준 이관",
        "registration_network": "192.168.0.0/24",
        "excluded_ips": ["192.168.0.1"],
        "devices": [
            {
                "device_id": name,
                "device_type": "SENSOR",
                "mqtt_principal": name,
                "source": "baseline-manifest:test",
                "policy": OPERATING_POLICY,
            }
            for name in ("esp32_01", "esp32_02")
        ],
    }
    manifest.update(changes)
    for key in [key for key, value in manifest.items() if value is DROP]:
        del manifest[key]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


@pytest.fixture
def cli_db(tmp_path: Path):
    path = tmp_path / "cli.db"
    apply_migrations(path, MIGRATIONS_DIR)
    connection = connect_database(path)
    insert_legacy_device(connection, "esp32_01", "192.168.0.4")
    insert_legacy_device(connection, "esp32_02", "192.168.0.5")
    connection.close()
    return path


def revision_count(path: Path) -> int:
    connection = connect_database(path)
    try:
        return count(connection, "device_policy_revisions")
    finally:
        connection.close()


class TestCli:
    def test_dry_run_is_the_default_and_changes_nothing(self, cli_db, tmp_path, capsys) -> None:
        manifest = write_manifest(tmp_path / "manifest.json")

        code = backfill_device_policies.main(["--db", str(cli_db), "--manifest", str(manifest)])

        assert code == 0
        assert "[dry-run]" in capsys.readouterr().out
        assert revision_count(cli_db) == 0

    def test_apply_creates_the_revisions(self, cli_db, tmp_path, capsys) -> None:
        manifest = write_manifest(tmp_path / "manifest.json")

        code = backfill_device_policies.main(
            ["--db", str(cli_db), "--manifest", str(manifest), "--apply"]
        )

        assert code == 0
        assert "esp32_01" in capsys.readouterr().out
        assert revision_count(cli_db) == 2

    def test_manifest_without_principal_applies(self, cli_db, tmp_path) -> None:
        manifest = write_manifest(
            tmp_path / "manifest.json",
            devices=[
                {
                    "device_id": name,
                    "device_type": "SENSOR",
                    "source": "baseline-manifest:test",
                    "policy": OPERATING_POLICY,
                }
                for name in ("esp32_01", "esp32_02")
            ],
        )

        code = backfill_device_policies.main(
            ["--db", str(cli_db), "--manifest", str(manifest), "--apply"]
        )

        assert code == 0
        assert revision_count(cli_db) == 2

    def test_blocked_backfill_exits_2_and_lists_problems(self, cli_db, tmp_path, capsys) -> None:
        manifest = write_manifest(
            tmp_path / "manifest.json",
            devices=[
                {
                    "device_id": "esp32_01",
                    "device_type": "SENSOR",
                    "mqtt_principal": "esp32_01",
                    "source": "baseline-manifest:test",
                    "policy": OPERATING_POLICY,
                }
            ],
        )

        for extra in ([], ["--apply"]):
            code = backfill_device_policies.main(
                ["--db", str(cli_db), "--manifest", str(manifest), *extra]
            )
            assert code == 2
            assert "MISSING_OVERRIDE:esp32_02" in capsys.readouterr().err
        assert revision_count(cli_db) == 0

    def test_missing_database_file_is_an_error(self, tmp_path, capsys) -> None:
        manifest = write_manifest(tmp_path / "manifest.json")

        code = backfill_device_policies.main(
            ["--db", str(tmp_path / "missing.db"), "--manifest", str(manifest)]
        )

        assert code == 2
        assert not (tmp_path / "missing.db").exists()  # 빈 DB를 만들지 않는다

    @pytest.mark.parametrize(
        "changes",
        [
            {"schema_version": "v0"},
            {"effective_from": "2026-10-01T00:00:13Z"},
            {"effective_from": "2026-10-01 00:00:00"},
            {"unknown_field": 1},
            {"devices": []},
            {"registration_network": "not-a-network"},
            {"excluded_ips": ["999.1.1.1"]},
        ],
    )
    def test_invalid_manifest_is_rejected(self, cli_db, tmp_path, capsys, changes) -> None:
        manifest = write_manifest(tmp_path / "manifest.json", **changes)

        code = backfill_device_policies.main(
            ["--db", str(cli_db), "--manifest", str(manifest), "--apply"]
        )

        assert code == 2
        assert revision_count(cli_db) == 0

    @pytest.mark.parametrize("reason", [DROP, None, 123, "", "   ", ["x"], "line1\nline2"])
    def test_invalid_reason_is_rejected_in_dry_run_and_apply(
        self, cli_db, tmp_path, capsys, reason
    ) -> None:
        manifest = write_manifest(tmp_path / "manifest.json", reason=reason)

        for extra in ([], ["--apply"]):
            code = backfill_device_policies.main(
                ["--db", str(cli_db), "--manifest", str(manifest), *extra]
            )
            assert code == 2

        assert "reason" in capsys.readouterr().err
        assert revision_count(cli_db) == 0  # "None" 같은 값이 사유로 저장되지 않는다

    @pytest.mark.parametrize(
        "changes",
        [
            {"registration_network": 123},
            {"registration_network": ["192.168.0.0/24"]},
            {"excluded_ips": "192.168.0.1"},
            {"excluded_ips": [1]},
            {"excluded_ips": {"a": "192.168.0.1"}},
        ],
    )
    def test_network_settings_with_wrong_types_are_rejected(
        self, cli_db, tmp_path, changes
    ) -> None:
        manifest = write_manifest(tmp_path / "manifest.json", **changes)

        code = backfill_device_policies.main(
            ["--db", str(cli_db), "--manifest", str(manifest), "--apply"]
        )

        assert code == 2
        assert revision_count(cli_db) == 0

    @pytest.mark.parametrize("field", ["packet_rate_max_pps", "byte_rate_max_bytes_per_second"])
    def test_huge_number_in_manifest_is_a_validation_error_not_a_traceback(
        self, cli_db, tmp_path, capsys, field
    ) -> None:
        manifest = write_manifest(
            tmp_path / "manifest.json",
            devices=[
                {
                    "device_id": name,
                    "device_type": "SENSOR",
                    "source": "baseline-manifest:test",
                    "policy": {**OPERATING_POLICY, field: 10**400},
                }
                for name in ("esp32_01", "esp32_02")
            ],
        )

        code = backfill_device_policies.main(
            ["--db", str(cli_db), "--manifest", str(manifest), "--apply"]
        )

        assert code == 2
        assert field in capsys.readouterr().err
        assert revision_count(cli_db) == 0

    def test_over_long_integer_literal_is_rejected_cleanly(self, cli_db, tmp_path) -> None:
        # Python의 정수 문자열 변환 제한에 걸리면 JSONDecodeError가 아닌 ValueError가 난다.
        manifest = tmp_path / "manifest.json"
        manifest.write_text('{"schema_version": ' + "9" * 5000 + "}", encoding="utf-8")

        assert backfill_device_policies.main(["--db", str(cli_db), "--manifest", str(manifest)]) == 2

    def test_unreadable_manifest_is_rejected(self, cli_db, tmp_path) -> None:
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")

        assert backfill_device_policies.main(["--db", str(cli_db), "--manifest", str(bad)]) == 2

    def test_duplicate_devices_in_manifest_are_rejected(self, cli_db, tmp_path) -> None:
        entry = {
            "device_id": "esp32_01",
            "device_type": "SENSOR",
            "mqtt_principal": "esp32_01",
            "source": "x",
            "policy": OPERATING_POLICY,
        }
        manifest = write_manifest(tmp_path / "manifest.json", devices=[entry, entry])

        assert (
            backfill_device_policies.main(
                ["--db", str(cli_db), "--manifest", str(manifest), "--apply"]
            )
            == 2
        )
        assert revision_count(cli_db) == 0
