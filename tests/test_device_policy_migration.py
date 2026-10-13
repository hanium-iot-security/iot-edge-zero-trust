"""Migration 007(device_policy_revisions)과 DB 제약·트리거 검증.

서비스 검증을 우회하는 직접 SQL(seed/backfill/수동 작업)도 같은 규칙을 지켜야 한다.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from db.migration_runner import (
    MIGRATIONS_DIR,
    MigrationError,
    apply_migrations,
    connect_database,
)
from edge.policy.device_policy_repository import diagnose_device_ip_conflicts
from tests.device_policy_support import (
    count,
    insert_legacy_device,
    insert_revision_raw,
    open_db,
)


OLD_MIGRATIONS = (
    "001_init.sql",
    "002_packet_gateway.sql",
    "003_phase4_detection.sql",
    "004_trust_score_compensation.sql",
    "005_packet_checkpoint_recovery.sql",
    "006_firewall_release_requests.sql",
)


def migrations_subset(destination: Path, names: tuple[str, ...]) -> Path:
    destination.mkdir(parents=True)
    for name in names:
        shutil.copy(MIGRATIONS_DIR / name, destination / name)
    return destination


def columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]


@pytest.fixture
def db(tmp_path: Path):
    connection = open_db(tmp_path)
    insert_legacy_device(connection, "dev_a", "192.168.0.10")
    insert_legacy_device(connection, "dev_b", "192.168.0.11")
    try:
        yield connection
    finally:
        connection.close()


# ── 적용 ─────────────────────────────────────────────────────────────────────


class TestApply:
    def test_devices_gains_nullable_registration_columns_and_keeps_trust_columns(
        self, db: sqlite3.Connection
    ) -> None:
        names = columns(db, "devices")

        for kept in ("device_id", "ip_address", "status", "trust_score", "last_seen_at", "created_at"):
            assert kept in names
        for added in ("device_type", "mqtt_principal", "registration_effective_from"):
            assert added in names
        row = db.execute(
            "SELECT device_type, mqtt_principal, registration_effective_from "
            "FROM devices WHERE device_id = 'dev_a'"
        ).fetchone()
        assert tuple(row) == (None, None, None)

    def test_existing_006_database_keeps_trust_firewall_and_history_data(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "existing-006.db"
        apply_migrations(path, migrations_subset(tmp_path / "old", OLD_MIGRATIONS))
        original_columns = (
            "device_id, ip_address, status, trust_score, last_seen_at, created_at"
        )
        with connect_database(path) as connection:
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
                VALUES ('esp32_02', '2026-10-01T00:00:00Z', '2026-10-01T00:00:10Z',
                        45, -20, -20, -20, 25, '[1]', 'trust-v2')
                """
            )
            original_rule_columns = ", ".join(row["name"] for row in connection.execute("PRAGMA table_info(firewall_rules)"))
            queries = {
                "devices": f"SELECT {original_columns} FROM devices ORDER BY device_id",
                "events": "SELECT * FROM detection_events ORDER BY id",
                "isolation": "SELECT * FROM isolation_history ORDER BY id",
                "rules": f"SELECT {original_rule_columns} FROM firewall_rules ORDER BY id",
                "history": "SELECT * FROM trust_score_history ORDER BY id",
            }
            before = {
                name: [tuple(row) for row in connection.execute(sql)]
                for name, sql in queries.items()
            }

        result = apply_migrations(path, MIGRATIONS_DIR)

        assert result.applied_versions == [7, 8, 9, 10, 11, 12, 13]
        with connect_database(path) as connection:
            after = {
                name: [tuple(row) for row in connection.execute(sql)]
                for name, sql in queries.items()
            }
            assert count(connection, "device_policy_revisions") == 0
        assert after == before

    def test_duplicate_existing_ip_fails_007_and_rolls_back_everything(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "duplicate-ip.db"
        apply_migrations(path, migrations_subset(tmp_path / "old", OLD_MIGRATIONS))
        with connect_database(path) as connection:
            insert_legacy_device(connection, "dev_a", "192.168.0.7")
            insert_legacy_device(connection, "dev_b", "192.168.0.7")
            diagnosis = diagnose_device_ip_conflicts(connection)

        # 사전 진단은 자료를 바꾸지 않고 무엇이 문제인지 알려 준다.
        assert diagnosis["duplicate_ips"] == [
            {"ip_address": "192.168.0.7", "device_ids": ["dev_a", "dev_b"]}
        ]

        with pytest.raises(MigrationError):
            apply_migrations(path, MIGRATIONS_DIR)

        with connect_database(path) as connection:
            versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations")]
            assert 7 not in versions
            assert "device_type" not in columns(connection, "devices")
            assert connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'device_policy_revisions'"
            ).fetchone() is None
            # 자료는 임의로 바뀌지 않았다.
            ips = [row[0] for row in connection.execute("SELECT ip_address FROM devices")]
            assert ips == ["192.168.0.7", "192.168.0.7"]

    def test_diagnose_reports_blank_ip_devices(self, tmp_path: Path) -> None:
        path = tmp_path / "blank-ip.db"
        apply_migrations(path, migrations_subset(tmp_path / "old", OLD_MIGRATIONS))
        with connect_database(path) as connection:
            insert_legacy_device(connection, "dev_blank", "")
            insert_legacy_device(connection, "dev_null", None)
            insert_legacy_device(connection, "dev_ok", "192.168.0.9")

            diagnosis = diagnose_device_ip_conflicts(connection)

        assert diagnosis["blank_ip_device_ids"] == ["dev_blank", "dev_null"]
        assert diagnosis["duplicate_ips"] == []


# ── devices 제약 ─────────────────────────────────────────────────────────────


class TestDevicesConstraints:
    def test_duplicate_ip_is_rejected_but_blank_ips_may_repeat(
        self, db: sqlite3.Connection
    ) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            insert_legacy_device(db, "dev_c", "192.168.0.10")

        insert_legacy_device(db, "dev_blank1", "")
        insert_legacy_device(db, "dev_blank2", "")
        insert_legacy_device(db, "dev_null1", None)
        insert_legacy_device(db, "dev_null2", None)

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.000.4",  # 앞자리 0은 다른 정규화 형태
            "192.168.0.04",
            "192.168.0",
            "192.168.0.4.5",
            "a.b.c.d",
            " 192.168.0.4",
            "192.168.0.4 ",
            "192..0.4",
            ".192.168.0.4",
            "192.168.0.4.",
            "192.168.0.4/24",
            "1234567890.1.1.1",
        ],
    )
    def test_non_canonical_ip_shape_is_rejected_on_insert_and_update(
        self, db: sqlite3.Connection, ip: str
    ) -> None:
        with pytest.raises(sqlite3.IntegrityError, match="canonical"):
            insert_legacy_device(db, "dev_x", ip)

        insert_legacy_device(db, "dev_blank", "")
        with pytest.raises(sqlite3.IntegrityError, match="canonical"):
            db.execute("UPDATE devices SET ip_address = ? WHERE device_id = 'dev_blank'", (ip,))

    def test_device_without_ip_can_receive_a_canonical_ip(self, db: sqlite3.Connection) -> None:
        insert_legacy_device(db, "dev_blank", None)

        db.execute("UPDATE devices SET ip_address = '192.168.0.50' WHERE device_id = 'dev_blank'")

        row = db.execute("SELECT ip_address FROM devices WHERE device_id = 'dev_blank'").fetchone()
        assert row[0] == "192.168.0.50"

    def test_ip_uniqueness_also_applies_to_updates(self, db: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE devices SET ip_address = '192.168.0.11' WHERE device_id = 'dev_a'")

    def test_registration_effective_from_is_immutable_once_set(
        self, db: sqlite3.Connection
    ) -> None:
        db.execute(
            "UPDATE devices SET registration_effective_from = '2026-10-02T00:00:10Z' "
            "WHERE device_id = 'dev_a'"
        )

        for statement in (
            "UPDATE devices SET registration_effective_from = '2026-10-02T00:00:20Z' "
            "WHERE device_id = 'dev_a'",
            "UPDATE devices SET registration_effective_from = NULL WHERE device_id = 'dev_a'",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                db.execute(statement)
        # 같은 값으로 다시 쓰는 것은 변경이 아니다.
        db.execute(
            "UPDATE devices SET registration_effective_from = '2026-10-02T00:00:10Z' "
            "WHERE device_id = 'dev_a'"
        )

    def test_unset_registration_effective_from_can_be_filled_once(
        self, db: sqlite3.Connection
    ) -> None:
        db.execute(
            "UPDATE devices SET registration_effective_from = '2026-10-02T00:00:10Z' "
            "WHERE device_id = 'dev_b'"
        )

        row = db.execute(
            "SELECT registration_effective_from FROM devices WHERE device_id = 'dev_b'"
        ).fetchone()
        assert row[0] == "2026-10-02T00:00:10Z"

    def test_trust_fields_remain_updatable(self, db: sqlite3.Connection) -> None:
        db.execute(
            "UPDATE devices SET status = 'warning', trust_score = 70, "
            "last_seen_at = '2026-10-02T00:00:00Z' WHERE device_id = 'dev_a'"
        )

        row = db.execute(
            "SELECT status, trust_score, last_seen_at FROM devices WHERE device_id = 'dev_a'"
        ).fetchone()
        assert tuple(row) == ("warning", 70, "2026-10-02T00:00:00Z")

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            ("device_type", "ROUTER"),
            ("device_type", "sensor"),
            ("mqtt_principal", ""),
            ("mqtt_principal", "x" * 129),
            ("registration_effective_from", "2026-10-02T00:00:13Z"),
            ("registration_effective_from", "2026-10-02T00:00:10"),
            ("registration_effective_from", "2026-13-02T00:00:10Z"),
        ],
    )
    def test_registration_metadata_checks(
        self, db: sqlite3.Connection, column: str, value: str
    ) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(f"UPDATE devices SET {column} = ? WHERE device_id = 'dev_a'", (value,))


# ── revision 제약 ────────────────────────────────────────────────────────────


class TestRevisionConstraints:
    def test_valid_revision_is_stored(self, db: sqlite3.Connection) -> None:
        insert_revision_raw(db)

        row = db.execute(
            "SELECT revision, effective_from, registration_state, publish_count_max "
            "FROM device_policy_revisions"
        ).fetchone()
        assert tuple(row) == (1, "2026-10-02T00:00:10Z", "PENDING", 15)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("revision", 0),
            ("revision", -1),
            ("revision", 1.5),
            ("revision", "x"),
            ("effective_from", "2026-10-02T00:00:13Z"),  # 10초 경계 아님
            ("effective_from", "2026-10-02T00:00:10"),  # Z 없음
            ("effective_from", "2026-10-02 00:00:10Z"),
            ("effective_from", "2026-10-02T00:00:10.500Z"),  # 소수 초 금지
            ("effective_from", "2026-13-02T00:00:10Z"),  # 없는 날짜
            ("effective_from", None),
            ("registration_state", "NORMAL"),
            ("registration_state", "pending"),
            ("registration_state", None),
            ("policy_profile", ""),
            ("expected_publish_interval_seconds", 0),
            ("expected_publish_interval_seconds", -1),
            ("expected_publish_interval_seconds", 86401),
            ("expected_publish_interval_seconds", "fast"),
            ("publish_count_max", 0),
            ("publish_count_max", 10001),
            ("publish_count_max", 15.5),  # 정수 컬럼에 소수
            ("publish_count_max", "many"),
            ("payload_size_max_bytes", 0),
            ("payload_size_max_bytes", 1048577),
            ("packet_rate_max_pps", 0),
            ("packet_rate_max_pps", 100001),
            ("packet_rate_max_pps", float("nan")),  # NaN은 NULL로 저장돼 NOT NULL에서 거부
            ("packet_rate_max_pps", float("inf")),
            ("byte_rate_max_bytes_per_second", -1),
            ("byte_rate_max_bytes_per_second", 125000001),
            ("created_at", "yesterday"),
            ("created_at", "2026-10-02T00:00:03"),
            ("created_by", ""),
            ("created_by", "   "),
            ("created_by", "x" * 129),
            ("reason", ""),
            ("reason", "  "),
            ("reason", "x" * 501),
        ],
    )
    def test_invalid_value_is_rejected(self, db: sqlite3.Connection, field, value) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            insert_revision_raw(db, **{field: value})

        assert count(db, "device_policy_revisions") == 0

    def test_zero_is_never_a_valid_threshold(self, db: sqlite3.Connection) -> None:
        # 0을 "탐지 끄기"로 해석하지 않는다(저장 자체를 거부).
        for field in (
            "publish_count_max",
            "payload_size_max_bytes",
            "packet_rate_max_pps",
            "byte_rate_max_bytes_per_second",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                insert_revision_raw(db, **{field: 0})

    def test_unknown_device_is_rejected_by_foreign_key(self, db: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            insert_revision_raw(db, device_id="ghost")

    def test_device_with_revisions_cannot_be_deleted(self, db: sqlite3.Connection) -> None:
        insert_revision_raw(db)

        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            db.execute("DELETE FROM devices WHERE device_id = 'dev_a'")

    def test_revision_numbers_must_be_sequential_per_device(self, db: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError, match="previous revision plus one"):
            insert_revision_raw(db, revision=2)
        insert_revision_raw(db, revision=1)
        with pytest.raises(sqlite3.IntegrityError, match="previous revision plus one"):
            insert_revision_raw(db, revision=3, effective_from="2026-10-02T00:00:20Z")
        with pytest.raises(sqlite3.IntegrityError):
            insert_revision_raw(db, revision=1, effective_from="2026-10-02T00:00:30Z")
        # 다른 기기의 순번은 독립이다.
        insert_revision_raw(db, device_id="dev_b", revision=1)

    def test_effective_from_must_increase(self, db: sqlite3.Connection) -> None:
        insert_revision_raw(db, revision=1, effective_from="2026-10-02T00:00:20Z")

        for same_or_earlier in ("2026-10-02T00:00:20Z", "2026-10-02T00:00:10Z"):
            with pytest.raises(sqlite3.IntegrityError):
                insert_revision_raw(db, revision=2, effective_from=same_or_earlier)

        insert_revision_raw(db, revision=2, effective_from="2026-10-02T00:00:30Z")

    def test_state_transitions_are_enforced_for_direct_inserts(
        self, db: sqlite3.Connection
    ) -> None:
        insert_revision_raw(db, revision=1, registration_state="PENDING")
        insert_revision_raw(
            db, revision=2, registration_state="ACTIVE", effective_from="2026-10-02T00:00:20Z"
        )
        with pytest.raises(sqlite3.IntegrityError, match="cannot return to PENDING"):
            insert_revision_raw(
                db, revision=3, registration_state="PENDING", effective_from="2026-10-02T00:00:30Z"
            )
        insert_revision_raw(
            db, revision=3, registration_state="DISABLED", effective_from="2026-10-02T00:00:30Z"
        )
        for state in ("DISABLED", "ACTIVE", "PENDING"):
            with pytest.raises(sqlite3.IntegrityError, match="DISABLED device"):
                insert_revision_raw(
                    db, revision=4, registration_state=state, effective_from="2026-10-02T00:00:40Z"
                )

    def test_existing_revisions_are_immutable(self, db: sqlite3.Connection) -> None:
        insert_revision_raw(db)

        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE device_policy_revisions SET publish_count_max = 99")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE device_policy_revisions SET reason = 'changed'")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("DELETE FROM device_policy_revisions")

        assert db.execute("SELECT publish_count_max FROM device_policy_revisions").fetchone()[0] == 15

    def test_failed_insert_leaves_no_partial_row(self, db: sqlite3.Connection) -> None:
        db.execute("BEGIN IMMEDIATE")
        insert_revision_raw(db, revision=1)
        with pytest.raises(sqlite3.IntegrityError):
            insert_revision_raw(db, revision=3, effective_from="2026-10-02T00:00:20Z")
        db.execute("ROLLBACK")

        assert count(db, "device_policy_revisions") == 0
