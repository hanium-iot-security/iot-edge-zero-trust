from pathlib import Path
import sqlite3

import pytest

from db.migration_runner import (
    MigrationError,
    _apply_single_migration,
    apply_migrations,
    connect_database,
    discover_migrations,
)


MIGRATIONS_DIR = Path("db/migrations")


def _seed_device_and_event(connection: sqlite3.Connection) -> None:
    connection.execute("INSERT INTO devices(device_id) VALUES ('esp32_direct')")
    connection.execute(
        """
        INSERT INTO detection_events(id, device_id, detector_type, event_type)
        VALUES (7, 'esp32_direct', 'RULE', 'DIRECT_ISOLATION')
        """
    )


def _insert_direct_rule(connection: sqlite3.Connection, **overrides) -> int:
    values = {
        "device_id": "esp32_direct",
        "source_ip": "192.168.0.77",
        "scope": "PI_INPUT_IPV4_ALL",
        "protocol": None,
        "dest_port": None,
        "trigger_event_id": 7,
        "source_rule_id": None,
        "approved_policy_revision": 1,
        "requested_by": "system:trust-score-v2",
        "request_id": "11111111-1111-4111-8111-111111111111",
        "reason": "trust score crossed isolation threshold",
    }
    values.update(overrides)
    columns = ", ".join(values)
    parameters = ", ".join(f":{column}" for column in values)
    cursor = connection.execute(
        f"INSERT INTO firewall_rules ({columns}) VALUES ({parameters})", values
    )
    return int(cursor.lastrowid)


def test_direct_root_ipv4_rule_is_accepted_without_mqtt_parent(tmp_path: Path) -> None:
    db_path = tmp_path / "direct.db"
    result = apply_migrations(db_path, MIGRATIONS_DIR)
    assert result.applied_versions == list(range(1, 19))
    with connect_database(db_path) as connection:
        _seed_device_and_event(connection)
        rule_id = _insert_direct_rule(connection)
        row = connection.execute("SELECT * FROM firewall_rules WHERE id = ?", (rule_id,)).fetchone()
        assert row["scope"] == "PI_INPUT_IPV4_ALL"
        assert row["source_rule_id"] is None
        assert connection.execute("SELECT count(*) FROM firewall_rules").fetchone()[0] == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"device_id": None},
        {"device_id": "missing-device"},
        {"trigger_event_id": None},
        {"trigger_event_id": 0},
        {"trigger_event_id": -1},
        {"trigger_event_id": 999},
        {"trigger_event_id": "invalid-event"},
        {"trigger_event_id": 7.5},
        {"requested_by": None},
        {"requested_by": ""},
        {"requested_by": "   "},
        {"requested_by": "operator@example"},
        {"requested_by": "system:trust-score-v2 "},
        {"approved_policy_revision": None},
        {"approved_policy_revision": 0},
        {"approved_policy_revision": -1},
        {"approved_policy_revision": "invalid-revision"},
        {"approved_policy_revision": 1.5},
        {"request_id": None},
        {"request_id": ""},
        {"request_id": "11111111-1111-3111-8111-111111111111"},
        {"request_id": "11111111-1111-4111-c111-111111111111"},
        {"request_id": "AAAAAAAA-1111-4111-8111-111111111111"},
        {"request_id": "111111111111-4111-8111-1111-11111111"},
        {"request_id": "g1111111-1111-4111-8111-111111111111"},
        {"reason": None},
        {"reason": ""},
        {"reason": "   "},
        {"protocol": "tcp"},
        {"dest_port": 1883},
    ],
)
def test_direct_root_rejects_missing_or_malformed_approval(
    tmp_path: Path, overrides: dict,
) -> None:
    db_path = tmp_path / "invalid-direct.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_device_and_event(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_direct_rule(connection, **overrides)
        assert connection.execute("SELECT count(*) FROM firewall_rules").fetchone()[0] == 0


def _through_017(tmp_path: Path) -> Path:
    migrations_dir = tmp_path / "through-017"
    migrations_dir.mkdir()
    for path in MIGRATIONS_DIR.glob("*.sql"):
        if int(path.name.split("_", 1)[0]) <= 17:
            (migrations_dir / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    db_path = tmp_path / "existing-017.db"
    assert apply_migrations(db_path, migrations_dir).applied_versions == list(range(1, 18))
    return db_path


def _seed_historical_rows(connection: sqlite3.Connection) -> None:
    _seed_device_and_event(connection)
    connection.execute(
        """
        INSERT INTO firewall_rules (
            id, device_id, source_ip, status, reason, trigger_event_id,
            applied_at, released_at, last_error, created_at, updated_at,
            retry_count, last_attempted_at, next_retry_at, requested_by
        ) VALUES (
            10, 'esp32_direct', '192.168.0.77', 'APPLIED', 'legacy MQTT', 7,
            '2026-10-01T00:00:00Z', NULL, 'old retry error',
            '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z',
            2, '2026-10-02T00:00:00Z', '2026-10-03T00:00:00Z', 'legacy-system'
        )
        """
    )
    # The 011 child branch permits absent device/trigger evidence and a human actor.
    _insert_direct_rule(
        connection, id=100, device_id=None, trigger_event_id=None,
        source_rule_id=10, requested_by="operator@example", status="REMOVED",
        applied_at="2026-10-04T00:00:00Z", released_at="2026-10-05T00:00:00Z",
        created_at="2026-10-04T00:00:00Z", updated_at="2026-10-05T00:00:00Z",
    )
    connection.execute(
        """
        INSERT INTO firewall_release_requests (
            id, firewall_rule_id, status, requested_by, reason, requested_at, processed_at
        ) VALUES (20, 100, 'SUCCEEDED', 'operator@example', 'historical child release',
                  '2026-10-05T00:00:00Z', '2026-10-05T00:00:01Z')
        """
    )
    connection.execute(
        """
        INSERT INTO firewall_release_requests (
            id, firewall_rule_id, requested_by, reason, requested_at
        ) VALUES (21, 10, 'operator@example', 'parent release', '2026-10-06T00:00:00Z')
        """
    )
    connection.execute(
        """
        INSERT INTO isolation_history (id, device_id, action, reason, trust_score, trigger_event_id)
        VALUES (55, 'esp32_direct', 'ISOLATED', 'old isolation audit', 20, 7)
        """
    )
    connection.execute(
        """
        INSERT INTO device_recovery_audits(operation_id, device_id, requested_at, payload_json)
        VALUES ('recovery-017', 'esp32_direct', '2026-10-07T00:00:00Z', '{"old":true}')
        """
    )
    connection.execute(
        "INSERT INTO firewall_rules(id, source_ip, status) VALUES (900, '192.168.0.99', 'REMOVED')"
    )
    connection.execute("DELETE FROM firewall_rules WHERE id = 900")


def _rows(connection: sqlite3.Connection, table: str) -> list[tuple]:
    order = "name" if table == "sqlite_sequence" else "rowid"
    return [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY {order}")]


def _snapshot(connection: sqlite3.Connection) -> dict:
    return {
        "rows": {
            table: _rows(connection, table)
            for table in (
                "firewall_rules", "firewall_release_requests", "isolation_history",
                "device_recovery_audits", "sqlite_sequence",
            )
        },
        "columns": [tuple(row) for row in connection.execute("PRAGMA table_info(firewall_rules)")],
        "foreign_keys": [tuple(row) for row in connection.execute("PRAGMA foreign_key_list(firewall_rules)")],
        "release_foreign_keys": [
            tuple(row) for row in connection.execute("PRAGMA foreign_key_list(firewall_release_requests)")
        ],
        "indexes": [
            tuple(row) for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'firewall_rules' ORDER BY name"
            )
        ],
    }


def test_018_preserves_legacy_rows_links_audits_indexes_and_sequence(tmp_path: Path) -> None:
    db_path = _through_017(tmp_path)
    with connect_database(db_path) as connection:
        _seed_historical_rows(connection)
        before = _snapshot(connection)

    assert apply_migrations(db_path, MIGRATIONS_DIR).applied_versions == [18]
    with connect_database(db_path) as connection:
        assert _snapshot(connection) == before
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        rule_id = _insert_direct_rule(
            connection, request_id="22222222-2222-4222-8222-222222222222",
        )
        assert rule_id == 901
        # Both scopes remain independently unique for the same source address.
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
            _insert_direct_rule(connection, request_id="33333333-3333-4333-8333-333333333333")
        # A release targets this direct rule and keeps the existing exact-rule FK.
        connection.execute(
            """
            INSERT INTO firewall_release_requests(firewall_rule_id, requested_by, reason, requested_at)
            VALUES (?, 'operator@example', 'direct release', '2026-10-08T00:00:00Z')
            """, (rule_id,),
        )
        for protected_rule in (10, 100, rule_id):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM firewall_rules WHERE id = ?", (protected_rule,))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE device_recovery_audits SET payload_json = '{}' ")
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute("DELETE FROM device_recovery_audits")
        after = _snapshot(connection)

    repeated = apply_migrations(db_path, MIGRATIONS_DIR)
    assert repeated.applied_versions == []
    assert repeated.skipped_versions == list(range(1, 19))
    with connect_database(db_path) as connection:
        assert _snapshot(connection) == after


@pytest.mark.parametrize("status", ["PENDING", "APPLIED", "FAILED", "REMOVED"])
def test_direct_root_evidence_cannot_be_removed_by_set_null(tmp_path: Path, status: str) -> None:
    db_path = tmp_path / "protected-evidence.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_device_and_event(connection)
        rule_id = _insert_direct_rule(connection, status=status)
        for statement in (
            "DELETE FROM detection_events WHERE id = 7",
            "DELETE FROM devices WHERE device_id = 'esp32_direct'",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
                connection.execute(statement)
        row = connection.execute("SELECT * FROM firewall_rules WHERE id = ?", (rule_id,)).fetchone()
        assert row["device_id"] == "esp32_direct"
        assert row["trigger_event_id"] == 7
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_018_constraint_failure_rolls_back_rebuild_and_restores_foreign_keys(tmp_path: Path) -> None:
    db_path = _through_017(tmp_path)
    migrations_dir = tmp_path / "failing-018"
    migrations_dir.mkdir()
    for path in MIGRATIONS_DIR.glob("*.sql"):
        sql = path.read_text(encoding="utf-8")
        if path.name == "018_direct_ipv4_isolation.sql":
            sql = sql.replace("id INTEGER PRIMARY KEY AUTOINCREMENT,", "id INTEGER PRIMARY KEY AUTOINCREMENT CHECK(id < 100),", 1)
        (migrations_dir / path.name).write_text(sql, encoding="utf-8")
    migration = discover_migrations(migrations_dir)[-1]
    with connect_database(db_path) as connection:
        _seed_historical_rows(connection)
        before = _snapshot(connection)
        schema_before = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'firewall_rules'"
        ).fetchone()[0]
        with pytest.raises(MigrationError, match="018_direct_ipv4_isolation.*CHECK"):
            _apply_single_migration(connection, migration)
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert _snapshot(connection) == before
        assert connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'firewall_rules'"
        ).fetchone()[0] == schema_before
        assert connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 17
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name IN ('firewall_rules_018', 'firewall_sequence_018')"
        ).fetchall() == []
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    assert apply_migrations(db_path, MIGRATIONS_DIR).applied_versions == [18]
