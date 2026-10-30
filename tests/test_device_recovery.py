"""Ordinary recovery must atomically save evidence without full-DB copying."""

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from backend.app.config import settings
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import baseline_recovery as baseline
from edge.trust import device_recovery as core
from edge.trust.firewall_runtime_snapshot import SNAPSHOT_SCHEMA_VERSION


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "recovery.db"
    apply_migrations(path, MIGRATIONS_DIR)
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO devices(device_id, ip_address, status, trust_score) VALUES (?, ?, ?, ?)",
            [("esp32_02", "192.168.0.5", "isolated", 20),
             ("pico_01", "192.168.0.8", "normal", 100)],
        )
    snapshot = tmp_path / "runtime.json"
    snapshot.write_text(json.dumps({
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "available": True, "managed_rules": [], "error": None,
    }), encoding="utf-8")
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_path", str(snapshot))
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "firewall.lock"))
    return path


def recover(database, **overrides):
    arguments = dict(
        db_path=database, device_ids=["esp32_02"], expected_trust_scores={"esp32_02": 20},
        confirm=baseline.CONFIRMATION,
        operation_id="20261030T010000Z-test", reason="malicious firmware removed",
        requested_by="operator", approved_by="operator", requested_at="2026-10-30T01:00:00Z",
        preflight={"can_execute": True},
    )
    return core.execute_device_recovery(**(arguments | overrides))


def state(database):
    with sqlite3.connect(database) as db:
        return db.execute("SELECT status, trust_score FROM devices WHERE device_id='esp32_02'").fetchone()


def receipts(database):
    with sqlite3.connect(database) as db:
        return [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM device_recovery_audits")]


def test_success_is_atomic_and_never_copies_or_scans_whole_database(database, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("ordinary recovery must not run full backup / integrity scan / JSON publication")
    for name in ["_create_backup", "_verify_database_path", "_write_json_log"]:
        monkeypatch.setattr(baseline, name, forbidden)
    result = recover(database)
    assert state(database) == ("normal", 100)
    assert receipts(database) == [result]
    assert result["backup_reference"] is None
    assert result["before_device"]["ip_address"] == "192.168.0.5"
    assert result["before_trust_score"] == 20
    assert result["runtime_firewall_check"]["esp32_02"]["passed"] is True
    assert result["checked_devices"]["esp32_02"]["ip_address"] == "192.168.0.5"
    assert not (database.parent / "not-created").exists()
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT status,trust_score FROM devices WHERE device_id='pico_01'").fetchone() == ("normal", 100)


@pytest.mark.parametrize("failure", ["audit_insert", "serialization", "update", "after_update", "commit"])
def test_failure_before_commit_rolls_back_state_and_success_receipt(database, monkeypatch, failure):
    options = {}
    if failure == "serialization":
        options["preflight"] = {"cannot_serialize": object()}
    elif failure == "commit":
        connect = sqlite3.connect
        class FailingCommit(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError("forced commit failure")
        monkeypatch.setattr(core.sqlite3, "connect", lambda *a, **k: connect(*a, **(k | {"factory": FailingCommit})))
    else:
        sql = {
            "audit_insert": "CREATE TRIGGER force_audit_failure BEFORE INSERT ON device_recovery_audits BEGIN SELECT RAISE(ABORT,'forced insert'); END",
            "update": "CREATE TRIGGER force_update_failure BEFORE UPDATE ON devices BEGIN SELECT RAISE(ABORT,'forced update'); END",
            "after_update": "CREATE TRIGGER corrupt_update AFTER UPDATE ON devices WHEN NEW.device_id='esp32_02' BEGIN UPDATE devices SET trust_score=99 WHERE device_id=NEW.device_id; END",
        }[failure]
        with sqlite3.connect(database) as db:
            db.execute(sql)
    with pytest.raises(baseline.BaselineRecoveryError):
        recover(database, **options)
    assert state(database) == ("isolated", 20)
    assert receipts(database) == []


def test_expired_runtime_evidence_after_insert_rolls_back_both(database, monkeypatch):
    real_insert = core.insert_audit
    def expire_after_insert(db, payload):
        real_insert(db, payload)
        # Simulate the file expiring while the transaction is still open.
        snapshot = json.loads(Path(settings.firewall_runtime_snapshot_path).read_text())
        snapshot["observed_at"] = "2020-01-01T00:00:00Z"
        Path(settings.firewall_runtime_snapshot_path).write_text(json.dumps(snapshot))
    monkeypatch.setattr(core, "insert_audit", expire_after_insert)
    with pytest.raises(baseline.BaselineRecoveryHoldError):
        recover(database)
    assert state(database) == ("isolated", 20)
    assert receipts(database) == []


@pytest.mark.parametrize("change", ["ip", "firewall", "pending_event"])
def test_state_changes_while_waiting_for_firewall_lock_are_rechecked(database, monkeypatch, change):
    real_lock = core.single_instance_lock
    @contextmanager
    def changing_lock(path, **kwargs):
        with real_lock(path, **kwargs):
            if str(path) == settings.firewall_lock_path:
                with sqlite3.connect(database) as db:
                    if change == "ip":
                        db.execute("UPDATE devices SET ip_address='192.168.0.55' WHERE device_id='esp32_02'")
                    elif change == "firewall":
                        db.execute("INSERT INTO firewall_rules(device_id,source_ip,status) VALUES ('esp32_02','192.168.0.5','PENDING')")
                    else:
                        db.execute("INSERT INTO detection_events(device_id,detector_type,event_type,severity,score_delta,applied_to_score) VALUES ('esp32_02','AI','AI_PACKET_ANOMALY','medium',-15,0)")
            yield
    monkeypatch.setattr(core, "single_instance_lock", changing_lock)
    with pytest.raises(baseline.BaselineRecoveryError):
        recover(database)
    assert state(database) == ("isolated", 20)
    assert receipts(database) == []


def test_waiting_for_firewall_lock_leaves_writer_available(database, monkeypatch):
    real_lock = core.single_instance_lock
    @contextmanager
    def checking_lock(path, **kwargs):
        if str(path) == settings.firewall_lock_path:
            with sqlite3.connect(database, timeout=.1) as writer:
                writer.execute("UPDATE devices SET last_seen_at='2026-10-30T01:00:00Z' WHERE device_id='pico_01'")
        with real_lock(path, **kwargs):
            yield
    monkeypatch.setattr(core, "single_instance_lock", checking_lock)
    recover(database)
    assert state(database) == ("normal", 100)


def test_same_command_lock_as_full_baseline_prevents_concurrent_reset(database):
    lock = database.with_suffix(database.suffix + ".baseline-recovery.lock")
    with baseline.single_instance_lock(lock):
        with pytest.raises(baseline.BaselineRecoveryInProgressError):
            recover(database)
    assert state(database) == ("isolated", 20)
    assert receipts(database) == []


@pytest.mark.parametrize("sql", [
    "UPDATE device_recovery_audits SET requested_at='changed'",
    "DELETE FROM device_recovery_audits",
    "INSERT OR REPLACE INTO device_recovery_audits SELECT * FROM device_recovery_audits",
])
def test_committed_receipt_is_immutable_even_with_replace(database, sql):
    result = recover(database)
    with sqlite3.connect(database) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(sql)
    assert receipts(database) == [result]


def test_commit_response_error_does_not_erase_committed_state_or_receipt(database, monkeypatch):
    connect = sqlite3.connect
    class LostCommitResponse(sqlite3.Connection):
        def commit(self):
            super().commit()
            raise OSError("response lost after commit")
    monkeypatch.setattr(core.sqlite3, "connect", lambda *a, **k: connect(*a, **(k | {"factory": LostCommitResponse})))
    with pytest.raises(baseline.BaselineRecoveryCommittedError):
        recover(database)
    assert state(database) == ("normal", 100)
    assert receipts(database)[0]["result"] == "SUCCESS"


def test_unmigrated_schema_holds_without_changing_device(database):
    with sqlite3.connect(database) as db:
        db.execute("DROP TABLE device_recovery_audits")
    with pytest.raises(baseline.BaselineRecoveryHoldError, match="017"):
        recover(database)
    assert state(database) == ("isolated", 20)


def test_two_callers_commit_exactly_one_recovery(database):
    ready = threading.Barrier(2)
    def attempt(index):
        ready.wait(timeout=5)
        try:
            return recover(database, operation_id=f"concurrent-{index}")["result"]
        except baseline.BaselineRecoveryError:
            return "REJECTED"
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, range(2)))
    assert sorted(outcomes) == ["REJECTED", "SUCCESS"]
    assert state(database) == ("normal", 100)
    assert len(receipts(database)) == 1


def test_non_wal_database_is_not_silently_reconfigured(database):
    with sqlite3.connect(database) as db:
        db.execute("PRAGMA journal_mode=DELETE")
    with pytest.raises(baseline.BaselineRecoveryHoldError, match="WAL"):
        recover(database)
    assert state(database) == ("isolated", 20)
    assert receipts(database) == []
    with sqlite3.connect(database) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
