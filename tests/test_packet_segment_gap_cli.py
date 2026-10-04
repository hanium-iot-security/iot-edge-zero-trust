"""Operational recovery boundaries: evidence, backup races, locks and HOLD."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import pytest

from edge.detection import run_packet_segment_gap_recovery as cli

spec = importlib.util.spec_from_file_location("gap_test_seed", Path(__file__).with_name("test_packet_segment_gap_recovery.py"))
seed_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed_module)


@pytest.fixture
def operation(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text("output/\ndata/\n")
    for args in (("init",), ("add", ".gitignore"),
                 ("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "seed")):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    output = root / "output"
    output.mkdir()
    seed = seed_module.seed_segment_gap_database(output / "iot.db")
    pcap = output / "failed-1.pcap"
    pcap.write_bytes(b"synthetic failed capture evidence")
    pcap.with_suffix(".pcap.capture.json").write_text('{"kernel_drops":56}')
    monkeypatch.delenv("ORCHESTRATOR_LOCK_PATH", raising=False)
    monkeypatch.setattr(cli, "_implementation_root", lambda: root)
    args = cli.build_parser().parse_args([
        "dry-run", "--db-path", str(seed["database_path"]), "--repository-root", str(root),
        "--capture-session-id", seed["capture_session_id"], "--failed-segment-id", str(seed["failed_segment_id"]),
        "--pcap-path", str(pcap), "--approved-by", "operator", "--reason", "Reviewed capture loss",
        "--artifact-dir", str(output), "--plan-output", str(output / "plan.json"),
    ])
    before = state(seed["database_path"])
    result = cli.dry_run(args)
    assert state(seed["database_path"]) == before
    execute = cli.build_parser().parse_args(["execute", "--db-path", str(seed["database_path"]),
                                             "--plan-file", result["plan_file"], "--confirm", cli.CONFIRMATION])
    # Windows cannot run production Execute. Only platform/locks are replaced;
    # the real SQLite backup, transaction, schema and revalidation still run.
    monkeypatch.setattr(cli.safety, "require_execute_platform", lambda platform: None)
    return seed, root, output, pcap, execute


def state(database):
    with sqlite3.connect(database) as connection:
        return ([tuple(row) for row in connection.execute("SELECT * FROM detector_checkpoints ORDER BY 1")],
                connection.execute("SELECT count(*) FROM packet_segment_gap_recoveries").fetchone()[0])


def rewrite_plan(args, change):
    path = Path(args.plan_file)
    payload = json.loads(path.read_text())
    change(payload)
    payload["plan_sha256"] = cli.recovery.calculate_plan_sha256(payload)
    path.write_text(json.dumps(payload))


def test_execute_preserves_source_and_backup_and_advances_both(operation):
    seed, _, _, pcap, args = operation
    before_pcap = pcap.read_bytes()
    result = cli.execute(args)
    assert result["database_committed"] is True
    assert pcap.read_bytes() == before_pcap
    assert state(seed["database_path"])[1] == 1
    assert state(result["backup_path"])[1] == 0
    with sqlite3.connect(seed["database_path"]) as conn:
        assert {row[0] for row in conn.execute("SELECT last_completed_window_end FROM detector_checkpoints WHERE source_table='packet_feature_logs'")} == {seed["window_end"]}


@pytest.mark.parametrize("target", ["source", "preserved", "sidecar"])
def test_changed_evidence_blocks_before_db_mutation(operation, target):
    seed, _, _, pcap, args = operation
    plan = json.loads(Path(args.plan_file).read_text())
    path = pcap if target == "source" else Path(plan["evidence"][0 if target == "preserved" else 1]["preserved"])
    path.write_bytes(b"changed")
    before = state(seed["database_path"])
    with pytest.raises(ValueError, match="evidence changed"):
        cli.execute(args)
    assert state(seed["database_path"]) == before


def test_aliasing_lock_cannot_truncate_original_evidence(operation, monkeypatch):
    seed, _, _, pcap, args = operation
    locks = (cli.safety.ResolvedRecoveryLock(pcap, ("detection_orchestrator",)),)
    monkeypatch.setattr(cli, "_resolved_locks", lambda root, database: locks)
    rewrite_plan(args, lambda plan: plan.update(locks=list(cli.safety.serialize_resolved_locks(locks))))
    content = pcap.read_bytes()
    with pytest.raises(ValueError, match="distinct"):
        cli.execute(args)
    assert pcap.read_bytes() == content
    assert state(seed["database_path"])[1] == 0


def test_external_write_during_backup_blocks(operation, monkeypatch):
    seed, _, _, _, args = operation
    real_backup = cli.safety.create_sqlite_backup
    def racing_backup(database, backup):
        artifact = real_backup(database, backup)
        with sqlite3.connect(database) as conn:
            conn.execute("UPDATE devices SET last_seen_at='2026-10-04T04:00:00Z'")
        return artifact
    monkeypatch.setattr(cli.safety, "create_sqlite_backup", racing_backup)
    before = state(seed["database_path"])
    with pytest.raises(ValueError, match="database changed during backup"):
        cli.execute(args)
    assert state(seed["database_path"]) == before


def test_reviewed_plan_change_during_backup_blocks(operation, monkeypatch):
    seed, _, _, _, args = operation
    real_backup = cli.safety.create_sqlite_backup
    def racing_backup(database, backup):
        artifact = real_backup(database, backup)
        Path(args.plan_file).write_text("{}")
        return artifact
    monkeypatch.setattr(cli.safety, "create_sqlite_backup", racing_backup)
    before = state(seed["database_path"])
    with pytest.raises(ValueError, match="plan file changed"):
        cli.execute(args)
    assert state(seed["database_path"]) == before


def test_backup_failure_leaves_checkpoints_untouched(operation, monkeypatch):
    seed, _, _, _, args = operation
    monkeypatch.setattr(cli.safety, "create_sqlite_backup", lambda *args: (_ for _ in ()).throw(OSError("disk failure")))
    before = state(seed["database_path"])
    with pytest.raises(OSError):
        cli.execute(args)
    assert state(seed["database_path"]) == before


def test_lock_cleanup_failure_reports_committed_hold(operation, monkeypatch):
    seed, _, _, _, args = operation
    @contextmanager
    def failing_cleanup(locks):
        yield
        raise OSError("cleanup failure")
    monkeypatch.setattr(cli.safety, "acquire_recovery_locks", failing_cleanup)
    with pytest.raises(cli.CommittedRecoveryError, match="database committed"):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 1


def test_result_write_failure_reports_committed_hold(operation, monkeypatch):
    seed, _, _, _, args = operation
    monkeypatch.setattr(cli, "_private_json", lambda *args: (_ for _ in ()).throw(OSError("disk failure")))
    with pytest.raises(cli.CommittedRecoveryError):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 1


def test_malformed_plan_rejected_before_backup(operation, monkeypatch):
    seed, _, _, _, args = operation
    rewrite_plan(args, lambda plan: plan.update(evidence=[{}]))
    monkeypatch.setattr(cli.safety, "create_sqlite_backup", lambda *args: pytest.fail("backup should not run"))
    with pytest.raises(ValueError, match="envelope"):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 0


def test_conflicting_shell_lock_override_rejected(operation, monkeypatch):
    seed, _, _, _, args = operation
    monkeypatch.setenv("ORCHESTRATOR_LOCK_PATH", "unrelated.lock")
    with pytest.raises(ValueError, match="shell lock override"):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 0


def test_different_implementation_checkout_rejected(operation, monkeypatch):
    seed, root, _, _, args = operation
    monkeypatch.setattr(cli, "_implementation_root", lambda: root.parent)
    with pytest.raises(ValueError, match="executing implementation"):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO/symlink file safety")
def test_non_regular_plan_rejected_without_open(tmp_path):
    fifo = tmp_path / "plan.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        cli._read_plan(fifo)
    source = tmp_path / "plan.json"
    source.write_text("{}")
    link = tmp_path / "plan.link"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="regular file"):
        cli._read_plan(link)
