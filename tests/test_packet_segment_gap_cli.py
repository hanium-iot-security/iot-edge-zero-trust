"""Operational recovery boundaries: evidence, backup races, locks and HOLD."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import pytest

from edge.detection import run_packet_segment_gap_recovery as cli


def test_resolved_settings_binding_excludes_credential_values(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKET_IF_ARTIFACT_DIR", "")
    monkeypatch.setenv("RECOVERY_ADMIN_API_KEY", "private-test-value-a")
    before = cli._deployment_binding(tmp_path)
    monkeypatch.setenv("RECOVERY_ADMIN_API_KEY", "private-test-value-b")
    after = cli._deployment_binding(tmp_path)
    assert before["resolved_settings_sha256"] == after["resolved_settings_sha256"]
    monkeypatch.setenv("PACKET_IF_EXPECTED_MODEL_VERSION", "changed-public-model-version")
    assert cli._deployment_binding(tmp_path)["resolved_settings_sha256"] != after["resolved_settings_sha256"]

import test_packet_segment_gap_recovery as seed_module


def test_chain_parser_requires_explicit_ordered_ids_and_pcaps():
    args = cli.build_parser().parse_args([
        "dry-run-chain", "--db-path", "/repo/data/iot.db", "--repository-root", "/repo",
        "--capture-session-id", seed_module.CAPTURE_UUID,
        "--failed-segment-ids", "2", "3", "4", "--pcap-paths", "/a/1.pcap", "/a/2.pcap", "/a/3.pcap",
        "--approved-by", "operator", "--reason", "Explicit reviewed chain",
        "--artifact-dir", "/repo/output", "--plan-output", "/repo/output/plan.json",
    ])
    assert args.failed_segment_ids == [2, 3, 4]
    assert args.pcap_paths == ["/a/1.pcap", "/a/2.pcap", "/a/3.pcap"]


@pytest.fixture(params=["single", "chain"])
def operation(tmp_path, monkeypatch, request):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text("output/\ndata/\n")
    for args in (("init",), ("add", ".gitignore"),
                 ("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "seed")):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    output = root / "output"
    output.mkdir()
    chain = request.param == "chain"
    seed = (seed_module.seed_segment_gap_chain_database(output / "iot.db") if chain
            else seed_module.seed_segment_gap_database(output / "iot.db"))
    seed["audit_count"] = 3 if chain else 1
    if chain:
        seed["window_end"] = seed_module.utc(40)
    pcap = output / "failed-1.pcap"
    pcap.write_bytes(b"synthetic failed capture evidence")
    pcap.with_suffix(".pcap.capture.json").write_text('{"kernel_drops":56}')
    monkeypatch.delenv("ORCHESTRATOR_LOCK_PATH", raising=False)
    monkeypatch.setattr(cli, "_implementation_root", lambda: root)
    selection = ["--failed-segment-id", str(seed["failed_segment_id"]), "--pcap-path", str(pcap)]
    if chain:
        pcaps = [pcap, output / "failed-2.pcap", output / "failed-3.pcap"]
        for extra in pcaps[1:]:
            extra.write_bytes(b"different exact capture evidence " + extra.name.encode())
        selection = ["--failed-segment-ids", *map(str, seed["failed_segment_ids"]),
                     "--pcap-paths", *map(str, pcaps)]
    args = cli.build_parser().parse_args([
        "dry-run-chain" if chain else "dry-run", "--db-path", str(seed["database_path"]), "--repository-root", str(root),
        "--capture-session-id", seed["capture_session_id"], *selection,
        "--approved-by", "operator", "--reason", "Reviewed capture loss",
        "--artifact-dir", str(output), "--plan-output", str(output / "plan.json"),
    ])
    before = state(seed["database_path"])
    result = cli.dry_run_chain(args) if chain else cli.dry_run(args)
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
    assert state(seed["database_path"])[1] == seed["audit_count"]
    assert state(result["backup_path"])[1] == 0
    with sqlite3.connect(seed["database_path"]) as conn:
        assert {row[0] for row in conn.execute("SELECT last_completed_window_end FROM detector_checkpoints WHERE source_table='packet_feature_logs'")} == {seed["window_end"]}


@pytest.mark.parametrize("target", ["source", "preserved", "sidecar", "last_source", "last_preserved"])
def test_changed_evidence_blocks_before_db_mutation(operation, target):
    seed, _, _, pcap, args = operation
    plan = json.loads(Path(args.plan_file).read_text())
    if target.startswith("last_"):
        path = Path(plan["evidence"][-1]["source" if target == "last_source" else "preserved"])
    else:
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


def online_plan(operation):
    seed, root, output, _, _ = operation
    args = cli.build_parser().parse_args([
        "dry-run-chain", "--db-path", str(seed["database_path"]), "--repository-root", str(root),
        "--capture-session-id", seed["capture_session_id"],
        "--failed-segment-ids", *map(str, seed["failed_segment_ids"]),
        "--pcap-paths", *[str(output / f"failed-{index}.pcap") for index in (1, 2, 3)],
        "--approved-by", "operator", "--reason", "Reviewed capture-preserving chain",
        "--artifact-dir", str(output), "--plan-output", str(output / "online-plan.json"),
        "--allow-source-appends",
    ])
    result = cli.dry_run_chain(args)
    return cli.build_parser().parse_args([
        "execute", "--db-path", str(seed["database_path"]), "--plan-file", result["plan_file"],
        "--confirm", cli.CONFIRMATION,
    ])


@pytest.mark.parametrize("operation", ["chain"], indirect=True)
def test_explicit_online_chain_accepts_actual_separate_connection_append(operation, monkeypatch):
    seed, _, _, _, _ = operation
    args = online_plan(operation)
    real_backup = cli.safety.create_sqlite_backup

    def racing_backup(database, backup):
        artifact = real_backup(database, backup)
        # This is a real second SQLite connection and commit, not a mocked
        # data_version. Existing consumers/checkpoints remain stopped.
        with sqlite3.connect(database) as writer:
            writer.execute("UPDATE devices SET last_seen_at=?", (seed_module.utc(70),))
            writer.execute("INSERT INTO mqtt_logs(device_id,topic,payload,received_at) "
                           "VALUES ('esp32_01','iot/esp32_01/sensor','{}',?)", (seed_module.utc(70),))
            writer.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status,"
                           "start_delay_seconds,captured_duration_seconds) VALUES (1,'live-ready.pcap','eth0',?,?,'READY',0,10)",
                           (seed_module.utc(60), seed_module.utc(70)))
            writer.execute("INSERT INTO gateway_metrics(collected_at,memory_percent,disk_percent,interface_metrics_json) "
                           "VALUES (?,10,10,'{}')", (seed_module.utc(70),))
        return artifact

    monkeypatch.setattr(cli.safety, "create_sqlite_backup", racing_backup)
    result = cli.execute(args)
    assert result["database_committed"] is True
    assert state(seed["database_path"])[1] == 3
    with sqlite3.connect(seed["database_path"]) as conn:
        stored = json.loads(conn.execute("SELECT plan_json FROM packet_segment_gap_recoveries LIMIT 1").fetchone()[0])
    assert stored["execution_mode"] == "source-appends-v1"
    assert stored["source_scope"]["scope_sha256"]


@pytest.mark.parametrize("operation", ["chain"], indirect=True)
@pytest.mark.parametrize("when", ["backup", "live"])
@pytest.mark.parametrize("sql", [
    "UPDATE packet_feature_logs SET total_bytes=234 WHERE id=1",
    "UPDATE packet_capture_segments SET packet_count=234 WHERE id=1",
    "UPDATE devices SET trust_score=70",
    "UPDATE detector_checkpoints SET updated_at='changed' WHERE detector_name='trust_score_v2'",
    "UPDATE schema_migrations SET name='changed' WHERE version=8",
    "INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status,error_code) "
    f"VALUES (1,'new-failure.pcap','eth0','{seed_module.utc(60)}','{seed_module.utc(70)}','FAILED','PARTIAL_CAPTURE')",
])
def test_online_chain_rechecks_retained_backup_and_live_protected_inputs(operation, monkeypatch, when, sql):
    seed, _, _, _, _ = operation
    args = online_plan(operation)
    real_backup = cli.safety.create_sqlite_backup
    external_state = []

    def racing_backup(database, backup):
        artifact = real_backup(database, backup) if when == "live" else None
        with sqlite3.connect(database) as writer:
            writer.execute(sql)
        external_state.append(state(database))
        return artifact if artifact is not None else real_backup(database, backup)

    monkeypatch.setattr(cli.safety, "create_sqlite_backup", racing_backup)
    with pytest.raises(ValueError, match="protected source scope changed"):
        cli.execute(args)
    assert state(seed["database_path"]) == external_state[0]
    assert state(seed["database_path"])[1] == 0


@pytest.mark.parametrize("operation", ["chain"], indirect=True)
@pytest.mark.parametrize("target", ["env", "model", "plan"])
def test_online_chain_rejects_deployment_or_plan_change_during_backup(operation, monkeypatch, target):
    seed, root, output, _, _ = operation
    model = output / "model"
    model.mkdir()
    for name in ("model.joblib", "metadata.json", "training_report.json"):
        (model / name).write_bytes(b"artifact evidence")
    env = root / ".env"
    env.write_text(f"PACKET_IF_ARTIFACT_DIR={model.as_posix()}\nMQTT_SUBSCRIBER_PASSWORD=synthetic-secret\n")
    args = online_plan(operation)
    assert "synthetic-secret" not in Path(args.plan_file).read_text()
    real_backup = cli.safety.create_sqlite_backup

    def racing_backup(database, backup):
        artifact = real_backup(database, backup)
        if target == "env":
            env.write_text(env.read_text() + "TRUST_AI_MODE=observe\n")
        elif target == "model":
            (model / "model.joblib").write_bytes(b"different model bytes")
        else:
            Path(args.plan_file).write_text("{}")
        return artifact

    monkeypatch.setattr(cli.safety, "create_sqlite_backup", racing_backup)
    before = state(seed["database_path"])
    with pytest.raises(ValueError, match="changed"):
        cli.execute(args)
    assert state(seed["database_path"]) == before


@pytest.mark.parametrize("operation", ["chain"], indirect=True)
def test_online_chain_rejects_scope_plan_tamper_before_backup(operation, monkeypatch):
    seed, _, _, _, _ = operation
    args = online_plan(operation)
    plan_path = Path(args.plan_file)
    payload = json.loads(plan_path.read_text())
    payload["source_scope"]["high_water_marks"]["packet_capture_segments"] += 1
    plan_path.write_text(json.dumps(payload))
    monkeypatch.setattr(cli.safety, "create_sqlite_backup", lambda *args: pytest.fail("backup should not run"))
    with pytest.raises(ValueError, match="SHA256"):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 0


@pytest.mark.parametrize("operation", ["chain"], indirect=True)
def test_online_chain_uses_deployment_capture_policy_for_live_tail(operation, monkeypatch):
    seed, root, _, _, _ = operation
    (root / ".env").write_text("PCAP_MAX_START_DELAY_SECONDS=0.2\nPACKET_MIN_CAPTURE_DURATION_SECONDS=9.8\n")
    args = online_plan(operation)
    plan = json.loads(Path(args.plan_file).read_text())
    assert plan["source_scope"]["capture_policy"]["max_start_delay_seconds"] == 0.2
    real_backup = cli.safety.create_sqlite_backup

    def racing_backup(database, backup):
        artifact = real_backup(database, backup)
        with sqlite3.connect(database) as writer:
            # Default policy would admit this, but the deployed policy does not.
            writer.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status,"
                           "start_delay_seconds,captured_duration_seconds) VALUES (1,'late-ready.pcap','eth0',?,?,'READY',0.3,9.7)",
                           (seed_module.utc(60), seed_module.utc(70)))
        return artifact

    monkeypatch.setattr(cli.safety, "create_sqlite_backup", racing_backup)
    with pytest.raises(ValueError, match="not eligible"):
        cli.execute(args)
    assert state(seed["database_path"])[1] == 0


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
    assert state(seed["database_path"])[1] == seed["audit_count"]


def test_result_write_failure_reports_committed_hold(operation, monkeypatch):
    seed, _, _, _, args = operation
    monkeypatch.setattr(cli, "_private_json", lambda *args: (_ for _ in ()).throw(OSError("disk failure")))
    with pytest.raises(cli.CommittedRecoveryError):
        cli.execute(args)
    assert state(seed["database_path"])[1] == seed["audit_count"]


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
