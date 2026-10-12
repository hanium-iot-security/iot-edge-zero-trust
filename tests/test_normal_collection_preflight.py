"""Operational readiness must fail closed without approving collection data."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from db.migration_runner import apply_migrations
from edge.features import normal_collection_preflight as preflight


EPOCH = datetime(2026, 10, 9, 3, tzinfo=timezone.utc).timestamp()
COMMIT = "a" * 40
BOOT = "11111111-2222-4333-8444-555555555555"
SESSION = "90909090-1111-4111-8111-111111111111"
DEVICES = ["esp32_01", "esp32_02", "pico_01"]
SOURCES = {
    "mqtt_feature_builder": "mqtt_logs",
    "mqtt_feature_rule": "feature_logs",
    "mqtt_message_rule": "mqtt_logs",
    "packet_rule": "packet_feature_logs",
    "packet_if": "packet_feature_logs",
    "trust_score_v2": "detection_events",
}
ENABLED = ["mqtt_feature_rule", "mqtt_message_rule", "packet_rule", "packet_if"]
SERVICES = (
    "packet-capture.service", "mqtt-subscriber.service", "mqtt-feature-builder.service",
    "detection-orchestrator.service", "packet-feature-extractor.timer", "firewall-worker.service",
)
SECRET = "PREFLIGHT_FIXTURE_SECRET_NEVER_REPORT"


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Clock:
    """No real sleep or OS scheduler dependency in observation tests."""

    def __init__(self, epoch=EPOCH + 5):
        self.epoch = epoch
        self.elapsed = 0.0

    def time(self):
        return self.epoch

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        assert 0 <= seconds <= 30
        self.epoch += seconds
        self.elapsed += seconds


def policy(device, revision=1):
    return {
        "id": DEVICES.index(device) + 1, "device_id": device, "revision": revision,
        "effective_from": utc(EPOCH - 300), "registration_state": "ACTIVE",
        "policy_profile": "periodic-sensor-v1", "expected_publish_interval_seconds": 5.0,
        "publish_count_max": 15, "payload_size_max_bytes": 5120,
        "packet_rate_max_pps": 10.0, "byte_rate_max_bytes_per_second": 2500.0,
        "created_at": utc(EPOCH - 300), "created_by": "fixture", "reason": "fixture",
    }


def observation(index):
    boundary = EPOCH + index * 10
    return {
        "observed_at": utc(boundary + 5), "code_commit": COMMIT, "boot_id": BOOT,
        "tracked_worktree_dirty": False, "ntp_synchronized": True, "free_bytes": 4 * 1024 ** 3,
        "configuration": {
            "trust_ai_mode": "observe", "feature_window_seconds": 10,
            "pcap_window_seconds": 10, "enabled_stages": ENABLED.copy(),
            "required_stages": ENABLED.copy(),
            "database_path_matches_project": True,
            "capture_policy": {"max_start_delay_seconds": 1.0, "minimum_duration_seconds": 9.0,
                               "epsilon_seconds": 0.01, "version": "packet-capture-policy-v1"},
        },
        "services": {name: "active" for name in SERVICES},
        "running_sessions": [{"id": 1, "session_id": SESSION, "status": "RUNNING", "capture_interface": "eth0"}],
        "devices": [
            {"device_id": device, "ip_address": f"192.168.0.{offset}", "status": "normal",
             "trust_score": 100, "registration_state": "ACTIVE", "current_policy_revision": 1,
             "mqtt_topic": f"iot/{device}/sensor"}
            for offset, device in enumerate(DEVICES, 4)
        ],
        "device_policy_revisions": [policy(device) for device in DEVICES],
        "mqtt_latest": {device: {"id": 1 + index * 3 + offset, "received_at": utc(boundary + 4)}
                        for offset, device in enumerate(DEVICES)},
        "checkpoints": [
            {"detector_name": name, "source_table": source, "last_processed_id": index + 1,
             "last_completed_window_end": utc(boundary)}
            for name, source in SOURCES.items()
        ],
    }


@pytest.fixture
def observations():
    return [observation(index) for index in range(3)]


def assess(observations):
    return preflight.assess_observations(observations, DEVICES)


def assert_hold(observations):
    result = assess(observations)
    assert result["status"] == "HOLD"
    assert result["hold_reasons"]
    return result


def test_three_observations_require_two_advances_without_inactive_mqtt_if(observations):
    for item in observations:
        # Its checkpoint may be ancient: this stage is deliberately disabled.
        item["checkpoints"].append({
            "detector_name": "mqtt_if", "source_table": "feature_logs",
            "last_processed_id": 0, "last_completed_window_end": utc(EPOCH - 86400),
        })
    result = assess(observations)
    assert result["status"] == "PASS"
    assert result["hold_reasons"] == []
    assert result["scope"] == "operational_runtime_observation_only"
    assert len(result["observations"]) == 3
    assert set(result["not_evaluated"]) == {
        "formal_collection_import", "training_approval", "new_capture_group",
        "physical_firmware_sources", "normal_profile_p0", "runtime_process_mode_and_models",
        "individual_model_inference",
    }
    assert all(value is False for value in result["not_evaluated"].values())


@pytest.mark.parametrize("count", [0, 1, 2, 4])
def test_exactly_three_observations_are_required(observations, count):
    items = observations[:count] if count < 4 else observations + [observation(3)]
    assert_hold(items)


@pytest.mark.parametrize("name", list(SOURCES))
def test_each_required_checkpoint_must_advance_twice(observations, name):
    previous = next(row for row in observations[1]["checkpoints"] if row["detector_name"] == name)
    final = next(row for row in observations[2]["checkpoints"] if row["detector_name"] == name)
    final.update(previous)
    assert_hold(observations)


def test_trust_with_no_events_may_keep_null_id_while_boundary_advances(observations):
    for item in observations:
        next(row for row in item["checkpoints"] if row["detector_name"] == "trust_score_v2")["last_processed_id"] = None
    assert assess(observations)["status"] == "PASS"


def test_missing_trust_id_key_is_not_treated_as_explicit_no_events(observations):
    for item in observations:
        row = next(row for row in item["checkpoints"] if row["detector_name"] == "trust_score_v2")
        del row["last_processed_id"]
    assert_hold(observations)


@pytest.mark.parametrize("kind", ["stale_receipt", "future_receipt", "invalid_receipt", "stale_checkpoint",
                                 "future_checkpoint", "invalid_checkpoint", "checkpoint_id_regression",
                                 "receipt_id_regression", "wrong_source_table", "duplicate_checkpoint"])
def test_unreliable_receipt_or_checkpoint_blocks_readiness(observations, kind):
    item = observations[2]
    checkpoint = item["checkpoints"][0]
    if kind.endswith("receipt"):
        item["mqtt_latest"][DEVICES[0]]["received_at"] = {
            "stale_receipt": utc(EPOCH), "future_receipt": utc(EPOCH + 26), "invalid_receipt": "garbage",
        }[kind]
    elif kind in ("stale_checkpoint", "future_checkpoint", "invalid_checkpoint"):
        if kind == "stale_checkpoint":
            # Keep both advances so this isolates freshness, not regression.
            for index, earlier in enumerate(observations):
                earlier["checkpoints"][0]["last_completed_window_end"] = utc(EPOCH - 50 + index * 10)
        checkpoint["last_completed_window_end"] = {
            "stale_checkpoint": utc(EPOCH - 30), "future_checkpoint": utc(EPOCH + 30), "invalid_checkpoint": "garbage",
        }[kind]
    elif kind == "checkpoint_id_regression":
        checkpoint["last_processed_id"] = 0
    elif kind == "receipt_id_regression":
        item["mqtt_latest"][DEVICES[0]]["id"] = 1
    elif kind == "wrong_source_table":
        checkpoint["source_table"] = "feature_logs"
    else:
        item["checkpoints"].append(deepcopy(checkpoint))
    assert_hold(observations)


@pytest.mark.parametrize("change", ["boot", "commit", "session", "ip", "registration", "revision",
                                   "policy", "trust_score", "trust_mode", "enabled", "required", "window", "capture_policy"])
def test_scope_changes_during_observation_block_readiness(observations, change):
    item = observations[1]
    if change == "boot":
        item["boot_id"] = "22222222-3333-4444-8555-666666666666"
    elif change == "commit":
        item["code_commit"] = "b" * 40
    elif change == "session":
        item["running_sessions"][0]["session_id"] = "22222222-3333-4444-8555-666666666666"
    elif change == "ip":
        item["devices"][0]["ip_address"] = "192.168.0.99"
    elif change == "registration":
        item["devices"][0]["registration_state"] = "DISABLED"
    elif change == "revision":
        item["devices"][0]["current_policy_revision"] = 2
    elif change == "policy":
        item["device_policy_revisions"][0]["payload_size_max_bytes"] = 1024
    elif change == "trust_score":
        item["devices"][0]["trust_score"] = 80
    elif change == "trust_mode":
        item["configuration"]["trust_ai_mode"] = "enforce"
    elif change in ("enabled", "required"):
        item["configuration"][change + "_stages"].remove("packet_if")
    elif change == "window":
        item["configuration"]["feature_window_seconds"] = 20
    else:
        item["configuration"]["capture_policy"]["max_start_delay_seconds"] = 0.5
    assert_hold(observations)


@pytest.mark.parametrize("field", ["boot_id", "code_commit", "observed_at", "tracked_worktree_dirty", "ntp_synchronized", "free_bytes",
                                  "configuration", "services", "running_sessions", "devices", "mqtt_latest", "checkpoints"])
def test_missing_observation_fields_are_not_zero_filled(observations, field):
    for item in observations:
        del item[field]
    assert_hold(observations)


@pytest.mark.parametrize("kind", ["ntp_no", "ntp_unsupported", "service_error", "service_inactive",
                                 "insufficient_space", "no_device", "no_policy", "no_receipt", "no_checkpoint",
                                 "no_session", "two_sessions", "short_interval", "long_interval", "dirty_checkout", "wrong_database"])
def test_missing_or_unusable_operating_evidence_blocks_readiness(observations, kind):
    item = observations[1]
    if kind in ("ntp_no", "ntp_unsupported"):
        item["ntp_synchronized"] = False if kind == "ntp_no" else None
    elif kind.startswith("service_"):
        item["services"][SERVICES[0]] = "error" if kind == "service_error" else "inactive"
    elif kind == "insufficient_space":
        item["free_bytes"] = 1024 ** 3 - 1
    elif kind == "no_device":
        item["devices"].pop()
    elif kind == "no_policy":
        item["device_policy_revisions"].pop()
    elif kind == "no_receipt":
        del item["mqtt_latest"][DEVICES[0]]
    elif kind == "no_checkpoint":
        item["checkpoints"].pop()
    elif kind == "no_session":
        item["running_sessions"] = []
    elif kind == "two_sessions":
        item["running_sessions"].append(dict(item["running_sessions"][0], id=2))
    elif kind == "dirty_checkout":
        item["tracked_worktree_dirty"] = True
    elif kind == "wrong_database":
        item["configuration"]["database_path_matches_project"] = False
    elif kind == "short_interval":
        item["observed_at"] = utc(EPOCH + 14)
    else:
        item = observations[2]
        item["observed_at"] = utc(EPOCH + 46)  # Exactly 31 seconds after observation 2.
        for receipt in item["mqtt_latest"].values():
            receipt["received_at"] = utc(EPOCH + 45)
    assert_hold(observations)


def test_unknown_and_secret_fields_do_not_escape_report(observations, monkeypatch):
    monkeypatch.setenv("MQTT_PASSWORD", SECRET)
    for item in observations:
        item["environment"] = {"MQTT_PASSWORD": SECRET}
        item["raw_stdout"] = SECRET
        item["configuration"]["mqtt_password"] = SECRET
        item["devices"][0]["private_config"] = SECRET
    encoded = json.dumps(assess(observations), sort_keys=True)
    assert SECRET not in encoded
    assert "MQTT_PASSWORD" not in encoded


def insert_revision(db, device, revision=1, effective=EPOCH - 300, registration="ACTIVE"):
    row = policy(device, revision)
    row.update(effective_from=utc(effective), created_at=utc(effective), registration_state=registration)
    columns = [name for name in row if name != "id"]
    db.execute("INSERT INTO device_policy_revisions (" + ",".join(columns) + ") VALUES (" +
               ",".join("?" for _ in columns) + ")", tuple(row[name] for name in columns))


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "gateway"
    database = root / "backend/data/iot_security.db"
    database.parent.mkdir(parents=True)
    apply_migrations(database)
    with closing(sqlite3.connect(database)) as db, db:
        for offset, device in enumerate(DEVICES, 4):
            db.execute("INSERT INTO devices (device_id,ip_address,status,trust_score,device_type,"
                       "mqtt_principal,registration_effective_from) VALUES (?,?,'normal',100,'SENSOR',?,?)",
                       (device, f"192.168.0.{offset}", device, utc(EPOCH - 300)))
            insert_revision(db, device)
            db.execute("INSERT INTO mqtt_logs (device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) "
                       "VALUES (?,?,?,2,?,1,1)", (device, f"iot/{device}/sensor", "{}", utc(EPOCH + 4)))
        db.execute("INSERT INTO packet_capture_sessions (session_id,capture_interface,started_at,first_window_start,status) "
                   "VALUES (?,'eth0',?,?,'RUNNING')", (SESSION, utc(EPOCH - 300), utc(EPOCH - 300)))
        for name, source in SOURCES.items():
            db.execute("INSERT INTO detector_checkpoints (detector_name,source_table,last_processed_id,last_completed_window_end) "
                       "VALUES (?,?,1,?)", (name, source, utc(EPOCH)))
    return SimpleNamespace(root=root, db=database)


def test_runner_takes_three_observations_and_two_virtual_waits(project):
    clock, calls = Clock(), []

    def observe(root, device_ids):
        assert root == project.root and device_ids == DEVICES
        item = observation(len(calls))
        item["observed_at"] = utc(clock.time())
        for row in item["mqtt_latest"].values():
            row["received_at"] = utc(clock.time() - 1)
        calls.append(clock.time())
        return item

    result = preflight.run_preflight(project.root, DEVICES, observe=observe, sleep=clock.sleep)
    assert result["status"] == "PASS"
    assert calls == [EPOCH + 5, EPOCH + 17, EPOCH + 29]
    assert clock.elapsed == 24


@pytest.mark.parametrize("seconds", [9, 31])
def test_runner_rejects_observation_budget_outside_contract(project, seconds):
    with pytest.raises(ValueError):
        preflight.run_preflight(project.root, DEVICES, sample_interval_seconds=seconds,
                                observe=lambda *_: pytest.fail("Invalid interval performed an observation"),
                                sleep=lambda *_: pytest.fail("Invalid interval slept"))


@pytest.mark.parametrize("configuration", ["enabled_missing_required", "required_missing_packet_if", "duplicate_enabled"])
def test_same_but_invalid_stage_configuration_does_not_pass(observations, configuration):
    for item in observations:
        if configuration == "enabled_missing_required":
            item["configuration"]["enabled_stages"].remove("packet_if")
        elif configuration == "required_missing_packet_if":
            item["configuration"]["required_stages"].remove("packet_if")
        else:
            item["configuration"]["enabled_stages"].append("packet_if")
    assert_hold(observations)


@pytest.mark.parametrize("key", ["enabled_stages", "required_stages"])
def test_stage_order_change_is_preserved_and_blocks_scope_match(observations, key):
    observations[1]["configuration"][key].reverse()
    assert_hold(observations)


@pytest.mark.parametrize("section", ["devices", "device_policy_revisions", "running_sessions", "mqtt_latest", "checkpoints"])
def test_absent_data_at_all_observations_is_not_synthesized(observations, section):
    for item in observations:
        item[section] = {} if section == "mqtt_latest" else []
    assert_hold(observations)


@pytest.fixture
def report_root(project):
    subprocess.run(["git", "init", "--quiet"], cwd=project.root, check=True, capture_output=True)
    (project.root / ".gitignore").write_text("output/\n", encoding="utf-8")
    (project.root / "output").mkdir()
    return project.root


def test_new_ignored_report_is_saved_without_overwriting_existing_file(report_root, observations):
    path = report_root / "output/preflight.json"
    result = assess(observations)
    preflight.save_report(report_root, path, result)
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "PASS"
    original = path.read_bytes()
    with pytest.raises(ValueError):
        preflight.save_report(report_root, path, {"status": "HOLD"})
    assert path.read_bytes() == original


@pytest.mark.parametrize("which", ["database", "source", "outside_output", "outside_root"])
def test_report_cannot_target_original_or_unapproved_paths(report_root, project, observations, which):
    original = project.db.read_bytes()
    candidates = {
        "database": project.db,
        "source": report_root / "edge/features/new-source.py",
        "outside_output": report_root / "new-report.json",
        "outside_root": report_root.parent / "new-report.json",
    }
    with pytest.raises(ValueError):
        preflight.save_report(report_root, candidates[which], assess(observations))
    assert project.db.read_bytes() == original
    assert not candidates[which].exists() or candidates[which] == project.db


@pytest.mark.parametrize("which", ["file", "ancestor", "inside_ancestor"])
def test_report_symlink_cannot_escape_or_overwrite(report_root, observations, monkeypatch, which):
    outside = report_root.parent / "outside"
    outside.mkdir()
    existing = outside / "evidence.json"
    existing.write_bytes(b"sealed original")
    link = report_root / "output/link"
    if which == "inside_ancestor":
        target = report_root / "output/inside"
        target.mkdir()
    else:
        target = existing if which == "file" else outside
    try:
        link.symlink_to(target, target_is_directory=which != "file")
    except OSError:
        # Windows without symlink privilege still exercises the rejection branch.
        if which != "file":
            link.mkdir()
        original = Path.is_symlink
        monkeypatch.setattr(Path, "is_symlink", lambda self: self == link or original(self))
    destination = link if which == "file" else link / "new.json"
    with pytest.raises(ValueError):
        preflight.save_report(report_root, destination, assess(observations))
    assert existing.read_bytes() == b"sealed original"
    assert not (outside / "new.json").exists()


def test_report_rejects_new_output_file_when_git_does_not_ignore_it(report_root, observations):
    (report_root / ".gitignore").write_text("", encoding="utf-8")
    destination = report_root / "output/not-ignored.json"
    with pytest.raises(ValueError):
        preflight.save_report(report_root, destination, assess(observations))
    assert not destination.exists()


def test_deleted_tracked_report_path_is_not_recreated_even_under_ignore_rule(report_root, observations):
    destination = report_root / "output/tracked.json"
    destination.write_bytes(b"tracked source evidence")
    subprocess.run(["git", "add", "-f", "--", str(destination)], cwd=report_root,
                   check=True, capture_output=True)
    destination.unlink()
    with pytest.raises(ValueError):
        preflight.save_report(report_root, destination, assess(observations))
    assert not destination.exists()


def test_windows_junction_ancestor_is_rejected_without_accessing_target(report_root, observations, monkeypatch):
    ancestor = report_root / "output/junction"
    ancestor.mkdir()
    monkeypatch.setattr(Path, "is_junction", lambda self: self == ancestor, raising=False)
    destination = ancestor / "new.json"
    with pytest.raises(ValueError):
        preflight.save_report(report_root, destination, assess(observations))
    assert not destination.exists()


@pytest.fixture
def collection_environment(project, monkeypatch):
    baseline = observation(0)
    configuration = dict(baseline["configuration"], database_path=str(project.db))
    system = {name: baseline[name] for name in ("boot_id", "ntp_synchronized", "free_bytes", "services")}
    monkeypatch.setattr(preflight, "_configuration", lambda root: deepcopy(configuration))
    monkeypatch.setattr(preflight, "_system_observation", lambda root: deepcopy(system))
    monkeypatch.setattr(preflight, "_git_head", lambda root: COMMIT)
    monkeypatch.setattr(preflight, "_git_tracked_dirty", lambda root: False)
    monkeypatch.setattr(preflight, "_utc_now", lambda: datetime.fromtimestamp(EPOCH + 5, timezone.utc))


def test_real_schema_derives_current_registration_without_using_future_policy(project, collection_environment):
    with closing(sqlite3.connect(project.db)) as db, db:
        for device in DEVICES:
            insert_revision(db, device, 2, EPOCH + 100, "DISABLED")
        columns = {row[1] for row in db.execute("PRAGMA table_info(devices)")}
    assert not columns.intersection({"registration_state", "current_policy_revision", "mqtt_topic"})
    result = preflight.collect_observation(project.root, DEVICES)
    assert len(result["devices"]) == 3
    for row in result["devices"]:
        assert row["registration_state"] == "ACTIVE"
        assert row["current_policy_revision"] == 1
        assert row["mqtt_topic"] == f"iot/{row['device_id']}/sensor"
    assert {(row["detector_name"], row["source_table"]) for row in result["checkpoints"]} == set(SOURCES.items())


def test_collection_uses_read_only_sqlite_and_preserves_original_bytes(project, collection_environment, monkeypatch):
    original = project.db.read_bytes()
    source = project.root / "data/pcap/ready/original.pcap"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"sealed packet fixture")
    original_connect = sqlite3.connect
    observed_connections = []

    def read_only_connect(database, *args, **kwargs):
        assert isinstance(database, str) and "mode=ro" in database
        assert kwargs.get("uri") is True
        connection = original_connect(database, *args, **kwargs)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("UPDATE devices SET trust_score=0")
        connection.rollback()  # Failed DML can still start sqlite3's implicit transaction.
        observed_connections.append(database)
        return connection

    monkeypatch.setattr(sqlite3, "connect", read_only_connect)
    result = preflight.collect_observation(project.root, DEVICES)
    assert observed_connections
    assert len(result["devices"]) == 3
    assert project.db.read_bytes() == original
    assert source.read_bytes() == b"sealed packet fixture"


def test_missing_db_receipt_is_preserved_as_missing_not_fabricated(project, collection_environment):
    with closing(sqlite3.connect(project.db)) as db, db:
        db.execute("DELETE FROM mqtt_logs WHERE device_id=?", (DEVICES[0],))
    result = preflight.collect_observation(project.root, DEVICES)
    assert result["mqtt_latest"].get(DEVICES[0]) in (None, {})
    items = [deepcopy(result) for _ in range(3)]
    for index, item in enumerate(items):
        item["observed_at"] = utc(EPOCH + 5 + 10 * index)
        for receipt in item["mqtt_latest"].values():
            receipt["received_at"] = utc(EPOCH + 4 + 10 * index)
        for row in item["checkpoints"]:
            row["last_completed_window_end"] = utc(EPOCH + 10 * index)
    assert_hold(items)


def test_runtime_errors_are_codes_and_never_original_exception_text(project, collection_environment, monkeypatch):
    def fail_system(root):
        raise OSError(SECRET)

    monkeypatch.setattr(preflight, "_system_observation", fail_system)
    result = preflight.run_preflight(project.root, DEVICES, sleep=Clock().sleep)
    assert result["status"] == "HOLD"
    assert SECRET not in json.dumps(result)


def test_cli_failure_outputs_codes_without_environment_or_exception_values(project, monkeypatch, capsys):
    monkeypatch.setenv("MQTT_PASSWORD", SECRET)

    def fail(*args, **kwargs):
        raise OSError(SECRET)

    monkeypatch.setattr(preflight, "run_preflight", fail)
    args = ["--project-root", str(project.root)]
    for device in DEVICES:
        args.extend(("--device", device))
    assert preflight.main(args) != 0
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    report = json.loads(output.out)
    assert report["status"] == "HOLD"
    assert all(value is False for value in report["not_evaluated"].values())


def test_cli_argument_error_does_not_echo_sensitive_value(capsys):
    with pytest.raises(SystemExit) as error:
        preflight.main(["--device", DEVICES[0], "--sample-interval-seconds", SECRET])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    assert json.loads(output.out)["status"] == "HOLD"
