"""Candidate collection preserves evidence without touching gateway state."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from uuid import UUID

import pytest

from db.migration_runner import apply_migrations
from edge.features import collect_normal_candidate as collector
from edge.packet.pcap_naming import build_pcap_filename


EPOCH = datetime(2026, 10, 4, 12, tzinfo=timezone.utc).timestamp()
GROUP = "90909090-1111-4111-8111-111111111111"
COMMIT = "a" * 40
DEVICES = ("esp32_01", "esp32_02", "pico_01")


class Clock:
    def __init__(self, epoch=EPOCH + 3.25):
        self.epoch = epoch
        self.elapsed = 0.0
        self.on_sleep = None

    def time(self):
        return self.epoch

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        assert 0 <= seconds <= 30
        self.epoch += seconds
        self.elapsed += seconds
        if self.on_sleep:
            self.on_sleep()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def insert_revision(db, device, revision, epoch, registration="ACTIVE"):
    db.execute(
        "INSERT INTO device_policy_revisions (device_id,revision,effective_from,"
        "registration_state,policy_profile,expected_publish_interval_seconds,"
        "publish_count_max,payload_size_max_bytes,packet_rate_max_pps,"
        "byte_rate_max_bytes_per_second,created_at,created_by,reason) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (device, revision, collector.utc(epoch), registration, "periodic-sensor-v1",
         5, 3, 512, 10, 2500, collector.utc(epoch), "test", "isolated test"),
    )


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "gateway"
    path = root / "backend/data/iot_security.db"
    path.parent.mkdir(parents=True)
    apply_migrations(path)
    with closing(sqlite3.connect(path)) as db, db:
        for index, device in enumerate(DEVICES, 4):
            db.execute(
                "INSERT INTO devices (device_id,ip_address,status,trust_score,"
                "device_type,mqtt_principal,registration_effective_from) "
                "VALUES (?,?,'normal',100,'SENSOR',?,?)",
                (device, f"192.168.0.{index}", device, collector.utc(EPOCH - 200)),
            )
            insert_revision(db, device, 1, EPOCH - 200, "PENDING")
            insert_revision(db, device, 2, EPOCH - 100)
        db.execute(
            "INSERT INTO packet_capture_sessions (session_id,capture_interface,"
            "started_at,first_window_start,status) VALUES (?,'eth0',?,?,'RUNNING')",
            (GROUP, collector.utc(EPOCH - 300), collector.utc(EPOCH - 300)),
        )
        for stage in collector.STAGES:
            db.execute(
                "INSERT INTO detector_checkpoints (detector_name,source_table,"
                "last_completed_window_end) VALUES (?,'feature_logs',?)",
                (stage, collector.utc(EPOCH)),
            )
    return SimpleNamespace(root=root, db=path)


@pytest.fixture
def environment(monkeypatch, project):
    clock = Clock()
    monkeypatch.setattr(collector, "time", clock)
    monkeypatch.setattr(collector, "settings", SimpleNamespace(
        trust_ai_mode="observe", feature_window_seconds=10,
        orchestrator_enabled_stages=",".join(collector.STAGES),
        database_url="sqlite:///" + project.db.as_posix(),
    ))
    monkeypatch.setattr(collector, "git_head", lambda root: COMMIT)
    monkeypatch.setattr(collector.shutil, "disk_usage", lambda root: SimpleNamespace(free=4 * 1024 ** 3))
    return clock


def add_artifact(project, epoch, folder="ready", session_pk=1, interface="eth0"):
    name = build_pcap_filename(
        session_id=GROUP, interface=interface,
        window_start=datetime.fromtimestamp(epoch, timezone.utc),
        window_end=datetime.fromtimestamp(epoch + 10, timezone.utc), tmp=False,
    )
    with closing(sqlite3.connect(project.db)) as db, db:
        segment_id = db.execute(
            "INSERT INTO packet_capture_segments (capture_session_id,file_name,"
            "capture_interface,window_start,window_end,status) VALUES (?,?,?,?,?,'READY')",
            (session_pk, name, interface, collector.utc(epoch), collector.utc(epoch + 10)),
        ).lastrowid
    source = project.root / "data/pcap" / folder / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"sealed-pcap-" + str(segment_id).encode())
    source.with_name(name + ".capture.json").write_text('{"success": true}\n', encoding="utf-8")
    return segment_id, source


def test_state_derives_registration_revision_and_topic_from_real_schema(project, environment):
    with closing(sqlite3.connect(project.db)) as db, db:
        insert_revision(db, "pico_01", 3, EPOCH + 20000, "DISABLED")
        columns = {row[1] for row in db.execute("PRAGMA table_info(devices)")}
    assert not columns.intersection({"registration_state", "current_policy_revision", "mqtt_topic"})
    result = collector.state(project.db)
    assert len(result["device_policy_revisions"]) == 7  # Keep future provenance, not future state.
    for device in result["devices"]:
        assert device["registration_state"] == "ACTIVE"
        assert device["current_policy_revision"] == 2
        assert device["mqtt_topic"] == f"iot/{device['device_id']}/sensor"
    with closing(collector.read_db(project.db)) as db:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("UPDATE devices SET trust_score=0")
    assert collector.state(project.db) == result


@pytest.mark.parametrize("folder", ["ready", "processed", "failed"])
def test_preserve_file_is_read_only_and_identical_evidence_is_not_recopied(tmp_path, monkeypatch, folder):
    source = tmp_path / "gateway/data/pcap" / folder / "sealed.pcap"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"original bytes")
    destination = tmp_path / "evidence.pcap"
    original_stat = source.stat()
    assert collector.preserve_file(tmp_path / "gateway", source.name, destination)
    assert source.read_bytes() == destination.read_bytes() == b"original bytes"
    assert source.stat().st_mtime_ns == original_stat.st_mtime_ns
    monkeypatch.setattr(collector.shutil, "copyfileobj", lambda *args: pytest.fail("Duplicate evidence was recopied"))
    assert collector.preserve_file(tmp_path / "gateway", source.name, destination)


def test_ready_to_processed_move_is_retried_without_consuming_source(tmp_path, monkeypatch):
    root = tmp_path / "gateway"
    ready = root / "data/pcap/ready/sealed.pcap"
    processed = root / "data/pcap/processed/sealed.pcap"
    ready.parent.mkdir(parents=True)
    processed.parent.mkdir(parents=True)
    ready.write_bytes(b"moved by extractor")
    original_open = Path.open

    def racing_open(path, mode="r", *args, **kwargs):
        if path == ready and mode == "rb":
            ready.rename(processed)
            raise FileNotFoundError("extractor moved the sealed file")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", racing_open)
    destination = tmp_path / "evidence.pcap"
    first = collector.preserve_file(root, ready.name, destination)
    # A collector may rediscover immediately or at the following scheduled poll.
    assert first or collector.preserve_file(root, ready.name, destination)
    assert processed.read_bytes() == destination.read_bytes() == b"moved by extractor"
    assert not ready.exists()


def test_existing_artifact_mismatch_never_overwrites_evidence(tmp_path):
    root = tmp_path / "gateway"
    source = root / "data/pcap/ready/sealed.pcap"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"new source")
    destination = tmp_path / "evidence.pcap"
    destination.write_bytes(b"previous evidence")
    with pytest.raises(ValueError, match="changed"):
        collector.preserve_file(root, source.name, destination)
    assert destination.read_bytes() == b"previous evidence"
    assert source.read_bytes() == b"new source"


@pytest.mark.parametrize("name", ["", ".", "..", "../escape.pcap", "/escape.pcap",
                                  "sub/file.pcap", "sub\\file.pcap", "file:stream", "sealed.pcap.tmp"])
def test_unsafe_or_unsealed_names_are_rejected_before_copy(tmp_path, name):
    destination = tmp_path / "evidence.pcap"
    with pytest.raises(ValueError):
        collector.preserve_file(tmp_path / "gateway", name, destination)
    assert not destination.exists()


@pytest.mark.parametrize("which", ["source", "destination"])
def test_artifact_symlinks_are_rejected(tmp_path, which):
    root = tmp_path / "gateway"
    source = root / "data/pcap/ready/sealed.pcap"
    source.parent.mkdir(parents=True)
    destination = tmp_path / "evidence.pcap"
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"identical")
    link = source if which == "source" else destination
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("This host does not allow unprivileged file symlinks")
    if which == "destination":
        source.write_bytes(b"identical")
    with pytest.raises(ValueError):
        collector.preserve_file(root, source.name, destination)
    assert outside.read_bytes() == b"identical"


def test_preserve_segments_selects_only_its_bounded_group_and_seals_both_artifacts(project, monkeypatch):
    one, source_one = add_artifact(project, EPOCH)
    two, source_two = add_artifact(project, EPOCH + 10, "processed")
    add_artifact(project, EPOCH - 10)
    add_artifact(project, EPOCH + 20)
    with closing(sqlite3.connect(project.db)) as db, db:
        db.execute("INSERT INTO packet_capture_sessions (session_id,capture_interface,started_at,status) "
                   "VALUES ('80808080-1111-4111-8111-111111111111','eth1',?,'COMPLETED')", (collector.utc(EPOCH),))
    add_artifact(project, EPOCH, session_pk=2, interface="eth1")
    package = project.root / "output/run"
    package.mkdir(parents=True)
    manifest = {"capture_session_pk": 1, "start_utc": collector.utc(EPOCH),
                "end_utc": collector.utc(EPOCH + 20), "capture_artifacts": []}
    collector.preserve_segments(project.root, project.db, package, manifest)
    assert [item["segment_id"] for item in manifest["capture_artifacts"]] == [one, two]
    for item, source in zip(manifest["capture_artifacts"], (source_one, source_two)):
        for prefix, suffix in (("pcap", ""), ("diagnostics", ".capture.json")):
            preserved = package / item[prefix + "_path"]
            assert preserved.read_bytes() == source.with_name(source.name + suffix).read_bytes()
            assert collector.sha256(preserved) == item[prefix + "_sha256"]
    monkeypatch.setattr(collector.shutil, "copyfileobj", lambda *args: pytest.fail("Unchanged artifact recopied"))
    collector.preserve_segments(project.root, project.db, package, manifest)
    assert len(list((package / "pcap").iterdir())) == 4


@pytest.mark.parametrize("slots,poll", [([], 15), ([([], 60)], 15),
    ([( ["pico_01", "pico_01"], 60)], 15), ([( ["pico_01"], 50)], 15),
    ([( ["pico_01"], 65)], 15), ([( ["pico_01"], 60)], 0),
    ([( ["pico_01"], 60)], -1), ([( ["pico_01"], 60)], 30.1),
    ([( ["pico_01"], 60)], float("nan")), ([( ["pico_01"], 60)], float("inf"))])
def test_invalid_plan_or_poll_is_rejected_without_runtime_reads(tmp_path, monkeypatch, slots, poll):
    root = tmp_path / "gateway"
    root.mkdir()
    output = root / "output/new"
    monkeypatch.setattr(collector, "state", lambda *args: pytest.fail("Invalid plan reached runtime DB"))
    with pytest.raises(ValueError):
        collector.collect(root, output, slots, poll)
    assert not output.exists()


def test_evidence_outside_output_and_existing_output_are_refused(tmp_path, monkeypatch):
    root = tmp_path / "gateway"
    root.mkdir()
    existing = root / "output/existing"
    existing.mkdir(parents=True)
    retained = existing / "manifest.json"
    retained.write_bytes(b"existing evidence")
    monkeypatch.setattr(collector, "state", lambda *args: pytest.fail("Unsafe output reached runtime DB"))
    for output in (root / "tracked-evidence", tmp_path / "outside", existing):
        with pytest.raises(ValueError):
            collector.collect(root, output, [(["pico_01"], 60)])
    assert retained.read_bytes() == b"existing evidence"
    assert not (root / "tracked-evidence").exists()


@pytest.mark.parametrize("url", ["sqlite:///:memory:", "postgresql://localhost/unused",
                                  "sqlite:///backend/data/other.db"])
def test_configured_database_must_match_live_checkout_before_any_read(project, environment, monkeypatch, url):
    collector.settings.database_url = url
    monkeypatch.setattr(collector, "state", lambda *args: pytest.fail("Wrong database configuration reached runtime DB"))
    output = project.root / "output/wrong-db"
    with pytest.raises(ValueError):
        collector.collect(project.root, output, [(["pico_01"], 60)])
    assert not output.exists()


def test_full_phase8_plan_uses_future_aligned_nonoverlapping_ranges(project, environment, monkeypatch):
    baseline = collector.state(project.db)
    monkeypatch.setattr(collector, "state", lambda path: deepcopy(baseline))
    finalized = []
    preserved = set()

    def preserve(root, db, package, manifest):
        assert package not in finalized, "Finished run was polled again"
        preserved.add(package)

    def finalize(root, db, package, manifest, before):
        assert before == baseline
        assert collector.utc(environment.time()) >= manifest["end_utc"]
        finalized.append(package)
        manifest["status"] = "CANDIDATE_QC_PASSED"
        collector.save_json(package / "manifest.json", manifest)
        return {"status": "PASS", "hold_reasons": []}

    monkeypatch.setattr(collector, "preserve_segments", preserve)
    monkeypatch.setattr(collector, "finalize", finalize)
    slots = [(["pico_01"], 1800), (["esp32_01"], 1800), (["esp32_02"], 1800), (list(DEVICES), 3600)]
    initial = environment.time()
    output = project.root / "output/phase8"
    result = collector.collect(project.root, output, slots, poll_seconds=30)
    assert result == read_json(output / "plan.json")
    assert result["status"] == "CANDIDATE_COLLECTION_COMPLETE"
    assert result["source_capture_group_id"] == GROUP
    assert result["all_runs_share_capture_group"] is True
    assert result["training_approved"] is result["whole_capture_session_approved"] is False
    manifests = [read_json(output / run["path"] / "manifest.json") for run in result["runs"]]
    bounds = [(datetime.fromisoformat(m["start_utc"].replace("Z", "+00:00")).timestamp(),
               datetime.fromisoformat(m["end_utc"].replace("Z", "+00:00")).timestamp()) for m in manifests]
    assert bounds[0][0] > initial
    assert all(start % 10 == end % 10 == 0 for start, end in bounds)
    assert [end - start for start, end in bounds] == [1800, 1800, 1800, 3600]
    assert all(left[1] == right[0] for left, right in zip(bounds, bounds[1:]))
    assert bounds[-1][1] - bounds[0][0] == 150 * 60
    assert len({UUID(m["run_id"]) for m in manifests}) == 4
    assert set(finalized) == preserved and len(finalized) == 4
    for index, manifest in enumerate(manifests):
        assert manifest["included_device_ids"] == slots[index][0]
        assert manifest["source_capture_group_id"] == GROUP
        assert manifest["background_traffic_present"] is True
        assert manifest["collection_mode"] == ("simultaneous_target_observation" if index < 3 else "simultaneous")
        assert manifest["training_approved"] is manifest["whole_capture_session_approved"] is False
        assert manifest["firmware_provenance"]["status"] == "UNCONFIRMED"


def test_runtime_source_change_keeps_real_partial_snapshot_and_artifacts(project, environment, monkeypatch):
    _, source = add_artifact(project, EPOCH + 20)
    changed = False

    def external_writer():
        nonlocal changed
        if changed:
            return
        changed = True
        payload = '{"device_id":"pico_01","seq":40}'
        with closing(sqlite3.connect(project.db)) as db, db:
            db.execute("INSERT INTO mqtt_logs (device_id,topic,payload,payload_size,received_at,"
                       "is_json_valid,is_topic_valid,payload_raw,payload_decode_status) "
                       "VALUES ('pico_01','iot/pico_01/sensor',?,?,?,1,1,?,'OK')",
                       (payload, len(payload.encode()), collector.utc(environment.time()), payload.encode()))

    environment.on_sleep = external_writer
    monkeypatch.setattr(collector, "git_head", lambda root: "b" * 40 if changed else COMMIT)
    monkeypatch.setattr(collector, "export_normal_collection", lambda *args: pytest.fail("Incomplete run was exported as complete"))
    output = project.root / "output/interrupted"
    result = collector.collect(project.root, output, [(["pico_01"], 60)])
    assert result["status"] == "HOLD"
    package = output / result["runs"][0]["path"]
    manifest = read_json(package / "manifest.json")
    assert manifest["status"] == "HOLD_INCOMPLETE"
    assert "collection_interrupted" in manifest["collection_issues"]
    assert manifest["training_approved"] is manifest["whole_capture_session_approved"] is False
    snapshot = package / manifest["snapshot"]["path"]
    assert snapshot.is_file() and collector.sha256(snapshot) == manifest["snapshot"]["sha256"]
    with closing(sqlite3.connect(snapshot)) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT payload_raw FROM mqtt_logs").fetchone()[0] == b'{"device_id":"pico_01","seq":40}'
        assert db.execute("SELECT trust_score FROM devices WHERE device_id='pico_01'").fetchone()[0] == 100
    artifact = manifest["capture_artifacts"][0]
    assert (package / artifact["pcap_path"]).read_bytes() == source.read_bytes()
    assert source.exists() and source.with_name(source.name + ".capture.json").exists()
    assert not (package / "qc-report.json").exists()


@pytest.mark.parametrize("change", ["checkpoint_timeout", "capture_session_changed"])
def test_finalize_keeps_snapshot_but_never_passes_incomplete_runtime_state(project, environment, monkeypatch, change):
    baseline = collector.state(project.db)
    with closing(sqlite3.connect(project.db)) as db, db:
        db.execute("UPDATE detector_checkpoints SET last_completed_window_end=?", (collector.utc(EPOCH + 60),))
        if change == "checkpoint_timeout":
            db.execute("DELETE FROM detector_checkpoints WHERE detector_name='packet_if'")
        else:
            db.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=?", (collector.utc(EPOCH + 60),))
    package = project.root / "output/finalize"
    package.mkdir(parents=True)
    manifest = {"run_id": "test-finalize", "capture_session_pk": 1,
                "source_capture_group_id": GROUP, "code_commit": COMMIT,
                "start_utc": collector.utc(EPOCH), "end_utc": collector.utc(EPOCH + 60),
                "capture_artifacts": [], "collection_issues": [],
                "training_approved": False, "whole_capture_session_approved": False}

    def content_pass(path):
        raw_manifest = read_json(path / "manifest.json")
        assert raw_manifest["status"] == "RAW_CAPTURED"
        assert collector.sha256(path / "after.db") == raw_manifest["snapshot"]["sha256"]
        return {"status": "PASS", "hold_reasons": []}

    monkeypatch.setattr(collector, "export_normal_collection", content_pass)
    report = collector.finalize(project.root, project.db, package, manifest, baseline)
    assert report["status"] == "HOLD"
    assert report["hold_reasons"]
    assert read_json(package / "manifest.json")["status"] == "HOLD"
    assert read_json(package / "qc-report.json")["status"] == "HOLD"
    assert (package / "after.db").is_file()
    if change == "checkpoint_timeout":
        assert "checkpoint_timeout" in report["hold_reasons"]
        assert environment.elapsed == 120
    else:
        assert read_json(package / "after-state.json")["running_sessions"] == []


def test_fileless_failed_segment_is_retained_for_qc_without_a_fabricated_artifact(project):
    with closing(sqlite3.connect(project.db)) as db, db:
        segment_id = db.execute(
            "INSERT INTO packet_capture_segments (capture_session_id,file_name,capture_interface,"
            "window_start,window_end,status,error_code,captured_duration_seconds) "
            "VALUES (1,NULL,'eth0',?,?,'FAILED','LATE_CAPTURE',0)",
            (collector.utc(EPOCH), collector.utc(EPOCH + 10)),
        ).lastrowid
    package = project.root / "output/fileless"
    package.mkdir(parents=True)
    manifest = {"capture_session_pk": 1, "start_utc": collector.utc(EPOCH),
                "end_utc": collector.utc(EPOCH + 10), "capture_artifacts": []}
    collector.preserve_segments(project.root, project.db, package, manifest)
    assert manifest["capture_artifacts"] == [{"segment_id": segment_id}]
    assert not list((package / "pcap").iterdir())


def test_wal_source_snapshot_is_standalone_without_changing_source(project):
    snapshot = project.root / "output/sealed.db"
    snapshot.parent.mkdir()
    # Keep the live WAL connection open, including a committed uncheckpointed
    # update, just as the subscriber does while the online backup is taken.
    with closing(sqlite3.connect(project.db)) as live:
        assert live.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        live.execute("UPDATE devices SET last_seen_at='2026-10-04T12:01:01Z' WHERE device_id='pico_01'")
        live.commit()
        wal = Path(str(project.db) + "-wal")
        source_wal = wal.read_bytes()
        collector.backup_snapshot(project.db, snapshot)
        with closing(collector.read_db(snapshot)) as copied:
            assert copied.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert copied.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert copied.execute("SELECT last_seen_at FROM devices WHERE device_id='pico_01'").fetchone()[0] == "2026-10-04T12:01:01Z"
        assert live.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert wal.read_bytes() == source_wal
        assert not Path(str(snapshot) + "-wal").exists()
        assert not Path(str(snapshot) + "-shm").exists()


def test_cli_requested_stop_enters_hold_instead_of_abrupt_exit(monkeypatch, tmp_path, capsys):
    import signal

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def requested_stop(*args, **kwargs):
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

    monkeypatch.setattr(collector, "collect", requested_stop)
    monkeypatch.setattr("sys.argv", ["collector", "--output", str(tmp_path / "output"), "--device", "pico_01"])
    try:
        assert collector.main() == 2
        assert json.loads(capsys.readouterr().out)["status"] == "HOLD"
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
