"""Late original bytes stay forensic evidence while detection crosses an audited gap."""

from datetime import timedelta
import hashlib
import json
import socket
import sqlite3

import dpkt
import pytest
from sqlalchemy import text

from backend.app import config as app_config
from edge.detection import ai_runtime_repository
from edge.features import run_packet_feature_extractor as extractor
from edge.orchestration import run_detection_orchestrator as orchestrator
from edge.packet import capture_session_repository as captures
from edge.packet.capture_runtime import CaptureOutcome, CaptureRuntimeConfig, execute_capture_window
from test_confirmed_gap_runtime import _observe_anomaly, _warning_evidence
from test_segment_gap_runtime import (
    runtime, _time, _registry, _checkpoint, CAPTURE_ID, DEVICE_ID, DEVICE_IP,
    format_db_utc, run_producer_cycle, CYCLE_COMPLETED, PACKET_RULE, PACKET_IF,
    TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE,
)

PI_IP = "192.0.2.20"
LATE_SECONDS = 1.270588


class _Clock:
    def __init__(self, start):
        self.current = start
        self.elapsed = 0.0

    def now(self):
        return self.current

    def monotonic(self):
        return self.elapsed

    def advance(self, seconds):
        self.current += timedelta(seconds=seconds)
        self.elapsed += seconds


class _Capture:
    """Only the process is a double: runtime validates and publishes real PCAP."""

    def __init__(self, clock, packet_count):
        self.clock = clock
        self.packet_count = packet_count
        self.requested_seconds = None

    def capture_window(self, *, interface, output_path, window_seconds):
        self.requested_seconds = window_seconds
        tcp = dpkt.tcp.TCP(sport=50000, dport=1883, flags=dpkt.tcp.TH_ACK, data=b"sensor")
        ip = dpkt.ip.IP(src=socket.inet_aton(DEVICE_IP), dst=socket.inet_aton(PI_IP),
                        p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        frame = bytes(dpkt.ethernet.Ethernet(
            src=b"\x00\x00\x00\x00\x00\x01", dst=b"\x00\x00\x00\x00\x00\x02",
            type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
        with output_path.open("wb") as stream:
            writer = dpkt.pcap.Writer(stream)
            for index in range(self.packet_count):
                writer.writepkt(frame, ts=self.clock.now().timestamp() + 0.1 + index * 0.01)
        self.clock.advance(window_seconds)
        stopped = self.clock.now()
        self.clock.advance(0.02)
        return CaptureOutcome(
            completed_full_window=True, exit_code=-15, terminated_cleanly=True,
            stop_requested_at=stopped, process_wait_completed_at=self.clock.now(),
            stderr_complete=True, stderr_error=None, packets_captured=self.packet_count,
            packets_received=self.packet_count, packets_dropped=0,
            packets_dropped_by_interface=None,
        )


def _captured_segment(factory, source, directories, seconds, *, delay=0.2, count=1):
    start = _time(seconds)
    clock = _Clock(start + timedelta(seconds=delay))
    process = _Capture(clock, count)
    result = execute_capture_window(
        process, directories, session_id=CAPTURE_ID,
        window_start=start, window_end=_time(seconds + 10),
        capture_started_at=clock.now(), clock=clock.now, monotonic=clock.monotonic,
    )
    with factory() as db:
        values = dict(
            capture_session_pk=source, file_name=result.file_name, capture_interface="eth0",
            window_start=start, window_end=_time(seconds + 10),
            actual_capture_started_at=result.actual_capture_started_at,
            capture_stop_requested_at=result.capture_stop_requested_at,
            capture_process_exited_at=result.capture_process_exited_at,
            start_delay_seconds=result.start_delay_seconds,
            captured_duration_seconds=result.captured_duration_seconds,
        )
        if result.success:
            segment_id = captures.insert_ready_segment(db, **values)
        else:
            segment_id = captures.insert_failed_segment(
                db, **values, error_code=result.error_code, error_message=result.error_message)
        db.commit()
        if result.success:
            segment = db.execute(text("SELECT * FROM packet_capture_segments WHERE id=:id"),
                                 {"id": segment_id}).mappings().one()
            assert extractor.process_segment(
                db, dict(segment), directories.ready_dir, PI_IP, {DEVICE_IP: DEVICE_ID}
            ) == "PROCESSED"
        feature_id = db.execute(
            text("SELECT id FROM packet_feature_logs WHERE capture_segment_id=:id"),
            {"id": segment_id}).scalar_one_or_none()
    return segment_id, feature_id, result, process


def _chain(runtime, tmp_path, monkeypatch, *, healthy_tail=True):
    factory, _, source = runtime
    directories = CaptureRuntimeConfig(
        "eth0", 10, tmp_path / "incoming", tmp_path / "ready", tmp_path / "failed")
    directories.ensure_directories()
    monkeypatch.setattr(app_config, "settings", app_config.settings.model_copy(
        update={"pcap_failed_dir": str(directories.failed_dir)}))
    _, initial, _, _ = _captured_segment(factory, source, directories, 0)
    failed, absent, result, process = _captured_segment(
        factory, source, directories, 10, delay=LATE_SECONDS)
    assert not result.success and result.error_code == "PARTIAL_CAPTURE"
    assert absent is None and result.final_path.parent == directories.failed_dir
    assert process.requested_seconds == pytest.approx(10 - LATE_SECONDS)
    assert result.capture_stop_requested_at == _time(20)
    metadata = json.loads(result.diagnostics_path.read_text(encoding="utf-8"))
    assert metadata["schema_version"] == "packet-capture-diagnostics-v2"
    assert metadata["completed_full_window"] is True
    assert metadata["quality_failure_reason"] == "start_delay_exceeds_policy"
    assert result.start_delay_seconds == pytest.approx(LATE_SECONDS)
    assert result.captured_duration_seconds == pytest.approx(10 - LATE_SECONDS)
    tail = None
    if healthy_tail:
        _, tail, _, _ = _captured_segment(factory, source, directories, 20, count=201)
    with factory() as db:
        for seconds in range(0, 30, 10):
            db.execute(text(
                "INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at,"
                "is_json_valid,is_topic_valid) VALUES (:device,:topic,'{}',2,:at,1,1)"
            ), {"device": DEVICE_ID, "topic": f"iot/{DEVICE_ID}/sensor",
                "at": format_db_utc(_time(seconds + 1))})
        db.commit()
    run_producer_cycle(session_factory=factory, now=_time(31))
    registry = _registry(tmp_path)
    predictions = []
    delegate = next(item.stage.delegate for item in registry.stages if item.name == PACKET_IF)
    predict = delegate.predict_rows

    def observed_prediction(artifact, rows):
        predictions.extend(int(row["packet_count"]) for row in rows)
        return predict(artifact, rows)

    delegate.predict_rows = observed_prediction
    first = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert first.status == CYCLE_COMPLETED and first.cutoff == _time(10)
    registry = _warning_evidence(factory, registry)
    with factory() as db, db.begin():
        _observe_anomaly(db, registry.runtime_evidence, 0)
    return registry, initial, failed, tail, result, predictions


def _enable(monkeypatch, enabled=True):
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": enabled}))


def _assert_no_partial_outputs(db, failed):
    assert db.execute(text(
        "SELECT COUNT(*) FROM packet_feature_logs WHERE capture_segment_id=:id"
    ), {"id": failed}).scalar_one() == 0
    assert db.execute(text(
        "SELECT COUNT(*) FROM detection_events WHERE analysis_window_start=:start "
        "AND analysis_window_end=:end"
    ), {"start": format_db_utc(_time(10)), "end": format_db_utc(_time(20))}).scalar_one() == 0
    assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"),
                      {"device": DEVICE_ID}).scalar_one() == 100


def test_actual_late_pcap_audits_gap_then_real_extracted_attack_is_scored(runtime, tmp_path, monkeypatch):
    registry, initial, failed, tail, result, predictions = _chain(runtime, tmp_path, monkeypatch)
    factory, _, _ = runtime
    originals = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in (result.final_path, result.diagnostics_path)}
    with factory() as db:
        before = ai_runtime_repository.read_ai_completions(db)
        assert extractor._fetch_ready_segments(db, 10) == []
        _assert_no_partial_outputs(db, failed)
    _enable(monkeypatch)
    gap = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert gap.status == CYCLE_COMPLETED and gap.cutoff == _time(20)
    assert all(item.detector_name not in (PACKET_RULE, PACKET_IF) for item in gap.stage_results)
    with factory() as db:
        audit = db.execute(text("SELECT * FROM packet_detection_gaps")).mappings().one()
        proof = json.loads(audit["evidence_json"])
        assert audit["status"] == "UNINSPECTED" and audit["reason"] == "RECORDED_CAPTURE_GAP"
        assert audit["window_start"] == format_db_utc(_time(10))
        assert audit["window_end"] == format_db_utc(_time(20))
        assert proof["version"] == 3 and proof["loss_kind"] == "PARTIAL_CAPTURE"
        assert proof["failed_segments"][0]["segment"]["id"] == failed
        assert proof["failed_segments"][0]["pcap_sha256"] == originals[result.final_path]
        assert proof["failed_segments"][0]["diagnostics_sha256"] == originals[result.diagnostics_path]
        assert ai_runtime_repository.read_ai_completions(db) == before
        assert db.execute(text(
            "SELECT closed,last_decision FROM ai_warning_aggregates WHERE detector_name='packet_if'"
        )).one() == (1, "INPUT_INTERRUPTED")
        for detector in (PACKET_RULE, PACKET_IF):
            checkpoint = _checkpoint(db, detector)
            assert checkpoint["last_processed_id"] == initial
            assert checkpoint["last_completed_window_end"] == format_db_utc(_time(20))
        _assert_no_partial_outputs(db, failed)
    assert predictions == [1]
    actual = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert actual.status == CYCLE_COMPLETED and actual.cutoff == _time(30)
    with factory() as db:
        assert db.execute(text(
            "SELECT packet_count FROM packet_feature_logs WHERE id=:id"
        ), {"id": tail}).scalar_one() == 201
        assert db.execute(text(
            "SELECT COUNT(*) FROM detection_events WHERE applied_to_score=1 "
            "AND analysis_window_start=:start AND analysis_window_end=:end"
        ), {"start": format_db_utc(_time(20)), "end": format_db_utc(_time(30))}).scalar_one() > 0
        assert db.execute(text("SELECT trust_score FROM devices WHERE device_id=:device"),
                          {"device": DEVICE_ID}).scalar_one() < 100
        # Exclude only the fixture's historical 0-10 warning seed. Neither the
        # partial Window nor its real successor may create a new late event.
        assert db.execute(text(
            "SELECT COUNT(*) FROM detection_events WHERE processing_reason='LATE_EVENT' "
            "AND analysis_window_start>=:start AND analysis_window_end<=:end"
        ), {"start": format_db_utc(_time(10)), "end": format_db_utc(_time(30))}).scalar_one() == 0
        for detector in (PACKET_RULE, PACKET_IF):
            assert _checkpoint(db, detector)["last_processed_id"] == tail
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)[
            "last_completed_window_end"] == format_db_utc(_time(30))
        assert db.execute(text(
            "SELECT status,error_code FROM packet_capture_segments WHERE id=:id"
        ), {"id": failed}).one() == ("FAILED", "PARTIAL_CAPTURE")
    assert predictions == [1, 201]
    assert originals == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in originals}


@pytest.mark.parametrize("blocker", ["policy_disabled", "no_healthy_successor"])
def test_actual_late_pcap_keeps_hold_without_enabled_policy_and_healthy_successor(
    runtime, tmp_path, monkeypatch, blocker
):
    registry, initial, failed, _, _, predictions = _chain(
        runtime, tmp_path, monkeypatch, healthy_tail=blocker != "no_healthy_successor")
    factory, _, _ = runtime
    _enable(monkeypatch, blocker != "policy_disabled")
    result = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    assert result.status != CYCLE_COMPLETED
    with factory() as db:
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 0
        for detector in (PACKET_RULE, PACKET_IF):
            checkpoint = _checkpoint(db, detector)
            assert checkpoint["last_processed_id"] == initial
            assert checkpoint["last_completed_window_end"] == format_db_utc(_time(10))
        assert db.execute(text("SELECT closed,last_decision FROM ai_warning_aggregates")).one() == (
            0, "BELOW_THRESHOLD")
        _assert_no_partial_outputs(db, failed)
    assert predictions == [1]


def test_actual_late_pcap_warning_failure_rolls_back_both_boundaries_and_audit(
    runtime, tmp_path, monkeypatch
):
    registry, _, failed, _, _, predictions = _chain(runtime, tmp_path, monkeypatch)
    factory, _, _ = runtime
    with factory() as db:
        before = [_checkpoint(db, detector) for detector in (PACKET_RULE, PACKET_IF)]
    interrupt = ai_runtime_repository.interrupt_ai_warnings

    def fail_after_interruption(*args, **kwargs):
        interrupt(*args, **kwargs)
        raise RuntimeError("late partial warning persistence failed")

    monkeypatch.setattr(ai_runtime_repository, "interrupt_ai_warnings", fail_after_interruption)
    _enable(monkeypatch)
    with pytest.raises(RuntimeError, match="late partial warning persistence failed"):
        orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
    with factory() as db:
        assert [_checkpoint(db, detector) for detector in (PACKET_RULE, PACKET_IF)] == before
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 0
        assert db.execute(text("SELECT closed,last_decision FROM ai_warning_aggregates")).one() == (
            0, "BELOW_THRESHOLD")
        _assert_no_partial_outputs(db, failed)
    assert predictions == [1]


def test_actual_audited_late_pcap_still_blocks_normal_dataset_export_and_import(
    runtime, tmp_path, monkeypatch
):
    from edge.packet.capture_policy import CapturePolicy
    from edge.phase5 import import_verified_collection as importer
    from test_export_packet_if_dataset import _export

    registry, _, failed, _, result, _ = _chain(runtime, tmp_path, monkeypatch)
    factory, db_path, source = runtime
    _enable(monkeypatch)
    assert orchestrator.run_orchestration_cycle(
        session_factory=factory, registry=registry).cutoff == _time(20)
    with factory() as db:
        captures.close_session(db, source, _time(30), "COMPLETED")
        db.commit()
        output_path = tmp_path / "must-not-publish.csv"
        with pytest.raises(ValueError, match="ineligible Segment for Packet IF export"):
            _export(db, output_path=output_path, session_ids=[CAPTURE_ID])
        assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar_one() == 1
        _assert_no_partial_outputs(db, failed)
    assert not output_path.exists() and not output_path.with_suffix(".manifest.json").exists()

    spec = importer.VerifiedCollectionSessionSpec.from_dict({
        "session_id": CAPTURE_ID, "collection_slot_id": "late-partial-training-guard",
        "split": "train", "traffic_label": "normal", "scenario": "normal_stable",
        "collection_device_id": "esp32_01", "firmware_version": "phase5-normal-pilot-v1",
        "payload_schema_version": "phase5-normal-payload-v1",
        "payload_schema_provenance": "FIRMWARE_REPORTED", "capture_source_commit_sha": "a" * 40,
    })
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(importer.VerifiedCollectionImportError, match="FAILED Segment"):
            importer._build_session_plan(
                connection, session_spec=spec, device_ips={DEVICE_ID: DEVICE_IP},
                pcap_dir=result.final_path.parent, capture_policy=CapturePolicy())
