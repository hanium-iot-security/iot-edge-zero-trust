"""Real pcap -> extractor -> stored Broker evidence -> Rule -> Trust regression."""

from datetime import datetime, timezone
import json
import socket

import dpkt
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection.packet_rule_detector import DEFAULT_PACKET_RULE_POLICY, PacketRuleDetectorStage
from edge.features.run_packet_feature_extractor import process_segment, settings
from edge.packet.capture_policy import CapturePolicy
from edge.trust.trust_score_v2 import apply_trust_score_v2_until


PI_IP = "192.168.0.20"
PEER_IP = "192.168.0.30"
START = datetime(2026, 7, 26, 10, tzinfo=timezone.utc)
END = datetime(2026, 7, 26, 10, 0, 10, tzinfo=timezone.utc)
START_TEXT = "2026-07-26T10:00:00Z"
END_TEXT = "2026-07-26T10:00:10Z"


def _packet(flags, port=1883, *, outbound=False, payload=b""):
    tcp = dpkt.tcp.TCP(
        sport=1883 if outbound else 40000,
        dport=40000 if outbound else port,
        flags=flags, data=payload,
    )
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_aton(PI_IP if outbound else PEER_IP),
        dst=socket.inet_aton(PEER_IP if outbound else PI_IP),
        p=dpkt.ip.IP_PROTO_TCP, data=tcp,
    )
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01",
        dst=b"\x00\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    ))


def _traffic(case):
    if case == "other_port_scan_with_mqtt":
        return [_packet(0x02, 2000 + index) for index in range(40)] + [_packet(0x18)] * 24
    if case == "publish_flood":
        # MQTT QoS 0 PUBLISH(topic=t, payload=x) on an existing connection.
        return [_packet(0x18, payload=b"\x30\x04\x00\x01tx")] * 200
    syn_count, mqtt_count = {
        "syn_burst": (24, 48),
        "normal": (1, 5),
        "reconnect": (3, 6),
        "syn_boundary": (10, 21),
        "mqtt_boundary": (11, 20),
        "above_both": (11, 21),
    }[case]
    # Repeated SYNs deliberately retain the same 4-tuple: retransmissions count
    # as captured packets, not as unique connections.
    return ([_packet(0x02)] * syn_count
            + [_packet(0x10)] * (mqtt_count - syn_count)
            + [_packet(0x12, outbound=True)] * syn_count)


@pytest.fixture
def pipeline_db(tmp_path):
    path = tmp_path / "broker.db"
    apply_migrations(path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as db:
            db.execute(text("PRAGMA foreign_keys=ON"))
            db.execute(text("""INSERT INTO devices (
                device_id, ip_address, status, trust_score, registration_effective_from
            ) VALUES ('sensor', :peer, 'normal', 100, :start)"""),
                {"peer": PEER_IP, "start": START_TEXT})
            db.execute(text("""INSERT INTO device_policy_revisions (
                device_id, revision, effective_from, registration_state, policy_profile,
                expected_publish_interval_seconds, publish_count_max, payload_size_max_bytes,
                packet_rate_max_pps, byte_rate_max_bytes_per_second, created_at, created_by, reason
            ) VALUES ('sensor', 1, :start, 'ACTIVE', 'periodic-sensor-v1',
                5, 15, 5120, 10, 2500, :start, 'test', 'pcap integration')"""),
                {"start": START_TEXT})
            db.execute(text("""INSERT INTO packet_capture_sessions (
                id, session_id, capture_interface, started_at, first_window_start, ended_at, status
            ) VALUES (1, '11111111-1111-4111-8111-111111111111', 'eth0',
                :start, :start, :end, 'COMPLETED')"""), {"start": START_TEXT, "end": END_TEXT})
            db.execute(text("""INSERT INTO packet_capture_segments (
                id, capture_session_id, file_name, capture_interface, window_start, window_end,
                status, start_delay_seconds, captured_duration_seconds
            ) VALUES (1, 1, 'broker.pcap', 'eth0', :start, :end, 'READY', 0, 10)"""),
                {"start": START_TEXT, "end": END_TEXT})
            db.commit()
            yield db
    finally:
        engine.dispose()


@pytest.mark.parametrize("case,configured,syn_count,event_types,score", [
    ("syn_burst", True, 24, {"BROKER_DOS_SUSPECTED"}, 75),
    ("other_port_scan_with_mqtt", True, 0, {"PORT_SCAN"}, 80),
    ("normal", True, 1, set(), 100),
    ("reconnect", True, 3, set(), 100),
    ("publish_flood", True, 0, {"PACKET_RATE_ANOMALY"}, 80),
    ("syn_boundary", True, 10, set(), 100),
    ("mqtt_boundary", True, 11, set(), 100),
    ("above_both", True, 11, {"BROKER_DOS_SUSPECTED"}, 75),
    ("syn_burst", False, None, {"BROKER_DOS_EVIDENCE_UNAVAILABLE"}, 100),
])
def test_pcap_to_rule_and_trust(
    pipeline_db, tmp_path, monkeypatch, case, configured, syn_count, event_types, score,
):
    with (tmp_path / "broker.pcap").open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        for index, packet in enumerate(_traffic(case)):
            writer.writepkt(packet, ts=START.timestamp() + index * 0.01)
    segment = {"id": 1, "file_name": "broker.pcap", "window_start": START_TEXT, "window_end": END_TEXT}
    assert process_segment(
        pipeline_db, segment, tmp_path, PI_IP, {PEER_IP: "sensor"},
        broker_target_ip=PI_IP if configured else None,
    ) == "PROCESSED"
    feature = pipeline_db.execute(text("""SELECT * FROM packet_feature_logs
        WHERE direction='INBOUND'""")).mappings().one()
    assert feature["device_id"] == "sensor"
    assert feature["broker_target_syn_count"] == syn_count
    assert feature["broker_target_ip"] == (PI_IP if configured else None)
    assert feature["broker_target_port"] == (1883 if configured else None)
    outbound = pipeline_db.execute(text("""SELECT broker_target_syn_count
        FROM packet_feature_logs WHERE direction='OUTBOUND'""")).scalars().all()
    assert all(count == (0 if configured else None) for count in outbound)
    pipeline_db.commit()

    # Historical evidence remains tied to the stored endpoint after env/config changes.
    monkeypatch.setattr(settings, "broker_target_ip", "192.168.0.99")
    stage = PacketRuleDetectorStage(capture_policy=CapturePolicy(), rule_policy=DEFAULT_PACKET_RULE_POLICY)
    with pipeline_db.begin():
        result = stage.run_until(pipeline_db, cycle_range_start=START, cycle_cutoff=END)
        trust = apply_trust_score_v2_until(
            pipeline_db, cycle_range_start=START, cycle_cutoff=END, ai_mode="observe", decision_at=END,
        )
    assert result.created_event_count == len(event_types)
    events = pipeline_db.execute(text("SELECT * FROM detection_events")).mappings().all()
    assert {event["event_type"] for event in events} == event_types
    for event in events:
        evidence = json.loads(event["evidence_json"])
        assert evidence["broker_target_ip"] == (PI_IP if configured else None)
        assert evidence["broker_target_port"] == (1883 if configured else None)
        assert evidence["raw_counts"]["broker_target_syn_count"] == syn_count
        assert event["analysis_window_start"] == START_TEXT
        assert event["analysis_window_end"] == END_TEXT
        if not configured:
            assert event["score_delta"] == event["applied_to_score"] == 0
    assert pipeline_db.execute(text("SELECT trust_score FROM devices")).scalar_one() == score
    assert trust.created_history_count == int(score < 100)
    assert trust.created_firewall_rule_count == 0
    assert pipeline_db.execute(text("SELECT COUNT(*) FROM firewall_rules")).scalar_one() == 0
