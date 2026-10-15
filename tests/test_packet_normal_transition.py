"""Sealed fixture proof and rejection cases for bounded normal transitions."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import socket
import sqlite3

import dpkt
import pytest

from ai.packet_normal_transition import validate_transition
from edge.packet.capture_policy import CapturePolicy


GROUP = "93da8689-a5de-4af4-a6cb-5872dd9807e4"
BASE = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def utc(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def seal(root, name, value):
    path = root / name
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def frame(kind, payload=b""):
    remaining, length = len(payload), bytearray()
    while True:
        part, remaining = remaining % 128, remaining // 128
        length.append(part | (128 if remaining else 0))
        if not remaining:
            return bytes([kind]) + bytes(length) + payload


def publish(topic, body):
    topic = topic.encode()
    return frame(0x30, len(topic).to_bytes(2, "big") + topic + body)


def ethernet(src, dst, sport, dport, seq, flags, payload=b"", ack=0):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=payload, win=1024)
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x01"*6, dst=b"\x02"*6, type=0x800, data=ip))


def make_evidence(root, device="pico_01", kind="sender_restore"):
    topic = f"iot/{device}/sensor"
    pico = device == "pico_01"
    schema = "pico-bme280-v1" if pico else "esp32-telemetry-v1"
    source = seal(root, "sender.bin", b"public and installed sender bytes")
    installed = seal(root, "installed-readback.bin", b"public and installed sender bytes")
    runtime = seal(root, "runtime.bin", b"read-back runtime build bytes")
    library = seal(root, "library.bin", b"read-back MQTT library bytes")
    attestations = {}
    for phase, lower, upper, observed in (("before", 0, 20, -10), ("after", 21, 40, 20.5)):
        attestations[phase] = seal(root, f"{phase}.json", {
            "schema_version": "packet-device-installation-v1", "device_id": device,
            "source_capture_group_id": GROUP, "phase": phase, "observed_at": utc(observed),
            "effective_from": utc(lower), "effective_until": utc(upper),
            "payload_schema": schema, "firmware_id": "normal-sender-v1", "power_management": "PM_NONE",
            "public_sender": source, "installed_sender": installed, "runtime": runtime, "libraries": [library],
            "verification_scope": "device-readback", "runtime_id": "runtime-build-v1", "library_ids": ["mqtt-library-v1"],
        })
    operation = seal(root, "operation.json", {
        "schema_version": "packet-controlled-operation-v1", "kind": kind,
        "device_id": device, "source_capture_group_id": GROUP,
        "started_at": utc(20), "completed_at": utc(21), "authorization": "human-authorized",
        "execution_id": "actual-controlled-operation-1",
    })
    db = sqlite3.connect(root / "snapshot.db")
    db.executescript("""
        CREATE TABLE packet_capture_sessions(id INTEGER, session_id TEXT, started_at TEXT, ended_at TEXT);
        CREATE TABLE mqtt_logs(id INTEGER PRIMARY KEY, device_id TEXT, topic TEXT, payload TEXT,
          payload_size INTEGER, payload_raw BLOB, payload_decode_status TEXT, received_at TEXT,
          is_json_valid INTEGER, is_topic_valid INTEGER, error_message TEXT);
    """)
    db.execute("INSERT INTO packet_capture_sessions VALUES(7,?,?,?)", (GROUP, utc(-10), utc(50)))
    samples = []
    for index, seconds in enumerate((1, 6, 11, 16, 23, 28, 33, 38)):
        seq = index + 1 if index < 4 or kind == "wifi_mqtt_reconnect" else index - 3
        uptime = 100 + seconds if index < 4 or kind == "wifi_mqtt_reconnect" else seconds - 21
        value = {"device_id": device, ("seq" if pico else "sequence"): seq,
                 ("uptime_ms" if pico else "uptime_s"): int(uptime * (1000 if pico else 1))}
        if pico:
            value.update(temperature_c=22.5, humidity_pct=50, pressure_hpa=1000)
        raw = json.dumps(value, separators=(",", ":")).encode()
        db.execute("INSERT INTO mqtt_logs VALUES(?,?,?,?,?,?,?,?,1,1,NULL)",
                   (index+1, device, topic, raw.decode(), len(raw), raw, "OK", utc(seconds)))
        samples.append((seconds, raw))
    db.commit()
    db.close()
    packets = []
    ip, broker = "192.168.0.8", "192.168.0.20"
    oldseq = 100
    for seconds, raw in samples[:4]:
        payload = publish(topic, raw)
        packets.append((seconds-.01, ethernet(ip, broker, 3000, 1883, oldseq, dpkt.tcp.TH_ACK, payload)))
        oldseq += len(payload)
    packets.extend([
        (21.1, ethernet(ip, broker, 3001, 1883, 500, dpkt.tcp.TH_SYN)),
        (21.2, ethernet(broker, ip, 1883, 3001, 900, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, ack=501)),
        (21.3, ethernet(ip, broker, 3001, 1883, 501, dpkt.tcp.TH_ACK, ack=901)),
    ])
    connect = frame(0x10, b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x07fixture")
    packets.extend([(21.4, ethernet(ip, broker, 3001, 1883, 501, dpkt.tcp.TH_ACK, connect)),
                    (21.5, ethernet(broker, ip, 1883, 3001, 901, dpkt.tcp.TH_ACK, frame(0x20, b"\x00\x00")))])
    seq = 501 + len(connect)
    for seconds, raw in samples[4:]:
        payload = publish(topic, raw)
        # Include coalesced or split TCP payload support rather than relying on packet boundaries.
        packets.append((seconds-.02, ethernet(ip, broker, 3001, 1883, seq, dpkt.tcp.TH_ACK, payload[:3])))
        packets.append((seconds-.01, ethernet(ip, broker, 3001, 1883, seq+3, dpkt.tcp.TH_ACK, payload[3:])))
        seq += len(payload)
    stream = io.BytesIO()
    writer = dpkt.pcap.Writer(stream)
    for seconds, packet in packets:
        writer.writepkt(packet, BASE.timestamp()+seconds)
    pcap = seal(root, "transition.pcap", stream.getvalue())
    evidence = {
        "schema_version": "packet-normal-transition-evidence-v1", "source_capture_group_id": GROUP,
        "capture_session_pk": 7, "role": "train", "start_utc": utc(0), "end_utc": utc(40),
        "included_device_ids": [device], "devices": [{"device_id": device, "ip_address": ip,
            "mqtt_topic": topic, "payload_schema": schema}], "broker_ip": broker,
        "capture_policy": asdict(CapturePolicy()), "capture_filter": "tcp port 1883", "code_commit": "a"*40,
        "snapshot": seal(root, "snapshot.db", (root / "snapshot.db").read_bytes()),
        "operation": operation, "before": attestations["before"], "after": attestations["after"],
        "pcaps": [pcap], "training_approved": False, "whole_capture_session_approved": False,
    }
    return evidence


def validate(root, evidence):
    return validate_transition(root, seal(root, "evidence.json", evidence))


@pytest.mark.parametrize("device", ["pico_01", "esp32_01", "esp32_02"])
@pytest.mark.parametrize("kind", ["sender_restore", "public_sender_deploy", "power_restart", "wifi_mqtt_reconnect"])
def test_proves_controlled_transition_from_original_bytes(tmp_path, device, kind):
    result = validate(tmp_path, make_evidence(tmp_path, device, kind))
    assert result["included_device_ids"] == [device]
    assert result["training_approved"] is False
    assert result["whole_capture_session_approved"] is False
    assert result["verified_transition"]["mqtt_log_ids"] == list(range(1, 9))
    assert {item["path"] for item in result["input_files"]} >= {"evidence.json", "snapshot.db", "transition.pcap"}


@pytest.mark.parametrize("key,value,code", [
    ("role", "holdout", "transition_role"), ("start_utc", utc(1), "transition_full_windows"),
    ("training_approved", True, "transition_approval"), ("whole_capture_session_approved", True, "transition_approval"),
    ("included_device_ids", ["pico_01", "ESP32_01"], "transition_one_device"),
    ("source_capture_group_id", 123, "transition_capture_uuid"),
])
def test_rejects_scope_changes(tmp_path, key, value, code):
    evidence = make_evidence(tmp_path)
    evidence[key] = value
    with pytest.raises(ValueError, match=code):
        validate(tmp_path, evidence)


@pytest.mark.parametrize("artifact", ["sender.bin", "runtime.bin", "library.bin", "operation.json", "transition.pcap", "snapshot.db"])
def test_rejects_hash_tampering(tmp_path, artifact):
    evidence = make_evidence(tmp_path)
    with (tmp_path / artifact).open("ab") as handle:
        handle.write(b"changed")
    with pytest.raises(ValueError, match="transition_file_checksum"):
        validate(tmp_path, evidence)


def change_json(root, evidence, key, mutate):
    value = json.loads((root / evidence[key]["path"]).read_text())
    mutate(value)
    evidence[key] = seal(root, evidence[key]["path"], value)


@pytest.mark.parametrize("phase,field,value,code", [
    ("before", "observed_at", utc(2), "transition_attestation_scope"),
    ("after", "effective_until", utc(30), "transition_attestation_scope"),
    ("after", "power_management", "UNVERIFIED", "transition_attestation_identity"),
    ("after", "device_id", "ESP32_01", "transition_attestation_identity"),
    ("after", "runtime_id", "UNVERIFIED", "transition_attestation_identity"),
    ("after", "library_ids", ["UNKNOWN"], "transition_library_identity"),
    ("after", "verification_scope", "PUBLIC_SOURCE_ONLY", "transition_attestation_verification_scope"),
])
def test_rejects_unproven_installation(tmp_path, phase, field, value, code):
    evidence = make_evidence(tmp_path)
    change_json(tmp_path, evidence, phase, lambda item: item.update({field: value}))
    with pytest.raises(ValueError, match=code):
        validate(tmp_path, evidence)


def test_rejects_escape_even_if_hash_matches(tmp_path):
    evidence = make_evidence(tmp_path)
    evidence["before"]["path"] = "../before.json"
    with pytest.raises(ValueError, match="transition_unsafe_path"):
        validate(tmp_path, evidence)


@pytest.mark.parametrize("sql,code", [
    ("UPDATE mqtt_logs SET topic='iot/other/sensor' WHERE id=1", "transition_payload_identity"),
    ("DELETE FROM mqtt_logs WHERE id=2", "transition_sample_sequence"),
    ("UPDATE mqtt_logs SET payload_raw=NULL WHERE id=1", "transition_payload_bytes"),
    ("UPDATE packet_capture_sessions SET session_id='other'", "transition_snapshot_capture"),
])
def test_rejects_snapshot_semantics_even_when_resealed(tmp_path, sql, code):
    evidence = make_evidence(tmp_path)
    with sqlite3.connect(tmp_path / "snapshot.db") as db:
        db.execute(sql)
    evidence["snapshot"] = seal(tmp_path, "snapshot.db", (tmp_path / "snapshot.db").read_bytes())
    with pytest.raises(ValueError, match=code):
        validate(tmp_path, evidence)


def test_wifi_reconnect_does_not_allow_sequence_reset(tmp_path):
    evidence = make_evidence(tmp_path)
    change_json(tmp_path, evidence, "operation", lambda item: item.update(kind="wifi_mqtt_reconnect"))
    with pytest.raises(ValueError, match="transition_power_preserving_continuity"):
        validate(tmp_path, evidence)


def test_missing_connack_bytes_cannot_be_replaced_by_a_claim(tmp_path):
    evidence = make_evidence(tmp_path)
    raw = (tmp_path / "transition.pcap").read_bytes().replace(b"\x20\x02\x00\x00", b"\x20\x02\x00\x05")
    evidence["pcaps"] = [seal(tmp_path, "transition.pcap", raw)]
    with pytest.raises(ValueError, match="transition_mqtt_connack"):
        validate(tmp_path, evidence)


def rewrite_packets(root, evidence, mutate):
    raw = io.BytesIO((root / "transition.pcap").read_bytes())
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    for stamp, packet in dpkt.pcap.Reader(raw):
        ethernet_packet = dpkt.ethernet.Ethernet(packet)
        keep = mutate(ethernet_packet)
        if keep is not False:
            writer.writepkt(bytes(ethernet_packet), stamp)
    evidence["pcaps"] = [seal(root, "transition.pcap", output.getvalue())]


def test_tcp_stream_must_belong_to_observed_syn_sequence(tmp_path):
    evidence = make_evidence(tmp_path)

    def change(packet):
        tcp = packet.data.data
        if tcp.sport == 3001 and not tcp.flags & dpkt.tcp.TH_SYN:
            tcp.seq += 100

    rewrite_packets(tmp_path, evidence, change)
    with pytest.raises(ValueError, match="transition_tcp_handshake_sequence"):
        validate(tmp_path, evidence)


def test_original_sender_file_is_not_installed_readback_evidence(tmp_path):
    evidence = make_evidence(tmp_path)
    change_json(tmp_path, evidence, "before", lambda value: value.update(installed_sender=value["public_sender"]))
    with pytest.raises(ValueError, match="transition_independent_readback"):
        validate(tmp_path, evidence)


def test_syn_without_mqtt_connect_is_not_a_normal_transition(tmp_path):
    evidence = make_evidence(tmp_path)

    def change(packet):
        tcp = packet.data.data
        if tcp.sport == 3001 and tcp.data.startswith(b"\x10"):
            return False

    rewrite_packets(tmp_path, evidence, change)
    with pytest.raises(ValueError, match="transition_mqtt_connect|transition_tcp_handshake_sequence"):
        validate(tmp_path, evidence)


def test_missing_runtime_bytes_are_not_eligible(tmp_path):
    evidence = make_evidence(tmp_path)
    (tmp_path / "runtime.bin").unlink()
    with pytest.raises(ValueError):
        validate(tmp_path, evidence)


@pytest.mark.parametrize("device", ["ESP32_01", "ESP32_02"])
def test_uppercase_esp_alias_is_not_the_registered_device(tmp_path, device):
    evidence = make_evidence(tmp_path, device)
    with pytest.raises(ValueError, match="transition_device_identity"):
        validate(tmp_path, evidence)


def test_unknown_control_kind_is_not_a_normal_label(tmp_path):
    evidence = make_evidence(tmp_path)
    change_json(tmp_path, evidence, "operation", lambda item: item.update(kind="unknown_disconnect"))
    with pytest.raises(ValueError, match="transition_operation_identity"):
        validate(tmp_path, evidence)


def test_snapshot_sidecar_is_not_immutable_evidence(tmp_path):
    evidence = make_evidence(tmp_path)
    (tmp_path / "snapshot.db-wal").write_bytes(b"pending")
    with pytest.raises(ValueError, match="transition_snapshot_not_standalone"):
        validate(tmp_path, evidence)


@pytest.mark.parametrize("mutation,code", [
    ("port", "transition_unexpected_target_traffic"),
    ("payload", "transition_mqtt_payload_bytes"),
    ("fragment", "transition_unexpected_target_traffic"),
    ("reset", "transition_new_flow_reset"),
])
def test_protocol_bytes_still_checked_after_resealing(tmp_path, mutation, code):
    evidence = make_evidence(tmp_path)

    def change(packet):
        ip, tcp = packet.data, packet.data.data
        if tcp.sport == 3001:
            if mutation == "port":
                tcp.dport = 1884
            elif mutation == "payload":
                tcp.data = bytes(tcp.data).replace(b"22.5", b"22.6")
            elif mutation == "fragment":
                ip.offset = 1
            elif mutation == "reset":
                tcp.flags |= dpkt.tcp.TH_RST

    rewrite_packets(tmp_path, evidence, change)
    with pytest.raises(ValueError, match=code):
        validate(tmp_path, evidence)
