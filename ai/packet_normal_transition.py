"""Verify sealed, controlled normal-transition evidence for development datasets.

This verifies the supplied original bytes and their recorded observation scope. It
does not authenticate a human's operation record, approve a whole Capture Session,
or turn an unexplained alert into a normal label. Missing read-back/runtime proof,
incomplete MQTT streams, and unsupported traffic fail closed. Capture segment and
Packet feature eligibility remain the caller's responsibility.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import sqlite3
from uuid import UUID

import dpkt

from ai.pico_reception_qc import _pcap_records
from ai.export_normal_collection import _hash
from edge.packet.capture_policy import CapturePolicy

SCHEMA = "packet-normal-transition-evidence-v1"
KINDS = frozenset({"sender_restore", "public_sender_deploy", "power_restart", "wifi_mqtt_reconnect"})
_SHA = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_DEVICE_SCHEMAS = {"pico_01": "pico-bme280-v1", "esp32_01": "esp32-telemetry-v1",
                   "esp32_02": "esp32-telemetry-v1"}
_UNKNOWN = frozenset({"UNKNOWN", "UNVERIFIED", "UNDETERMINED"})


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _exact(value, keys, code):
    _require(isinstance(value, dict) and set(value) == set(keys), code)
    return value


def _time(value):
    _require(type(value) is str, "transition_timestamp")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("transition_timestamp") from exc
    _require(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0, "transition_timestamp")
    return stamp.astimezone(timezone.utc)


def _db_time(value):
    # Legacy SQLite receiver timestamps without offsets are explicitly stored UTC.
    if type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?", value):
        value = value.replace(" ", "T") + "Z"
    return _time(value)


class _Files:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.verified = {}

    def file(self, ref):
        _exact(ref, {"path", "sha256"}, "transition_file_ref")
        value, digest = ref["path"], ref["sha256"]
        _require(type(value) is str and value and "\\" not in value and ":" not in value
                 and not Path(value).is_absolute() and ".." not in Path(value).parts, "transition_unsafe_path")
        _require(type(digest) is str and _SHA.fullmatch(digest), "transition_file_sha256")
        path = (self.root / value).resolve()
        _require(path.is_relative_to(self.root) and path.is_file(), "transition_unsafe_path")
        _require(_hash(path) == digest, "transition_file_checksum")
        previous = self.verified.setdefault(value, digest)
        _require(previous == digest, "transition_file_conflicting_ref")
        return path

    def json(self, ref):
        path = self.file(ref)
        _require(path.stat().st_size <= 2*1024*1024, "transition_json_size")
        try:
            def pairs(items):
                result = {}
                for key, value in items:
                    _require(key not in result, "transition_duplicate_json_key")
                    result[key] = value
                return result

            return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("transition_json_number")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("transition_json") from exc

    def finish(self):
        for path, digest in self.verified.items():
            self.file({"path": path, "sha256": digest})
        return [{"path": path, "sha256": digest} for path, digest in sorted(self.verified.items())]


def _installation(files, ref, evidence, device, phase, left, right):
    value = files.json(ref)
    _exact(value, {"schema_version", "device_id", "source_capture_group_id", "phase", "observed_at",
                   "effective_from", "effective_until", "payload_schema", "firmware_id", "power_management",
                   "public_sender", "installed_sender", "runtime", "libraries", "verification_scope",
                   "runtime_id", "library_ids"}, "transition_attestation_fields")
    _require(value["verification_scope"] == "device-readback", "transition_attestation_verification_scope")
    _require(value["schema_version"] == "packet-device-installation-v1" and value["device_id"] == device["device_id"]
             and value["source_capture_group_id"] == evidence["source_capture_group_id"] and value["phase"] == phase
             and value["payload_schema"] == device["payload_schema"]
             and type(value["firmware_id"]) is str and _IDENTIFIER.fullmatch(value["firmware_id"])
             and type(value["power_management"]) is str and _IDENTIFIER.fullmatch(value["power_management"])
             and value["power_management"].upper() not in _UNKNOWN
             and value["firmware_id"].upper() not in _UNKNOWN
             and type(value["runtime_id"]) is str and _IDENTIFIER.fullmatch(value["runtime_id"])
             and value["runtime_id"].upper() not in _UNKNOWN,
             "transition_attestation_identity")
    _require(_time(value["observed_at"]) <= left and _time(value["effective_from"]) <= left
             and _time(value["effective_until"]) >= right, "transition_attestation_scope")
    for key in ("public_sender", "installed_sender", "runtime"):
        path = files.file(value[key])
        _require(path.stat().st_size > 0, "transition_empty_installation_artifact")
    # This contract deliberately requires byte read-back equivalence, not a source
    # filename or an assertion that an unknown compiled image came from that source.
    _require(value["public_sender"]["sha256"] == value["installed_sender"]["sha256"],
             "transition_installed_sender_mismatch")
    _require(files.file(value["public_sender"]) != files.file(value["installed_sender"]),
             "transition_independent_readback")
    _require(isinstance(value["libraries"], list) and value["libraries"], "transition_library_artifacts")
    _require(isinstance(value["library_ids"], list) and len(value["library_ids"]) == len(value["libraries"])
             and all(type(item) is str and _IDENTIFIER.fullmatch(item) and item.upper() not in _UNKNOWN
                     for item in value["library_ids"]) and len(set(value["library_ids"])) == len(value["library_ids"]),
             "transition_library_identity")
    library_paths = set()
    for ref in value["libraries"]:
        path = files.file(ref)
        _require(path.stat().st_size > 0 and ref["path"] not in library_paths, "transition_library_artifacts")
        library_paths.add(ref["path"])
    return value


def _payload(row, device):
    raw = row["payload_raw"]
    _require(isinstance(raw, bytes) and raw and row["payload_size"] == len(raw)
             and row["payload_decode_status"] == "OK" and row["is_json_valid"] == 1
             and row["is_topic_valid"] == 1 and row["error_message"] is None, "transition_payload_bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("transition_payload_json") from exc
    pico = device["payload_schema"] == "pico-bme280-v1"
    sequence, uptime = ("seq", "uptime_ms") if pico else ("sequence", "uptime_s")
    keys = {"device_id", sequence, uptime} | ({"temperature_c", "humidity_pct", "pressure_hpa"} if pico else set())
    _require(isinstance(value, dict) and set(value) == keys and value["device_id"] == device["device_id"]
             and row["device_id"] == device["device_id"] and row["topic"] == device["mqtt_topic"]
             and row["payload"] == text, "transition_payload_identity")
    _require(type(value[sequence]) is int and value[sequence] > 0 and type(value[uptime]) is int
             and value[uptime] >= 0, "transition_payload_sequence_fields")
    if pico:
        for key, lower, upper in (("temperature_c", -40, 85), ("humidity_pct", 0, 100), ("pressure_hpa", 300, 1100)):
            number = value[key]
            _require(type(number) in (int, float) and math.isfinite(number) and lower <= number <= upper,
                     "transition_sensor_value")
    return {"id": row["id"], "received_at": _db_time(row["received_at"]), "sequence": value[sequence],
            "uptime": value[uptime]/(1000 if pico else 1), "raw": raw}


def _snapshot_samples(files, evidence, device, start, end, operation):
    path = files.file(evidence["snapshot"])
    _require(not any(Path(str(path)+suffix).exists() for suffix in ("-wal", "-shm", "-journal")),
             "transition_snapshot_not_standalone")
    with closing(sqlite3.connect(path.as_uri()+"?mode=ro&immutable=1", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        _require([row[0] for row in db.execute("PRAGMA integrity_check")] == ["ok"], "transition_snapshot_integrity")
        capture = db.execute("SELECT * FROM packet_capture_sessions WHERE id=?", (evidence["capture_session_pk"],)).fetchone()
        _require(capture is not None and capture["session_id"] == evidence["source_capture_group_id"]
                 and _db_time(capture["started_at"]) <= start
                 and capture["ended_at"] is not None and _db_time(capture["ended_at"]) >= end,
                 "transition_snapshot_capture")
        rows = db.execute("SELECT * FROM mqtt_logs WHERE device_id=? AND julianday(received_at)>=julianday(?) "
                          "AND julianday(received_at)<julianday(?) ORDER BY julianday(received_at),id",
                          (device["device_id"], evidence["start_utc"], evidence["end_utc"])).fetchall()
        samples = [_payload(row, device) for row in rows]
    lower, upper = _time(operation["started_at"]), _time(operation["completed_at"])
    before = [row for row in samples if row["received_at"] < lower]
    after = [row for row in samples if row["received_at"] >= upper]
    _require(len(before) >= 2 and len(after) >= 2 and len(before)+len(after) == len(samples)
             and (before[0]["received_at"]-start).total_seconds() < 10
             and (end-after[-1]["received_at"]).total_seconds() <= 10, "transition_stable_sides")
    for phase in (before, after):
        for a, b in zip(phase, phase[1:]):
            _require(b["sequence"] == a["sequence"]+1 and b["uptime"] > a["uptime"]
                     and b["received_at"] > a["received_at"], "transition_sample_sequence")
            gap = (b["received_at"]-a["received_at"]).total_seconds()
            _require(3 <= gap <= 10 and abs(gap-(b["uptime"]-a["uptime"])) <= 2,
                     "transition_stable_cadence")
    if operation["kind"] == "wifi_mqtt_reconnect":
        _require(after[0]["sequence"] == before[-1]["sequence"]+1
                 and after[0]["uptime"] > before[-1]["uptime"], "transition_power_preserving_continuity")
    else:
        _require(after[0]["sequence"] == 1 and after[0]["uptime"] < before[-1]["uptime"],
                 "transition_declared_reset")
    return before, after


def _stream(packets):
    """Contiguous TCP bytes; exact retransmissions are allowed, conflicts/holes are not."""
    data, stamps, base = bytearray(), [], None
    for stamp, tcp in packets:
        payload = bytes(tcp.data)
        if not payload:
            continue
        if base is None:
            base = tcp.seq
        offset = (tcp.seq-base) & 0xffffffff
        _require(offset <= len(data), "transition_tcp_byte_hole")
        overlap = min(len(payload), len(data)-offset)
        _require(data[offset:offset+overlap] == payload[:overlap], "transition_tcp_byte_conflict")
        data.extend(payload[overlap:])
        stamps.extend([stamp]*(len(payload)-overlap))
    return bytes(data), stamps


def _frames(packets):
    raw, stamps = _stream(packets)
    frames, index = [], 0
    while index < len(raw):
        begin, header = index, raw[index]
        index += 1
        remaining, multiplier = 0, 1
        for _ in range(4):
            _require(index < len(raw), "transition_mqtt_truncated")
            part = raw[index]
            index += 1
            remaining += (part & 127)*multiplier
            if not part & 128:
                break
            multiplier *= 128
        else:
            raise ValueError("transition_mqtt_remaining_length")
        finish = index+remaining
        _require(finish <= len(raw), "transition_mqtt_truncated")
        frames.append((header, raw[index:finish], stamps[begin], stamps[finish-1]))
        index = finish
    return frames


def _connect(body):
    # MQTT 3.1.1 QoS0 telemetry sender. Authentication is parsed but never returned.
    _require(len(body) >= 12 and body[:7] == b"\x00\x04MQTT\x04", "transition_mqtt_connect")
    flags, offset = body[7], 10
    _require(flags & 1 == 0 and flags & 0x3c == 0 and flags & 2, "transition_mqtt_connect")
    _require(not (flags & 0x40) or flags & 0x80, "transition_mqtt_connect")
    for field in range(1+bool(flags & 0x80)+bool(flags & 0x40)):
        _require(offset+2 <= len(body), "transition_mqtt_connect")
        length = int.from_bytes(body[offset:offset+2], "big")
        offset += 2
        _require(offset+length <= len(body) and (field != 0 or length > 0), "transition_mqtt_connect")
        offset += length
    _require(offset == len(body), "transition_mqtt_connect")


def _check_publish(frames, samples, topic, allow_connect):
    observed, closed = [], False
    for header, body, begin, finish in frames:
        _require(not closed, "transition_mqtt_after_disconnect")
        if header == 0x10 and allow_connect:
            _connect(body)
        elif header == 0x30:
            _require(len(body) >= 2, "transition_mqtt_publish")
            length = int.from_bytes(body[:2], "big")
            _require(length > 0 and 2+length <= len(body) and body[2:2+length] == topic.encode(),
                     "transition_mqtt_topic")
            observed.append((body[2+length:], begin, finish))
        else:
            _require(header in (0xc0, 0xe0) and not body, "transition_unexpected_mqtt_control")
            closed = header == 0xe0
    _require(len(observed) == len(samples), "transition_mqtt_publish_count")
    for (payload, _, finished), sample in zip(observed, samples):
        _require(payload == sample["raw"] and 0 <= sample["received_at"].timestamp()-finished <= 1,
                 "transition_mqtt_payload_bytes")


def _protocol(files, evidence, device, start, end, operation, before, after):
    _require(isinstance(evidence["pcaps"], list) and evidence["pcaps"], "transition_pcap_refs")
    address, broker = socket.inet_aton(device["ip_address"]), socket.inet_aton(evidence["broker_ip"])
    flows, seen_packets = {}, set()
    for ref in evidence["pcaps"]:
        _require(ref["path"] not in seen_packets, "transition_duplicate_pcap")
        seen_packets.add(ref["path"])
        path = files.file(ref)
        with path.open("rb") as handle:
            for stamp, raw in _pcap_records(handle):
                _require(start.timestamp() <= stamp < end.timestamp(), "transition_pcap_time")
                ip = dpkt.ethernet.Ethernet(raw).data
                if not isinstance(ip, dpkt.ip.IP) or address not in (ip.src, ip.dst):
                    continue
                _require(not ip.mf and ip.offset == 0 and ip.len == len(ip) and isinstance(ip.data, dpkt.tcp.TCP),
                         "transition_unexpected_target_traffic")
                tcp = ip.data
                forward = ip.src == address and ip.dst == broker and tcp.dport == 1883
                reverse = ip.src == broker and ip.dst == address and tcp.sport == 1883
                _require(forward or reverse, "transition_unexpected_target_traffic")
                port = tcp.sport if forward else tcp.dport
                flows.setdefault(port, {"client": [], "broker": []})["client" if forward else "broker"].append((stamp, tcp))
    _require(len(flows) == 2, "transition_requires_two_tcp_flows")
    for flow in flows.values():
        for direction in flow.values():
            direction.sort(key=lambda item: item[0])
    old = [flow for flow in flows.values() if any(tcp.data and stamp < _time(operation["started_at"]).timestamp()
                                                for stamp, tcp in flow["client"])]
    _require(len(old) == 1, "transition_old_flow")
    old = old[0]
    new = next(flow for flow in flows.values() if flow is not old)
    _require(not any(tcp.flags & dpkt.tcp.TH_RST for direction in new.values() for _, tcp in direction),
             "transition_new_flow_reset")
    _require(not any(stamp >= _time(operation["completed_at"]).timestamp() and tcp.data
                     for stamp, tcp in old["client"]), "transition_old_flow_after_operation")
    syn = [(stamp, tcp) for stamp, tcp in new["client"] if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK]
    synack = [(stamp, tcp) for stamp, tcp in new["broker"]
              if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK]
    _require(len(syn) == len(synack) == 1 and _time(operation["started_at"]).timestamp() <= syn[0][0]
             < synack[0][0] < after[0]["received_at"].timestamp(), "transition_tcp_handshake")
    client_data = [(stamp, tcp) for stamp, tcp in new["client"] if tcp.data]
    server_data = [(stamp, tcp) for stamp, tcp in new["broker"] if tcp.data]
    client_sequence = (syn[0][1].seq+1) & 0xffffffff
    server_sequence = (synack[0][1].seq+1) & 0xffffffff
    _require(client_data and server_data and synack[0][1].ack == client_sequence
             and client_data[0][1].seq == client_sequence and server_data[0][1].seq == server_sequence,
             "transition_tcp_handshake_sequence")
    first_application = min(client_data[0][0], server_data[0][0])
    _require(synack[0][0] < first_application, "transition_tcp_handshake_chronology")
    # CONNECT may carry the final ACK, but later telemetry cannot complete an
    # earlier application exchange retroactively.
    _require(any(synack[0][0] < stamp <= first_application and tcp.seq == client_sequence
                 and tcp.ack == server_sequence and tcp.flags & dpkt.tcp.TH_ACK
                 and not tcp.flags & dpkt.tcp.TH_SYN for stamp, tcp in new["client"]),
             "transition_tcp_handshake_sequence")
    _require(not any(tcp.flags & dpkt.tcp.TH_FIN and stamp < client_data[-1][0]
                     for direction in new.values() for stamp, tcp in direction), "transition_new_flow_closed_early")
    client, server = _frames(new["client"]), _frames(new["broker"])
    _require(client and client[0][0] == 0x10 and sum(frame[0] == 0x10 for frame in client) == 1,
             "transition_mqtt_connect")
    _require(server and server[0][0] == 0x20 and server[0][1] == b"\x00\x00"
             and client[0][3] <= server[0][2], "transition_mqtt_connack")
    _require(all(header == 0xd0 and not body for header, body, _, _ in server[1:]),
             "transition_unexpected_broker_control")
    publishes = [frame for frame in client if frame[0] == 0x30]
    _require(publishes and server[0][3] <= publishes[0][2], "transition_publish_before_connack")
    _check_publish(client, after, device["mqtt_topic"], True)
    _check_publish(_frames(old["client"]), before, device["mqtt_topic"], False)
    _require(all(header == 0xd0 and not body for header, body, _, _ in _frames(old["broker"])),
             "transition_unexpected_broker_control")
    return {"kind": operation["kind"], "mqtt_log_ids": [item["id"] for item in before+after],
            "before_samples": len(before), "after_samples": len(after), "new_client_port":
            next(port for port, flow in flows.items() if flow is new)}


def validate_transition(root: Path, evidence_ref: dict) -> dict:
    """Return parsed evidence after verifying all referenced originals; errors are fixed codes.

    Only one target device per evidence record is supported. Independent records
    still share their actual Capture UUID; callers enforce one role for the group.
    All PCAPs must cover the selected interval only and include complete streams.
    """
    try:
        files = _Files(root)
        evidence = files.json(evidence_ref)
        _exact(evidence, {"schema_version", "source_capture_group_id", "capture_session_pk", "role", "start_utc",
                          "end_utc", "included_device_ids", "devices", "broker_ip", "capture_policy", "capture_filter",
                          "code_commit", "snapshot", "operation", "before", "after", "pcaps", "training_approved",
                          "whole_capture_session_approved"}, "transition_fields")
        _require(evidence["schema_version"] == SCHEMA, "transition_schema")
        _require(evidence["role"] in ("train", "calibration", "validation"), "transition_role")
        _require(evidence["training_approved"] is False and evidence["whole_capture_session_approved"] is False,
                 "transition_approval")
        _require(type(evidence["capture_session_pk"]) is int and evidence["capture_session_pk"] > 0,
                 "transition_capture_pk")
        _require(type(evidence["source_capture_group_id"]) is str
                 and str(UUID(evidence["source_capture_group_id"], version=4)) == evidence["source_capture_group_id"],
                 "transition_capture_uuid")
        _require(type(evidence["code_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", evidence["code_commit"]),
                 "transition_code_commit")
        start, end = _time(evidence["start_utc"]), _time(evidence["end_utc"])
        _require(start < end and not start.microsecond and not end.microsecond and start.second % 10 == end.second % 10 == 0,
                 "transition_full_windows")
        CapturePolicy(**evidence["capture_policy"])
        _require(type(evidence["capture_filter"]) is str and evidence["capture_filter"].strip(), "transition_capture_filter")
        _require(isinstance(evidence["included_device_ids"], list) and len(evidence["included_device_ids"]) == 1
                 and isinstance(evidence["devices"], list) and len(evidence["devices"]) == 1, "transition_one_device")
        device = _exact(evidence["devices"][0], {"device_id", "ip_address", "mqtt_topic", "payload_schema"},
                        "transition_device_fields")
        identifier = device["device_id"]
        _require(evidence["included_device_ids"] == [identifier] and identifier in _DEVICE_SCHEMAS
                 and device["payload_schema"] == _DEVICE_SCHEMAS[identifier]
                 and device["mqtt_topic"] == f"iot/{identifier}/sensor", "transition_device_identity")
        for address in (device["ip_address"], evidence["broker_ip"]):
            _require(str(ipaddress.IPv4Address(address)) == address, "transition_ip_address")
        _require(device["ip_address"] != evidence["broker_ip"], "transition_ip_address")
        operation = files.json(evidence["operation"])
        _exact(operation, {"schema_version", "kind", "device_id", "source_capture_group_id", "started_at",
                           "completed_at", "authorization", "execution_id"}, "transition_operation_fields")
        _require(operation["schema_version"] == "packet-controlled-operation-v1" and operation["kind"] in KINDS
                 and operation["device_id"] == identifier and operation["source_capture_group_id"] == evidence["source_capture_group_id"]
                 and operation["authorization"] == "human-authorized" and type(operation["execution_id"]) is str
                 and _IDENTIFIER.fullmatch(operation["execution_id"]), "transition_operation_identity")
        lower, upper = _time(operation["started_at"]), _time(operation["completed_at"])
        _require((lower-start).total_seconds() >= 10 and lower < upper and (end-upper).total_seconds() >= 10,
                 "transition_operation_bounds")
        before = _installation(files, evidence["before"], evidence, device, "before", start, lower)
        after = _installation(files, evidence["after"], evidence, device, "after", upper, end)
        if operation["kind"] != "public_sender_deploy":
            for key in ("public_sender", "runtime", "libraries", "power_management", "firmware_id", "runtime_id", "library_ids"):
                left = before[key]
                right = after[key]
                # Artifact locations can differ while their actual bytes remain identical.
                if key in ("public_sender", "runtime"):
                    left, right = left["sha256"], right["sha256"]
                elif key == "libraries":
                    left, right = sorted(item["sha256"] for item in left), sorted(item["sha256"] for item in right)
                _require(left == right, "transition_unexpected_installation_change")
        before_rows, after_rows = _snapshot_samples(files, evidence, device, start, end, operation)
        proof = _protocol(files, evidence, device, start, end, operation, before_rows, after_rows)
        return {**evidence, "input_files": files.finish(), "verified_transition": proof}
    except (OSError, sqlite3.Error, dpkt.Error, KeyError, IndexError, TypeError, OverflowError) as exc:
        raise ValueError("transition_original_evidence_invalid") from exc
    except ValueError as exc:
        # Library errors can include raw values (e.g. IPs); expose only our fixed codes.
        if re.fullmatch(r"transition_[a-z0-9_]+", str(exc)):
            raise
        raise ValueError("transition_original_evidence_invalid") from exc
