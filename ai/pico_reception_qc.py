"""Bounded, opt-in PCAP evidence for one Pico P0 arrival recovery episode.

This verifies observed bytes and timestamps; it does not identify a physical cause
or authenticate normal behavior. Strict collection QC remains the default.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import socket
import struct

import dpkt

from edge.detection.phase4_time import parse_db_utc

STRICT_POLICY = "strict-v1"
WIRE_JITTER_POLICY = "pico-p0-wire-jitter-v1"
# A development quality allowance from the existing P0 sender lower bound (5 - 4).
# It is neither a measured physical limit nor a value fitted to one observed case.
RECOVERY_ALLOWANCE_SECONDS = 5.0 - 4.0


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _utc(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _publish(row):
    payload = row["payload_raw"]
    _require(isinstance(payload, bytes), "jitter_payload_missing")
    topic = row["topic"].encode("utf-8")
    body = len(topic).to_bytes(2, "big") + topic + payload
    remaining, header = len(body), bytearray()
    while True:
        value, remaining = remaining % 128, remaining // 128
        header.append(value | (128 if remaining else 0))
        if not remaining:
            return b"\x30" + bytes(header) + body


def _pcap_records(handle):
    """dpkt parses Ethernet; explicitly reject incomplete PCAP record headers/bodies."""
    header = handle.read(24)
    _require(len(header) == 24, "jitter_truncated_pcap_header")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    _require(header[:4] in formats, "jitter_unsupported_pcap_format")
    endian, divisor = formats[header[:4]]
    version_major, version_minor, _, _, snaplen, network = struct.unpack(endian+"HHIIII", header[4:])
    _require((version_major, version_minor) == (2, 4) and network == dpkt.pcap.DLT_EN10MB,
             "jitter_unsupported_link_type")
    while True:
        raw = handle.read(16)
        if not raw:
            return
        _require(len(raw) == 16, "jitter_truncated_pcap_record")
        seconds, fraction, caplen, original = struct.unpack(endian+"IIII", raw)
        _require(0 < caplen <= snaplen and caplen == original and fraction < divisor,
                 "jitter_truncated_pcap_packet")
        body = handle.read(caplen)
        _require(len(body) == caplen, "jitter_truncated_pcap_packet")
        yield seconds + fraction/divisor, body


def verify_reception_jitter(rows, *, run_id, source_capture_group_id, device_ip, pcaps):
    """Verify four adjacent samples against already hash-verified PCAP paths.

    pcaps consists of (segment_id, relative_path, verified_path, sha256) tuples.
    The caller retains the existing Capture/diagnostic and full content checks.
    Exceptions contain only fixed codes; evidence never includes payload bytes.
    """
    rows = sorted(rows, key=lambda row: (parse_db_utc(row["received_at"], allow_subseconds=True), row["id"]))
    times = [parse_db_utc(row["received_at"], allow_subseconds=True).timestamp() for row in rows]
    gaps = [b-a for a, b in zip(times, times[1:])]
    _require(all(0 < gap <= 10 for gap in gaps), "jitter_reception_bounds")
    compressed = [index for index, gap in enumerate(gaps) if gap < 3]
    _require(len(compressed) == 1, "jitter_requires_one_compressed_pair")
    index = compressed[0]
    _require(0 < index < len(gaps)-1, "jitter_episode_must_be_internal")
    selected = rows[index-1:index+3]
    selected_times = times[index-1:index+3]
    observed = gaps[index-1:index+2]
    values = [json.loads(row["payload_raw"]) for row in selected]
    _require(all(isinstance(value, dict) and type(value.get("seq")) is int
                 and type(value.get("uptime_ms")) is int for value in values),
             "jitter_sender_fields")
    _require(all(b["seq"] == a["seq"] + 1 for a, b in zip(values, values[1:])), "jitter_sequence")
    sender = [(b["uptime_ms"] - a["uptime_ms"])/1000 for a, b in zip(values, values[1:])]
    _require(all(4 <= gap <= 8 for gap in sender), "jitter_sender_bounds")
    allowance = RECOVERY_ALLOWANCE_SECONDS
    _require(observed[0] > sender[0] and observed[1] < sender[1]
             and abs(sum(observed[:2]) - sum(sender[:2])) <= allowance
             and 3 <= observed[2] <= 10 and abs(observed[2] - sender[2]) <= allowance,
             "jitter_delay_did_not_recover")

    expected = [_publish(row) for row in selected]
    lower, upper = selected_times[0] - 2*allowance, selected_times[-1]
    packets, evidence_pcaps = [], []
    address = socket.inet_aton(device_ip)
    try:
        for segment_id, relative, path, sha in pcaps:
            used = False
            with path.open("rb") as handle:
                for stamp, body in _pcap_records(handle):
                    if not lower <= stamp <= upper:
                        continue
                    ethernet = dpkt.ethernet.Ethernet(body)
                    ip = ethernet.data
                    if not isinstance(ip, dpkt.ip.IP) or address not in (ip.src, ip.dst):
                        continue
                    if not isinstance(ip.data, dpkt.tcp.TCP) or 1883 not in (ip.data.sport, ip.data.dport):
                        continue
                    tcp = ip.data
                    _require(ip.len == len(ip) and not ip.mf and ip.offset == 0,
                             "jitter_truncated_or_fragmented_ip")
                    _require(not (tcp.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST))
                             and tcp.win > 0, "jitter_tcp_control_or_zero_window")
                    flow = (ip.src, ip.dst, tcp.sport, tcp.dport)
                    packets.append((stamp, flow, tcp.seq, bytes(tcp.data), ip.src == address))
                    used = True
            if used:
                evidence_pcaps.append({"segment_id": segment_id, "path": relative, "sha256": sha})
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            _require(digest.hexdigest() == sha, "jitter_pcap_changed_during_read")
    except (OSError, dpkt.Error, ValueError, TypeError, IndexError, OverflowError) as exc:
        # dpkt and file errors may contain input bytes; never surface their strings.
        raise ValueError("jitter_pcap_evidence_invalid") from exc

    data = sorted((row for row in packets if row[4] and row[3]), key=lambda row: row[0])
    _require(bool(data) and len({row[1] for row in data}) == 1, "jitter_missing_or_multiple_tcp_flows")
    flow = data[0][1]
    _require(flow[3] == 1883, "jitter_not_broker_publish_flow")
    reverse = (flow[1], flow[0], flow[3], flow[2])
    _require(all(row[1] in (flow, reverse) for row in packets), "jitter_multiple_tcp_flows")
    _require(not any(row[3] and not row[4] for row in packets), "jitter_unexpected_broker_data")
    next_seq, frame_index, offset = data[0][2], 0, 0
    first, complete = [], []
    previous_stamp = None
    for stamp, _, sequence, payload, _ in data:
        _require(sequence == next_seq, "jitter_tcp_byte_hole_duplicate_or_conflict")
        _require(previous_stamp is None or stamp >= previous_stamp, "jitter_packet_time_order")
        _require(frame_index < len(expected), "jitter_extra_publish_frame")
        if offset == 0:
            first.append(stamp)
        target = expected[frame_index]
        _require(len(payload) <= len(target)-offset, "jitter_coalesced_publish_frames")
        _require(payload == target[offset:offset+len(payload)], "jitter_publish_bytes_mismatch")
        next_seq, offset, previous_stamp = (next_seq + len(payload)) & 0xFFFFFFFF, offset + len(payload), stamp
        if offset == len(target):
            complete.append(stamp)
            _require(stamp-first[-1] <= allowance, "jitter_frame_assembly_delay")
            frame_index, offset = frame_index+1, 0
    _require(frame_index == 4 and offset == 0, "jitter_incomplete_publish_frames")
    _require(all(b > a for a, b in zip(complete, complete[1:])), "jitter_frame_completion_order")
    _require(all(0 <= received-ended <= allowance for received, ended in zip(selected_times, complete)),
             "jitter_receiver_delay")
    wire_gaps = [b-a for a, b in zip(complete, complete[1:])]
    _require(wire_gaps[0] > sender[0] and 0 < wire_gaps[1] < 3
             and abs(sum(wire_gaps[:2])-sum(sender[:2])) <= allowance
             and 3 <= wire_gaps[2] <= 10 and abs(wire_gaps[2]-sender[2]) <= allowance,
             "jitter_wire_did_not_show_recovery")
    samples = [{"mqtt_log_id": row["id"], "seq": value["seq"], "uptime_ms": value["uptime_ms"],
                "received_at": row["received_at"], "frame_first_byte_at": _utc(begin),
                "frame_complete_at": _utc(finish), "payload_sha256": hashlib.sha256(row["payload_raw"]).hexdigest()}
               for row, value, begin, finish in zip(selected, values, first, complete)]
    return {"policy": WIRE_JITTER_POLICY, "status": "VERIFIED_SINGLE_RECOVERY", "run_id": run_id,
            "source_capture_group_id": source_capture_group_id, "device_id": "pico_01",
            "physical_cause": "UNDETERMINED", "recovery_allowance_seconds": allowance,
            "allowance_basis": "development_quality_choice_existing_p0_sender_margin_5_minus_4",
            "reception_intervals_seconds": observed, "sender_intervals_seconds": sender,
            "wire_complete_intervals_seconds": wire_gaps,
            "tcp_flow": {"source_ip": socket.inet_ntoa(flow[0]), "destination_ip": socket.inet_ntoa(flow[1]),
                         "source_port": flow[2], "destination_port": flow[3]},
            "samples": samples, "pcaps": evidence_pcaps}
