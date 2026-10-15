"""Validate already captured telemetry on the host; never reads hardware or settings.

Input is JSONL of actual gateway mqtt_logs rows containing topic/payload/received_at
or sensor proof records containing the six real telemetry fields. No sample data is
generated. Content validation cannot authenticate the physical provenance of data.
"""
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import statistics
import sys


# This host-only verifier lives at <repository>/firmware/pico_wh_bme280/.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
from edge.features.feature_utils import extract_payload_device_id, is_malformed_payload
from edge.mqtt.topic_utils import is_telemetry_topic


def require_number(value, name):
    try:
        valid = not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("Invalid finite numeric field: " + name)
    return value


def require_int(value, name, minimum):
    if type(value) is not int or value < minimum:
        raise ValueError("Invalid integer field: " + name)
    return value


def validate_payload(value):
    if not isinstance(value, dict) or value.get("device_id") != "pico_01":
        raise ValueError("Expected pico_01 telemetry object")
    sequence = require_int(value.get("seq"), "seq", 1)
    uptime = require_int(value.get("uptime_ms"), "uptime_ms", 0)
    temperature = require_number(value.get("temperature_c"), "temperature_c")
    humidity = require_number(value.get("humidity_pct"), "humidity_pct")
    pressure = require_number(value.get("pressure_hpa"), "pressure_hpa")
    if not -40 <= temperature <= 85:
        raise ValueError("Temperature outside BME280 operating range")
    if not 0 <= humidity <= 100:
        raise ValueError("Humidity outside percentage range")
    if not 300 <= pressure <= 1100:
        raise ValueError("Pressure outside BME280 operating range in hPa")
    return sequence, uptime, temperature, humidity, pressure


def received_utc(value):
    if not isinstance(value, str):
        raise ValueError("Gateway received_at must be UTC text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Gateway received_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def verify(records, *, mode, payload_max, min_samples, check_reception_cadence=True):
    if mode not in ("sensor-proof", "gateway"):
        raise ValueError("Unknown verification mode")
    require_int(payload_max, "payload_max", 1)
    require_int(min_samples, "min_samples", 2)
    payloads = []
    received = []
    sizes = []
    for record in records:
        if mode == "gateway":
            if not isinstance(record, dict):
                raise ValueError("Gateway row must be an object")
            required = ("device_id", "topic", "payload", "payload_size", "received_at",
                        "is_json_valid", "is_topic_valid", "error_message")
            if any(name not in record for name in required):
                raise ValueError("Missing actual gateway row field")
            topic = record.get("topic")
            text = record.get("payload")
            if topic != "iot/pico_01/sensor" or not is_telemetry_topic(topic):
                raise ValueError("Unexpected gateway topic")
            if not isinstance(text, str):
                raise ValueError("Gateway payload must be UTF-8 JSON text")
            encoded = text.encode("utf-8")
            if is_malformed_payload(encoded) or extract_payload_device_id(encoded) != "pico_01":
                raise ValueError("Gateway parser rejects payload identity")
            for name in ("is_json_valid", "is_topic_valid"):
                if type(record[name]) is not int or record[name] != 1:
                    raise ValueError("Gateway flagged invalid telemetry: " + name)
            if record["error_message"] not in (None, ""):
                raise ValueError("Gateway recorded a telemetry error")
            if record["device_id"] != "pico_01":
                raise ValueError("Gateway attributed another device")
            if require_int(record["payload_size"], "payload_size", 0) != len(encoded):
                raise ValueError("Gateway payload byte count differs")
            if len(encoded) > payload_max:
                raise ValueError("Telemetry exceeds configured payload limit")
            value = json.loads(text)
            received.append(received_utc(record.get("received_at")))
            sizes.append(len(encoded))
        else:
            value = record
            if not isinstance(record, dict):
                raise ValueError("Sensor proof row must be an object")
            for name, upper in (("raw_t", 0xFFFFF), ("raw_p", 0xFFFFF),
                                ("raw_h", 0xFFFF)):
                raw = require_int(record.get(name), name, 0)
                if raw > upper:
                    raise ValueError("Invalid raw sensor measurement")
            state = {}
            for name in ("ctrl_hum", "ctrl_meas", "status"):
                state[name] = require_int(record.get(name), name, 0)
                if state[name] > 0xFF:
                    raise ValueError("Invalid sensor register byte: " + name)
            if state["ctrl_hum"] & 0x07 != 0x01 or state["ctrl_meas"] & 0xFC != 0x24:
                raise ValueError("Sensor proof does not enable all channels at x1")
            if state["status"] & 0x09 or state["ctrl_meas"] & 0x03:
                raise ValueError("Sensor proof conversion is incomplete")
        payloads.append(validate_payload(value))
    if len(payloads) < min_samples:
        raise ValueError("Too few captured samples")
    for left, right in zip(payloads, payloads[1:]):
        if right[0] != left[0] + 1 or right[1] <= left[1]:
            raise ValueError("Sequence must be consecutive and uptime must increase within one run")
    sample_intervals = [(right[1] - left[1]) / 1000 for left, right in zip(payloads, payloads[1:])]
    if any(value < 4.0 or value > 8.0 for value in sample_intervals):
        raise ValueError("Sender cadence contains a burst or long interruption")
    if not 4.5 <= statistics.median(sample_intervals) <= 6.5:
        raise ValueError("Median sender cadence is inconsistent with five seconds")
    reception_intervals = []
    if mode == "gateway":
        reception_intervals = [(right - left).total_seconds() for left, right in zip(received, received[1:])]
        if any(value <= 0 for value in reception_intervals):
            raise ValueError("Gateway received_at must increase")
        if any(value > 10.0 or (check_reception_cadence and value < 3.0) for value in reception_intervals):
            raise ValueError("Gateway reception has a burst or interruption requiring inspection")
    return {
        "status": "CAPTURED_CONTENT_CHECKS_PASSED",
        "mode": mode,
        "samples": len(payloads),
        "first_seq": payloads[0][0],
        "last_seq": payloads[-1][0],
        "sender_span_seconds": (payloads[-1][1] - payloads[0][1]) / 1000,
        "sender_interval_median_seconds": statistics.median(sample_intervals),
        "gateway_interval_median_seconds": statistics.median(reception_intervals) if reception_intervals else None,
        "max_payload_bytes": max(sizes) if sizes else None,
        "temperature_c_range": [min(row[2] for row in payloads), max(row[2] for row in payloads)],
        "humidity_pct_range": [min(row[3] for row in payloads), max(row[3] for row in payloads)],
        "pressure_hpa_range": [min(row[4] for row in payloads), max(row[4] for row in payloads)],
        "hardware_io_performed_by_verifier": False,
        "physical_sensor_provenance_authenticated": False,
        "registration_policy_trust_firewall_verified_by_this_tool": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mode", choices=("sensor-proof", "gateway"), required=True)
    parser.add_argument("--payload-max", type=int, default=5120)
    parser.add_argument("--min-samples", type=int)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.payload_max < 1:
        parser.error("--payload-max must be positive")
    minimum = args.min_samples if args.min_samples is not None else (7 if args.mode == "sensor-proof" else 12)
    if minimum < 2:
        parser.error("--min-samples must be at least two")
    try:
        records = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
        result = verify(records, mode=args.mode, payload_max=args.payload_max, min_samples=minimum)
    except (ValueError, TypeError, KeyError, OSError, OverflowError):
        # Don't print input data or exception strings: input should contain only telemetry.
        print(json.dumps({"status": "CAPTURED_CONTENT_CHECKS_FAILED", "mode": args.mode}))
        return 1
    if args.report:
        if args.report.resolve() == args.input.resolve():
            parser.error("Report must not overwrite the input evidence")
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
