"""Validate synthetic contract fixtures, never live captures or hardware provenance."""

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path

import pytest


VERIFIER = Path(__file__).resolve().parents[1] / "firmware" / "pico_wh_bme280" / "verify_pico_telemetry.py"


@pytest.fixture
def verifier():
    spec = importlib.util.spec_from_file_location("pico_test_verifier", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload(sequence):
    return {"device_id": "pico_01", "seq": sequence, "uptime_ms": sequence * 5000,
            "temperature_c": 25.1, "humidity_pct": 48.0, "pressure_hpa": 1006.5}


def _records(mode="sensor-proof", count=3):
    payloads = [_payload(sequence) for sequence in range(1, count + 1)]
    if mode == "sensor-proof":
        return [dict(payload, raw_t=519888, raw_h=3200, raw_p=415148,
                     ctrl_hum=0x01, ctrl_meas=0x24, status=0) for payload in payloads]
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = []
    for index, payload in enumerate(payloads):
        text = json.dumps(payload)
        rows.append({"device_id": "pico_01", "topic": "iot/pico_01/sensor", "payload": text,
                     "payload_size": len(text.encode("utf-8")), "is_json_valid": 1,
                     "is_topic_valid": 1, "error_message": None,
                     "received_at": (start + timedelta(seconds=index * 5)).isoformat()})
    return rows


def _verify(verifier, records, mode="sensor-proof", **kwargs):
    return verifier.verify(records, mode=mode, payload_max=kwargs.get("payload_max", 5120),
                           min_samples=kwargs.get("min_samples", 2))


def _change_payload(records, mode, field, value):
    if mode == "sensor-proof":
        records[1][field] = value
    else:
        payload = json.loads(records[1]["payload"])
        payload[field] = value
        records[1]["payload"] = json.dumps(payload)
        records[1]["payload_size"] = len(records[1]["payload"].encode("utf-8"))


@pytest.mark.parametrize("mode", ["sensor-proof", "gateway"])
def test_valid_continuous_capture_has_content_summary_without_provenance_claim(verifier, mode):
    rows = _records(mode)
    result = _verify(verifier, rows, mode)
    assert result["status"] == "CAPTURED_CONTENT_CHECKS_PASSED"
    assert result["samples"] == 3
    assert (result["first_seq"], result["last_seq"]) == (1, 3)
    assert result["sender_span_seconds"] == 10
    assert result["sender_interval_median_seconds"] == 5
    assert result["gateway_interval_median_seconds"] == (5 if mode == "gateway" else None)
    assert result["max_payload_bytes"] == (max(row["payload_size"] for row in rows) if mode == "gateway" else None)
    assert result["temperature_c_range"] == [25.1, 25.1]
    assert result["humidity_pct_range"] == [48.0, 48.0]
    assert result["pressure_hpa_range"] == [1006.5, 1006.5]
    assert result["hardware_io_performed_by_verifier"] is False
    assert result["physical_sensor_provenance_authenticated"] is False
    assert result["registration_policy_trust_firewall_verified_by_this_tool"] is False


@pytest.mark.parametrize("field", ["raw_t", "raw_h", "raw_p"])
def test_every_sensor_proof_row_requires_all_raw_channels(verifier, field):
    rows = _records()
    del rows[1][field]
    with pytest.raises(ValueError):
        _verify(verifier, rows)


@pytest.mark.parametrize("field,upper", [("raw_t", 0xFFFFF), ("raw_h", 0xFFFF),
                                         ("raw_p", 0xFFFFF)])
@pytest.mark.parametrize("invalid", ["overflow", "negative", "bool", "float"])
def test_sensor_proof_rejects_invalid_raw_channel_types_and_widths(verifier, field, upper, invalid):
    value = {"overflow": upper + 1, "negative": -1,
             "bool": True, "float": 12.0}[invalid]
    rows = _records()
    rows[1][field] = value
    with pytest.raises(ValueError):
        _verify(verifier, rows)


@pytest.mark.parametrize("field,midpoint", [("raw_t", 0x80000), ("raw_h", 0x8000),
                                            ("raw_p", 0x80000)])
def test_sensor_proof_accepts_midpoint_raw_values_with_active_completed_configuration(verifier, field, midpoint):
    rows = _records()
    rows[1][field] = midpoint
    assert _verify(verifier, rows)["status"] == "CAPTURED_CONTENT_CHECKS_PASSED"


@pytest.mark.parametrize("field", ["ctrl_hum", "ctrl_meas", "status"])
def test_every_sensor_proof_row_requires_configuration_and_completion_evidence(verifier, field):
    rows = _records()
    del rows[1][field]
    with pytest.raises(ValueError):
        _verify(verifier, rows)


@pytest.mark.parametrize("field", ["ctrl_hum", "ctrl_meas", "status"])
@pytest.mark.parametrize("value", [-1, 256, True, 1.0, "1", None])
def test_sensor_configuration_evidence_requires_integer_register_bytes(verifier, field, value):
    rows = _records()
    rows[1][field] = value
    with pytest.raises(ValueError):
        _verify(verifier, rows)


@pytest.mark.parametrize("state", [
    pytest.param((0x00, 0x24, 0), id="humidity-skipped"),
    pytest.param((0x01, 0x04, 0), id="temperature-skipped"),
    pytest.param((0x01, 0x20, 0), id="pressure-skipped"),
    pytest.param((0x02, 0x24, 0), id="humidity-x2"),
    pytest.param((0x01, 0x44, 0), id="temperature-x2"),
    pytest.param((0x01, 0x28, 0), id="pressure-x2"),
    pytest.param((0x01, 0x25, 0), id="forced-mode-unfinished"),
    pytest.param((0x01, 0x27, 0), id="normal-mode-active"),
    pytest.param((0x01, 0x24, 0x01), id="calibration-update-unfinished"),
    pytest.param((0x01, 0x24, 0x08), id="measurement-busy"),
])
def test_sensor_proof_rejects_skipped_channels_wrong_oversampling_and_incomplete_conversion(verifier, state):
    rows = _records()
    rows[1].update(zip(("ctrl_hum", "ctrl_meas", "status"), state))
    with pytest.raises(ValueError):
        _verify(verifier, rows)


@pytest.mark.parametrize("field", ["device_id", "topic", "payload", "payload_size", "received_at",
                                   "is_json_valid", "is_topic_valid", "error_message"])
def test_every_gateway_row_requires_actual_ingestion_fields(verifier, field):
    rows = _records("gateway")
    del rows[1][field]
    with pytest.raises(ValueError):
        _verify(verifier, rows, "gateway")


@pytest.mark.parametrize("field", ["is_json_valid", "is_topic_valid"])
@pytest.mark.parametrize("value", [0, 2, True, 1.0, "1", None])
def test_gateway_validity_flags_require_exact_integer_one(verifier, field, value):
    rows = _records("gateway")
    rows[1][field] = value
    with pytest.raises(ValueError):
        _verify(verifier, rows, "gateway")


@pytest.mark.parametrize("value", ["synthetic parser error", 0, False, [], {}])
def test_gateway_rejects_any_error_marker_other_than_none_or_empty_text(verifier, value):
    rows = _records("gateway")
    rows[1]["error_message"] = value
    with pytest.raises(ValueError):
        _verify(verifier, rows, "gateway")


def test_gateway_accepts_empty_error_text_and_counts_utf8_bytes(verifier):
    rows = _records("gateway")
    payload = json.loads(rows[1]["payload"])
    payload["note"] = "센서"
    text = json.dumps(payload, ensure_ascii=False)
    rows[1].update(payload=text, payload_size=len(text.encode("utf-8")), error_message="")
    assert len(text.encode("utf-8")) > len(text)
    result = _verify(verifier, rows, "gateway", payload_max=len(text.encode("utf-8")))
    assert result["max_payload_bytes"] == len(text.encode("utf-8"))

    rows[1]["payload_size"] = len(text)
    with pytest.raises(ValueError, match="byte count"):
        _verify(verifier, rows, "gateway")


@pytest.mark.parametrize("value", [True, 1.0, "1", -1])
def test_gateway_payload_size_requires_nonnegative_integer(verifier, value):
    rows = _records("gateway")
    rows[1]["payload_size"] = value
    with pytest.raises(ValueError):
        _verify(verifier, rows, "gateway")


def test_gateway_payload_limit_is_enforced_in_bytes(verifier):
    rows = _records("gateway")
    maximum = max(row["payload_size"] for row in rows)
    _verify(verifier, rows, "gateway", payload_max=maximum)
    with pytest.raises(ValueError, match="payload limit"):
        _verify(verifier, rows, "gateway", payload_max=maximum - 1)


@pytest.mark.parametrize("field,value", [("device_id", "pico_02"), ("topic", "iot/pico_02/sensor"),
                                         ("topic", "iot/pico_01/status"), ("payload", "not JSON"),
                                         ("payload", "[]"), ("payload", b"{}")])
def test_gateway_requires_matching_device_topic_and_json_object(verifier, field, value):
    rows = _records("gateway")
    rows[1][field] = value
    if field == "payload" and isinstance(value, str):
        rows[1]["payload_size"] = len(value.encode("utf-8"))
    with pytest.raises(ValueError):
        _verify(verifier, rows, "gateway")


@pytest.mark.parametrize("mode", ["sensor-proof", "gateway"])
@pytest.mark.parametrize("field,value", [("device_id", "pico_02"), ("seq", True), ("seq", 2.0),
    ("seq", 0), ("uptime_ms", True), ("uptime_ms", 10000.0), ("uptime_ms", -1),
    ("temperature_c", float("nan")), ("temperature_c", -40.01), ("temperature_c", 85.01),
    ("humidity_pct", float("inf")), ("humidity_pct", -0.01), ("humidity_pct", 100.01),
    ("pressure_hpa", -float("inf")), ("pressure_hpa", 299.99), ("pressure_hpa", 1100.01),
    ("pressure_hpa", 100650), ("temperature_c", True), ("humidity_pct", "48")])
def test_payload_rejects_wrong_identity_types_nonfinite_values_and_units(verifier, mode, field, value):
    rows = _records(mode)
    _change_payload(rows, mode, field, value)
    with pytest.raises(ValueError):
        _verify(verifier, rows, mode)


def test_payload_accepts_operating_range_boundaries(verifier):
    rows = _records(count=2)
    rows[0].update(temperature_c=-40, humidity_pct=0, pressure_hpa=300)
    rows[1].update(temperature_c=85, humidity_pct=100, pressure_hpa=1100)
    result = _verify(verifier, rows)
    assert result["temperature_c_range"] == [-40, 85]
    assert result["humidity_pct_range"] == [0, 100]
    assert result["pressure_hpa_range"] == [300, 1100]


@pytest.mark.parametrize("mode", ["sensor-proof", "gateway"])
def test_oversized_numeric_integer_is_rejected_as_validation_error(verifier, mode):
    rows = _records(mode)
    _change_payload(rows, mode, "temperature_c", 10 ** 1000)
    with pytest.raises(ValueError, match="finite numeric"):
        _verify(verifier, rows, mode)


@pytest.mark.parametrize("mode", ["sensor-proof", "gateway"])
@pytest.mark.parametrize("sequence", [1, 3, 4])
def test_sequence_duplicates_gaps_and_reordering_are_rejected(verifier, mode, sequence):
    rows = _records(mode)
    _change_payload(rows, mode, "seq", sequence)
    with pytest.raises(ValueError, match="consecutive"):
        _verify(verifier, rows, mode)


@pytest.mark.parametrize("uptime", [5000, 4999])
def test_uptime_must_increase_within_one_boot(verifier, uptime):
    rows = _records()
    rows[1]["uptime_ms"] = uptime
    with pytest.raises(ValueError, match="uptime"):
        _verify(verifier, rows)


@pytest.mark.parametrize("interval_ms", [3999, 8001, 4100, 6600])
def test_sender_cadence_rejects_bursts_interruptions_and_wrong_median(verifier, interval_ms):
    rows = _records()
    for index, row in enumerate(rows):
        row["uptime_ms"] = 5000 + index * interval_ms
    with pytest.raises(ValueError, match="cadence"):
        _verify(verifier, rows)


@pytest.mark.parametrize("timestamp", ["2026-01-01T00:00:05", "invalid-date", None,
                                       "2026-01-01T00:00:00+00:00",
                                       "2026-01-01T00:00:02+00:00",
                                       "2026-01-01T00:00:11+00:00"])
def test_gateway_timestamps_require_timezone_and_continuous_reception(verifier, timestamp):
    rows = _records("gateway")
    rows[1]["received_at"] = timestamp
    with pytest.raises(ValueError):
        _verify(verifier, rows, "gateway")


def test_gateway_normalizes_timezone_offsets(verifier):
    rows = _records("gateway")
    rows[1]["received_at"] = "2026-01-01T09:00:05+09:00"
    assert _verify(verifier, rows, "gateway")["gateway_interval_median_seconds"] == 5


@pytest.mark.parametrize("argument,value", [("mode", "unknown"), ("payload_max", 0),
    ("payload_max", True), ("min_samples", 1), ("min_samples", 2.0)])
def test_verifier_rejects_invalid_contract_options(verifier, argument, value):
    kwargs = {"mode": "sensor-proof", "payload_max": 5120, "min_samples": 2}
    kwargs[argument] = value
    with pytest.raises(ValueError):
        verifier.verify(_records(), **kwargs)


def test_insufficient_capture_is_rejected(verifier):
    with pytest.raises(ValueError, match="Too few"):
        _verify(verifier, _records(count=2), min_samples=3)
