"""Candidate QC cadence checks are derived from a per-device Profile; P0 keeps the original numbers."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json

import pytest

from ai import export_normal_collection as qc
from ai.export_normal_collection import CandidateQCError, export_normal_collection, main, mqtt_qc_policy
from tests import test_normal_collection_export as base

package = base.package  # shared synthetic three-device candidate fixture

START = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
DURATION = 600


def utc(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def scenario(offsets, *, sequences=None, uptimes=None, device="esp32_01"):
    """Raw rows and matching 10 s feature rows for messages received at `offsets` seconds after START."""
    sequences = sequences or [100 + index for index in range(len(offsets))]
    uptimes = uptimes or [1000 + round(offset) for offset in offsets]
    raw, windows = [], defaultdict(list)
    for index, (offset, sequence, uptime) in enumerate(zip(offsets, sequences, uptimes), 1):
        payload = json.dumps({"device_id": device, "sequence": sequence, "uptime_s": uptime})
        received = START + timedelta(seconds=offset)
        row = {"id": index, "device_id": device, "topic": f"iot/{device}/sensor", "payload": payload,
               "payload_raw": payload.encode(), "payload_decode_status": "OK", "payload_size": len(payload),
               "received_at": utc(received), "is_json_valid": 1, "is_topic_valid": 1, "error_message": None}
        raw.append(row)
        windows[int(offset) // 10 * 10].append((received, len(payload)))
    features = []
    for second, items in sorted(windows.items()):
        times = sorted(time for time, _ in items)
        sizes = [size for _, size in items]
        intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])] or [5.0]
        features.append({"device_id": device, "window_start": utc(START + timedelta(seconds=second)),
                         "window_end": utc(START + timedelta(seconds=second + 10)),
                         "publish_count": len(items), "avg_payload_size": sum(sizes) / len(sizes),
                         "max_payload_size": max(sizes), "avg_message_interval": sum(intervals) / len(intervals),
                         "min_message_interval": min(intervals), "topic_count": 1,
                         "abnormal_topic_count": 0, "malformed_payload_count": 0})
    return raw, features


def holds(raw, features, profile, device="esp32_01"):
    report = {"hold_reasons": [], "mqtt_devices": {}}
    qc._mqtt_qc(raw, features, [device], START, START + timedelta(seconds=DURATION), report,
                {device: profile})
    return [item for item in report["hold_reasons"] if not item.startswith("mqtt_feature")]


def steady(gap, first=1.0):
    return [first + gap * index for index in range(int((DURATION - first) // gap) + 1)]


class TestPolicyDerivation:
    def test_p0_equals_the_original_constants(self):
        policy = mqtt_qc_policy("P0")
        assert policy["sender_gap_seconds"] == [4, 8] and policy["sender_median_seconds"] == [4.5, 6.5]
        assert policy["reception_gap_seconds"] == [3, 10] and policy["edge_gap_seconds"] == 10
        assert policy["interval_max_seconds"] == 5

    def test_p1_widens_every_cadence_bound_from_its_4_to_6_second_schedule(self):
        policy = mqtt_qc_policy("P1")
        assert policy["sender_gap_seconds"] == [3, 9] and policy["sender_median_seconds"] == [3.5, 7.5]
        assert policy["reception_gap_seconds"] == pytest.approx([2.4, 12]) and policy["edge_gap_seconds"] == 12

    def test_unknown_profile_is_refused(self):
        with pytest.raises(CandidateQCError, match="unknown_qc_profile"):
            mqtt_qc_policy("P9")

    @pytest.mark.parametrize("profiles,code", [
        ({"pico_01": "P1"}, "profile_not_supported_for_device"),
        ({"esp32_09": "P1"}, "qc_profile_device_not_in_run"),
        ({"esp32_01": "P7"}, "unknown_qc_profile"),
    ])
    def test_invalid_profile_assignments_are_refused(self, profiles, code):
        with pytest.raises(CandidateQCError, match=code):
            qc._qc_profiles(profiles, ["esp32_01", "pico_01"])


class TestCadenceUnderProfiles:
    def test_p0_accepts_the_default_five_second_schedule_under_both_profiles(self):
        raw, features = scenario(steady(5))
        assert holds(raw, features, "P0") == [] and holds(raw, features, "P1") == []

    def test_sustained_four_seconds_is_rejected_by_p0_and_accepted_by_p1(self):
        raw, features = scenario(steady(4))
        assert any("sender_cadence" in item for item in holds(raw, features, "P0"))
        assert holds(raw, features, "P1") == []

    def test_sustained_six_seconds_is_rejected_by_p0_and_accepted_by_p1(self):
        raw, features = scenario(steady(6))
        assert any("message_count_shortfall" in item for item in holds(raw, features, "P0"))
        assert holds(raw, features, "P1") == []

    def test_mixed_four_and_six_second_schedule_is_accepted_by_p1(self):
        offsets, now = [1.0], 1.0
        while now < DURATION - 6:
            now += 4 if len(offsets) % 2 else 6
            offsets.append(now)
        raw, features = scenario(offsets)
        assert holds(raw, features, "P1") == []


class TestRealLossesStayRejected:
    @pytest.fixture(params=["P0", "P1"])
    def profile(self, request):
        return request.param

    @staticmethod
    def base_offsets(profile):
        return steady(5 if profile == "P0" else 4)

    def test_skipped_sequence(self, profile):
        offsets = self.base_offsets(profile)
        sequences = [100 + index + (index > 10) for index in range(len(offsets))]
        raw, features = scenario(offsets, sequences=sequences)
        assert any("sequence_or_sender_gap" in item for item in holds(raw, features, profile))

    def test_duplicate_sequence(self, profile):
        offsets = self.base_offsets(profile)
        sequences = [100 + index - (index > 10) for index in range(len(offsets))]
        raw, features = scenario(offsets, sequences=sequences)
        assert any("sequence_or_sender_gap" in item for item in holds(raw, features, profile))

    def test_restart_resets_sequence_and_uptime(self, profile):
        offsets = self.base_offsets(profile)
        sequences = [100 + index if index < 10 else 1 + index - 10 for index in range(len(offsets))]
        uptimes = [1000 + round(offset) if index < 10 else round(offset) - round(offsets[10])
                   for index, offset in enumerate(offsets)]
        raw, features = scenario(offsets, sequences=sequences, uptimes=uptimes)
        assert any("sequence_or_sender_gap" in item for item in holds(raw, features, profile))

    def test_uptime_reversal(self, profile):
        offsets = self.base_offsets(profile)
        uptimes = [1000 + round(offset) for offset in offsets]
        uptimes[10] = uptimes[9] - 3
        raw, features = scenario(offsets, uptimes=uptimes)
        assert any("sequence_or_sender_gap" in item for item in holds(raw, features, profile))

    def test_reception_gap_beyond_the_profile_bound(self, profile):
        offsets = self.base_offsets(profile)
        shifted = [offset + (14 if index >= 10 else 0) for index, offset in enumerate(offsets)]
        raw, features = scenario(shifted, uptimes=[1000 + round(offset) for offset in offsets])
        assert any("reception_gap_or_burst" in item for item in holds(raw, features, profile))

    def test_reception_burst_below_the_profile_bound(self, profile):
        offsets = self.base_offsets(profile)
        offsets[10] = offsets[9] + 1.0
        raw, features = scenario(offsets, uptimes=[1000 + round(offset) for offset in self.base_offsets(profile)])
        assert any("reception_gap_or_burst" in item for item in holds(raw, features, profile))

    def test_messages_missing_from_the_start_of_the_range(self, profile):
        raw, features = scenario([offset + 13 for offset in self.base_offsets(profile)])
        assert any("edge_reception_gap" in item for item in holds(raw, features, profile))

    def test_a_cadence_slower_than_the_profile_allows(self):
        raw, features = scenario(steady(6.5))
        assert any("message_count_shortfall" in item for item in holds(raw, features, "P1"))


class TestExportIntegration:
    def test_profile_is_recorded_and_the_default_report_still_passes(self, package):
        report = export_normal_collection(package)
        assert report["status"] == "PASS"
        assert {item["profile"] for item in report["qc_policy"].values()} == {"P0"}

    def test_one_esp32_can_use_p1(self, package, tmp_path):
        report = export_normal_collection(package, output_dir=tmp_path / "out", qc_profiles={"esp32_01": "P1"})
        assert report["status"] == "PASS"
        assert report["qc_policy"]["esp32_01"]["profile"] == "P1"
        assert report["qc_policy"]["esp32_02"]["profile"] == "P0"

    def test_pico_cannot_use_p1(self, package, tmp_path):
        report = export_normal_collection(package, output_dir=tmp_path / "out", qc_profiles={"pico_01": "P1"})
        assert report["status"] == "HOLD"
        assert "mqtt:profile_not_supported_for_device" in report["hold_reasons"]

    def test_cli_profile_flag(self, package, tmp_path, capsys):
        argv = ["--package-dir", str(package)]
        assert main([*argv, "--output-dir", str(tmp_path / "ok"), "--qc-profile", "esp32_01=P1"]) == 0
        assert main([*argv, "--output-dir", str(tmp_path / "hold"), "--qc-profile", "pico_01=P1"]) == 2
        with pytest.raises(SystemExit):
            main([*argv, "--output-dir", str(tmp_path / "bad"), "--qc-profile", "esp32_01"])
