from datetime import datetime, timedelta, timezone

from edge.detection.ai_run_evidence import AICompletionCollector


START = datetime(2026, 10, 10, tzinfo=timezone.utc)


def test_normal_inference_has_completion_evidence_without_anomaly_event() -> None:
    collector = AICompletionCollector("packet_if")
    collector.input("esp32_02", START)
    collector.inferred("esp32_02", START, anomaly=False,
                       model_version="packet-if-v2", bundle_sha256="a" * 64,
                       ai_revision=2)
    (record,) = collector.records(START + timedelta(seconds=10))
    assert (record.input_count, record.inference_count, record.normal_count,
            record.anomaly_count) == (1, 1, 1, 0)
    assert record.model_version == "packet-if-v2"
    assert record.bundle_sha256 == "a" * 64
    assert record.ai_revision == 2


def test_off_exclusion_keeps_policy_revision_and_mode() -> None:
    collector = AICompletionCollector("mqtt_if")
    collector.input("esp32_02", START)
    collector.exclude("esp32_02", START, "AI_OFF_AT_WINDOW",
                      ai_revision=3, ai_mode="OFF")
    (record,) = collector.records(START + timedelta(seconds=20))
    assert record.completed_window_end == START + timedelta(seconds=10)
    assert record.ai_revision == 3 and record.ai_mode == "OFF"
    assert record.inference_count == record.normal_count == 0


def test_other_device_exclusion_and_empty_stage_are_not_normal_inference() -> None:
    collector = AICompletionCollector("mqtt_if")
    collector.input("esp32_01", START)
    collector.exclude("esp32_01", START, "AI_OFF_AT_WINDOW")
    collector.input("esp32_02", START)
    collector.exclude("esp32_02", START, "QUALITY_EXCLUDED")
    records = collector.records(START + timedelta(seconds=10))
    assert len(records) == 2
    assert all(record.inference_count == record.normal_count == 0 for record in records)
    assert [record.exclusion_counts for record in records] == [
        {"AI_OFF_AT_WINDOW": 1}, {"QUALITY_EXCLUDED": 1},
    ]
    (empty,) = AICompletionCollector("mqtt_if").records(START + timedelta(seconds=10))
    assert empty.device_id is None and empty.window_start is None
    assert empty.input_count == empty.inference_count == empty.normal_count == 0


def test_device_completion_uses_its_source_window_not_later_cycle_cutoff() -> None:
    collector = AICompletionCollector("packet_if")
    collector.input("esp32_01", START)
    collector.inferred("esp32_01", START, anomaly=False,
                       model_version="packet-if-v2", bundle_sha256="a" * 64,
                       ai_revision=1)
    later = START + timedelta(seconds=20)
    collector.input("esp32_02", later)
    collector.exclude("esp32_02", later, "QUALITY_EXCLUDED")

    first, second = collector.records(START + timedelta(seconds=30))
    assert first.device_id == "esp32_01"
    assert first.completed_window_end == START + timedelta(seconds=10)
    assert second.device_id == "esp32_02"
    assert second.completed_window_end == START + timedelta(seconds=30)
    assert second.inference_count == second.normal_count == 0
