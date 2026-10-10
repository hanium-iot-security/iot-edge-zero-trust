from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from edge.detection.ai_warning_aggregation import (
    AIObservation, WarningLedger, WarningPolicy,
)


START = datetime(2026, 10, 10, tzinfo=timezone.utc)
POLICY = WarningPolicy("warning-dev-v1", window_seconds=60,
                       count_threshold=3, cooldown_seconds=120)


def observation(event_id: int, seconds: int, **overrides) -> AIObservation:
    values = dict(event_id=event_id, device_id="esp32_02", detector_name="mqtt_if",
                  event_type="AI_ANOMALY", model_version="mqtt-candidate-v1",
                  window_start=START + timedelta(seconds=seconds))
    values.update(overrides)
    return AIObservation(**values)


def test_first_n_warns_once_and_duplicate_id_or_window_does_not_count() -> None:
    ledger = WarningLedger()
    assert ledger.ingest(observation(1, 0), POLICY, received_at=START).status == "BELOW_THRESHOLD"
    assert ledger.ingest(observation(1, 0), POLICY, received_at=START).status == "DUPLICATE"
    assert ledger.ingest(observation(2, 0), POLICY, received_at=START).status == "DUPLICATE"
    ledger.ingest(observation(3, 10), POLICY, received_at=START)
    decision = ledger.ingest(observation(4, 20), POLICY, received_at=START)
    assert decision.notify and decision.aggregate.count == 3
    assert ledger.ingest(observation(5, 30), POLICY, received_at=START).status == "ALREADY_NOTIFIED"


def test_cooldown_restart_and_late_window_keep_originals_without_realert() -> None:
    ledger = WarningLedger()
    for event_id, seconds in ((1, 0), (2, 10), (3, 20)):
        ledger.ingest(observation(event_id, seconds), POLICY, received_at=START)
    # A persisted ledger can be reloaded after a process restart.
    ledger = deepcopy(ledger)
    for event_id, seconds in ((4, 60), (5, 70)):
        ledger.ingest(observation(event_id, seconds), POLICY,
                      received_at=START + timedelta(seconds=60))
    suppressed = ledger.ingest(observation(6, 80), POLICY,
                               received_at=START + timedelta(seconds=60))
    assert suppressed.status == "COOLDOWN_SUPPRESSED"
    assert suppressed.aggregate.count == 3
    late = ledger.ingest(observation(7, 30), POLICY,
                         received_at=START + timedelta(seconds=180))
    assert late.status == "LATE_ATTACHED"
    assert late.aggregate.closed and 7 in late.aggregate.event_ids
    assert not late.notify
    # C expiry alone does not notify; an eligible new input may.
    assert ledger.ingest(observation(8, 90), POLICY,
                         received_at=START + timedelta(seconds=180)).notify


def test_model_switch_off_and_quality_exclusion_do_not_announce_recovery() -> None:
    ledger = WarningLedger()
    for event_id, seconds in ((1, 0), (2, 10), (3, 20)):
        ledger.ingest(observation(event_id, seconds), POLICY, received_at=START)
    assert ledger.ingest(observation(4, 30, mode="OFF"), POLICY,
                         received_at=START).status == "AI_MODE_EXCLUDED"
    assert ledger.ingest(observation(5, 40, quality_eligible=False), POLICY,
                         received_at=START).status == "QUALITY_EXCLUDED"
    for event_id, seconds in ((6, 0), (7, 10), (8, 20)):
        result = ledger.ingest(observation(event_id, seconds, model_version="mqtt-candidate-v2"),
                               POLICY, received_at=START)
    assert result.notify
    assert len(ledger.last_notification) == 2
    assert ledger.aggregates[("esp32_02", "mqtt_if", "AI_ANOMALY",
                              "mqtt-candidate-v1", POLICY.version, START)].count == 3


def test_rule_or_normal_event_cannot_enter_observe_warning_count() -> None:
    ledger = WarningLedger()
    for event_type in ("PORT_SCAN", "BROKER_DOS", "AI_NORMAL", ""):
        with pytest.raises(ValueError, match="AI anomaly"):
            ledger.ingest(observation(10, 0, event_type=event_type), POLICY,
                          received_at=START)
    assert not ledger.aggregates


def test_warning_policy_version_and_packet_detector_have_separate_counts() -> None:
    ledger = WarningLedger()
    next_policy = WarningPolicy("warning-dev-v2", window_seconds=60,
                                count_threshold=3, cooldown_seconds=120)
    for event_id, seconds in ((1, 0), (2, 10), (3, 20)):
        assert ledger.ingest(observation(event_id, seconds), POLICY,
                             received_at=START).notify == (event_id == 3)
    for event_id, seconds in ((4, 0), (5, 10), (6, 20)):
        result = ledger.ingest(observation(event_id, seconds), next_policy,
                               received_at=START)
    assert result.notify
    for event_id, seconds in ((7, 0), (8, 10), (9, 20)):
        result = ledger.ingest(
            observation(event_id, seconds, detector_name="packet_if",
                        event_type="AI_PACKET_ANOMALY"),
            POLICY, received_at=START,
        )
    assert result.notify
    assert len(ledger.last_notification) == 3
