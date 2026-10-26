"""Read-only actual score effects must come from completed decisions or linked audit."""
import json
from datetime import timedelta

import pytest
from sqlalchemy import text

from backend.app.services.detection_event_query_service import list_detection_events
from backend.app.schemas.detection_event_schema import DetectionEventListResponse
from test_ai_observation import database, _device, _event, _run, _snapshot, START, _utc


def items(db):
    return {row["id"]: row for row in DetectionEventListResponse.model_validate(
        list_detection_events(db)).model_dump()["items"]}


@pytest.mark.parametrize("reason", ["ALREADY_ISOLATED", "LATE_EVENT", "UNMAPPED_DEVICE",
    "PENDING_AT_WINDOW", "DISABLED_AT_WINDOW", "NOT_REPRESENTATIVE", "AI_OBSERVATION_ONLY"])
def test_historical_non_applied_event_keeps_raw_candidate_but_reports_zero(database, reason):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db)
        db.execute(text("UPDATE detection_events SET processed_at=:at, processing_reason=:reason"),
                   {"at": _utc(START + timedelta(seconds=10)), "reason": reason})
        before = _snapshot(db)
        item = items(db)[event_id]
        assert item["score_delta"] == item["policy_score_delta"] == -15
        assert item["actual_score_delta"] == 0
        assert item["score_effect_reason"] == "NOT_APPLIED"
        assert item["evidence"] == {"model_version": "fixture-v1"}
        assert _snapshot(db) == before


@pytest.mark.parametrize("applied,reason,processed", [
    (0, None, None), (1, "APPLIED_TO_TRUST", _utc(START)),
    (0, "UNRECOGNIZED_LEGACY_REASON", _utc(START)),
    (0, "ALREADY_ISOLATED", None), (0, "LEGACY_MIGRATION", _utc(START)),
])
def test_pending_and_missing_audit_are_unknown(database, applied, reason, processed):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db, evidence=json.dumps({"trust_decision": {"actual_delta": -15}}))
        db.execute(text("UPDATE detection_events SET applied_to_score=:applied, "
                        "processing_reason=:reason, processed_at=:at"),
                   {"applied": applied, "reason": reason, "at": processed})
        item = items(db)[event_id]
        assert item["actual_score_delta"] is None
        assert item["window_actual_delta"] is None


@pytest.mark.parametrize("multiple", [False, True])
def test_applied_effect_uses_actual_history_without_allocating_group_cap(database, multiple):
    _, factory = database
    with factory.begin() as db:
        _device(db, score=10, status="danger")
        first = _event(db, "ABNORMAL_TOPIC", detector_type="RULE", family="MESSAGE_POLICY", score_delta=-20)
        if multiple:
            _event(db, "DEVICE_ID_MISMATCH", detector_type="RULE", family="IDENTITY", score_delta=-25)
        _run(db, ai_mode="observe")
        before = _snapshot(db)
        rows = items(db)
        assert rows[first]["policy_score_delta"] == -20
        for item in rows.values():
            assert item["window_actual_delta"] == -10
            assert item["trust_score_history_id"] is not None
            assert item["actual_score_delta"] == (None if multiple else -10)
            assert item["score_effect_reason"] == ("GROUP_HISTORY" if multiple else "EVENT_HISTORY")
        assert _snapshot(db) == before


def test_old_observation_zero_recovers_captured_nominal_policy_without_rewriting(database):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db, score_delta=0, evidence=json.dumps({"trust_decision": {
            "ai_mode": "observe", "policy_version": "trust-ai-observation-v1",
            "policy_score_delta": -15, "original_score_delta": -7, "actual_delta": 0}}))
        db.execute(text("UPDATE detection_events SET processed_at=:at, processing_reason='AI_OBSERVATION_ONLY'"),
                   {"at": _utc(START)})
        item = items(db)[event_id]
        assert item["score_delta"] == 0
        assert item["policy_score_delta"] == -15
        assert item["actual_score_delta"] == 0


@pytest.mark.parametrize("column,value", [
    ("actual_delta", -1), ("analysis_window_start", "2020-01-01T00:00:00Z"),
    ("device_id", "another-device"), ("representative_event_ids_json", "[1, 1]"),
    ("representative_event_ids_json", '{"id": 1}'),
    ("representative_event_ids_json", "not-json"),
])
def test_inconsistent_audit_cannot_claim_an_actual_effect(database, column, value):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db)
        _run(db, ai_mode="enforce")
        db.execute(text(f"UPDATE trust_score_history SET {column}=:value"), {"value": value})
        item = items(db)[event_id]
        assert item["actual_score_delta"] is None
        assert item["window_actual_delta"] is None
        assert item["score_effect_reason"] == "UNKNOWN"


def test_conflicting_non_applied_marker_and_linked_history_stays_unknown(database):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db)
        _run(db, ai_mode="enforce")
        db.execute(text("UPDATE detection_events SET applied_to_score=0, processing_reason='ALREADY_ISOLATED'"))
        assert items(db)[event_id]["actual_score_delta"] is None



def test_current_observe_configuration_never_hides_historical_enforced_ai_effect(database, monkeypatch):
    from backend.app.config import settings
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db)
        _run(db, ai_mode="enforce")
        before = _snapshot(db)
        monkeypatch.setattr(settings, "trust_ai_mode", "observe")
        item = items(db)[event_id]
        assert item["actual_score_delta"] == -15
        assert item["score_effect_reason"] == "EVENT_HISTORY"
        assert _snapshot(db) == before
