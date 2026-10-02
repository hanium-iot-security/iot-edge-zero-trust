"""AI observation policy regressions using isolated, migrated SQLite databases."""

from datetime import datetime, timedelta, timezone
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from backend.app.config import Settings, settings
from backend.app.schemas.detection_event_schema import DetectionEventListResponse
from backend.app.services.detection_event_query_service import list_detection_events
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust.trust_policy import incident_family_for_event, score_delta_for_event
from edge.trust.trust_score_service import update_trust_scores
from edge.trust.trust_score_v2 import apply_trust_score_v2_until


START = datetime(2026, 10, 2, 0, 0, tzinfo=timezone.utc)
OBSERVED = "AI_OBSERVATION_ONLY"
AI_TYPES = ("AI_ANOMALY", "AI_PACKET_ANOMALY")


def _utc(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "trust_ai_mode", "enforce")
    path = tmp_path / "ai-observation.db"
    apply_migrations(path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    factory = sessionmaker(bind=engine)
    try:
        yield path, factory
    finally:
        engine.dispose()


def _device(db, score=100, status="normal"):
    db.execute(
        text("INSERT INTO devices (device_id, ip_address, trust_score, status) "
             "VALUES ('esp32_01', '192.168.0.21', :score, :status)"),
        {"score": score, "status": status},
    )


def _event(db, event_type="AI_ANOMALY", *, detector_type="AI", family="AI_ONLY",
           device_id="esp32_01", start=START, score_delta=-15, evidence='{"model_version":"fixture-v1"}'):
    result = db.execute(
        text("""
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity, score_delta,
                applied_to_score, description, detected_at, analysis_window_start,
                analysis_window_end, incident_family, policy_version, evidence_json
            ) VALUES (
                :device, :detector, :event, 'high', :delta, 0, 'observation fixture',
                :end, :start, :end, :family, 'detector-fixture-v1', :evidence
            )
        """),
        {"device": device_id, "detector": detector_type, "event": event_type,
         "delta": score_delta, "start": _utc(start), "end": _utc(start + timedelta(seconds=10)),
         "family": family, "evidence": evidence},
    )
    return int(result.lastrowid)


def _run(db, *, start=START, **options):
    return apply_trust_score_v2_until(
        db, cycle_range_start=start, cycle_cutoff=start + timedelta(seconds=10), **options,
    )


def _event_row(db, event_id):
    return dict(db.execute(
        text("SELECT * FROM detection_events WHERE id = :id"), {"id": event_id},
    ).mappings().one())


def _snapshot(db):
    tables = ("devices", "detection_events", "trust_score_history", "isolation_history",
              "firewall_rules", "detector_checkpoints")
    return {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY rowid"))]
            for table in tables}


def _assert_no_enforcement(db, score, status):
    assert tuple(db.execute(text("SELECT trust_score, status FROM devices")).one()) == (score, status)
    for table in ("trust_score_history", "isolation_history", "firewall_rules"):
        assert db.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one() == 0


@pytest.mark.parametrize("event_type", AI_TYPES)
@pytest.mark.parametrize("family", ["AI_ONLY", None])
def test_observation_processes_ai_without_score_or_isolation_side_effects(database, event_type, family):
    _, factory = database
    original = {"model_version": "packet-fixture-v2", "anomaly_score": -0.72,
                "threshold": -0.51, "features": {"packet_count": 3}}
    with factory.begin() as db:
        _device(db, score=35, status="danger")
        event_id = _event(db, event_type, family=family, score_delta=-7, evidence=json.dumps(original))
        result = _run(db, ai_mode="observe")
        row = _event_row(db, event_id)
        assert (row["score_delta"], row["applied_to_score"], row["processing_reason"]) == (0, 0, OBSERVED)
        assert row["processed_at"] == _utc(START + timedelta(seconds=10))
        evidence = json.loads(row["evidence_json"])
        assert {key: evidence[key] for key in original} == original
        assert evidence["trust_decision"] == {
            "ai_mode": "observe", "policy_version": "trust-ai-observation-v1",
            "policy_score_delta": -15, "original_score_delta": -7, "actual_delta": 0,
            "processed_at": _utc(START + timedelta(seconds=10)),
        }
        assert row["policy_version"] == "detector-fixture-v1"
        assert result.selected_event_count == result.processed_event_count == 1
        assert result.created_history_count == result.created_isolation_count == result.created_firewall_rule_count == 0
        assert result.changes == []
        _assert_no_enforcement(db, 35, "danger")


@pytest.mark.parametrize("raw_evidence", ["not JSON", '[1, {"score": -0.7}]', '"legacy note"', "null"])
def test_observation_preserves_non_object_evidence(database, raw_evidence):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db, evidence=raw_evidence)
        _run(db, ai_mode="observe")
        evidence = json.loads(_event_row(db, event_id)["evidence_json"])
        assert evidence["original_evidence"] == raw_evidence
        assert evidence["trust_decision"]["actual_delta"] == 0


def test_repeated_ai_windows_remain_observations_and_advance_checkpoint(database):
    _, factory = database
    with factory.begin() as db:
        _device(db, score=35, status="danger")
        for window in range(12):
            start = START + timedelta(seconds=10 * window)
            for event_type in AI_TYPES:
                _event(db, event_type, start=start)
            result = _run(db, start=start, ai_mode="observe")
            assert result.processed_event_count == 2
            assert result.changes == []
        _assert_no_enforcement(db, 35, "danger")
        assert db.execute(text("SELECT COUNT(*) FROM detection_events WHERE processing_reason = :reason"),
                          {"reason": OBSERVED}).scalar_one() == 24
        assert db.execute(text("SELECT last_completed_window_end FROM detector_checkpoints "
                               "WHERE detector_name = 'trust_score_v2'")).scalar_one() == _utc(START + timedelta(seconds=120))


def test_observation_keeps_rule_families_window_cap_and_isolation(database):
    _, factory = database
    with factory.begin() as db:
        _device(db, score=55, status="danger")
        ai_ids = [_event(db, event_type) for event_type in AI_TYPES]
        rule_ids = {}
        for event_type in ("ABNORMAL_PUBLISH_RATE", "PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY",
                           "DEVICE_ID_MISMATCH", "ABNORMAL_TOPIC", "LARGE_PAYLOAD"):
            rule_ids[event_type] = _event(
                db, event_type, detector_type="RULE", family=incident_family_for_event(event_type),
                score_delta=score_delta_for_event(event_type),
            )
        result = _run(db, ai_mode="observe")
        change = result.changes[0]
        assert (change.calculated_delta, change.capped_delta, change.actual_delta, change.new_score) == (-65, -30, -30, 25)
        assert set(change.representative_event_ids) == {
            rule_ids["ABNORMAL_PUBLISH_RATE"], rule_ids["DEVICE_ID_MISMATCH"], rule_ids["ABNORMAL_TOPIC"],
        }
        assert result.created_history_count == result.created_isolation_count == result.created_firewall_rule_count == 1
        assert tuple(db.execute(text("SELECT trust_score, status FROM devices")).one()) == (25, "isolated")
        assert db.execute(text("SELECT status FROM firewall_rules")).scalar_one() == "PENDING"
        for event_id in ai_ids:
            assert _event_row(db, event_id)["processing_reason"] == OBSERVED
        for event_type in ("PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY", "LARGE_PAYLOAD"):
            assert _event_row(db, rule_ids[event_type])["processing_reason"] == "NOT_REPRESENTATIVE"


def test_observation_is_not_replayed_when_rerun_or_switched_to_enforcement(database):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        previous_ids = [_event(db, event_type) for event_type in AI_TYPES]
        _run(db, ai_mode="observe")
        before = _snapshot(db)
        for mode in ("observe", "enforce"):
            assert _run(db, ai_mode=mode).processed_event_count == 0
            assert _snapshot(db) == before
        next_start = START + timedelta(seconds=10)
        new_id = _event(db, "AI_PACKET_ANOMALY", start=next_start)
        result = _run(db, start=next_start, ai_mode="enforce")
        assert result.changes[0].actual_delta == -15
        assert result.changes[0].new_score == 85
        assert _event_row(db, new_id)["processing_reason"] == "APPLIED_TO_TRUST"
        for event_id in previous_ids:
            assert _event_row(db, event_id)["processing_reason"] == OBSERVED
            assert _event_row(db, event_id)["score_delta"] == 0
        assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one() == 1


def test_observation_requires_ai_detector_type(database):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db, detector_type="RULE")
        result = _run(db, ai_mode="observe")
        assert result.changes[0].new_score == 85
        assert _event_row(db, event_id)["processing_reason"] == "APPLIED_TO_TRUST"


def test_observation_and_checkpoint_roll_back_when_rule_enforcement_fails(database):
    _, factory = database
    with factory.begin() as db:
        _device(db, score=35, status="danger")
        db.execute(text("UPDATE devices SET ip_address = NULL"))
        _event(db)
        _event(db, "DEVICE_ID_MISMATCH", detector_type="RULE", family="IDENTITY", score_delta=-25)
    with factory() as db:
        before = _snapshot(db)
    with pytest.raises(ValueError, match="no firewall source IP"):
        with factory.begin() as db:
            _run(db, ai_mode="observe")
    with factory() as db:
        assert _snapshot(db) == before


def test_observations_remain_queryable_through_existing_api_response_contract(database):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        ai_ids = {_event(db, event_type) for event_type in AI_TYPES}
        _event(db, "ABNORMAL_TOPIC", detector_type="RULE", family="MESSAGE_POLICY", score_delta=-20)
        _run(db, ai_mode="observe")
        payload = list_detection_events(
            db, device_id="esp32_01", detector_type="AI", applied_to_score=0,
            processing_reason=OBSERVED,
        )
        response = DetectionEventListResponse.model_validate(payload).model_dump(mode="json")
        assert response["total"] == 2
        assert {row["id"] for row in response["items"]} == ai_ids
        assert {row["event_type"] for row in response["items"]} == set(AI_TYPES)
        for row in response["items"]:
            assert (row["score_delta"], row["applied_to_score"], row["processing_reason"]) == (0, 0, OBSERVED)
            assert row["processed_at"] == _utc(START + timedelta(seconds=10))
            assert row["evidence"]["model_version"] == "fixture-v1"
            assert row["evidence"]["trust_decision"]["ai_mode"] == "observe"
            assert row["evidence"]["trust_decision"]["actual_delta"] == 0
        assert list_detection_events(db)["total"] == 3


@pytest.mark.parametrize("options, score, status, expected_reason", [
    ({"family": "IDENTITY"}, 100, "normal", "INVALID_INCIDENT_FAMILY"),
    ({"event_type": "AI_UNSUPPORTED_EVENT"}, 100, "normal", "UNMAPPED_EVENT_TYPE"),
    ({"device_id": None}, 100, "normal", "UNMAPPED_DEVICE"),
    ({"device_id": "missing-device"}, 100, "normal", "UNMAPPED_DEVICE"),
    ({"start": START - timedelta(seconds=10), "family": "IDENTITY"}, 100, "normal", "LATE_EVENT"),
    ({}, 20, "isolated", "ALREADY_ISOLATED"),
])
def test_existing_rejection_reasons_take_priority_over_observation(database, options, score, status, expected_reason):
    _, factory = database
    original_evidence = '{"model_version":"unchanged"}'
    with factory.begin() as db:
        _device(db, score=score, status=status)
        event_id = _event(db, evidence=original_evidence, **options)
        _run(db, ai_mode="observe")
        row = _event_row(db, event_id)
        assert row["processing_reason"] == expected_reason
        assert row["applied_to_score"] == 0
        assert row["score_delta"] == -15
        assert row["evidence_json"] == original_evidence
        assert row["processed_at"] == _utc(START + timedelta(seconds=10))
        _assert_no_enforcement(db, score, status)


@pytest.mark.parametrize("configured_mode, explicit_mode, delta", [
    ("enforce", None, -15), ("observe", None, 0),
    ("observe", "enforce", -15), ("enforce", "observe", 0),
])
def test_settings_mode_is_used_unless_explicitly_overridden(database, monkeypatch, configured_mode, explicit_mode, delta):
    _, factory = database
    monkeypatch.setattr(settings, "trust_ai_mode", configured_mode)
    with factory.begin() as db:
        _device(db)
        _event(db)
        _run(db, **({} if explicit_mode is None else {"ai_mode": explicit_mode}))
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 100 + delta


@pytest.mark.parametrize("bad_mode", ["off", "OBSERVE", "", True])
def test_invalid_mode_is_rejected_before_database_mutation(database, bad_mode):
    _, factory = database
    with factory.begin() as db:
        _device(db)
        _event(db)
        before = _snapshot(db)
        with pytest.raises(ValueError):
            _run(db, ai_mode=bad_mode)
        assert _snapshot(db) == before


def test_trust_ai_setting_defaults_to_enforce_and_validates_environment(monkeypatch):
    monkeypatch.delenv("TRUST_AI_MODE", raising=False)
    assert Settings(_env_file=None).trust_ai_mode == "enforce"
    monkeypatch.setenv("TRUST_AI_MODE", "observe")
    assert Settings(_env_file=None).trust_ai_mode == "observe"
    monkeypatch.setenv("TRUST_AI_MODE", "off")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize("guard", ["configuration", "stored-observation"])
def test_legacy_trust_update_cannot_bypass_observation_policy(database, monkeypatch, guard):
    path, factory = database
    with factory.begin() as db:
        _device(db)
        _event(db)
        if guard == "stored-observation":
            _run(db, ai_mode="observe")
    if guard == "configuration":
        monkeypatch.setattr(settings, "trust_ai_mode", "observe")
    with factory() as db:
        before = _snapshot(db)
    with pytest.raises(RuntimeError):
        update_trust_scores(path)
    with factory() as db:
        assert _snapshot(db) == before


def test_legacy_guard_serializes_with_first_observation_commit(database, monkeypatch):
    """A first observation cannot commit between the legacy guard and scoring."""
    from edge.trust import trust_score_service as legacy

    path, factory = database
    with factory.begin() as db:
        _device(db)
        event_id = _event(db, "AI_PACKET_ANOMALY")

    class RetryLegacyAfterObservation(RuntimeError):
        pass

    fetch_candidates = legacy._fetch_candidate_events

    def observe_after_guard(connection):
        candidates = fetch_candidates(connection)
        assert [row["id"] for row in candidates] == [event_id]
        # Interleave a real v2 transaction on another SQLite connection exactly
        # where the old legacy guard had already checked for observation rows.
        with pytest.raises(OperationalError, match="locked"):
            with factory.begin() as observer:
                observer.execute(text("PRAGMA busy_timeout=0"))
                _run(observer, ai_mode="observe")
        # End this legacy attempt without scoring, then let observation win the
        # next transaction. The retried legacy call must re-read the guard.
        raise RetryLegacyAfterObservation

    with monkeypatch.context() as scoped:
        scoped.setattr(legacy, "_fetch_candidate_events", observe_after_guard)
        with pytest.raises(RetryLegacyAfterObservation):
            update_trust_scores(path)

    with factory.begin() as db:
        _assert_no_enforcement(db, 100, "normal")
        result = _run(db, ai_mode="observe")
        assert result.observed_ai_event_count == 1
    with factory() as db:
        before = _snapshot(db)
        assert _event_row(db, event_id)["processing_reason"] == OBSERVED
    with pytest.raises(RuntimeError, match="observation records"):
        update_trust_scores(path)
    with factory() as db:
        assert _snapshot(db) == before
        _assert_no_enforcement(db, 100, "normal")
