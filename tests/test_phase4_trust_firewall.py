from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import firewall_repository
from edge.trust.trust_score_v2 import (
    PROCESSING_ALREADY_ISOLATED,
    PROCESSING_APPLIED,
    PROCESSING_INVALID_INCIDENT_FAMILY,
    PROCESSING_LATE_EVENT,
    PROCESSING_LEGACY_MIGRATION,
    PROCESSING_UNMAPPED_DEVICE,
    PROCESSING_UNMAPPED_EVENT_TYPE,
    apply_trust_score_v2_until,
)
from edge.trust.trust_policy import score_delta_for_event


CYCLE_START = datetime(2026, 7, 23, 10, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc)
WINDOW_START = "2026-07-23T10:00:00Z"
WINDOW_END = "2026-07-23T10:00:10Z"


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase4-trust-firewall.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


def test_trust_v2_suppresses_ai_when_rule_events_exist_and_caps_window(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        first = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            incident_family="MESSAGE_POLICY",
        )
        duplicate_family = _insert_event(
            db,
            "esp32_01",
            "LARGE_PAYLOAD",
            incident_family="MESSAGE_POLICY",
        )
        mismatch = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            detector_type="RULE",
            incident_family="IDENTITY",
        )
        ai = _insert_event(
            db,
            "esp32_01",
            "AI_ANOMALY",
            detector_type="AI",
            incident_family="AI_ONLY",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert result.selected_event_count == 4
        assert result.created_history_count == 1
        change = result.changes[0]
        assert change.calculated_delta == -45
        assert change.capped_delta == -30
        assert change.actual_delta == -30
        assert change.new_score == 70
        assert set(change.representative_event_ids) == {first, mismatch}

        device = db.execute(
            text("SELECT trust_score, status FROM devices WHERE device_id = 'esp32_01'")
        ).mappings().one()
        assert device["trust_score"] == 70
        assert device["status"] == "warning"
        rows = db.execute(
            text("SELECT id, applied_to_score, processing_reason FROM detection_events")
        ).mappings().all()
        reasons = {row["id"]: row["processing_reason"] for row in rows}
        assert reasons[first] == PROCESSING_APPLIED
        assert reasons[duplicate_family] == "NOT_REPRESENTATIVE"
        assert reasons[ai] == "NOT_REPRESENTATIVE"


def test_trust_v2_does_not_isolate_at_exactly_30(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=60)
        _insert_event(db, "esp32_01", "DEVICE_ID_MISMATCH", incident_family="IDENTITY")
        _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="MESSAGE_POLICY")
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert result.changes[0].new_score == 30
        assert result.created_isolation_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM isolation_history")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM firewall_rules")).scalar_one() == 0
        status = db.execute(
            text("SELECT status FROM devices WHERE device_id = 'esp32_01'")
        ).scalar_one()
        assert status == "danger"


def test_trust_v2_applies_ai_only_once_when_no_rule_event(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        first_ai = _insert_event(
            db,
            "esp32_01",
            "AI_ANOMALY",
            detector_type="AI",
            incident_family="AI_ONLY",
            severity="medium",
            detected_at="2026-07-23T10:00:04Z",
        )
        _insert_event(
            db,
            "esp32_01",
            "AI_PACKET_ANOMALY",
            detector_type="AI",
            incident_family="AI_ONLY",
            severity="medium",
            detected_at="2026-07-23T10:00:05Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        change = result.changes[0]
        assert change.calculated_delta == -15
        assert change.new_score == 85
        assert change.representative_event_ids == [first_ai]


def test_trust_v2_packet_event_penalties_affect_scores(SessionLocal) -> None:
    expected = {
        "PACKET_RATE_ANOMALY": -20,
        "BYTE_RATE_ANOMALY": -20,
        "PORT_SCAN": -20,
        "BROKER_DOS_SUSPECTED": -25,
        "AI_PACKET_ANOMALY": -15,
    }
    with SessionLocal() as db:
        for index, (event_type, expected_delta) in enumerate(expected.items(), start=1):
            device_id = f"esp32_{index:02d}"
            _insert_device(db, device_id, trust_score=100)
            _insert_event(
                db,
                device_id,
                event_type,
                detector_type="AI" if event_type == "AI_PACKET_ANOMALY" else "RULE",
            )
            assert score_delta_for_event(event_type) == expected_delta
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        rows = db.execute(
            text(
                """
                SELECT device_id, trust_score
                FROM devices
                ORDER BY device_id
                """
            )
        ).mappings().all()
        for row, expected_delta in zip(rows, expected.values(), strict=True):
            assert row["trust_score"] == 100 + expected_delta


def test_trust_v2_marks_invalid_family_without_hiding_valid_event(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        invalid_family = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            incident_family="IDENTITY",
        )
        valid_event = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            incident_family="IDENTITY",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert result.changes[0].representative_event_ids == [valid_event]
        assert result.changes[0].new_score == 75
        rows = db.execute(
            text(
                """
                SELECT id, processing_reason, applied_to_score
                FROM detection_events
                ORDER BY id
                """
            )
        ).mappings().all()
        reasons = {row["id"]: row["processing_reason"] for row in rows}
        applied = {row["id"]: row["applied_to_score"] for row in rows}
        assert reasons[invalid_family] == PROCESSING_INVALID_INCIDENT_FAMILY
        assert reasons[valid_event] == PROCESSING_APPLIED
        assert applied[invalid_family] == 0
        assert applied[valid_event] == 1


def test_trust_v2_marks_unknown_event_type_without_hiding_valid_event(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        unknown_event = _insert_event(db, "esp32_01", "UNREGISTERED_EVENT")
        valid_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            incident_family="MESSAGE_POLICY",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert result.changes[0].representative_event_ids == [valid_event]
        assert result.changes[0].new_score == 80
        rows = db.execute(
            text(
                """
                SELECT id, processing_reason, applied_to_score
                FROM detection_events
                ORDER BY id
                """
            )
        ).mappings().all()
        reasons = {row["id"]: row["processing_reason"] for row in rows}
        applied = {row["id"]: row["applied_to_score"] for row in rows}
        assert reasons[unknown_event] == PROCESSING_UNMAPPED_EVENT_TYPE
        assert reasons[valid_event] == PROCESSING_APPLIED
        assert applied[unknown_event] == 0
        assert applied[valid_event] == 1


def test_trust_v2_representative_tie_break_uses_penalty_severity_time_and_id(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        high_smaller_penalty = _insert_event(
            db,
            "esp32_01",
            "LARGE_PAYLOAD",
            incident_family="MESSAGE_POLICY",
            severity="high",
            detected_at="2026-07-23T10:00:01Z",
        )
        stronger_penalty = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            incident_family="MESSAGE_POLICY",
            severity="low",
            detected_at="2026-07-23T10:00:05Z",
        )
        lower_severity = _insert_event(
            db,
            "esp32_01",
            "PACKET_RATE_ANOMALY",
            incident_family="FLOODING",
            severity="medium",
            detected_at="2026-07-23T10:00:01Z",
        )
        higher_severity = _insert_event(
            db,
            "esp32_01",
            "BYTE_RATE_ANOMALY",
            incident_family="FLOODING",
            severity="high",
            detected_at="2026-07-23T10:00:05Z",
        )
        later_identity = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            incident_family="IDENTITY",
            severity="high",
            detected_at="2026-07-23T10:00:04Z",
        )
        earlier_identity = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            incident_family="IDENTITY",
            severity="high",
            detected_at="2026-07-23T10:00:03Z",
        )
        same_time_larger_id = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            incident_family="IDENTITY",
            severity="high",
            detected_at="2026-07-23T10:00:03Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        representative_ids = set(result.changes[0].representative_event_ids)
        assert stronger_penalty in representative_ids
        assert higher_severity in representative_ids
        assert earlier_identity in representative_ids
        assert high_smaller_penalty not in representative_ids
        assert lower_severity not in representative_ids
        assert later_identity not in representative_ids
        assert same_time_larger_id not in representative_ids


def test_trust_v2_applies_windows_in_analysis_chronological_order(
    SessionLocal,
) -> None:
    second_cutoff = datetime(2026, 7, 23, 10, 0, 20, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        later_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            event_id=10,
            incident_family="MESSAGE_POLICY",
            analysis_window_start="2026-07-23T10:00:10Z",
            analysis_window_end="2026-07-23T10:00:20Z",
            detected_at="2026-07-23T10:00:11Z",
        )
        earlier_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            event_id=11,
            incident_family="MESSAGE_POLICY",
            analysis_window_start=WINDOW_START,
            analysis_window_end=WINDOW_END,
            detected_at="2026-07-23T10:00:01Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=second_cutoff,
            )

        assert [change.representative_event_ids for change in result.changes] == [
            [earlier_event],
            [later_event],
        ]
        history = db.execute(
            text(
                """
                SELECT analysis_window_start, previous_score, new_score
                FROM trust_score_history
                ORDER BY id ASC
                """
            )
        ).mappings().all()
        assert [row["analysis_window_start"] for row in history] == [
            WINDOW_START,
            "2026-07-23T10:00:10Z",
        ]
        assert [(row["previous_score"], row["new_score"]) for row in history] == [
            (100, 80),
            (80, 60),
        ]


def test_trust_v2_orders_legacy_events_by_detected_at_fallback_window(
    SessionLocal,
) -> None:
    second_cutoff = datetime(2026, 7, 23, 10, 0, 20, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        later_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            event_id=10,
            incident_family="MESSAGE_POLICY",
            analysis_window_start=None,
            analysis_window_end=None,
            detected_at="2026-07-23T10:00:11Z",
        )
        earlier_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            event_id=11,
            incident_family="MESSAGE_POLICY",
            analysis_window_start=None,
            analysis_window_end=None,
            detected_at="2026-07-23T10:00:01Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=second_cutoff,
            )

        assert [change.representative_event_ids for change in result.changes] == [
            [earlier_event],
            [later_event],
        ]
        assert [change.analysis_window_start for change in result.changes] == [
            CYCLE_START,
            CUTOFF,
        ]


def test_trust_v2_marks_past_window_events_as_late_without_legacy_inference(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        detected_before_range = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            analysis_window_start="2026-07-23T09:59:50Z",
            analysis_window_end="2026-07-23T10:00:00Z",
            detected_at="2026-07-23T09:59:59Z",
        )
        late_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            analysis_window_start="2026-07-23T09:59:50Z",
            analysis_window_end="2026-07-23T10:00:00Z",
            detected_at="2026-07-23T10:00:10Z",
        )
        current_event = _insert_event(db, "esp32_01", "ABNORMAL_TOPIC")
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert result.processed_event_count == 3
        assert result.changes[0].representative_event_ids == [current_event]
        assert result.changes[0].new_score == 80
        events = db.execute(
            text(
                """
                SELECT id, processing_reason, applied_to_score
                FROM detection_events
                ORDER BY id
                """
            )
        ).mappings().all()
        reasons = {row["id"]: row["processing_reason"] for row in events}
        applied = {row["id"]: row["applied_to_score"] for row in events}
        assert reasons[detected_before_range] == PROCESSING_LATE_EVENT
        assert reasons[late_event] == PROCESSING_LATE_EVENT
        assert reasons[current_event] == PROCESSING_APPLIED
        assert applied[detected_before_range] == 0
        assert applied[late_event] == 0
        assert applied[current_event] == 1
        checkpoint = db.execute(
            text(
                """
                SELECT last_processed_id, last_completed_window_end
                FROM detector_checkpoints
                WHERE detector_name = 'trust_score_v2'
                  AND source_table = 'detection_events'
                """
            )
        ).mappings().one()
        assert checkpoint["last_processed_id"] == current_event
        assert checkpoint["last_completed_window_end"] == "2026-07-23T10:00:10Z"


def test_trust_v2_keeps_explicit_legacy_migration_marker_without_scoring(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        legacy_event = _insert_event(
            db,
            "esp32_01",
            PROCESSING_LEGACY_MIGRATION,
            analysis_window_start="2026-07-23T09:59:50Z",
            analysis_window_end="2026-07-23T10:00:00Z",
            detected_at="2026-07-23T09:59:59Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert result.processed_event_count == 1
        assert result.created_history_count == 0
        row = db.execute(
            text(
                """
                SELECT processing_reason, applied_to_score
                FROM detection_events
                WHERE id = :id
                """
            ),
            {"id": legacy_event},
        ).mappings().one()
        assert row["processing_reason"] == PROCESSING_LEGACY_MIGRATION
        assert row["applied_to_score"] == 0


def test_trust_v2_does_not_permanently_skip_lower_id_future_window_event(
    SessionLocal,
) -> None:
    next_cycle_start = CUTOFF
    next_cycle_cutoff = datetime(2026, 7, 23, 10, 0, 20, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        future_event = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            event_id=10,
            incident_family="IDENTITY",
            analysis_window_start="2026-07-23T10:00:10Z",
            analysis_window_end="2026-07-23T10:00:20Z",
            detected_at="2026-07-23T10:00:11Z",
        )
        current_event = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_TOPIC",
            event_id=11,
            incident_family="MESSAGE_POLICY",
            analysis_window_start=WINDOW_START,
            analysis_window_end=WINDOW_END,
            detected_at="2026-07-23T10:00:09Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            first = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        assert first.changes[0].representative_event_ids == [current_event]
        assert db.execute(
            text("SELECT processing_reason FROM detection_events WHERE id = :id"),
            {"id": future_event},
        ).scalar_one() is None
        db.rollback()

        with db.begin():
            second = apply_trust_score_v2_until(
                db,
                cycle_range_start=next_cycle_start,
                cycle_cutoff=next_cycle_cutoff,
            )

        assert second.changes[0].representative_event_ids == [future_event]
        assert db.execute(
            text("SELECT trust_score FROM devices WHERE device_id = 'esp32_01'")
        ).scalar_one() == 55


def test_trust_v2_isolates_below_30_and_creates_firewall_pending(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=55, ip_address="192.168.0.21")
        event_id = _insert_event(db, "esp32_01", "DEVICE_ID_MISMATCH", incident_family="IDENTITY")
        _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="MESSAGE_POLICY")
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        change = result.changes[0]
        assert change.new_score == 25
        assert change.isolation_history_id is not None
        assert change.firewall_rule_id is not None
        isolation = db.execute(
            text(
                """
                SELECT trust_score_history_id, trigger_event_id
                FROM isolation_history
                """
            )
        ).mappings().one()
        assert isolation["trust_score_history_id"] == change.trust_score_history_id
        assert isolation["trigger_event_id"] == event_id
        firewall = db.execute(text("SELECT source_ip, status FROM firewall_rules")).mappings().one()
        assert firewall["source_ip"] == "192.168.0.21"
        assert firewall["status"] == "PENDING"


def test_trust_v2_marks_unmapped_and_already_isolated_without_score_change(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=20, status="isolated")
        isolated_event = _insert_event(db, "esp32_01", "ABNORMAL_TOPIC")
        unmapped_event = _insert_event(db, "missing_device", "ABNORMAL_TOPIC")
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            apply_trust_score_v2_until(
                db,
                cycle_range_start=CYCLE_START,
                cycle_cutoff=CUTOFF,
            )

        events = db.execute(
            text(
                """
                SELECT id, processing_reason, applied_to_score
                FROM detection_events
                ORDER BY id
                """
            )
        ).mappings().all()
        assert events[0]["id"] == isolated_event
        assert events[0]["processing_reason"] == PROCESSING_ALREADY_ISOLATED
        assert events[1]["id"] == unmapped_event
        assert events[1]["processing_reason"] == PROCESSING_UNMAPPED_DEVICE
        assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one() == 0


def test_trust_v2_rolls_back_when_isolation_firewall_ip_is_missing(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=55, ip_address=None)
        _insert_event(db, "esp32_01", "DEVICE_ID_MISMATCH", incident_family="IDENTITY")
        _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="MESSAGE_POLICY")
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="no firewall source IP"):
            with db.begin():
                apply_trust_score_v2_until(
                    db,
                    cycle_range_start=CYCLE_START,
                    cycle_cutoff=CUTOFF,
                )

        assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM isolation_history")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM detector_checkpoints")).scalar_one() == 0
        device = db.execute(
            text("SELECT trust_score, status FROM devices WHERE device_id = 'esp32_01'")
        ).mappings().one()
        assert device["trust_score"] == 55
        assert device["status"] == "normal"


def test_firewall_repository_retry_and_manual_reset_are_transaction_controlled(
    SessionLocal,
) -> None:
    now = datetime(2026, 7, 23, 10, 1, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=25, status="isolated")
        rule_id = firewall_repository.create_pending_rule_for_device(
            db,
            device_id="esp32_01",
            source_ip="192.168.0.21",
            reason="Trust Score below threshold",
            trigger_event_id=1,
        )
        db.commit()

    with SessionLocal() as db:
        assert [row["id"] for row in firewall_repository.list_pending_rules(db, now=now, limit=10)] == [rule_id]
        db.rollback()
        transaction = db.begin()
        firewall_repository.mark_applied(db, rule_id=rule_id, applied_at=now)
        transaction.rollback()
        assert db.execute(
            text("SELECT status FROM firewall_rules WHERE id = :id"),
            {"id": rule_id},
        ).scalar_one() == "PENDING"

        firewall_repository.record_transient_failure(
            db,
            rule_id=rule_id,
            attempted_at=now,
            error="temporary failure",
            retry_delay_seconds=10,
        )
        firewall_repository.record_transient_failure(
            db,
            rule_id=rule_id,
            attempted_at=datetime(2026, 7, 23, 10, 1, 10, tzinfo=timezone.utc),
            error="temporary failure",
            retry_delay_seconds=10,
        )
        firewall_repository.record_transient_failure(
            db,
            rule_id=rule_id,
            attempted_at=datetime(2026, 7, 23, 10, 1, 20, tzinfo=timezone.utc),
            error="temporary failure",
            retry_delay_seconds=10,
        )
        row = db.execute(
            text("SELECT status, retry_count FROM firewall_rules WHERE id = :id"),
            {"id": rule_id},
        ).mappings().one()
        assert row["status"] == "FAILED"
        assert row["retry_count"] == 3

        firewall_repository.reset_failed_to_pending(
            db,
            rule_id=rule_id,
            requested_at=datetime(2026, 7, 23, 10, 2, 0, tzinfo=timezone.utc),
        )
        row = db.execute(
            text("SELECT status, retry_count FROM firewall_rules WHERE id = :id"),
            {"id": rule_id},
        ).mappings().one()
        assert row["status"] == "PENDING"
        assert row["retry_count"] == 0


def test_firewall_repository_rejects_invalid_state_transitions(SessionLocal) -> None:
    now = datetime(2026, 7, 23, 10, 1, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=25, status="isolated")
        rule_id = firewall_repository.create_pending_rule_for_device(
            db,
            device_id="esp32_01",
            source_ip="192.168.0.21",
            reason="Trust Score below threshold",
            trigger_event_id=1,
        )
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="not APPLIED"):
            firewall_repository.mark_removed(db, rule_id=rule_id, released_at=now)
        db.rollback()

        firewall_repository.mark_applied(db, rule_id=rule_id, applied_at=now)
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="not PENDING"):
            firewall_repository.mark_applied(db, rule_id=rule_id, applied_at=now)
        db.rollback()
        with pytest.raises(ValueError, match="not PENDING"):
            firewall_repository.record_transient_failure(
                db,
                rule_id=rule_id,
                attempted_at=now,
                error="temporary failure",
            )
        db.rollback()
        with pytest.raises(ValueError, match="not PENDING"):
            firewall_repository.record_validation_failure(
                db,
                rule_id=rule_id,
                attempted_at=now,
                error="invalid rule",
            )
        db.rollback()
        with pytest.raises(ValueError, match="not FAILED"):
            firewall_repository.reset_failed_to_pending(
                db,
                rule_id=rule_id,
                requested_at=now,
            )


def _insert_device(
    db,
    device_id: str,
    *,
    trust_score: int,
    status: str = "normal",
    ip_address: str | None = "192.168.0.10",
) -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, :ip_address, :status, :trust_score)
            """
        ),
        {
            "device_id": device_id,
            "ip_address": ip_address,
            "status": status,
            "trust_score": trust_score,
        },
    )


def _insert_event(
    db,
    device_id: str,
    event_type: str,
    *,
    event_id: int | None = None,
    detector_type: str = "RULE",
    incident_family: str | None = None,
    severity: str = "high",
    detected_at: str = WINDOW_END,
    analysis_window_start: str = WINDOW_START,
    analysis_window_end: str = WINDOW_END,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO detection_events (
                id,
                device_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at,
                analysis_window_start,
                analysis_window_end,
                incident_family,
                policy_version
            )
            VALUES (
                :id,
                :device_id,
                :detector_type,
                :event_type,
                :severity,
                0,
                0,
                'phase4 test',
                :detected_at,
                :analysis_window_start,
                :analysis_window_end,
                :incident_family,
                'test-policy'
            )
            """
        ),
        {
            "id": event_id,
            "device_id": device_id,
            "detector_type": detector_type,
            "event_type": event_type,
            "severity": severity,
            "detected_at": detected_at,
            "analysis_window_start": analysis_window_start,
            "analysis_window_end": analysis_window_end,
            "incident_family": incident_family,
        },
    )
    return int(result.lastrowid)
