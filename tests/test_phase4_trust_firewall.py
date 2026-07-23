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
    PROCESSING_UNMAPPED_DEVICE,
    apply_trust_score_v2_until,
)


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


def test_trust_v2_applies_family_ai_and_window_caps(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=100)
        first = _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="topic")
        duplicate_family = _insert_event(
            db,
            "esp32_01",
            "ABNORMAL_PUBLISH_RATE",
            incident_family="topic",
        )
        mismatch = _insert_event(
            db,
            "esp32_01",
            "DEVICE_ID_MISMATCH",
            detector_type="RULE",
            incident_family="identity",
        )
        ai = _insert_event(
            db,
            "esp32_01",
            "AI_ANOMALY",
            detector_type="AI",
            incident_family="ai",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(db, cycle_cutoff=CUTOFF)

        assert result.selected_event_count == 4
        assert result.created_history_count == 1
        change = result.changes[0]
        assert change.calculated_delta == -60
        assert change.capped_delta == -30
        assert change.actual_delta == -30
        assert change.new_score == 70
        assert set(change.representative_event_ids) == {first, mismatch, ai}

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


def test_trust_v2_does_not_isolate_at_exactly_30(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=60)
        _insert_event(db, "esp32_01", "DEVICE_ID_MISMATCH", incident_family="identity")
        _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="topic")
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(db, cycle_cutoff=CUTOFF)

        assert result.changes[0].new_score == 30
        assert result.created_isolation_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM isolation_history")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM firewall_rules")).scalar_one() == 0
        status = db.execute(
            text("SELECT status FROM devices WHERE device_id = 'esp32_01'")
        ).scalar_one()
        assert status == "danger"


def test_trust_v2_isolates_below_30_and_creates_firewall_pending(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", trust_score=55, ip_address="192.168.0.21")
        event_id = _insert_event(db, "esp32_01", "DEVICE_ID_MISMATCH", incident_family="identity")
        _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="topic")
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = apply_trust_score_v2_until(db, cycle_cutoff=CUTOFF)

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
            apply_trust_score_v2_until(db, cycle_cutoff=CUTOFF)

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
        _insert_event(db, "esp32_01", "DEVICE_ID_MISMATCH", incident_family="identity")
        _insert_event(db, "esp32_01", "ABNORMAL_TOPIC", incident_family="topic")
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="no firewall source IP"):
            with db.begin():
                apply_trust_score_v2_until(db, cycle_cutoff=CUTOFF)

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
    detector_type: str = "RULE",
    incident_family: str | None = None,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO detection_events (
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
                :device_id,
                :detector_type,
                :event_type,
                'high',
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
            "device_id": device_id,
            "detector_type": detector_type,
            "event_type": event_type,
            "detected_at": WINDOW_END,
            "analysis_window_start": WINDOW_START,
            "analysis_window_end": WINDOW_END,
            "incident_family": incident_family,
        },
    )
    return int(result.lastrowid)
