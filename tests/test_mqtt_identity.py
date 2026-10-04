"""edge.mqtt.identity 공통 모듈 및 그 소비처(Subscriber last_seen_at, Feature
Builder 집계) 검증. MQTT Device Identity 정합성 검증 Matrix를 그대로 테스트로 옮긴다.

검증 Matrix:
  입력                                     기대 결과
  정상 Topic + 동일 등록 Device Payload      정상 저장·Feature 포함·Event 없음
  정상 Topic + 다른 등록 Device Payload      DEVICE_ID_MISMATCH, 정상 last_seen 갱신 금지, 정상 Feature 제외
  등록 Topic + 미등록 Payload Device         UNKNOWN_DEVICE, 등록 Device 정상 활동 귀속 금지
  미등록 Topic + 등록 Payload                UNKNOWN_DEVICE, 등록 Device 정상 활동 귀속 금지
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.features.collect_feature_logs import produce_mqtt_features_until
from edge.mqtt.identity import (
    IdentityStatus,
    classify_mqtt_identity,
    fetch_registered_device_ids,
)
from edge.mqtt.subscriber import build_mqtt_log_row, insert_mqtt_log
from tests.conftest import cleanup_device


REGISTERED = {"esp32_01", "esp32_02"}


@pytest.fixture()
def db_session(db_session_with_raw_payload):
    return db_session_with_raw_payload


# ── classify_mqtt_identity (순수 함수, DB 접근 없음) ──────────────────────────

class TestClassifyMqttIdentity:
    def test_matched_normal_topic_and_same_registered_payload(self) -> None:
        result = classify_mqtt_identity(
            "iot/esp32_01/sensor", '{"device_id":"esp32_01"}', REGISTERED
        )
        assert result.status is IdentityStatus.MATCHED
        assert result.attributed_device_id == "esp32_01"
        assert result.is_normal_telemetry is True

    def test_matched_when_only_payload_id_present_and_registered(self) -> None:
        # Topic 형식이 비정상(iot/{id}/sensor 아님)이어도 Payload로 등록 기기가
        # 명확히 식별되면 위조가 아니라 단순 비정상 Topic 사용이므로 MATCHED다
        # (= is_attributable True, Feature 집계 대상). 하지만 정상 Topic이
        # 아니므로 is_normal_telemetry는 False다 — last_seen_at은 갱신되지
        # 않아야 한다(ABNORMAL_TOPIC Rule은 별도 차원에서 계속 탐지한다).
        result = classify_mqtt_identity(
            "admin/system/control", '{"device_id":"esp32_01"}', REGISTERED
        )
        assert result.status is IdentityStatus.MATCHED
        assert result.attributed_device_id == "esp32_01"
        assert result.is_attributable is True
        assert result.is_strict_topic is False
        assert result.is_normal_telemetry is False

    def test_matched_when_payload_is_malformed_but_topic_identifies_device(self) -> None:
        # Topic은 정상 형식이고 등록 기기이지만, Payload가 JSON으로 파싱되지
        # 않아 Device ID를 못 뽑은 경우. Topic만으로 등록 기기가 식별되므로
        # MATCHED(is_attributable True)지만, Payload가 정상이 아니므로
        # is_normal_telemetry는 False여야 한다 — last_seen_at을 갱신하면 안 된다.
        result = classify_mqtt_identity(
            "iot/esp32_01/sensor", "not-valid-json", REGISTERED
        )
        assert result.status is IdentityStatus.MATCHED
        assert result.attributed_device_id == "esp32_01"
        assert result.payload_device_id is None
        assert result.is_attributable is True
        assert result.is_strict_topic is True
        assert result.is_normal_telemetry is False

    def test_normal_telemetry_requires_strict_topic_and_matching_payload(self) -> None:
        result = classify_mqtt_identity(
            "iot/esp32_01/sensor", '{"device_id":"esp32_01"}', REGISTERED
        )
        assert result.is_strict_topic is True
        assert result.is_attributable is True
        assert result.is_normal_telemetry is True

    def test_device_id_mismatch_when_both_registered_but_different(self) -> None:
        result = classify_mqtt_identity(
            "iot/esp32_01/sensor", '{"device_id":"esp32_02"}', REGISTERED
        )
        assert result.status is IdentityStatus.DEVICE_ID_MISMATCH
        assert result.attributed_device_id is None
        assert result.topic_device_id == "esp32_01"
        assert result.payload_device_id == "esp32_02"
        assert result.is_attributable is False
        assert result.is_normal_telemetry is False

    def test_unknown_device_when_topic_registered_payload_unregistered(self) -> None:
        result = classify_mqtt_identity(
            "iot/esp32_01/sensor", '{"device_id":"rogue_device"}', REGISTERED
        )
        assert result.status is IdentityStatus.UNKNOWN_DEVICE
        assert result.attributed_device_id is None
        assert result.unregistered_device_id == "rogue_device"
        assert result.is_attributable is False
        assert result.is_normal_telemetry is False

    def test_unknown_device_when_topic_unregistered_payload_registered(self) -> None:
        result = classify_mqtt_identity(
            "iot/rogue_device/sensor", '{"device_id":"esp32_01"}', REGISTERED
        )
        assert result.status is IdentityStatus.UNKNOWN_DEVICE
        assert result.attributed_device_id is None
        assert result.unregistered_device_id == "rogue_device"
        assert result.is_attributable is False
        assert result.is_normal_telemetry is False

    def test_no_candidate_when_neither_topic_nor_payload_has_device_id(self) -> None:
        result = classify_mqtt_identity("cmd/exec", '{"temperature":25.3}', REGISTERED)
        assert result.status is IdentityStatus.NO_CANDIDATE
        assert result.attributed_device_id is None
        assert result.is_attributable is False
        assert result.is_normal_telemetry is False


# ── fetch_registered_device_ids (Isolation 상태 무관) ─────────────────────────

def test_fetch_registered_device_ids_ignores_isolation_status(db_session) -> None:
    cleanup_device(db_session, "identity_reg_normal")
    cleanup_device(db_session, "identity_reg_isolated")
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('identity_reg_normal', '192.168.0.50', 'normal', 100),
                   ('identity_reg_isolated', '192.168.0.51', 'isolated', 10)
            """
        )
    )
    db_session.commit()

    registered = fetch_registered_device_ids(db_session)

    assert "identity_reg_normal" in registered
    assert "identity_reg_isolated" in registered

    cleanup_device(db_session, "identity_reg_normal")
    cleanup_device(db_session, "identity_reg_isolated")


# ── insert_mqtt_log: last_seen_at 갱신 Gate (devices/mqtt_logs만 필요) ────────

def _device_last_seen(db, device_id: str) -> str | None:
    row = db.execute(
        text("SELECT last_seen_at FROM devices WHERE device_id = :device_id"),
        {"device_id": device_id},
    ).mappings().one()
    return row["last_seen_at"]


class TestInsertMqttLogLastSeenGate:
    def _setup_devices(self, db) -> None:
        for device_id in ("identity_esp32_a", "identity_esp32_b"):
            cleanup_device(db, device_id)
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, status, trust_score)
                VALUES ('identity_esp32_a', '192.168.0.60', 'normal', 100),
                       ('identity_esp32_b', '192.168.0.61', 'normal', 100)
                """
            )
        )
        db.commit()

    def _teardown_devices(self, db) -> None:
        for device_id in ("identity_esp32_a", "identity_esp32_b", "identity_rogue"):
            cleanup_device(db, device_id)

    def test_matched_message_updates_last_seen_at(self, db_session) -> None:
        self._setup_devices(db_session)
        try:
            row = build_mqtt_log_row(
                "iot/identity_esp32_a/sensor",
                '{"device_id":"identity_esp32_a"}',
                received_at=datetime(2026, 8, 10, 9, 0, 1, tzinfo=timezone.utc),
            )
            insert_mqtt_log(db_session, row)

            assert _device_last_seen(db_session, "identity_esp32_a") == "2026-08-10T09:00:01Z"
        finally:
            self._teardown_devices(db_session)

    def test_device_id_mismatch_does_not_update_last_seen_at(self, db_session) -> None:
        self._setup_devices(db_session)
        try:
            # Topic은 identity_esp32_a, Payload는 identity_esp32_b로 위조.
            row = build_mqtt_log_row(
                "iot/identity_esp32_a/sensor",
                '{"device_id":"identity_esp32_b"}',
                received_at=datetime(2026, 8, 10, 9, 0, 1, tzinfo=timezone.utc),
            )
            log_id = insert_mqtt_log(db_session, row)

            # Raw 증적은 그대로 저장된다.
            stored = db_session.execute(
                text(
                    "SELECT device_id, topic, payload, error_message "
                    "FROM mqtt_logs WHERE id = :id"
                ),
                {"id": log_id},
            ).mappings().one()
            assert stored["topic"] == "iot/identity_esp32_a/sensor"
            assert stored["payload"] == '{"device_id":"identity_esp32_b"}'
            assert stored["error_message"] == "device_id_mismatch"

            # 그러나 어느 등록 Device의 last_seen_at도 갱신되지 않는다.
            assert _device_last_seen(db_session, "identity_esp32_a") is None
            assert _device_last_seen(db_session, "identity_esp32_b") is None
        finally:
            self._teardown_devices(db_session)

    def test_unknown_device_with_registered_topic_does_not_update_last_seen_at(
        self, db_session
    ) -> None:
        self._setup_devices(db_session)
        try:
            # Topic은 등록 기기(identity_esp32_a), Payload는 미등록 기기 위조.
            row = build_mqtt_log_row(
                "iot/identity_esp32_a/sensor",
                '{"device_id":"identity_rogue"}',
                received_at=datetime(2026, 8, 10, 9, 0, 1, tzinfo=timezone.utc),
            )
            insert_mqtt_log(db_session, row)

            assert _device_last_seen(db_session, "identity_esp32_a") is None
        finally:
            self._teardown_devices(db_session)

    def test_unknown_device_with_registered_payload_does_not_update_last_seen_at(
        self, db_session
    ) -> None:
        self._setup_devices(db_session)
        try:
            # Topic은 미등록 기기, Payload는 등록 기기(identity_esp32_a) 위조.
            row = build_mqtt_log_row(
                "iot/identity_rogue/sensor",
                '{"device_id":"identity_esp32_a"}',
                received_at=datetime(2026, 8, 10, 9, 0, 1, tzinfo=timezone.utc),
            )
            insert_mqtt_log(db_session, row)

            assert _device_last_seen(db_session, "identity_esp32_a") is None
        finally:
            self._teardown_devices(db_session)

    def test_abnormal_topic_with_valid_payload_does_not_update_last_seen_at(
        self, db_session
    ) -> None:
        self._setup_devices(db_session)
        try:
            row = build_mqtt_log_row(
                "iot/identity_esp32_a/cmd",
                '{"device_id":"identity_esp32_a"}',
                received_at=datetime(2026, 8, 10, 9, 0, 1, tzinfo=timezone.utc),
            )
            insert_mqtt_log(db_session, row)

            assert _device_last_seen(db_session, "identity_esp32_a") is None
        finally:
            self._teardown_devices(db_session)

    def test_valid_topic_with_malformed_payload_does_not_update_last_seen_at(
        self, db_session
    ) -> None:
        self._setup_devices(db_session)
        try:
            row = build_mqtt_log_row(
                "iot/identity_esp32_a/sensor",
                "not-valid-json",
                received_at=datetime(2026, 8, 10, 9, 0, 1, tzinfo=timezone.utc),
            )
            insert_mqtt_log(db_session, row)

            assert _device_last_seen(db_session, "identity_esp32_a") is None
        finally:
            self._teardown_devices(db_session)


# ── Feature Builder: Identity mismatch 메시지의 정상 Feature 집계 제외 ────────


@pytest.fixture
def FeatureSessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase6a-mqtt-identity-feature.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with TestingSessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, status, trust_score)
                VALUES ('identity_feat_a', '192.168.0.70', 'normal', 100),
                       ('identity_feat_b', '192.168.0.71', 'normal', 100)
                """
            )
        )
        db.commit()
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


def _feature_row(db, device_id: str):
    return db.execute(
        text(
            """
            SELECT publish_count
            FROM feature_logs
            WHERE device_id = :device_id
            ORDER BY window_start
            LIMIT 1
            """
        ),
        {"device_id": device_id},
    ).mappings().first()


def test_device_id_mismatch_excluded_from_feature_aggregation(FeatureSessionLocal) -> None:
    window_start = datetime(2026, 8, 10, 9, 0, 0, tzinfo=timezone.utc)
    with FeatureSessionLocal() as db:
        # 정상 메시지 1건 (identity_feat_a 정상 Telemetry)
        insert_mqtt_log(
            db,
            build_mqtt_log_row(
                "iot/identity_feat_a/sensor",
                '{"device_id":"identity_feat_a"}',
                received_at=window_start + timedelta(seconds=1),
            ),
        )
        # 위조 메시지 1건: Topic=identity_feat_a, Payload=identity_feat_b
        insert_mqtt_log(
            db,
            build_mqtt_log_row(
                "iot/identity_feat_a/sensor",
                '{"device_id":"identity_feat_b"}',
                received_at=window_start + timedelta(seconds=2),
            ),
        )
        db.commit()

        cutoff = window_start + timedelta(seconds=10)
        with db.begin():
            produce_mqtt_features_until(db, producer_cutoff=cutoff)

        feature_a = _feature_row(db, "identity_feat_a")
        feature_b = _feature_row(db, "identity_feat_b")

        # 정상 메시지 1건만 identity_feat_a Feature로 집계된다.
        assert feature_a is not None
        assert feature_a["publish_count"] == 1
        # 위조 메시지는 identity_feat_b에게도 귀속되지 않는다(집계 자체가 없음).
        assert feature_b is None


def test_unknown_device_excluded_from_feature_aggregation(FeatureSessionLocal) -> None:
    window_start = datetime(2026, 8, 10, 9, 0, 0, tzinfo=timezone.utc)
    with FeatureSessionLocal() as db:
        # 정상 메시지 1건
        insert_mqtt_log(
            db,
            build_mqtt_log_row(
                "iot/identity_feat_a/sensor",
                '{"device_id":"identity_feat_a"}',
                received_at=window_start + timedelta(seconds=1),
            ),
        )
        # 등록 Topic + 미등록 Payload Device
        insert_mqtt_log(
            db,
            build_mqtt_log_row(
                "iot/identity_feat_a/sensor",
                '{"device_id":"identity_feat_rogue"}',
                received_at=window_start + timedelta(seconds=2),
            ),
        )
        db.commit()

        cutoff = window_start + timedelta(seconds=10)
        with db.begin():
            produce_mqtt_features_until(db, producer_cutoff=cutoff)

        feature_a = _feature_row(db, "identity_feat_a")
        assert feature_a is not None
        assert feature_a["publish_count"] == 1


def test_abnormal_topic_and_malformed_payload_still_counted_as_rule_evidence(
    FeatureSessionLocal,
) -> None:
    window_start = datetime(2026, 8, 10, 9, 0, 40, tzinfo=timezone.utc)
    with FeatureSessionLocal() as db:
        # 등록 기기로 식별되지만 Topic 형식이 비정상.
        insert_mqtt_log(
            db,
            build_mqtt_log_row(
                "iot/identity_feat_a/cmd",
                '{"device_id":"identity_feat_a"}',
                received_at=window_start + timedelta(seconds=1),
            ),
        )
        # 등록 기기로 식별되지만 Payload가 JSON으로 파싱되지 않음.
        insert_mqtt_log(
            db,
            build_mqtt_log_row(
                "iot/identity_feat_a/sensor",
                "not-valid-json",
                received_at=window_start + timedelta(seconds=2),
            ),
        )
        db.commit()

        cutoff = window_start + timedelta(seconds=10)
        with db.begin():
            produce_mqtt_features_until(db, producer_cutoff=cutoff)

        feature_a = db.execute(
            text(
                """
                SELECT publish_count, abnormal_topic_count, malformed_payload_count
                FROM feature_logs
                WHERE device_id = :device_id
                ORDER BY window_start
                LIMIT 1
                """
            ),
            {"device_id": "identity_feat_a"},
        ).mappings().first()

        assert feature_a is not None
        assert feature_a["publish_count"] == 2
        assert feature_a["abnormal_topic_count"] == 1
        assert feature_a["malformed_payload_count"] == 1
