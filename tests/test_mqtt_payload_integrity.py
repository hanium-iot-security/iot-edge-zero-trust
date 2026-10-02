"""P8-S04: 잘못된 UTF-8 Payload를 Subscriber와 Feature 집계가 수신 시점 판정대로 해석하는지 검증.

저장된 `mqtt_logs.payload`는 잘못된 바이트가 U+FFFD로 치환돼 있어 다시 읽으면 정상 JSON처럼
보인다. MQTT Rule 연결은 P8-05 범위라 다루지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.features.collect_feature_logs import (
    collect_feature_windows,
    produce_mqtt_features_until,
)
from edge.features.feature_utils import extract_payload_device_id
from edge.mqtt.identity import IdentityStatus, classify_mqtt_identity
from edge.mqtt.subscriber import build_mqtt_log_row, insert_mqtt_log


REGISTERED = {"dev_a", "dev_b"}
WINDOW_START = datetime(2026, 10, 2, 9, 0, 0, tzinfo=timezone.utc)

# 문자열 값 안에 잘못된 UTF-8 바이트(0xFF)가 들어 있는 메시지. 치환 후 문자열은
# 정상 JSON처럼 보이지만 원본 바이트는 UTF-8로 해석할 수 없다.
INVALID_UTF8_SAME_DEVICE = b'{"device_id":"dev_a","note":"\xff"}'
INVALID_UTF8_OTHER_REGISTERED = b'{"device_id":"dev_b","note":"\xff"}'
INVALID_UTF8_UNREGISTERED = b'{"device_id":"dev_rogue","note":"\xff"}'


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "p8s04-mqtt-payload-integrity.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    maker = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with maker() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, status, trust_score)
                VALUES ('dev_a', '192.168.0.80', 'normal', 100),
                       ('dev_b', '192.168.0.81', 'normal', 100)
                """
            )
        )
        db.commit()
    try:
        yield maker
    finally:
        engine.dispose()


def _last_seen(db, device_id: str) -> str | None:
    return db.execute(
        text("SELECT last_seen_at FROM devices WHERE device_id = :device_id"),
        {"device_id": device_id},
    ).scalar_one()


def _ingest(db, topic: str, payload: bytes, *, offset_seconds: int = 1) -> int:
    row = build_mqtt_log_row(
        topic,
        payload,
        received_at=WINDOW_START + timedelta(seconds=offset_seconds),
    )
    return insert_mqtt_log(db, row)


# ── 저장된 유효성 → Identity 판정 ────────────────────────────────────────────


class TestClassifyWithStoredPayloadValidity:
    def test_invalid_payload_does_not_expose_device_id_from_text(self) -> None:
        # 치환된 문자열에는 등록 기기 ID가 보이지만 원본은 잘못된 Payload였다.
        replaced_text = INVALID_UTF8_SAME_DEVICE.decode("utf-8", errors="replace")
        assert extract_payload_device_id(replaced_text) == "dev_a"

        result = classify_mqtt_identity(
            "iot/dev_a/sensor", replaced_text, REGISTERED, is_payload_valid=False
        )

        assert result.status is IdentityStatus.MATCHED
        assert result.attributed_device_id == "dev_a"  # Topic으로만 귀속
        assert result.payload_device_id is None
        assert result.is_normal_telemetry is False

    def test_invalid_payload_with_unregistered_text_id_is_not_unknown_device(self) -> None:
        replaced_text = INVALID_UTF8_UNREGISTERED.decode("utf-8", errors="replace")

        result = classify_mqtt_identity(
            "iot/dev_a/sensor", replaced_text, REGISTERED, is_payload_valid=False
        )

        assert result.status is IdentityStatus.MATCHED
        assert result.payload_device_id is None
        assert result.unregistered_device_id is None

    def test_invalid_payload_without_topic_candidate_has_no_candidate(self) -> None:
        replaced_text = INVALID_UTF8_SAME_DEVICE.decode("utf-8", errors="replace")

        result = classify_mqtt_identity(
            "cmd/exec", replaced_text, REGISTERED, is_payload_valid=False
        )

        assert result.status is IdentityStatus.NO_CANDIDATE

    @pytest.mark.parametrize("flag", [None, True])
    def test_unknown_or_valid_flag_keeps_payload_interpretation(self, flag) -> None:
        result = classify_mqtt_identity(
            "iot/dev_a/sensor",
            '{"device_id":"dev_rogue"}',
            REGISTERED,
            is_payload_valid=flag,
        )

        assert result.status is IdentityStatus.UNKNOWN_DEVICE
        assert result.unregistered_device_id == "dev_rogue"


# ── Subscriber: 원본 바이트 기준 판정과 last_seen_at ─────────────────────────


class TestSubscriberUsesRawBytes:
    def test_invalid_utf8_is_recorded_invalid_and_stored_text_looks_valid(self) -> None:
        row = build_mqtt_log_row("iot/dev_a/sensor", INVALID_UTF8_SAME_DEVICE)

        # 수신 시점 판정은 잘못된 Payload이고, 크기는 원본 바이트 수다.
        assert row["is_json_valid"] == 0
        assert row["error_message"] == "invalid_payload"
        assert row["payload_size"] == len(INVALID_UTF8_SAME_DEVICE)
        # 저장 문자열은 치환돼 있어 그대로 다시 읽으면 정상처럼 보인다(회귀 대상 상황).
        assert "\ufffd" in row["payload"]
        assert extract_payload_device_id(row["payload"]) == "dev_a"

    def test_invalid_utf8_does_not_update_last_seen_at(self, SessionLocal) -> None:
        with SessionLocal() as db:
            log_id = _ingest(db, "iot/dev_a/sensor", INVALID_UTF8_SAME_DEVICE)

            assert _last_seen(db, "dev_a") is None
            # Raw 증적과 잘못된 Payload 판정은 그대로 남는다.
            stored = db.execute(
                text("SELECT is_json_valid, payload_size FROM mqtt_logs WHERE id = :id"),
                {"id": log_id},
            ).mappings().one()
            assert stored["is_json_valid"] == 0
            assert stored["payload_size"] == len(INVALID_UTF8_SAME_DEVICE)

    def test_valid_utf8_replacement_character_is_normal(self, SessionLocal) -> None:
        # 정상 UTF-8로 전송한 U+FFFD 문자는 치환 결과와 구분돼야 한다.
        payload = '{"device_id":"dev_a","note":"\ufffd"}'.encode("utf-8")

        with SessionLocal() as db:
            _ingest(db, "iot/dev_a/sensor", payload)

            assert _last_seen(db, "dev_a") == "2026-10-02T09:00:01Z"

    def test_multibyte_normal_payload_updates_last_seen_and_counts_bytes(
        self, SessionLocal
    ) -> None:
        payload = '{"device_id":"dev_a","note":"온도"}'.encode("utf-8")
        assert len(payload) > len(payload.decode("utf-8"))

        with SessionLocal() as db:
            log_id = _ingest(db, "iot/dev_a/sensor", payload)

            assert _last_seen(db, "dev_a") == "2026-10-02T09:00:01Z"
            size = db.execute(
                text("SELECT payload_size FROM mqtt_logs WHERE id = :id"), {"id": log_id}
            ).scalar_one()
            assert size == len(payload)


# ── Feature 집계: 같은 메시지를 Subscriber와 동일하게 해석 ────────────────────


def _feature(db, device_id: str):
    return db.execute(
        text(
            """
            SELECT publish_count, malformed_payload_count
            FROM feature_logs
            WHERE device_id = :device_id
            ORDER BY window_start
            LIMIT 1
            """
        ),
        {"device_id": device_id},
    ).mappings().first()


class TestFeatureAggregationUsesRawBytes:
    @pytest.mark.parametrize(
        "payload",
        [INVALID_UTF8_UNREGISTERED, INVALID_UTF8_OTHER_REGISTERED],
    )
    def test_invalid_utf8_counts_as_malformed_for_topic_device(
        self, SessionLocal, payload
    ) -> None:
        # 치환 문자열로 읽으면 미등록/다른 등록 기기의 Payload처럼 보여 집계에서
        # 빠진다. 원본 기준으로는 잘못된 Payload이므로 Topic 기기의 malformed로 집계한다.
        with SessionLocal() as db:
            _ingest(
                db,
                "iot/dev_a/sensor",
                b'{"device_id":"dev_a"}',
                offset_seconds=1,
            )
            _ingest(db, "iot/dev_a/sensor", payload, offset_seconds=2)
            db.commit()

            with db.begin():
                produce_mqtt_features_until(
                    db, producer_cutoff=WINDOW_START + timedelta(seconds=10)
                )

            feature_a = _feature(db, "dev_a")
            assert feature_a is not None
            assert feature_a["publish_count"] == 2
            assert feature_a["malformed_payload_count"] == 1
            # 치환 문자열에 보이는 다른 등록 기기에는 귀속되지 않는다.
            assert _feature(db, "dev_b") is None

    @pytest.mark.parametrize(
        ("rogue_row_is_json_valid", "expected_publish_count", "expected_malformed"),
        [
            # 수신 시 잘못된 Payload로 판정된 행: Topic 기기의 malformed로 집계.
            (0, 2, 1),
            # 대조군: 정상 UTF-8의 미등록 Device 위조는 기존대로 집계에서 제외.
            (1, 1, 0),
        ],
    )
    def test_legacy_collector_uses_stored_payload_validity(
        self,
        SessionLocal,
        rogue_row_is_json_valid,
        expected_publish_count,
        expected_malformed,
    ) -> None:
        rows = [
            ("2026-10-02 09:00:01", '{"device_id":"dev_a"}', 1),
            ("2026-10-02 09:00:02", '{"device_id":"dev_rogue","note":"\ufffd"}', rogue_row_is_json_valid),
        ]
        with SessionLocal() as db:
            for received_at, payload, is_json_valid in rows:
                db.execute(
                    text(
                        """
                        INSERT INTO mqtt_logs (
                            device_id, topic, payload, payload_size, received_at,
                            is_json_valid, is_topic_valid
                        )
                        VALUES ('dev_a', 'iot/dev_a/sensor', :payload, :size, :received_at,
                                :is_json_valid, 1)
                        """
                    ),
                    {
                        "payload": payload,
                        "size": len(payload.encode("utf-8")),
                        "received_at": received_at,
                        "is_json_valid": is_json_valid,
                    },
                )
            db.commit()

            collect_feature_windows(db, now=datetime(2026, 10, 2, 9, 0, 12), window_seconds=10)

            feature_a = _feature(db, "dev_a")
            assert feature_a is not None
            assert feature_a["publish_count"] == expected_publish_count
            assert feature_a["malformed_payload_count"] == expected_malformed

    def test_valid_mismatch_still_excluded(self, SessionLocal) -> None:
        # 정상 UTF-8의 위조(ID 불일치)는 기존대로 집계에서 제외된다.
        with SessionLocal() as db:
            _ingest(db, "iot/dev_a/sensor", b'{"device_id":"dev_a"}', offset_seconds=1)
            _ingest(db, "iot/dev_a/sensor", b'{"device_id":"dev_b"}', offset_seconds=2)
            db.commit()

            with db.begin():
                produce_mqtt_features_until(
                    db, producer_cutoff=WINDOW_START + timedelta(seconds=10)
                )

            feature_a = _feature(db, "dev_a")
            assert feature_a is not None
            assert feature_a["publish_count"] == 1
            assert feature_a["malformed_payload_count"] == 0
