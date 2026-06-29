"""run_ai_detector 통합 테스트. load_model과 predict_feature_window를 mock해 모델 파일 불필요."""

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import text

from edge.detection.run_ai_detector import run_ai_detector
from edge.detection.rule_detector import AI_ANOMALY, DETECTOR_AI


# ── 픽스처 ────────────────────────────────────────────────────────────────────

def _cleanup(db) -> None:
    for table in ("detection_events", "feature_logs", "mqtt_logs", "isolation_history", "devices"):
        db.execute(text(f"DELETE FROM {table}"))
    db.commit()


@pytest.fixture()
def fresh_db(db_session):
    _cleanup(db_session)
    try:
        yield db_session
    finally:
        db_session.rollback()
        _cleanup(db_session)


# ── mock 헬퍼 ─────────────────────────────────────────────────────────────────

_ANOMALY = {
    "is_anomaly": True,
    "prediction": -1,
    "anomaly_score": -0.15,
    "detector_type": DETECTOR_AI,
    "event_type": AI_ANOMALY,
}

_NORMAL = {
    "is_anomaly": False,
    "prediction": 1,
    "anomaly_score": 0.12,
    "detector_type": DETECTOR_AI,
    "event_type": None,
}

FAKE_MODEL = Path("ai/models/fake.joblib")


@contextmanager
def _patch_ai(return_value):
    """load_model과 predict_feature_window를 함께 mock합니다."""
    with patch("edge.detection.run_ai_detector.load_model"), \
         patch("edge.detection.run_ai_detector.predict_feature_window", return_value=return_value):
        yield


# ── DB 삽입 헬퍼 ──────────────────────────────────────────────────────────────

def _feature_log(db, device_id="esp32_01", **overrides):
    defaults = {
        "publish_count": 5,
        "min_message_interval": 2.0,
        "max_payload_size": 200,
        "malformed_payload_count": 0,
        "abnormal_topic_count": 0,
        "avg_payload_size": 150.0,
        "avg_message_interval": 3.0,
    }
    defaults.update(overrides)
    db.execute(
        text(
            """
            INSERT INTO feature_logs (
                device_id, window_start, window_end,
                publish_count, avg_payload_size, max_payload_size,
                avg_message_interval, min_message_interval,
                malformed_payload_count, abnormal_topic_count
            )
            VALUES (
                :device_id,
                datetime('now', '-20 seconds'),
                datetime('now', '-10 seconds'),
                :publish_count, :avg_payload_size, :max_payload_size,
                :avg_message_interval, :min_message_interval,
                :malformed_payload_count, :abnormal_topic_count
            )
            """
        ),
        {"device_id": device_id, **defaults},
    )
    return db.execute(text("SELECT last_insert_rowid()")).scalar()


def _event_count(db):
    return db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar()


# ── 빈 테이블 ────────────────────────────────────────────────────────────────

class TestEmptyTables:
    def test_no_rows_returns_zero(self, fresh_db):
        with _patch_ai(_ANOMALY):
            result = run_ai_detector(fresh_db, FAKE_MODEL)
        assert result == {"feature_events": 0}

    def test_no_rows_no_events(self, fresh_db):
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        assert _event_count(fresh_db) == 0

    def test_empty_table_with_missing_model_raises(self, fresh_db):
        """feature_logs가 비어 있어도 모델 파일 없으면 즉시 실패해야 합니다."""
        with pytest.raises(FileNotFoundError):
            run_ai_detector(fresh_db, Path("ai/models/nonexistent.joblib"))


# ── 정상 / 이상 판정 ──────────────────────────────────────────────────────────

class TestPrediction:
    def test_anomaly_creates_event(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            result = run_ai_detector(fresh_db, FAKE_MODEL)
        assert result["feature_events"] == 1
        assert _event_count(fresh_db) == 1

    def test_normal_creates_no_event(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_NORMAL):
            result = run_ai_detector(fresh_db, FAKE_MODEL)
        assert result["feature_events"] == 0
        assert _event_count(fresh_db) == 0

    def test_event_type_is_ai_anomaly(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(text("SELECT event_type FROM detection_events")).fetchone()
        assert row[0] == AI_ANOMALY

    def test_detector_type_is_ai(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(text("SELECT detector_type FROM detection_events")).fetchone()
        assert row[0] == DETECTOR_AI

    def test_severity_is_medium(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(text("SELECT severity FROM detection_events")).fetchone()
        assert row[0] == "medium"

    def test_description_format(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(text("SELECT description FROM detection_events")).fetchone()
        assert "Isolation Forest 기반 이상 탐지" in row[0]
        assert "-0.1500" in row[0]

    def test_score_delta_and_applied_to_score(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(
            text("SELECT score_delta, applied_to_score FROM detection_events")
        ).fetchone()
        assert row[0] == -15
        assert row[1] == 0

    def test_device_id_stored(self, fresh_db):
        _feature_log(fresh_db, device_id="esp32_77")
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(text("SELECT device_id FROM detection_events")).fetchone()
        assert row[0] == "esp32_77"

    def test_feature_log_id_stored(self, fresh_db):
        fid = _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        row = fresh_db.execute(text("SELECT feature_log_id FROM detection_events")).fetchone()
        assert row[0] == fid

    def test_multiple_anomalies_all_stored(self, fresh_db):
        _feature_log(fresh_db, device_id="esp32_01")
        _feature_log(fresh_db, device_id="esp32_02")
        with _patch_ai(_ANOMALY):
            result = run_ai_detector(fresh_db, FAKE_MODEL)
        assert result["feature_events"] == 2
        assert _event_count(fresh_db) == 2

    def test_mixed_normal_and_anomaly(self, fresh_db):
        _feature_log(fresh_db, device_id="esp32_01")
        _feature_log(fresh_db, device_id="esp32_02")

        import edge.detection.run_ai_detector as module
        call_count = [0]

        def alternating(feature_row, model_path):
            call_count[0] += 1
            return _ANOMALY if call_count[0] == 1 else _NORMAL

        with patch.object(module, "load_model"), \
             patch.object(module, "predict_feature_window", alternating):
            result = run_ai_detector(fresh_db, FAKE_MODEL)

        assert result["feature_events"] == 1
        assert _event_count(fresh_db) == 1


# ── commit / rollback ────────────────────────────────────────────────────────

class TestTransactionBehavior:
    def test_events_committed_to_db(self, fresh_db):
        """runner commit 검증: rollback 후에도 이벤트가 남아 있어야 합니다."""
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
        fresh_db.rollback()
        assert _event_count(fresh_db) == 1

    def test_model_not_found_rolls_back(self, fresh_db):
        """모델 파일 없음 예외 발생 시 롤백되어야 합니다."""
        _feature_log(fresh_db)
        with pytest.raises(FileNotFoundError):
            run_ai_detector(fresh_db, Path("ai/models/nonexistent.joblib"))
        assert _event_count(fresh_db) == 0

    def test_predict_error_rolls_back_partial_writes(self, fresh_db):
        """두 번째 predict 호출에서 실패 시 첫 번째 저장도 롤백되어야 합니다."""
        _feature_log(fresh_db, device_id="esp32_01")
        _feature_log(fresh_db, device_id="esp32_02")

        import edge.detection.run_ai_detector as module
        call_count = [0]

        def fail_on_second(feature_row, model_path):
            call_count[0] += 1
            if call_count[0] == 2:
                raise RuntimeError("simulated predict error")
            return _ANOMALY

        with patch.object(module, "load_model"), \
             patch.object(module, "predict_feature_window", fail_on_second):
            with pytest.raises(RuntimeError):
                run_ai_detector(fresh_db, FAKE_MODEL)

        assert _event_count(fresh_db) == 0


# ── 중복 재실행 방지 ──────────────────────────────────────────────────────────

class TestIdempotency:
    def test_rerun_does_not_duplicate_events(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
            run_ai_detector(fresh_db, FAKE_MODEL)
        assert _event_count(fresh_db) == 1

    def test_second_run_returns_zero(self, fresh_db):
        _feature_log(fresh_db)
        with _patch_ai(_ANOMALY):
            run_ai_detector(fresh_db, FAKE_MODEL)
            result = run_ai_detector(fresh_db, FAKE_MODEL)
        assert result == {"feature_events": 0}
