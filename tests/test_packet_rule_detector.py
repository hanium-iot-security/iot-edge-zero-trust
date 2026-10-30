from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from shutil import copyfile

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.predict_packet_isolation_forest import PacketIFArtifact, PacketIFPrediction
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.mqtt_adapters import MqttFeatureRuleStage
from edge.detection.packet_rule_detector import (
    PacketRuleDetectorStage,
    PacketRulePolicy,
    detect_packet_rules,
    effective_bytes_per_second,
    effective_packets_per_second,
)
from edge.detection.runtime_checkpoint_repository import get_detector_checkpoint
from edge.packet.capture_policy import CapturePolicy
from edge.trust.trust_score_v2 import apply_trust_score_v2_until


RANGE_START = datetime(2026, 7, 26, 10, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 7, 26, 10, 0, 10, tzinfo=timezone.utc)
NEXT_CUTOFF = datetime(2026, 7, 26, 10, 0, 20, tzinfo=timezone.utc)
SESSION_ID = "11111111-1111-4111-8111-111111111111"

TEST_POLICY = PacketRulePolicy(
    packet_rate_threshold=50.0,
    byte_rate_threshold=100_000.0,
    port_scan_distinct_port_threshold=15,
    port_scan_syn_threshold=15,
    broker_dos_tcp_syn_threshold=30,
    broker_dos_mqtt_packet_threshold=100,
    version="packet-rule-policy-test-v1",
)


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "packet-rule-runtime.db"
    legacy_migrations = tmp_path / "migrations-v2"
    legacy_migrations.mkdir()
    for source in MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"):
        if int(source.name[:3]) <= 6:
            copyfile(source, legacy_migrations / source.name)
    apply_migrations(db_path, legacy_migrations)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield session_factory
    finally:
        engine.dispose()


def _stage() -> PacketRuleDetectorStage:
    return PacketRuleDetectorStage(
        capture_policy=CapturePolicy(),
        rule_policy=TEST_POLICY,
    )


def _insert_device(db, *, device_id: str = "esp32_01", ip_address: str = "192.168.0.4") -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, :ip_address, 'normal', 100)
            """
        ),
        {"device_id": device_id, "ip_address": ip_address},
    )


def _enable_phase8(SessionLocal) -> None:
    apply_migrations(Path(SessionLocal.kw["bind"].url.database), MIGRATIONS_DIR)


def _insert_policy_revision(db, *, device_id="esp32_01", revision=1,
                            state="ACTIVE", effective="2026-07-26T10:00:00Z",
                            packet_max=10.0, byte_max=2500.0) -> None:
    db.execute(text("""INSERT INTO device_policy_revisions (
        device_id, revision, effective_from, registration_state,
        policy_profile, expected_publish_interval_seconds,
        publish_count_max, payload_size_max_bytes, packet_rate_max_pps,
        byte_rate_max_bytes_per_second, created_at, created_by, reason
    ) VALUES (:device_id, :revision, :effective, :state, 'periodic-sensor-v1',
        5, 15, 5120, :packet_max, :byte_max, :effective, 'test', 'test setup')"""),
        locals())


def _insert_capture_session(db, *, session_id: str = SESSION_ID, capture_interface: str = "eth0") -> int:
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at,
                first_window_start, ended_at, status
            )
            VALUES (
                :session_id, :capture_interface, '2026-07-26T10:00:00Z',
                '2026-07-26T10:00:00Z', '2026-07-26T10:01:00Z', 'COMPLETED'
            )
            """
        ),
        {"session_id": session_id, "capture_interface": capture_interface},
    )
    return int(result.lastrowid)


def _insert_packet_source(
    db,
    *,
    session_pk: int,
    feature_id: int,
    segment_id: int,
    device_id: str | None = "esp32_01",
    peer_ip: str = "192.168.0.4",
    direction: str = "INBOUND",
    capture_interface: str = "eth0",
    window_start: str = "2026-07-26T10:00:00Z",
    window_end: str = "2026-07-26T10:00:10Z",
    duration: float = 9.8,
    segment_status: str = "PROCESSED",
    segment_error_code: str | None = None,
    packet_count: int = 10,
    total_bytes: int = 1000,
    distinct_dest_port_count: int = 2,
    tcp_syn_count: int = 1,
    mqtt_related_packet_count: int = 8,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                id, capture_session_id, file_name, capture_interface,
                window_start, window_end, status, error_code, packet_count,
                processed_at, start_delay_seconds, captured_duration_seconds
            )
            VALUES (
                :segment_id, :session_pk, :file_name, :capture_interface,
                :window_start, :window_end, :segment_status, :segment_error_code,
                :packet_count, :window_end, 0.2, :duration
            )
            """
        ),
        {
            "segment_id": segment_id,
            "session_pk": session_pk,
            "file_name": f"segment-{segment_id}.pcap",
            "capture_interface": capture_interface,
            "window_start": window_start,
            "window_end": window_end,
            "segment_status": segment_status,
            "segment_error_code": segment_error_code,
            "packet_count": packet_count,
            "duration": duration,
        },
    )
    db.execute(
        text(
            """
            INSERT INTO packet_feature_logs (
                id, capture_segment_id, device_id, peer_ip, direction,
                window_start, window_end, packet_count, total_bytes,
                avg_packet_size, max_packet_size, mean_inter_arrival_time,
                distinct_dest_port_count, tcp_syn_count,
                mqtt_related_packet_count, non_mqtt_tcp_udp_packet_count,
                capture_scope
            )
            VALUES (
                :feature_id, :segment_id, :device_id, :peer_ip, :direction,
                :window_start, :window_end, :packet_count, :total_bytes,
                100.0, 120, 0.5,
                :distinct_dest_port_count, :tcp_syn_count,
                :mqtt_related_packet_count, 0,
                'gateway'
            )
            """
        ),
        {
            "feature_id": feature_id,
            "segment_id": segment_id,
            "device_id": device_id,
            "peer_ip": peer_ip,
            "direction": direction,
            "window_start": window_start,
            "window_end": window_end,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "distinct_dest_port_count": distinct_dest_port_count,
            "tcp_syn_count": tcp_syn_count,
            "mqtt_related_packet_count": mqtt_related_packet_count,
        },
    )


def test_phase8_packet_stage_uses_historical_ip_and_device_rate_limits(SessionLocal) -> None:
    start = "2026-07-26T10:00:00Z"
    next_start = "2026-07-26T10:00:10Z"
    _enable_phase8(SessionLocal)
    with SessionLocal() as db:
        for device_id, ip, packet_max, byte_max in (
            ("esp32_01", "192.168.0.4", 5, 50),
            ("esp32_02", "192.168.0.5", 10, 100),
        ):
            _insert_device(db, device_id=device_id, ip_address=ip)
            db.execute(text("""UPDATE devices SET registration_effective_from=:start
                WHERE device_id=:device_id"""),
                {"device_id": device_id, "start": start})
            _insert_policy_revision(db, device_id=device_id,
                                    packet_max=packet_max, byte_max=byte_max)
        _insert_policy_revision(db, revision=2, effective=next_start,
                                packet_max=50, byte_max=500)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db, session_pk=session_pk, feature_id=1, segment_id=1,
            packet_count=51, total_bytes=501, duration=9.8,
        )
        # The stored candidate is deliberately stale; the historical IP owns the row.
        db.execute(text("""INSERT INTO packet_feature_logs (
            capture_segment_id, device_id, peer_ip, direction, window_start,
            window_end, packet_count, total_bytes, avg_packet_size,
            max_packet_size, distinct_dest_port_count, tcp_syn_count,
            mqtt_related_packet_count
        ) SELECT capture_segment_id, 'esp32_01', '192.168.0.5', direction,
                 window_start, window_end, packet_count, total_bytes,
                 avg_packet_size, max_packet_size, distinct_dest_port_count,
                 tcp_syn_count, mqtt_related_packet_count
          FROM packet_feature_logs WHERE id=1"""))
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = _stage().run_until(
                db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
            )
        assert result.created_event_count == 2
        rows = db.execute(text("""SELECT device_id, event_type, policy_version,
            evidence_json FROM detection_events ORDER BY id""")).mappings().all()
        assert {(row["device_id"], row["event_type"]) for row in rows} == {
            ("esp32_01", "PACKET_RATE_ANOMALY"),
            ("esp32_01", "BYTE_RATE_ANOMALY"),
        }
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            assert evidence["device_id"] == "esp32_01"
            assert evidence["device_policy_revision"] == 1
            assert evidence["window_start"] == start
            assert evidence["captured_duration_seconds"] == 9.8
            assert evidence["candidate_device_id"] == "esp32_01"
            assert evidence["threshold"] == (5 if row["event_type"] == "PACKET_RATE_ANOMALY" else 50)
            assert evidence["unit"] == ("packets/second" if row["event_type"] == "PACKET_RATE_ANOMALY" else "bytes/second")
            assert row["policy_version"] == TEST_POLICY.version
        db.rollback()
        with db.begin():
            again = _stage().run_until(
                db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
            )
        assert again.created_event_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 2


def test_phase8_pending_packet_if_receives_input_but_trust_excludes_response(
    SessionLocal, tmp_path: Path,
) -> None:
    start = "2026-07-26T10:00:00Z"
    capture_policy = CapturePolicy()
    artifact = PacketIFArtifact(
        model=object(), model_path=tmp_path / "model.joblib",
        metadata_path=tmp_path / "metadata.json",
        training_report_path=tmp_path / "train.json",
        model_version="pending-test", threshold=0.1,
        bundle_sha256="a" * 64, capture_policy=capture_policy, metadata={},
    )
    seen = []

    def predict(_artifact, rows):
        seen.extend(rows)
        return tuple(PacketIFPrediction(
            model_version="pending-test", raw_decision_score=-0.2,
            anomaly_score=0.2, threshold=0.1, is_anomaly=True,
            feature_values=(
                float(row["packet_count"]), float(row["total_bytes"]),
                float(row["avg_packet_size"]), float(row["max_packet_size"]),
                float(row["mean_inter_arrival_time"]),
                float(row["distinct_dest_port_count"]),
            ),
        ) for row in rows)

    _enable_phase8(SessionLocal)
    with SessionLocal() as db:
        _insert_device(db)
        db.execute(text("""UPDATE devices SET registration_effective_from=:start
            WHERE device_id='esp32_01'"""),
            {"start": start})
        _insert_policy_revision(db, state="PENDING")
        session_pk = _insert_capture_session(db)
        _insert_packet_source(db, session_pk=session_pk, feature_id=1,
                              segment_id=1, packet_count=10, total_bytes=1000)
        db.commit()
    with SessionLocal() as db:
        with db.begin():
            result = PacketIsolationForestStage(
                artifact=artifact, expected_model_version="pending-test",
                capture_policy=capture_policy, predict_rows=predict,
            ).run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
        assert result.created_event_count == 1
        assert len(seen) == 1
        assert seen[0]["packet_count"] == 10
        db.rollback()
        with db.begin():
            trust = apply_trust_score_v2_until(
                db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
                decision_at=NEXT_CUTOFF,
            )
        assert trust.created_history_count == 0
        assert trust.created_firewall_rule_count == 0
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 100
        event = db.execute(text("""SELECT device_id, event_type, score_delta,
            applied_to_score, processing_reason, processed_at
            FROM detection_events""")).mappings().one()
        assert event["event_type"] == "AI_PACKET_ANOMALY"
        assert event["device_id"] == "esp32_01"
        assert event["score_delta"] == -15
        assert event["applied_to_score"] == 0
        assert event["processing_reason"] == "PENDING_AT_WINDOW"
        assert event["processed_at"] is not None


@pytest.mark.parametrize("mqtt_first", [True, False])
def test_rate_severity_ties_keep_one_flooding_penalty(SessionLocal, mqtt_first) -> None:
    with SessionLocal.begin() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db, session_pk=session_pk, feature_id=1, segment_id=1,
            packet_count=1000, total_bytes=2_000_000,
        )
        db.execute(text("""INSERT INTO feature_logs (
            device_id, window_start, window_end, publish_count, avg_payload_size,
            max_payload_size, avg_message_interval, min_message_interval
        ) VALUES ('esp32_01', '2026-07-26T10:00:00Z', '2026-07-26T10:00:10Z',
                  100, 100, 100, 0.1, 0.1)"""))
    packet_stage, mqtt_stage = _stage(), MqttFeatureRuleStage()
    stages = (mqtt_stage, packet_stage) if mqtt_first else (packet_stage, mqtt_stage)
    with SessionLocal.begin() as db:
        for stage in stages:
            stage.run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
        events = db.execute(text("SELECT * FROM detection_events ORDER BY id")).mappings().all()
        assert {event["event_type"] for event in events} == {
            "ABNORMAL_PUBLISH_RATE", "PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY",
        }
        assert all(event["severity"] == "high" for event in events)
        assert all(event["score_delta"] == -20 for event in events)
        assert all(event["incident_family"] == "FLOODING" for event in events)
        expected_representative = events[0]["id"]
        trust = apply_trust_score_v2_until(
            db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
            ai_mode="observe", decision_at=NEXT_CUTOFF,
        )
        assert trust.created_history_count == 1
        assert trust.created_firewall_rule_count == 0
        assert trust.changes[0].representative_event_ids == [expected_representative]
        assert trust.changes[0].actual_delta == -20
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 80
        assert db.execute(text("SELECT SUM(applied_to_score) FROM detection_events")).scalar_one() == 1
    with SessionLocal.begin() as db:
        for stage in stages:
            assert stage.run_until(
                db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
            ).created_event_count == 0
        retry = apply_trust_score_v2_until(
            db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
            ai_mode="observe", decision_at=NEXT_CUTOFF,
        )
        assert retry.created_history_count == 0
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 80


class TestEffectiveRateFormulas:
    def test_packets_per_second_uses_raw_captured_duration_not_ten_second_normalization(self) -> None:
        # Packet IF의 normalize_to_ten_second_rate(=count*10/duration)와 다른 공식이다.
        assert effective_packets_per_second(98.0, 9.8) == pytest.approx(10.0)

    def test_bytes_per_second(self) -> None:
        assert effective_bytes_per_second(9800.0, 9.8) == pytest.approx(1000.0)

    def test_zero_duration_raises(self) -> None:
        with pytest.raises(ValueError):
            effective_packets_per_second(10.0, 0.0)


class TestPacketRulePolicy:
    def test_rejects_nan_and_negative(self) -> None:
        with pytest.raises(ValueError):
            PacketRulePolicy(
                packet_rate_threshold=float("nan"),
                byte_rate_threshold=1.0,
                port_scan_distinct_port_threshold=1,
                port_scan_syn_threshold=1,
                broker_dos_tcp_syn_threshold=1,
                broker_dos_mqtt_packet_threshold=1,
                version="v1",
            )
        with pytest.raises(ValueError):
            PacketRulePolicy(
                packet_rate_threshold=-1.0,
                byte_rate_threshold=1.0,
                port_scan_distinct_port_threshold=1,
                port_scan_syn_threshold=1,
                broker_dos_tcp_syn_threshold=1,
                broker_dos_mqtt_packet_threshold=1,
                version="v1",
            )

    def test_rejects_empty_version(self) -> None:
        with pytest.raises(ValueError):
            PacketRulePolicy(
                packet_rate_threshold=1.0,
                byte_rate_threshold=1.0,
                port_scan_distinct_port_threshold=1,
                port_scan_syn_threshold=1,
                broker_dos_tcp_syn_threshold=1,
                broker_dos_mqtt_packet_threshold=1,
                version="",
            )


class TestDetectPacketRules:
    def _row(self, **overrides) -> dict:
        base = {
            "direction": "INBOUND",
            # Explicit endpoint evidence for handcrafted verified-count cases.
            "broker_target_ip": "192.168.0.20",
            "broker_target_port": 1883,
            "packet_count": 10,
            "total_bytes": 1000,
            "distinct_dest_port_count": 2,
            "tcp_syn_count": 1,
            "mqtt_related_packet_count": 8,
            "captured_duration_seconds": 9.8,
        }
        base.update(overrides)
        return base

    def test_normal_row_produces_no_events(self) -> None:
        assert detect_packet_rules(self._row(), TEST_POLICY) == []

    def test_packet_rate_anomaly(self) -> None:
        row = self._row(packet_count=1000, captured_duration_seconds=10.0)  # 100 pps > 50
        events = detect_packet_rules(row, TEST_POLICY)
        assert [e["event_type"] for e in events] == ["PACKET_RATE_ANOMALY"]
        assert events[0]["severity"] == "high"

    def test_byte_rate_anomaly(self) -> None:
        row = self._row(total_bytes=2_000_000, captured_duration_seconds=10.0)  # 200000 Bps > 100000
        events = detect_packet_rules(row, TEST_POLICY)
        assert [e["event_type"] for e in events] == ["BYTE_RATE_ANOMALY"]
        assert events[0]["severity"] == "high"

    def test_port_scan_requires_both_distinct_ports_and_syn(self) -> None:
        """다수 목적지 Port와 높은 SYN이 함께 존재하면 PORT_SCAN이 생성된다."""
        row = self._row(distinct_dest_port_count=20, tcp_syn_count=20)
        events = detect_packet_rules(row, TEST_POLICY)
        assert [e["event_type"] for e in events] == ["PORT_SCAN"]

    def test_single_port_high_syn_does_not_trigger_port_scan(self) -> None:
        """단일 MQTT Port(1883)의 높은 SYN은 PORT_SCAN을 생성하지 않는다.

        distinct_dest_port_count가 낮으면(목적지가 사실상 하나뿐이면) SYN이
        아무리 높아도 그건 Port Scan이 아니라 단일 목적지 Flood(BROKER_DOS_SUSPECTED
        영역)이므로 PORT_SCAN을 오탐하면 안 된다.
        """
        row = self._row(distinct_dest_port_count=1, tcp_syn_count=40)
        events = detect_packet_rules(row, TEST_POLICY)
        assert "PORT_SCAN" not in {e["event_type"] for e in events}

    def test_high_distinct_ports_alone_does_not_trigger_port_scan(self) -> None:
        """distinct_dest_port_count만 높고 SYN이 낮으면 PORT_SCAN이 아니다 (AND 조건)."""
        row = self._row(distinct_dest_port_count=20, tcp_syn_count=1)
        events = detect_packet_rules(row, TEST_POLICY)
        assert "PORT_SCAN" not in {e["event_type"] for e in events}

    def test_broker_dos_syn_alone_does_not_also_trigger_port_scan(self) -> None:
        """Broker DoS가 SYN 수만으로 Scan Family까지 중복 감점되지 않는다.

        목적지 Port가 사실상 하나(MQTT 1883)인 SYN Flood는 BROKER_DOS_SUSPECTED
        (FLOODING, -25)만 발생해야 하고, PORT_SCAN(SCAN, -20)까지 함께 잡혀서
        서로 다른 Incident Family로 이중 집계되면 안 된다.
        """
        row = self._row(distinct_dest_port_count=1, tcp_syn_count=40, mqtt_related_packet_count=150,
                        broker_target_syn_count=40)
        events = detect_packet_rules(row, TEST_POLICY)
        event_types = {e["event_type"] for e in events}
        assert event_types == {"BROKER_DOS_SUSPECTED"}

    def test_port_scan_and_broker_dos_can_still_fire_together_when_both_genuinely_match(self) -> None:
        """PORT_SCAN·BROKER_DOS_SUSPECTED는 서로 다른 근거를 보는 별개 Rule이라
        상호 배타적이지 않다 -- 다만 이제는 PORT_SCAN도 distinct_dest_port_count
        조건을 실제로 만족해야만 함께 발생한다 (예: 여러 Port를 스캔하면서
        동시에 MQTT Broker에도 SYN Flood를 거는 복합 공격)."""
        row = self._row(
            distinct_dest_port_count=20, tcp_syn_count=40, mqtt_related_packet_count=150,
            broker_target_syn_count=40,
        )
        events = detect_packet_rules(row, TEST_POLICY)
        event_types = {e["event_type"] for e in events}
        assert event_types == {"PORT_SCAN", "BROKER_DOS_SUSPECTED"}

    def test_broker_dos_requires_both_syn_and_mqtt_volume(self) -> None:
        """SYN은 높지만 mqtt_related_packet_count가 낮으면 BROKER_DOS_SUSPECTED가
        아니어야 한다 (AND 조건). distinct_dest_port_count는 낮게 둬서 PORT_SCAN도
        같이 섞이지 않게 한다."""
        row = self._row(distinct_dest_port_count=1, tcp_syn_count=40, mqtt_related_packet_count=5)
        events = detect_packet_rules(row, TEST_POLICY)
        assert events == []

    def test_other_port_scan_with_normal_mqtt_is_not_broker_dos(self) -> None:
        row = self._row(
            distinct_dest_port_count=20,
            tcp_syn_count=40,
            mqtt_related_packet_count=150,
            broker_target_syn_count=1,
        )
        assert {event["event_type"] for event in detect_packet_rules(row, TEST_POLICY)} == {"PORT_SCAN"}

    def test_missing_broker_metric_is_audited_without_penalty(self) -> None:
        row = self._row(
            distinct_dest_port_count=20,
            tcp_syn_count=40,
            mqtt_related_packet_count=150,
            broker_target_syn_count=None,
        )
        events = detect_packet_rules(row, TEST_POLICY)
        assert {event["event_type"] for event in events} == {
            "PORT_SCAN", "BROKER_DOS_EVIDENCE_UNAVAILABLE"
        }
        assert events[-1]["reason"] == "BROKER_TARGET_SYN_COUNT_MISSING"

    @pytest.mark.parametrize(
        "broker_syn,mqtt_count,expected",
        [(30, 101, False), (31, 100, False), (31, 101, True)],
    )
    def test_verified_broker_syn_and_mqtt_thresholds(
        self, broker_syn: int, mqtt_count: int, expected: bool
    ) -> None:
        row = self._row(
            tcp_syn_count=40,
            broker_target_syn_count=broker_syn,
            mqtt_related_packet_count=mqtt_count,
        )
        event_types = {event["event_type"] for event in detect_packet_rules(row, TEST_POLICY)}
        assert ("BROKER_DOS_SUSPECTED" in event_types) is expected

    @pytest.mark.parametrize("overrides", [
        {"broker_target_syn_count": -1},
        {"broker_target_syn_count": True},
        {"broker_target_syn_count": 31.0},
        {"broker_target_syn_count": "31"},
        {"broker_target_ip": None},
        {"broker_target_ip": "broker.local"},
        {"broker_target_ip": "::1"},
        {"broker_target_ip": 123},
        {"broker_target_port": None},
        {"broker_target_port": "1883"},
        {"broker_target_port": 8883},
        {"direction": "OUTBOUND"},
        {"direction": None},
    ])
    def test_present_broker_count_requires_stored_endpoint_evidence(self, overrides) -> None:
        row = self._row(
            tcp_syn_count=40, broker_target_syn_count=31, mqtt_related_packet_count=101,
        )
        row.update(overrides)
        with pytest.raises(ValueError, match="broker_target"):
            detect_packet_rules(row, TEST_POLICY)

    def test_outbound_zero_broker_count_is_not_a_broker_attack(self) -> None:
        row = self._row(direction="OUTBOUND", broker_target_syn_count=0)
        assert detect_packet_rules(row, TEST_POLICY) == []

    def test_multiple_rules_can_fire_together(self) -> None:
        row = self._row(
            packet_count=1000,
            total_bytes=2_000_000,
            distinct_dest_port_count=20,
            tcp_syn_count=20,
            captured_duration_seconds=10.0,
        )
        events = detect_packet_rules(row, TEST_POLICY)
        event_types = {e["event_type"] for e in events}
        assert event_types == {"PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY", "PORT_SCAN"}

    def test_excluded_management_peer_skips_all_packet_rules(self) -> None:
        policy = replace(
            TEST_POLICY,
            excluded_peer_ips=frozenset({"192.168.0.3"}),
        )
        row = self._row(
            device_id=None,
            peer_ip="192.168.0.3",
            packet_count=1_000,
            total_bytes=2_000_000,
            distinct_dest_port_count=20,
            tcp_syn_count=40,
            mqtt_related_packet_count=150,
            broker_target_syn_count=40,
            captured_duration_seconds=10.0,
        )

        assert detect_packet_rules(row, policy) == []

    def test_non_excluded_unregistered_peer_still_triggers_all_packet_rules(self) -> None:
        policy = replace(
            TEST_POLICY,
            excluded_peer_ips=frozenset({"192.168.0.3"}),
        )
        row = self._row(
            device_id=None,
            peer_ip="192.168.0.30",
            packet_count=1_000,
            total_bytes=2_000_000,
            distinct_dest_port_count=20,
            tcp_syn_count=40,
            mqtt_related_packet_count=150,
            broker_target_syn_count=40,
            captured_duration_seconds=10.0,
        )

        event_types = {event["event_type"] for event in detect_packet_rules(row, policy)}

        assert event_types == {
            "PACKET_RATE_ANOMALY",
            "BYTE_RATE_ANOMALY",
            "PORT_SCAN",
            "BROKER_DOS_SUSPECTED",
        }

    def test_non_excluded_registered_iot_peer_still_triggers_all_packet_rules(self) -> None:
        policy = replace(
            TEST_POLICY,
            excluded_peer_ips=frozenset({"192.168.0.3"}),
        )
        row = self._row(
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            packet_count=1_000,
            total_bytes=2_000_000,
            distinct_dest_port_count=20,
            tcp_syn_count=40,
            mqtt_related_packet_count=150,
            broker_target_syn_count=40,
            captured_duration_seconds=10.0,
        )

        event_types = {event["event_type"] for event in detect_packet_rules(row, policy)}

        assert event_types == {
            "PACKET_RATE_ANOMALY",
            "BYTE_RATE_ANOMALY",
            "PORT_SCAN",
            "BROKER_DOS_SUSPECTED",
        }

    def test_threshold_boundary_is_exclusive(self) -> None:
        # policy 기본값과 정확히 같은 값은 초과가 아니므로 이벤트가 없어야 한다.
        row = self._row(packet_count=int(50.0 * 10), captured_duration_seconds=10.0)  # 정확히 50pps
        assert detect_packet_rules(row, TEST_POLICY) == []


class TestPacketRuleDetectorStage:
    def test_count_without_stored_endpoint_does_not_advance_checkpoint(self, SessionLocal) -> None:
        with SessionLocal() as db:
            db.execute(text("ALTER TABLE packet_feature_logs ADD COLUMN broker_target_syn_count INTEGER"))
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=1, segment_id=1,
                tcp_syn_count=40, mqtt_related_packet_count=150,
            )
            db.execute(text("UPDATE packet_feature_logs SET broker_target_syn_count=40"))
            db.commit()
        with SessionLocal() as db:
            with pytest.raises(ValueError, match="stored IPv4 broker_target_ip"):
                with db.begin():
                    _stage().run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
            assert get_detector_checkpoint(
                db, detector_name="packet_rule", source_table="packet_feature_logs",
            ) is None
            assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0

    def test_missing_broker_metric_cannot_reduce_trust_or_request_firewall(
        self, SessionLocal,
    ) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=1, segment_id=1,
                distinct_dest_port_count=1, tcp_syn_count=40,
                mqtt_related_packet_count=150,
            )
            db.commit()
        with SessionLocal() as db:
            with db.begin():
                _stage().run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
                trust = apply_trust_score_v2_until(
                    db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF,
                )
            event = db.execute(text("""SELECT event_type, score_delta,
                applied_to_score, processing_reason FROM detection_events""")).mappings().one()
            assert event["event_type"] == "BROKER_DOS_EVIDENCE_UNAVAILABLE"
            assert event["score_delta"] == event["applied_to_score"] == 0
            assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 100
            assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one() == 0
            assert db.execute(text("SELECT COUNT(*) FROM firewall_rules")).scalar_one() == 0
            assert trust.created_firewall_rule_count == 0

    @pytest.mark.parametrize(
        "broker_syn,expected_broker_event",
        [(None, "BROKER_DOS_EVIDENCE_UNAVAILABLE"),
         (1, None),
         (31, "BROKER_DOS_SUSPECTED")],
    )
    def test_broker_metric_projection_and_legacy_null(
        self, SessionLocal, broker_syn: int | None, expected_broker_event: str | None
    ) -> None:
        with SessionLocal() as db:
            if broker_syn is not None:
                db.execute(text("ALTER TABLE packet_feature_logs ADD COLUMN broker_target_syn_count INTEGER"))
                db.execute(text("ALTER TABLE packet_feature_logs ADD COLUMN broker_target_ip TEXT"))
                db.execute(text("ALTER TABLE packet_feature_logs ADD COLUMN broker_target_port INTEGER"))
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=1, segment_id=1,
                distinct_dest_port_count=20, tcp_syn_count=40,
                mqtt_related_packet_count=150,
            )
            if broker_syn is not None:
                db.execute(text("""UPDATE packet_feature_logs SET broker_target_syn_count=:count,
                    broker_target_ip='192.168.0.20', broker_target_port=1883"""),
                           {"count": broker_syn})
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                _stage().run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
            events = db.execute(text("""
                SELECT event_type, score_delta, evidence_json FROM detection_events
                ORDER BY id
            """)).mappings().all()
            event_types = {row["event_type"] for row in events}
            for event in events:
                evidence = json.loads(event["evidence_json"])
                assert evidence["broker_target_ip"] == ("192.168.0.20" if broker_syn is not None else None)
                assert evidence["broker_target_port"] == (1883 if broker_syn is not None else None)
            assert "PORT_SCAN" in event_types
            if expected_broker_event is None:
                assert "BROKER_DOS_SUSPECTED" not in event_types
                assert "BROKER_DOS_EVIDENCE_UNAVAILABLE" not in event_types
            else:
                assert expected_broker_event in event_types
                if expected_broker_event == "BROKER_DOS_EVIDENCE_UNAVAILABLE":
                    audit = next(row for row in events if row["event_type"] == expected_broker_event)
                    assert audit["score_delta"] == 0
                    assert json.loads(audit["evidence_json"])["reason"] == "BROKER_TARGET_SYN_COUNT_MISSING"

    def test_excluded_management_peer_advances_checkpoint_without_event(self, SessionLocal) -> None:
        policy = replace(
            TEST_POLICY,
            excluded_peer_ips=frozenset({"192.168.0.3"}),
        )
        with SessionLocal() as db:
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db,
                session_pk=session_pk,
                feature_id=1,
                segment_id=1,
                device_id=None,
                peer_ip="192.168.0.3",
                duration=10.0,
                packet_count=1_000,
                total_bytes=2_000_000,
                distinct_dest_port_count=20,
                tcp_syn_count=40,
                mqtt_related_packet_count=150,
            )
            db.commit()

        stage = PacketRuleDetectorStage(
            capture_policy=CapturePolicy(),
            rule_policy=policy,
        )
        with SessionLocal() as db:
            with db.begin():
                result = stage.run_until(
                    db,
                    cycle_range_start=RANGE_START,
                    cycle_cutoff=CUTOFF,
                )

        assert result.selected_count == 1
        assert result.created_event_count == 0
        assert result.last_processed_id_after == 1
        assert result.completed_window_end_after == CUTOFF

        with SessionLocal() as db:
            assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs")).scalar_one() == 1
            assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
            checkpoint = get_detector_checkpoint(
                db,
                detector_name="packet_rule",
                source_table="packet_feature_logs",
            )
            assert checkpoint["last_processed_id"] == 1
            assert checkpoint["last_completed_window_end"] == "2026-07-26T10:00:10Z"

    def test_writes_event_checkpoint_in_one_transaction(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db,
                session_pk=session_pk,
                feature_id=1,
                segment_id=1,
                distinct_dest_port_count=30, tcp_syn_count=30,  # PORT_SCAN 유발 (AND 조건 만족)
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                result = _stage().run_until(
                    db,
                    cycle_range_start=RANGE_START,
                    cycle_cutoff=CUTOFF,
                )

        assert result.selected_count == 1
        assert result.created_event_count == 1
        assert result.last_processed_id_after == 1
        assert result.completed_window_end_after == CUTOFF

        with SessionLocal() as db:
            event = db.execute(
                text(
                    """
                    SELECT device_id, packet_feature_log_id, detector_type,
                           event_type, severity, score_delta, applied_to_score,
                           incident_family, subject_ip, evidence_json, policy_version
                    FROM detection_events
                    """
                )
            ).mappings().one()
            assert event["device_id"] == "esp32_01"
            assert event["packet_feature_log_id"] == 1
            assert event["detector_type"] == "RULE"
            assert event["event_type"] == "PORT_SCAN"
            assert event["severity"] == "high"
            assert event["score_delta"] == -20
            assert event["applied_to_score"] == 0
            assert event["incident_family"] == "SCAN"
            assert event["subject_ip"] == "192.168.0.4"
            assert event["policy_version"] == "packet-rule-policy-test-v1"

            evidence = json.loads(event["evidence_json"])
            assert evidence["capture_segment_id"] == 1
            assert evidence["rule_policy_version"] == "packet-rule-policy-test-v1"

            checkpoint = get_detector_checkpoint(
                db, detector_name="packet_rule", source_table="packet_feature_logs"
            )
            assert checkpoint["last_processed_id"] == 1
            assert checkpoint["last_completed_window_end"] == "2026-07-26T10:00:10Z"

    def test_unmapped_device_still_stores_event(self, SessionLocal) -> None:
        """미매핑 IP는 Event만 저장하고 점수·격리는 변경하지 않는다."""
        with SessionLocal() as db:
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db,
                session_pk=session_pk,
                feature_id=1,
                segment_id=1,
                device_id=None,
                peer_ip="192.168.0.99",
                distinct_dest_port_count=20,
                tcp_syn_count=20,
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                result = _stage().run_until(
                    db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF
                )
        assert result.created_event_count == 1

        with SessionLocal() as db:
            event = db.execute(
                text("SELECT device_id, subject_ip, applied_to_score FROM detection_events")
            ).mappings().one()
            assert event["device_id"] is None
            assert event["subject_ip"] == "192.168.0.99"
            assert event["applied_to_score"] == 0  # Trust 단계에서 별도 처리, 여기선 항상 0

    def test_ineligible_segment_is_excluded_but_still_advances_checkpoint(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db,
                session_pk=session_pk,
                feature_id=1,
                segment_id=1,
                segment_status="FAILED",
                segment_error_code="PARTIAL_CAPTURE",
                tcp_syn_count=999,  # 규칙상 위반이어도 부적격 Segment면 무시돼야 함
                distinct_dest_port_count=999,
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                result = _stage().run_until(
                    db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF
                )

        assert result.selected_count == 1
        assert result.created_event_count == 0
        assert result.last_processed_id_after == 1  # ID는 여전히 전진해야 함

        with SessionLocal() as db:
            count = db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar()
            assert count == 0
            checkpoint = get_detector_checkpoint(
                db, detector_name="packet_rule", source_table="packet_feature_logs"
            )
            assert checkpoint["last_completed_window_end"] == "2026-07-26T10:00:10Z"

    def test_outbound_rows_are_not_selected(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db,
                session_pk=session_pk,
                feature_id=1,
                segment_id=1,
                direction="OUTBOUND",
                tcp_syn_count=999,
                distinct_dest_port_count=999,
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                result = _stage().run_until(
                    db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF
                )
        assert result.selected_count == 0
        assert result.created_event_count == 0

    def test_rerun_same_window_does_not_duplicate_events(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=1, segment_id=1,
                distinct_dest_port_count=30, tcp_syn_count=30,
            )
            db.commit()

        stage = _stage()
        with SessionLocal() as db:
            with db.begin():
                stage.run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)

        # Checkpoint 조작 없이 동일 범위를 다시 실행 -- dedupe_key UNIQUE로 막혀야 함.
        with SessionLocal() as db:
            with db.begin():
                result = stage.run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
        assert result.created_event_count == 0

        with SessionLocal() as db:
            count = db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar()
            assert count == 1

    def test_empty_window_advances_checkpoint_without_events(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_capture_session(db)
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                result = _stage().run_until(
                    db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF
                )
        assert result.selected_count == 0
        assert result.created_event_count == 0
        assert result.last_processed_id_after is None

        with SessionLocal() as db:
            checkpoint = get_detector_checkpoint(
                db, detector_name="packet_rule", source_table="packet_feature_logs"
            )
            assert checkpoint["last_completed_window_end"] == "2026-07-26T10:00:10Z"

    def test_second_cycle_only_processes_new_rows(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=1, segment_id=1,
                distinct_dest_port_count=30, tcp_syn_count=30,
            )
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=2, segment_id=2,
                window_start="2026-07-26T10:00:10Z", window_end="2026-07-26T10:00:20Z",
                distinct_dest_port_count=30, tcp_syn_count=30,
            )
            db.commit()

        stage = _stage()
        with SessionLocal() as db:
            with db.begin():
                first = stage.run_until(db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF)
        assert first.selected_count == 1
        assert first.last_processed_id_after == 1

        with SessionLocal() as db:
            with db.begin():
                second = stage.run_until(db, cycle_range_start=CUTOFF, cycle_cutoff=NEXT_CUTOFF)
        assert second.selected_count == 1
        assert second.last_processed_id_before == 1
        assert second.last_processed_id_after == 2

        with SessionLocal() as db:
            count = db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar()
            assert count == 2

    def test_mixed_capture_sessions_in_one_cycle_are_rejected(self, SessionLocal) -> None:
        """Packet Session Gap 이전·이후 Row를 한 Cycle에 섞지 않는다. Packet IF뿐 아니라 모든 Required Detector에 적용되는 일반 규칙이다."""
        second_session_id = "22222222-2222-4222-8222-222222222222"
        with SessionLocal() as db:
            _insert_device(db)
            session_a_pk = _insert_capture_session(db, session_id=SESSION_ID)
            session_b_pk = _insert_capture_session(
                db, session_id=second_session_id, capture_interface="eth1"
            )
            _insert_packet_source(
                db, session_pk=session_a_pk, feature_id=1, segment_id=1,
            )
            _insert_packet_source(
                db, session_pk=session_b_pk, feature_id=2, segment_id=2,
                capture_interface="eth1",
                window_start="2026-07-26T10:00:00Z", window_end="2026-07-26T10:00:10Z",
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                with pytest.raises(RuntimeError, match="must not mix Capture Sessions"):
                    _stage().run_until(
                        db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF
                    )

    def test_expected_capture_session_is_recorded_in_result(self, SessionLocal) -> None:
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db,
                session_pk=session_pk,
                feature_id=1,
                segment_id=1,
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                result = _stage().run_until_for_capture_session(
                    db,
                    cycle_range_start=RANGE_START,
                    cycle_cutoff=CUTOFF,
                    expected_capture_session_id=SESSION_ID,
                )

        assert result.capture_session_id == SESSION_ID
        assert result.selected_count == 1

    def test_feature_from_unexpected_capture_session_is_rejected(
        self,
        SessionLocal,
    ) -> None:
        expected_session_id = "33333333-3333-4333-8333-333333333333"
        with SessionLocal() as db:
            _insert_device(db)
            _insert_capture_session(db, session_id=expected_session_id)
            other_session_pk = _insert_capture_session(db, session_id=SESSION_ID)
            _insert_packet_source(
                db,
                session_pk=other_session_pk,
                feature_id=1,
                segment_id=1,
            )
            db.commit()

        with SessionLocal() as db:
            with pytest.raises(RuntimeError, match="unexpected Capture Session"):
                with db.begin():
                    _stage().run_until_for_capture_session(
                        db,
                        cycle_range_start=RANGE_START,
                        cycle_cutoff=CUTOFF,
                        expected_capture_session_id=expected_session_id,
                    )

        with SessionLocal() as db:
            assert db.execute(
                text("SELECT COUNT(*) FROM detection_events")
            ).scalar_one() == 0
            assert get_detector_checkpoint(
                db,
                detector_name="packet_rule",
                source_table="packet_feature_logs",
            ) is None

    def test_feature_window_mismatched_with_segment_window_is_rejected(self, SessionLocal) -> None:
        """packet_feature_logs.window와 그 부모 packet_capture_segments.window가
        어긋나 있으면(데이터 정합성 오류) 조용히 넘어가지 않고 예외를 낸다."""
        with SessionLocal() as db:
            _insert_device(db)
            session_pk = _insert_capture_session(db)
            _insert_packet_source(
                db, session_pk=session_pk, feature_id=1, segment_id=1,
            )
            # Segment의 Window만 강제로 어긋나게 만든다 (실제로는 발생하면 안 되는
            # 데이터 정합성 오류 상황을 흉내낸다).
            db.execute(
                text(
                    "UPDATE packet_capture_segments SET window_start = "
                    "'2026-07-26T09:59:50Z', window_end = '2026-07-26T10:00:00Z' "
                    "WHERE id = 1"
                )
            )
            db.commit()

        with SessionLocal() as db:
            with db.begin():
                with pytest.raises(ValueError, match="must match its Capture Segment window"):
                    _stage().run_until(
                        db, cycle_range_start=RANGE_START, cycle_cutoff=CUTOFF
                    )
