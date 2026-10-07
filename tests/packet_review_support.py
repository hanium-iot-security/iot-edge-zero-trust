"""Phase 8 Packet Rule·Trust 검토 테스트가 공유하는 Fixture 보조 함수.

모든 DB는 실제 Migration(001~최신)으로 만든 임시 SQLite다. 운영 DB·PCAP을 사용하지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from edge.detection.packet_rule_detector import PacketRuleDetectorStage, PacketRulePolicy
from edge.packet.capture_policy import CapturePolicy
from edge.trust.trust_score_v2 import apply_trust_score_v2_until


SESSION_ID = "55555555-5555-4555-8555-555555555555"
BASE = datetime(2026, 10, 6, 1, 0, 0, tzinfo=timezone.utc)

# 운영 v3 기본값과 같은 전역 정책. 기기 정책이 없을 때(미등록 IP)만 Rate 임계값으로 쓰인다.
GLOBAL_POLICY = PacketRulePolicy(
    packet_rate_threshold=10.0,
    byte_rate_threshold=2_500.0,
    port_scan_distinct_port_threshold=5,
    port_scan_syn_threshold=5,
    broker_dos_tcp_syn_threshold=10,
    broker_dos_mqtt_packet_threshold=20,
    version="packet-rule-policy-v3",
)


def utc(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


def iso(seconds: int) -> str:
    return utc(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


def stage(policy: PacketRulePolicy = GLOBAL_POLICY) -> PacketRuleDetectorStage:
    return PacketRuleDetectorStage(capture_policy=CapturePolicy(), rule_policy=policy)


def register_device(
    db,
    *,
    device_id: str,
    ip: str,
    state: str = "ACTIVE",
    effective: int = 0,
    packet_max: float = 10.0,
    byte_max: float = 2500.0,
    trust_score: int = 100,
    status: str = "normal",
) -> None:
    """devices + revision 1을 같은 효력 시점으로 만든다(등록 API가 만드는 형태)."""
    db.execute(text(
        """
        INSERT INTO devices (device_id, ip_address, status, trust_score,
                             registration_effective_from)
        VALUES (:device_id, :ip, :status, :trust_score, :effective)
        """
    ), {"device_id": device_id, "ip": ip, "status": status,
        "trust_score": trust_score, "effective": iso(effective)})
    add_revision(db, device_id=device_id, revision=1, state=state, effective=effective,
                 packet_max=packet_max, byte_max=byte_max)


def add_revision(
    db,
    *,
    device_id: str,
    revision: int,
    state: str = "ACTIVE",
    effective: int = 0,
    packet_max: float = 10.0,
    byte_max: float = 2500.0,
    publish_max: int = 15,
    payload_max: int = 5120,
    created: str | None = None,
) -> None:
    """정책 revision을 추가한다. ``created``(접수 시각)는 기본적으로 효력 시점과 같다."""
    db.execute(text(
        """
        INSERT INTO device_policy_revisions (
            device_id, revision, effective_from, registration_state,
            policy_profile, expected_publish_interval_seconds,
            publish_count_max, payload_size_max_bytes, packet_rate_max_pps,
            byte_rate_max_bytes_per_second, created_at, created_by, reason
        ) VALUES (
            :device_id, :revision, :effective, :state, 'periodic-sensor-v1', 5,
            :publish_max, :payload_max, :packet_max, :byte_max, :created,
            'sunwoo-review', 'packet review fixture'
        )
        """
    ), {"device_id": device_id, "revision": revision, "effective": iso(effective),
        "state": state, "packet_max": packet_max, "byte_max": byte_max,
        "publish_max": publish_max, "payload_max": payload_max,
        "created": created or iso(effective)})


def capture_session(db, session_id: str = SESSION_ID) -> int:
    result = db.execute(text(
        """
        INSERT INTO packet_capture_sessions (
            session_id, capture_interface, started_at, first_window_start,
            ended_at, status
        ) VALUES (:session_id, 'eth0', :started, :started, :ended, 'COMPLETED')
        """
    ), {"session_id": session_id, "started": iso(0), "ended": iso(600)})
    return int(result.lastrowid)


def packet_row(
    db,
    *,
    session_pk: int,
    peer_ip: str,
    window: int = 0,
    device_id: str | None = None,
    packet_count: int = 10,
    total_bytes: int = 1000,
    duration: float = 10.0,
    distinct_dest_port_count: int = 1,
    tcp_syn_count: int = 1,
    mqtt_related_packet_count: int = 8,
    segment_status: str = "PROCESSED",
    segment_error_code: str | None = None,
    start_delay: float = 0.0,
) -> int:
    """INBOUND Packet Feature 1행을 넣고 Feature id를 반환한다.

    ``window``는 BASE로부터의 초(10의 배수)다. 실제 Capture처럼 한 Window에는 Segment가
    하나뿐이므로 같은 Window의 두 번째 행부터는 기존 Segment를 재사용한다(Segment 인자는
    처음 만들 때만 적용된다).
    """
    existing = db.execute(text(
        """
        SELECT id FROM packet_capture_segments
        WHERE capture_session_id = :session_pk AND window_start = :start
        """
    ), {"session_pk": session_pk, "start": iso(window)}).scalar_one_or_none()
    if existing is not None:
        segment_id = int(existing)
    else:
        late = segment_error_code == "LATE_CAPTURE"
        segment = db.execute(text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface, window_start,
                window_end, status, error_code, packet_count, processed_at,
                start_delay_seconds, captured_duration_seconds
            ) VALUES (
                :session_pk, :file_name, 'eth0', :start, :end, :status, :error_code,
                :packet_count, :end, :start_delay, :duration
            )
            """
        ), {
            "session_pk": session_pk,
            "file_name": None if late else f"review-{session_pk}-{window}.pcap",
            "start": iso(window), "end": iso(window + 10), "status": segment_status,
            "error_code": segment_error_code, "packet_count": packet_count,
            "start_delay": start_delay, "duration": 0.0 if late else duration,
        })
        segment_id = int(segment.lastrowid)
    feature = db.execute(text(
        """
        INSERT INTO packet_feature_logs (
            capture_segment_id, device_id, peer_ip, direction, window_start,
            window_end, packet_count, total_bytes, avg_packet_size,
            max_packet_size, mean_inter_arrival_time, distinct_dest_port_count,
            tcp_syn_count, mqtt_related_packet_count,
            non_mqtt_tcp_udp_packet_count, capture_scope
        ) VALUES (
            :segment_id, :device_id, :peer_ip, 'INBOUND', :start, :end,
            :packet_count, :total_bytes, 100.0, 120, 0.5, :ports, :syn, :mqtt,
            0, 'gateway'
        )
        """
    ), {
        "segment_id": segment_id, "device_id": device_id,
        "peer_ip": peer_ip, "start": iso(window), "end": iso(window + 10),
        "packet_count": packet_count, "total_bytes": total_bytes,
        "ports": distinct_dest_port_count, "syn": tcp_syn_count,
        "mqtt": mqtt_related_packet_count,
    })
    return int(feature.lastrowid)


def mqtt_feature_row(db, *, device_id: str, window: int = 0, publish_count: int = 40,
                     max_payload_size: int = 120) -> int:
    """MQTT Feature Builder가 만든 10초 Window 1행. Rule 판정은 실제 MqttFeatureRuleStage가 한다."""
    result = db.execute(text(
        """
        INSERT INTO feature_logs (
            device_id, window_start, window_end, publish_count,
            max_payload_size, malformed_payload_count
        ) VALUES (:device_id, :start, :end, :publish_count, :max_payload, 0)
        """
    ), {"device_id": device_id, "start": iso(window), "end": iso(window + 10),
        "publish_count": publish_count, "max_payload": max_payload_size})
    return int(result.lastrowid)


def ai_packet_event(db, *, device_id: str, window: int = 0) -> int:
    """Packet IF가 저장하는 AI_PACKET_ANOMALY(AI_ONLY −15)와 같은 형태의 Event."""
    result = db.execute(text(
        """
        INSERT INTO detection_events (
            device_id, detector_type, event_type, severity, score_delta,
            applied_to_score, analysis_window_start, analysis_window_end,
            incident_family, detected_at, evidence_json, dedupe_key, policy_version
        ) VALUES (
            :device_id, 'AI', 'AI_PACKET_ANOMALY', 'medium', -15, 0,
            :start, :end, 'AI_ONLY', :end, '{"model_version": "review-fixture"}',
            :dedupe, 'packet-if-review-fixture'
        )
        """
    ), {"device_id": device_id, "start": iso(window), "end": iso(window + 10),
        "dedupe": f"review-ai-{device_id}-{window}"})
    return int(result.lastrowid)


def run_mqtt_feature_rule(session_factory, *, start: int = 0, end: int = 10):
    from edge.detection.mqtt_adapters import MqttFeatureRuleStage

    with session_factory() as db:
        with db.begin():
            return MqttFeatureRuleStage().run_until(
                db, cycle_range_start=utc(start), cycle_cutoff=utc(end))


def run_packet_rule(session_factory, *, start: int = 0, end: int = 10,
                    policy: PacketRulePolicy = GLOBAL_POLICY):
    with session_factory() as db:
        with db.begin():
            return stage(policy).run_until(
                db, cycle_range_start=utc(start), cycle_cutoff=utc(end))


def run_trust(session_factory, *, start: int = 0, end: int = 10,
              decision: int | None = None, ai_mode: str = "enforce"):
    with session_factory() as db:
        with db.begin():
            return apply_trust_score_v2_until(
                db, cycle_range_start=utc(start), cycle_cutoff=utc(end),
                decision_at=utc(end + 5 if decision is None else decision),
                ai_mode=ai_mode,
            )


def events(session_factory) -> list[dict[str, Any]]:
    with session_factory() as db:
        return [dict(row) for row in db.execute(text(
            """
            SELECT id, device_id, subject_ip, event_type, score_delta,
                   applied_to_score, incident_family, processing_reason,
                   processed_at, evidence_json, analysis_window_start
            FROM detection_events ORDER BY id
            """
        )).mappings()]


def scalar(session_factory, sql: str, **params: Any) -> Any:
    with session_factory() as db:
        return db.execute(text(sql), params).scalar_one()
