"""P8-05 검토: Packet Rule 임계값·경계 조건·탐지 근거.

P8-05 구현(기기별 Packet Rate·Byte Rate 상한)을 검토하면서, 세부계획 4.4·6.1·
10절(V05·V06·V07·V10·V11)의 Packet 쪽 기대 결과를 독립적인 반례로 고정한다.
구현 코드는 수정하지 않는다. 검토 중 발견한 결함은 ``xfail(strict=True)``로 남겨
수정 담당자가 고치면 XPASS로 실패해 마커 제거를 알리게 한다.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection.packet_rule_detector import detect_packet_rules
from edge.policy.resolver import DevicePolicyRevision
from tests.packet_review_support import (
    GLOBAL_POLICY,
    add_revision,
    capture_session,
    events,
    iso,
    packet_row,
    register_device,
    run_packet_rule,
    run_trust,
    scalar,
    utc,
)


@pytest.fixture
def session_factory(tmp_path: Path):
    path = tmp_path / "sunwoo-packet-rule-review.db"
    apply_migrations(path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    try:
        yield sessionmaker(bind=engine, autoflush=False)
    finally:
        engine.dispose()


def _evidence(event: dict) -> dict:
    return json.loads(event["evidence_json"])


def _rate_events(rows: list[dict]) -> dict[tuple[str | None, str], dict]:
    return {
        (row["device_id"], row["event_type"]): row
        for row in rows
        if row["event_type"] in {"PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY"}
    }


# --- V05: 두 기기, 다른 임계값, 동일 입력 -----------------------------------------


def test_v05_same_packet_feature_is_judged_by_each_devices_own_limits(session_factory):
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=5.0, byte_max=400.0)
        register_device(db, device_id="esp32_02", ip="192.168.0.5",
                        packet_max=20.0, byte_max=4000.0)
        pk = capture_session(db)
        # 두 기기에 완전히 같은 관측값: 10 pps, 500 B/s.
        for ip in ("192.168.0.4", "192.168.0.5"):
            packet_row(db, session_pk=pk, peer_ip=ip, packet_count=100,
                       total_bytes=5000, duration=10.0)
        db.commit()

    run_packet_rule(session_factory)
    rate = _rate_events(events(session_factory))

    assert set(rate) == {
        ("esp32_01", "PACKET_RATE_ANOMALY"),
        ("esp32_01", "BYTE_RATE_ANOMALY"),
    }
    packet_evidence = _evidence(rate[("esp32_01", "PACKET_RATE_ANOMALY")])
    byte_evidence = _evidence(rate[("esp32_01", "BYTE_RATE_ANOMALY")])
    assert (packet_evidence["observed_value"], packet_evidence["threshold"]) == (10.0, 5.0)
    assert (byte_evidence["observed_value"], byte_evidence["threshold"]) == (500.0, 400.0)
    assert packet_evidence["unit"] == "packets/second"
    assert byte_evidence["unit"] == "bytes/second"
    assert packet_evidence["device_policy_revision"] == 1
    # 기기 revision은 전역 탐지 policy_version을 바꾸지 않는다(4.4-8).
    assert packet_evidence["rule_policy_version"] == GLOBAL_POLICY.version


# --- V06: 정확한 상한/직후 초과, 실제 분모 ------------------------------------------


def test_v06_exact_device_limit_is_not_detected_but_next_unit_is(session_factory):
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=10.0, byte_max=2500.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", window=0,
                   packet_count=100, total_bytes=25_000, duration=10.0)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", window=10,
                   packet_count=101, total_bytes=25_010, duration=10.0)
        db.commit()

    run_packet_rule(session_factory, start=0, end=10)
    assert _rate_events(events(session_factory)) == {}

    run_packet_rule(session_factory, start=10, end=20)
    rate = _rate_events(events(session_factory))
    assert set(rate) == {
        ("esp32_01", "PACKET_RATE_ANOMALY"),
        ("esp32_01", "BYTE_RATE_ANOMALY"),
    }
    assert _evidence(rate[("esp32_01", "PACKET_RATE_ANOMALY")])["observed_value"] == 10.1
    assert _evidence(rate[("esp32_01", "BYTE_RATE_ANOMALY")])["observed_value"] == 2501.0


def test_v06_rate_uses_actual_captured_duration_not_ten_second_window(session_factory):
    """96 packets / 9.5 s = 10.105 pps > 10 이므로 탐지돼야 한다.

    분모를 Window 길이 10초로 잘못 쓰면 9.6 pps로 누락된다(6.1 'Packet Rate 실제 수집 시간 분모').
    """
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=10.0, byte_max=2500.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4",
                   packet_count=96, total_bytes=23_800, duration=9.5)
        db.commit()

    run_packet_rule(session_factory)
    rate = _rate_events(events(session_factory))

    assert set(rate) == {
        ("esp32_01", "PACKET_RATE_ANOMALY"),
        ("esp32_01", "BYTE_RATE_ANOMALY"),
    }
    packet_evidence = _evidence(rate[("esp32_01", "PACKET_RATE_ANOMALY")])
    assert packet_evidence["observed_value"] == pytest.approx(96 / 9.5)
    assert packet_evidence["captured_duration_seconds"] == 9.5
    assert packet_evidence["raw_counts"]["packet_count"] == 96
    assert _evidence(rate[("esp32_01", "BYTE_RATE_ANOMALY")])["observed_value"] == pytest.approx(
        23_800 / 9.5
    )


@pytest.mark.parametrize(
    ("status", "error_code", "duration", "start_delay"),
    [
        ("FAILED", "LATE_CAPTURE", 0.0, 1.5),
        ("FAILED", "PARTIAL_CAPTURE", 4.0, 0.1),
        ("PROCESSED", None, 8.5, 0.1),  # 최소 유효 수집 9초 미만
    ],
)
def test_v06_low_device_limit_does_not_bypass_capture_eligibility(
    session_factory, status, error_code, duration, start_delay,
):
    """기기 임계값을 낮춰도 Capture 품질 조건(is_capture_eligible)은 그대로 유지된다."""
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=0.5, byte_max=10.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", packet_count=500,
                   total_bytes=50_000, duration=duration, start_delay=start_delay,
                   segment_status=status, segment_error_code=error_code)
        db.commit()

    result = run_packet_rule(session_factory)

    assert result.selected_count == 1
    assert result.created_event_count == 0
    assert result.completed_window_end_after == utc(10)


# --- V06/V11: 효력 경계, 늦은 처리, 재실행 ----------------------------------------


def test_v06_v11_late_window_keeps_revision_valid_at_window_start(session_factory):
    """rev2(상한 완화)가 이미 저장된 뒤 처리해도 0~10초 Window는 rev1로 판정한다."""
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=5.0, byte_max=2500.0)
        add_revision(db, device_id="esp32_01", revision=2, effective=10,
                     packet_max=50.0, byte_max=2500.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", window=0,
                   packet_count=60, total_bytes=1000)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", window=10,
                   packet_count=60, total_bytes=1000)
        db.commit()

    run_packet_rule(session_factory, start=0, end=10)
    rows = events(session_factory)
    assert [(row["event_type"], row["analysis_window_start"]) for row in rows] == [
        ("PACKET_RATE_ANOMALY", iso(0)),
    ]
    evidence = _evidence(rows[0])
    assert evidence["device_policy_revision"] == 1
    assert evidence["threshold"] == 5.0

    # 같은 Window 재실행(V11): rev2가 있어도 새 Event·중복이 생기지 않는다.
    again = run_packet_rule(session_factory, start=0, end=10)
    assert again.created_event_count == 0

    # 다음 Window는 rev2(50 pps)로 판정되어 6 pps는 비탐지.
    run_packet_rule(session_factory, start=10, end=20)
    assert scalar(session_factory, "SELECT COUNT(*) FROM detection_events") == 1


def test_v06_stricter_revision_applies_only_from_its_effective_window(session_factory):
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=50.0, byte_max=2500.0)
        add_revision(db, device_id="esp32_01", revision=2, effective=20,
                     packet_max=5.0, byte_max=2500.0)
        pk = capture_session(db)
        for window in (0, 10, 20):
            packet_row(db, session_pk=pk, peer_ip="192.168.0.4", window=window,
                       packet_count=60, total_bytes=1000)
        db.commit()

    run_packet_rule(session_factory, start=0, end=30)
    rows = events(session_factory)

    assert [(row["event_type"], row["analysis_window_start"]) for row in rows] == [
        ("PACKET_RATE_ANOMALY", iso(20)),
    ]
    assert _evidence(rows[0])["device_policy_revision"] == 2


# --- V07: 등록 효력 이전 Packet IP 귀속 ------------------------------------------


def test_v07_packet_ip_before_registration_is_not_attributed_retroactively(session_factory):
    with session_factory() as db:
        register_device(db, device_id="pico_01", ip="192.168.0.20", effective=10,
                        packet_max=10.0, byte_max=2500.0)
        pk = capture_session(db)
        for window in (0, 10):
            packet_row(db, session_pk=pk, peer_ip="192.168.0.20", window=window,
                       device_id="pico_01",  # 후보 컬럼은 신뢰된 귀속이 아니다
                       distinct_dest_port_count=8, tcp_syn_count=8)
        db.commit()

    run_packet_rule(session_factory, start=0, end=20)
    rows = events(session_factory)

    assert [(row["analysis_window_start"], row["device_id"], row["event_type"]) for row in rows] == [
        (iso(0), None, "PORT_SCAN"),
        (iso(10), "pico_01", "PORT_SCAN"),
    ]
    assert _evidence(rows[0])["candidate_device_id"] == "pico_01"

    run_trust(session_factory, start=0, end=20)
    after = events(session_factory)
    assert after[0]["processing_reason"] == "UNMAPPED_DEVICE"
    assert after[0]["applied_to_score"] == 0
    assert after[1]["applied_to_score"] == 1
    assert scalar(session_factory, "SELECT trust_score FROM devices") == 80


# --- V10: 미등록·정책 누락·관리 IP ------------------------------------------------


def test_v10_unregistered_ip_keeps_global_v3_limits_without_device_revision(session_factory):
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=500.0, byte_max=500_000.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.99", packet_count=101,
                   total_bytes=1000)
        db.commit()

    run_packet_rule(session_factory)
    run_trust(session_factory)
    rows = events(session_factory)

    assert [(row["device_id"], row["event_type"]) for row in rows] == [
        (None, "PACKET_RATE_ANOMALY"),
    ]
    evidence = _evidence(rows[0])
    assert evidence["threshold"] == GLOBAL_POLICY.packet_rate_threshold
    assert evidence["device_policy_revision"] is None
    assert rows[0]["subject_ip"] == "192.168.0.99"
    assert rows[0]["applied_to_score"] == 0
    assert scalar(session_factory, "SELECT trust_score FROM devices") == 100
    assert scalar(session_factory, "SELECT COUNT(*) FROM trust_score_history") == 0


def test_v10_policy_gap_skips_rate_fallback_but_keeps_security_rule_without_penalty(
    session_factory,
):
    """정책 누락 ACTIVE 기기: 새 기본값으로 조용히 Rate 판정·감점하지 않는다(4.4-6)."""
    with session_factory() as db:
        db.execute(text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score,
                                 registration_effective_from)
            VALUES ('esp32_01', '192.168.0.4', 'normal', 100, :start)
            """
        ), {"start": iso(0)})
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", packet_count=500,
                   total_bytes=500_000, distinct_dest_port_count=8, tcp_syn_count=8)
        db.commit()

    run_packet_rule(session_factory)
    run_trust(session_factory)
    rows = events(session_factory)

    assert {row["event_type"] for row in rows} == {"POLICY_UNAVAILABLE", "PORT_SCAN"}
    assert all(row["applied_to_score"] == 0 for row in rows)
    assert all(row["processing_reason"] == "POLICY_UNAVAILABLE" for row in rows)
    assert all(row["processed_at"] is not None for row in rows)
    assert scalar(session_factory, "SELECT trust_score FROM devices") == 100
    assert scalar(session_factory, "SELECT COUNT(*) FROM firewall_rules") == 0


def test_v10_management_exclusion_still_wins_over_registered_device_policy(session_factory):
    """관리 IP 예외를 기기별 정책으로 대체하지 않는다(6.2)."""
    policy = replace(GLOBAL_POLICY, excluded_peer_ips=frozenset({"192.168.0.30"}))
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.30",
                        packet_max=1.0, byte_max=10.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.30", packet_count=500,
                   total_bytes=500_000, distinct_dest_port_count=8, tcp_syn_count=40,
                   mqtt_related_packet_count=150)
        db.commit()

    result = run_packet_rule(session_factory, policy=policy)

    assert result.created_event_count == 0
    assert events(session_factory) == []


def test_device_limits_replace_only_rate_rules_not_scan_or_broker_dos(session_factory):
    """네 임계값 중 Packet은 Rate 2종만 기기별이다. Port Scan·Broker DoS 기준은 전역 유지."""
    with session_factory() as db:
        register_device(db, device_id="esp32_01", ip="192.168.0.4",
                        packet_max=100_000.0, byte_max=125_000_000.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip="192.168.0.4", packet_count=500,
                   total_bytes=50_000, distinct_dest_port_count=6, tcp_syn_count=11,
                   mqtt_related_packet_count=21)
        db.commit()

    run_packet_rule(session_factory)
    rows = events(session_factory)

    assert {row["event_type"] for row in rows} == {"PORT_SCAN", "BROKER_DOS_SUSPECTED"}
    by_type = {row["event_type"]: _evidence(row) for row in rows}
    assert by_type["PORT_SCAN"]["threshold"] == {
        "distinct_dest_port_count": 5, "tcp_syn_count": 5,
    }
    assert by_type["BROKER_DOS_SUSPECTED"]["threshold"] == {
        "tcp_syn_count": 10, "mqtt_related_packet_count": 20,
    }


# --- 검토 의견: 부동소수점 경계 -----------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=(
        "SW-P8-01: 115 packets / 9.2 s 는 수학적으로 정확히 12.5 pps지만 "
        "float 나눗셈이 12.500000000000002를 만들어 '>' 비교에서 탐지된다. "
        "정확한 상한은 비탐지라는 V06 계약과 어긋난다. 수정 시 이 마커를 제거한다."
    ),
)
def test_review_finding_exact_rational_boundary_is_not_detected():
    device_policy = DevicePolicyRevision(
        device_id="esp32_01", revision=1, effective_from=utc(0),
        publish_count_max=15, payload_size_max=5120,
        packet_rate_max=12.5, byte_rate_max=2500.0,
    )
    row = {
        "peer_ip": "192.168.0.4", "packet_count": 115, "total_bytes": 1000,
        "captured_duration_seconds": 9.2, "distinct_dest_port_count": 1,
        "tcp_syn_count": 1, "mqtt_related_packet_count": 8,
    }
    assert detect_packet_rules(row, GLOBAL_POLICY, device_policy=device_policy) == []
