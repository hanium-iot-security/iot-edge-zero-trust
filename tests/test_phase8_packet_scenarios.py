"""P8-10 검토: Packet 공격/회귀 시나리오의 기대 탐지·Trust·차단 결과.

실기기 시험의 기대값을 같은 계약으로 로컬에서 먼저 고정한다.
각 시나리오는 Packet Feature(·MQTT Feature) → Packet Rule·MQTT Feature Rule Stage → Trust v2
→ Firewall 요청까지 실제 코드 경로를 통과시키고, 기대 결과(Event·대표 감점·이력·격리·차단
요청)를 대조한다. Packet IF 모델 추론만은 결과 Event 형태의 Fixture로 대신한다(S8).
마지막으로 ``edge.scenarios.packet_review_report``가 정상 결과는 통과시키고, 계약 위반을
FAIL로 잡는지 확인한다.

시나리오 ↔ 세부계획:
- S1 같은 Window MQTT 과다 + Packet Rate + Byte Rate → FLOODING 대표 −20 한 건 (P8-10, 5.3)
- S2 같은 계열 Broker DoS → 대표 −25 (5.3)
- S3 SCAN + FLOODING 동시 → −30 cap, score < 30 격리·TCP 1883 DROP 요청 (V12)
- S4 서로 다른 Window 반복 → 누적 (5.3)
- S5 PENDING 기기의 공격 → 탐지 기록·감점/차단 제외, 활성화 후 비소급 (V08)
- S6 비활성화 예약 접수 후 → 새 감점·차단 제외 (V09, 5.2)
- S7 DISABLED 구간의 Packet 이상 → 기록하되 감점·차단 제외 (5.1)
- S8 AI observe + 같은 Window Rule → Rule 대표만 반영, AI는 무감점 관찰 (V23)
- S3 후속: 격리된 기기의 다음 Window 공격 → 중복 차단 요청 없음
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.scenarios.packet_review_report import (
    build_packet_review,
    main as review_main,
    open_readonly_session,
)
from tests.packet_review_support import (
    add_revision,
    ai_packet_event,
    capture_session,
    events,
    iso,
    mqtt_feature_row,
    packet_row,
    register_device,
    run_mqtt_feature_rule,
    run_packet_rule,
    run_trust,
    scalar,
    utc,
)


ATTACKER = ("esp32_02", "192.168.0.5")
CONTROL = ("esp32_01", "192.168.0.4")


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "sunwoo-packet-scenarios.db"
    apply_migrations(path, MIGRATIONS_DIR)
    return path


@pytest.fixture
def session_factory(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    try:
        yield sessionmaker(bind=engine, autoflush=False)
    finally:
        engine.dispose()


def _two_devices(db, *, attacker_score: int = 100, attacker_state: str = "ACTIVE") -> int:
    register_device(db, device_id=CONTROL[0], ip=CONTROL[1])
    register_device(db, device_id=ATTACKER[0], ip=ATTACKER[1], state=attacker_state,
                    trust_score=attacker_score,
                    status="normal" if attacker_score >= 80 else "warning"
                    if attacker_score >= 60 else "danger")
    pk = capture_session(db)
    # 제어 기기 정상 통신: 0.8 pps, 100 B/s.
    for window in (0, 10, 20):
        packet_row(db, session_pk=pk, peer_ip=CONTROL[1], window=window,
                   packet_count=8, total_bytes=1000)
    return pk


def _flood(db, pk: int, *, window: int = 0, **overrides) -> int:
    values = dict(packet_count=160, total_bytes=30_000)  # 16 pps, 3000 B/s
    values.update(overrides)
    return packet_row(db, session_pk=pk, peer_ip=ATTACKER[1], window=window, **values)


def _device(session_factory, device_id: str) -> tuple[int, str]:
    with session_factory() as db:
        row = db.execute(text(
            "SELECT trust_score, status FROM devices WHERE device_id=:d"
        ), {"d": device_id}).one()
    return int(row[0]), str(row[1])


def _history(session_factory) -> list[dict]:
    with session_factory() as db:
        return [dict(row) for row in db.execute(text(
            """
            SELECT device_id, analysis_window_start, previous_score, calculated_delta,
                   capped_delta, new_score, representative_event_ids_json
            FROM trust_score_history ORDER BY id
            """
        )).mappings()]


def _review(session_factory, **filters):
    with session_factory() as db:
        return build_packet_review(db, window_from=utc(0), window_to=utc(60), **filters)


# --- S1~S4: 대표 감점·cap·격리·누적 ----------------------------------------------


def test_s1_same_window_mqtt_packet_byte_flooding_applies_single_minus_20(session_factory):
    with session_factory() as db:
        pk = _two_devices(db)
        _flood(db, pk)
        mqtt_feature_row(db, device_id=ATTACKER[0], publish_count=40)
        db.commit()

    run_mqtt_feature_rule(session_factory)
    run_packet_rule(session_factory)
    run_trust(session_factory)

    rows = [row for row in events(session_factory) if row["device_id"] == ATTACKER[0]]
    assert sorted(row["event_type"] for row in rows) == [
        "ABNORMAL_PUBLISH_RATE", "BYTE_RATE_ANOMALY", "PACKET_RATE_ANOMALY",
    ]
    assert all(row["incident_family"] == "FLOODING" for row in rows)
    assert sum(row["applied_to_score"] for row in rows) == 1
    assert sorted(row["processing_reason"] for row in rows) == [
        "APPLIED_TO_TRUST", "NOT_REPRESENTATIVE", "NOT_REPRESENTATIVE",
    ]
    history = _history(session_factory)
    assert [(h["device_id"], h["previous_score"], h["calculated_delta"], h["new_score"])
            for h in history] == [(ATTACKER[0], 100, -20, 80)]
    assert _device(session_factory, ATTACKER[0]) == (80, "normal")
    assert _device(session_factory, CONTROL[0]) == (100, "normal")
    assert scalar(session_factory, "SELECT COUNT(*) FROM firewall_rules") == 0

    # 대표 Event가 셋 중 무엇인지는 동점 tie-break(구현 세부)이므로 고정하지 않는다.
    representative = json.loads(history[0]["representative_event_ids_json"])
    assert len(representative) == 1
    assert representative[0] in {row["id"] for row in rows}

    report = _review(session_factory)
    assert report.fail_count == 0, report.findings
    assert len(report.trust_history) == 1


def test_s2_broker_dos_in_same_family_becomes_minus_25_representative(session_factory):
    with session_factory() as db:
        pk = _two_devices(db)
        _flood(db, pk, tcp_syn_count=40, mqtt_related_packet_count=150)
        db.commit()

    run_packet_rule(session_factory)
    run_trust(session_factory)

    rows = {row["event_type"]: row for row in events(session_factory)
            if row["device_id"] == ATTACKER[0]}
    assert set(rows) == {"PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY", "BROKER_DOS_SUSPECTED"}
    assert rows["BROKER_DOS_SUSPECTED"]["applied_to_score"] == 1
    assert _history(session_factory)[0]["calculated_delta"] == -25
    assert _device(session_factory, ATTACKER[0]) == (75, "warning")
    assert _review(session_factory).fail_count == 0


def test_s3_scan_plus_flooding_is_capped_and_isolates_with_tcp_1883_drop(session_factory):
    with session_factory() as db:
        pk = _two_devices(db, attacker_score=50)
        _flood(db, pk, distinct_dest_port_count=8, tcp_syn_count=40,
               mqtt_related_packet_count=150)
        db.commit()

    run_packet_rule(session_factory)
    trust = run_trust(session_factory)

    history = _history(session_factory)
    assert [(h["calculated_delta"], h["capped_delta"], h["new_score"]) for h in history] == [
        (-45, -30, 20),
    ]
    representatives = json.loads(history[0]["representative_event_ids_json"])
    by_id = {row["id"]: row for row in events(session_factory)}
    assert sorted(by_id[i]["event_type"] for i in representatives) == [
        "BROKER_DOS_SUSPECTED", "PORT_SCAN",
    ]
    assert _device(session_factory, ATTACKER[0]) == (20, "isolated")
    assert trust.created_isolation_count == 1
    with session_factory() as db:
        rule = db.execute(text(
            """
            SELECT device_id, source_ip, protocol, dest_port, action, status,
                   trigger_event_id
            FROM firewall_rules
            """
        )).mappings().one()
    assert (rule["device_id"], rule["source_ip"]) == ATTACKER
    assert (rule["protocol"], rule["dest_port"], rule["action"]) == ("tcp", 1883, "DROP")
    assert rule["status"] == "PENDING"
    assert rule["trigger_event_id"] in representatives
    assert _device(session_factory, CONTROL[0]) == (100, "normal")

    report = _review(session_factory, device_id=ATTACKER[0])
    assert report.fail_count == 0, report.findings
    assert report.summary()["firewall_rule_count"] == 1

    # 격리 후 다음 Window의 공격: Event는 남지만 추가 감점·중복 차단 요청은 없다.
    with session_factory() as db:
        _flood(db, 1, window=10, distinct_dest_port_count=8, tcp_syn_count=40,
               mqtt_related_packet_count=150)
        db.commit()
    run_packet_rule(session_factory, start=10, end=20)
    run_trust(session_factory, start=10, end=20)
    later = [row for row in events(session_factory)
             if row["device_id"] == ATTACKER[0] and row["analysis_window_start"] == iso(10)]
    assert later and all(row["processing_reason"] == "ALREADY_ISOLATED" for row in later)
    assert _device(session_factory, ATTACKER[0]) == (20, "isolated")
    assert scalar(session_factory, "SELECT COUNT(*) FROM firewall_rules") == 1
    assert scalar(session_factory, "SELECT COUNT(*) FROM isolation_history") == 1


def test_s4_flooding_in_different_windows_accumulates(session_factory):
    with session_factory() as db:
        pk = _two_devices(db)
        _flood(db, pk, window=0)
        _flood(db, pk, window=10)
        db.commit()

    run_packet_rule(session_factory, start=0, end=10)
    run_trust(session_factory, start=0, end=10)
    run_packet_rule(session_factory, start=10, end=20)
    run_trust(session_factory, start=10, end=20)

    assert [(h["analysis_window_start"], h["new_score"]) for h in _history(session_factory)] == [
        (iso(0), 80), (iso(10), 60),
    ]
    # 같은 Window 재실행으로 중복 감점되지 않는다.
    run_packet_rule(session_factory, start=10, end=20)
    run_trust(session_factory, start=10, end=20)
    assert _device(session_factory, ATTACKER[0]) == (60, "warning")
    assert len(_history(session_factory)) == 2
    assert _review(session_factory).fail_count == 0


# --- S5~S6: 등록 상태 보호 --------------------------------------------------------


def test_s5_pending_device_attack_is_recorded_but_never_scored_even_after_activation(
    session_factory,
):
    with session_factory() as db:
        pk = _two_devices(db, attacker_score=40, attacker_state="PENDING")
        _flood(db, pk, distinct_dest_port_count=8, tcp_syn_count=40,
               mqtt_related_packet_count=150)
        add_revision(db, device_id=ATTACKER[0], revision=2, state="ACTIVE", effective=20)
        db.commit()

    run_packet_rule(session_factory)
    run_trust(session_factory)
    run_packet_rule(session_factory, start=10, end=30)
    run_trust(session_factory, start=10, end=30)

    rows = [row for row in events(session_factory) if row["device_id"] == ATTACKER[0]]
    assert {row["event_type"] for row in rows} == {
        "PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY", "PORT_SCAN", "BROKER_DOS_SUSPECTED",
    }
    assert all(row["processing_reason"] == "PENDING_AT_WINDOW" for row in rows)
    assert all(row["applied_to_score"] == 0 and row["processed_at"] for row in rows)
    # 탐지 이벤트의 후보 감점은 보존된다(실제 반영 결과와 구분).
    assert {row["score_delta"] for row in rows} >= {-20, -25}
    assert _device(session_factory, ATTACKER[0])[0] == 40
    assert _history(session_factory) == []
    assert scalar(session_factory, "SELECT COUNT(*) FROM firewall_rules") == 0
    assert scalar(session_factory, "SELECT COUNT(*) FROM isolation_history") == 0
    assert _review(session_factory).fail_count == 0


def test_s6_disable_request_stops_new_penalty_and_block_before_effective_time(
    session_factory,
):
    with session_factory() as db:
        pk = _two_devices(db, attacker_score=40)
        _flood(db, pk, distinct_dest_port_count=8, tcp_syn_count=8)
        # 00:00:05에 접수, 다음 경계가 아닌 00:00:30 효력의 비활성화 예약.
        add_revision(db, device_id=ATTACKER[0], revision=2, state="DISABLED",
                     effective=30, created="2026-10-06T01:00:05Z")
        db.commit()

    run_packet_rule(session_factory)
    run_trust(session_factory, decision=10)

    rows = [row for row in events(session_factory) if row["device_id"] == ATTACKER[0]]
    assert rows and all(
        row["processing_reason"] == "DISABLE_REQUESTED_OR_DISABLED" for row in rows
    )
    assert _device(session_factory, ATTACKER[0])[0] == 40
    assert scalar(session_factory, "SELECT COUNT(*) FROM firewall_rules") == 0
    assert _review(session_factory).fail_count == 0


def test_s7_disabled_window_packet_anomaly_is_recorded_without_response(session_factory):
    with session_factory() as db:
        pk = _two_devices(db, attacker_score=40)
        add_revision(db, device_id=ATTACKER[0], revision=2, state="DISABLED", effective=10)
        _flood(db, pk, window=10, distinct_dest_port_count=8, tcp_syn_count=8)
        db.commit()

    run_packet_rule(session_factory, start=0, end=20)
    run_trust(session_factory, start=0, end=20)

    rows = [row for row in events(session_factory) if row["device_id"] == ATTACKER[0]]
    # DISABLED 기기도 UNKNOWN이 아니라 같은 기기 통신으로 기록된다(5.1).
    assert {row["event_type"] for row in rows} == {
        "PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY", "PORT_SCAN",
    }
    assert all(row["processing_reason"] == "DISABLED_AT_WINDOW" for row in rows)
    assert all(row["applied_to_score"] == 0 and row["processed_at"] for row in rows)
    assert _device(session_factory, ATTACKER[0])[0] == 40
    assert scalar(session_factory, "SELECT COUNT(*) FROM firewall_rules") == 0
    assert _review(session_factory).fail_count == 0


@pytest.mark.parametrize("ai_mode", ["observe", "enforce"])
def test_s8_rule_representative_wins_and_ai_is_not_added_in_same_window(
    session_factory, ai_mode,
):
    with session_factory() as db:
        pk = _two_devices(db)
        _flood(db, pk)
        ai_id = ai_packet_event(db, device_id=ATTACKER[0])
        db.commit()

    run_packet_rule(session_factory)
    run_trust(session_factory, ai_mode=ai_mode)

    history = _history(session_factory)
    assert [(h["calculated_delta"], h["new_score"]) for h in history] == [(-20, 80)]
    ai_event = next(row for row in events(session_factory) if row["id"] == ai_id)
    assert ai_event["applied_to_score"] == 0
    if ai_mode == "observe":
        assert ai_event["processing_reason"] == "AI_OBSERVATION_ONLY"
        assert ai_event["score_delta"] == 0
    else:
        assert ai_event["processing_reason"] == "NOT_REPRESENTATIVE"
    assert _review(session_factory).fail_count == 0


# --- 검토 도구 자체 검증 ------------------------------------------------------------


def _scenario_s3(session_factory) -> None:
    with session_factory() as db:
        pk = _two_devices(db, attacker_score=50)
        _flood(db, pk, distinct_dest_port_count=8, tcp_syn_count=40,
               mqtt_related_packet_count=150)
        db.commit()
    run_packet_rule(session_factory)
    run_trust(session_factory)


def test_review_tool_flags_threshold_not_matching_revision(session_factory):
    _scenario_s3(session_factory)
    with session_factory() as db:
        event_id, evidence = db.execute(text(
            """
            SELECT id, evidence_json FROM detection_events
            WHERE event_type='PACKET_RATE_ANOMALY'
            """
        )).one()
        evidence = json.loads(evidence)
        evidence["threshold"] = 10.0 if evidence["threshold"] != 10.0 else 9.0
        db.execute(text("UPDATE detection_events SET evidence_json=:e WHERE id=:i"),
                   {"e": json.dumps(evidence), "i": event_id})
        db.commit()

    report = _review(session_factory)
    assert {(f.check, f.event_id) for f in report.findings if f.level == "FAIL"} == {
        ("POLICY_REVISION", event_id),
    }


def test_review_tool_flags_recompute_mismatch_and_wrong_unit(session_factory):
    _scenario_s3(session_factory)
    with session_factory() as db:
        event_id, evidence = db.execute(text(
            "SELECT id, evidence_json FROM detection_events WHERE event_type='BYTE_RATE_ANOMALY'"
        )).one()
        evidence = json.loads(evidence)
        evidence["observed_value"] = evidence["observed_value"] * 8  # bit/s 혼동
        evidence["unit"] = "bits/second"
        db.execute(text("UPDATE detection_events SET evidence_json=:e WHERE id=:i"),
                   {"e": json.dumps(evidence), "i": event_id})
        db.commit()

    checks = {f.check for f in _review(session_factory).findings if f.level == "FAIL"}
    assert checks == {"RATE_RECOMPUTE", "RATE_UNIT"}


def test_review_tool_flags_pending_applied_cap_violation_and_double_family(
    session_factory,
):
    """DB UNIQUE가 같은 Window 이력 중복은 막으므로, 내용 위반(cap·계열 중복·PENDING 반영)을 확인."""
    with session_factory() as db:
        pk = _two_devices(db, attacker_state="PENDING")
        _flood(db, pk)
        db.commit()
    run_packet_rule(session_factory)
    run_trust(session_factory)
    with session_factory() as db:
        ids = list(db.execute(text(
            """
            SELECT id FROM detection_events
            WHERE event_type IN ('PACKET_RATE_ANOMALY', 'BYTE_RATE_ANOMALY') ORDER BY id
            """
        )).scalars())
        db.execute(text("UPDATE detection_events SET applied_to_score=1 WHERE id=:i"),
                   {"i": ids[0]})
        db.execute(text(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end, previous_score,
                calculated_delta, capped_delta, actual_delta, new_score,
                representative_event_ids_json, policy_version
            ) VALUES (:d, :s, :e, 100, -40, -40, -40, 60, :rep, 'tampered')
            """
        ), {"d": ATTACKER[0], "s": iso(0), "e": iso(10), "rep": json.dumps(ids)})
        db.commit()

    fails = [(f.check, f.event_id) for f in _review(session_factory).findings
             if f.level == "FAIL"]
    assert {check for check, _ in fails} == {
        "RESPONSE_GATE", "WINDOW_HISTORY", "FAMILY_REPRESENTATIVE",
    }
    # 반영된 PENDING Event와, PENDING 기기의 감점 이력 둘 다 잡는다.
    assert ("RESPONSE_GATE", ids[0]) in fails
    assert ("RESPONSE_GATE", None) in fails


def test_review_tool_flags_score_applied_after_disable_request(session_factory):
    """비활성화 예약 접수 후 처리된 Event가 점수에 반영됐다면 FAIL(5.2)."""
    with session_factory() as db:
        pk = _two_devices(db)
        _flood(db, pk)
        add_revision(db, device_id=ATTACKER[0], revision=2, state="DISABLED",
                     effective=30, created="2026-10-06T01:00:05Z")
        db.commit()
    run_packet_rule(session_factory)
    run_trust(session_factory, decision=10)
    with session_factory() as db:
        event_id = db.execute(text(
            "SELECT id FROM detection_events WHERE event_type='PACKET_RATE_ANOMALY'"
        )).scalar_one()
        db.execute(text("UPDATE detection_events SET applied_to_score=1 WHERE id=:i"),
                   {"i": event_id})
        db.commit()

    fails = [(f.check, f.event_id, f.message) for f in _review(session_factory).findings
             if f.level == "FAIL"]
    assert [(check, event) for check, event, _ in fails] == [("RESPONSE_GATE", event_id)]
    assert "DISABLE_REQUESTED_OR_DISABLED" in fails[0][2]


def test_review_tool_links_firewall_rule_when_mqtt_event_is_isolation_trigger(
    session_factory,
):
    """격리 대표가 MQTT Event여도 차단 요청을 리포트에 포함하고 ISOLATION_LINK를 통과시킨다."""
    with session_factory() as db:
        pk = _two_devices(db, attacker_score=35)
        _flood(db, pk)
        mqtt_feature_row(db, device_id=ATTACKER[0], publish_count=40)
        db.commit()
    run_mqtt_feature_rule(session_factory)
    run_packet_rule(session_factory)
    run_trust(session_factory)

    with session_factory() as db:
        trigger_type = db.execute(text(
            """
            SELECT e.event_type FROM firewall_rules f
            JOIN detection_events e ON e.id = f.trigger_event_id
            """
        )).scalar_one()
    report = _review(session_factory, device_id=ATTACKER[0])
    assert trigger_type in {"ABNORMAL_PUBLISH_RATE", "PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY"}
    assert report.summary()["firewall_rule_count"] == 1
    assert report.fail_count == 0, report.findings


def _backup_copy(source: Path, destination: Path) -> Path:
    """실제 운영 절차처럼 SQLite Backup API로 단독 복사본을 만든다(WAL 아님)."""
    with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(destination)) as dst:
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
    return destination


def _file_hashes(path: Path) -> dict[str, str]:
    return {
        candidate.name: hashlib.sha256(candidate.read_bytes()).hexdigest()
        for candidate in path.parent.iterdir()
        if candidate.name.startswith(path.name)
    }


def test_review_cli_is_read_only_and_writes_json(db_path: Path, session_factory, tmp_path):
    _scenario_s3(session_factory)
    session_factory.kw["bind"].dispose()
    copy_dir = tmp_path / "review-copy"
    copy_dir.mkdir()
    copy = _backup_copy(db_path, copy_dir / "review-copy.db")
    before = _file_hashes(copy)
    out = tmp_path / "review" / "packet-review.json"

    code = review_main([
        "--db", str(copy), "--from", iso(0), "--to", iso(60),
        "--device-id", ATTACKER[0], "--json-out", str(out),
    ])

    assert code == 0
    # 복사본과 보조 파일(-journal/-wal/-shm)이 하나도 생기거나 바뀌지 않는다.
    assert _file_hashes(copy) == before
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["summary"]["fail_count"] == 0
    assert payload["summary"]["firewall_rule_count"] == 1
    assert payload["summary"]["packet_event_count_by_type"] == {
        "BROKER_DOS_SUSPECTED": 1, "BYTE_RATE_ANOMALY": 1,
        "PACKET_RATE_ANOMALY": 1, "PORT_SCAN": 1,
    }


def test_review_session_rejects_writes(db_path: Path, session_factory, tmp_path):
    _scenario_s3(session_factory)
    session_factory.kw["bind"].dispose()
    copy = _backup_copy(db_path, tmp_path / "write-probe.db")
    db = open_readonly_session(copy)
    try:
        with pytest.raises(OperationalError, match="readonly"):
            db.execute(text("UPDATE devices SET trust_score = 0"))
    finally:
        db.close()
    with closing(sqlite3.connect(copy)) as check:
        assert check.execute(
            "SELECT trust_score FROM devices WHERE device_id=?", (ATTACKER[0],)
        ).fetchone() == (20,)


def test_review_cli_returns_2_for_missing_db(tmp_path):
    assert review_main([
        "--db", str(tmp_path / "missing.db"), "--from", iso(0), "--to", iso(10),
    ]) == 2


def test_review_tool_warns_on_float_equal_boundary_detection(session_factory):
    """SW-P8-01 재현: 수학적으로 상한과 같은 관측값이 탐지되면 검토 도구가 WARN으로 드러낸다."""
    with session_factory() as db:
        register_device(db, device_id=ATTACKER[0], ip=ATTACKER[1],
                        packet_max=12.5, byte_max=2500.0)
        pk = capture_session(db)
        packet_row(db, session_pk=pk, peer_ip=ATTACKER[1], packet_count=115,
                   total_bytes=1000, duration=9.2)
        db.commit()
    run_packet_rule(session_factory)

    report = _review(session_factory)
    warnings = [(f.check, f.level) for f in report.findings if f.check == "RATE_RECOMPUTE"]
    assert warnings == [("RATE_RECOMPUTE", "WARN")]
    assert report.fail_count == 0
