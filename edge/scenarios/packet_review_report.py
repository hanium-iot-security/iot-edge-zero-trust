"""Phase 8 Packet Rule·Trust·차단 결과 검토 리포트 (P8-05/P8-10 검토 지원).

공격/회귀 시험이 끝난 **복사 DB**를 읽기 전용으로 열어, 지정한 UTC 구간의
Packet Rule Event가 Phase 8 계약대로 판정·반영됐는지 대조한다.
``compare_events.py``가 Event Type 일치만 확인하는 스팟체크라면, 이 도구는
"왜 그 판정이 나왔는가"를 Evidence·정책 revision·Trust 이력과 맞춰 본다.

검사 항목(ID는 리포트의 ``check`` 값과 같다):

- ``RATE_RECOMPUTE``: Packet/Byte Rate Event의 관측값이 Evidence의 원시 수
  ÷ ``captured_duration_seconds``로 재계산한 값과 같고 임계값을 **초과**(``>``)한다.
- ``RATE_UNIT``: 단위가 ``packets/second``·``bytes/second``다(bit/s·10초 총량 혼동 방지).
- ``POLICY_REVISION``: Evidence의 ``device_policy_revision``이 ``window_start`` 당시
  유효 revision과 같고, 임계값이 그 revision의 저장값과 같다. 등록 기기가 당시 정책을
  가졌는데 전역 기본값으로 판정된 경우도 잡는다.
- ``RESPONSE_GATE``: 점수에 반영된 Event와 Trust 이력이 당시 ACTIVE 기기의 것이다
  (PENDING·DISABLED·미등록·정책 누락 구간은 반영 금지). 처리 시점에 비활성화 예약이
  접수돼 있었다면 반영 금지(5.2)도 함께 본다.
- ``WINDOW_HISTORY``: 같은 기기·같은 10초 Window의 Trust 이력은 최대 1건이고
  ``capped_delta``가 −30 미만이 아니다.
- ``FAMILY_REPRESENTATIVE``: Trust 이력의 대표 Event에 같은 Incident Family가
  두 건 이상 없다(FLOODING 대표 −20/−25 계약).
- ``ISOLATION_LINK``: 이 구간 Event(MQTT 대표 포함)로 생성된 Firewall 요청은
  ``new_score < 30``인 Trust 이력의 대표 Event에서만 생긴다.

DB를 수정하지 않는다(SQLite ``mode=ro``). 운영 DB가 아닌 일관 백업 복사본에서 실행한다.

사용 예::

    python -m edge.scenarios.packet_review_report \
        --db /path/to/copy.db \
        --from 2026-10-06T01:00:00Z --to 2026-10-06T01:10:00Z \
        --device-id esp32_02 --json-out output/review/packet-review.json

종료 코드: 0 = FAIL 없음, 1 = FAIL 존재, 2 = 입력/DB 오류.
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from edge.detection.phase4_time import format_db_utc, parse_db_utc
from edge.policy.repository import load_policy_resolver
from edge.policy.resolver import POLICY_AVAILABLE, DevicePolicyResolver, PolicyResolution
from edge.trust.trust_policy import (
    BROKER_DOS_SUSPECTED,
    BYTE_RATE_ANOMALY,
    PACKET_RATE_ANOMALY,
    PORT_SCAN,
    incident_family_for_event,
)


PACKET_RULE_EVENT_TYPES = frozenset(
    {PACKET_RATE_ANOMALY, BYTE_RATE_ANOMALY, PORT_SCAN, BROKER_DOS_SUSPECTED}
)
RATE_UNITS = {
    PACKET_RATE_ANOMALY: ("packets/second", "packet_count", "packet_rate_max_pps"),
    BYTE_RATE_ANOMALY: ("bytes/second", "total_bytes", "byte_rate_max_bytes_per_second"),
}
WINDOW_DELTA_CAP = -30
ISOLATION_THRESHOLD = 30
FAIL = "FAIL"
WARN = "WARN"
_REL_TOLERANCE = 1e-9


@dataclass
class ReviewFinding:
    level: str
    check: str
    message: str
    event_id: int | None = None
    device_id: str | None = None
    window_start: str | None = None


@dataclass
class PacketReviewReport:
    window_from: str
    window_to: str
    device_id_filter: str | None
    subject_ip_filter: str | None
    policy_schema: bool
    events: list[dict[str, Any]] = field(default_factory=list)
    trust_history: list[dict[str, Any]] = field(default_factory=list)
    firewall_rules: list[dict[str, Any]] = field(default_factory=list)
    findings: list[ReviewFinding] = field(default_factory=list)

    @property
    def fail_count(self) -> int:
        return sum(1 for finding in self.findings if finding.level == FAIL)

    @property
    def warn_count(self) -> int:
        return sum(1 for finding in self.findings if finding.level == WARN)

    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        applied = 0
        for event in self.events:
            by_type[str(event["event_type"])] += 1
            applied += int(event["applied_to_score"] == 1)
        return {
            "packet_event_count": len(self.events),
            "packet_event_count_by_type": dict(sorted(by_type.items())),
            "applied_to_score_count": applied,
            "trust_history_count": len(self.trust_history),
            "firewall_rule_count": len(self.firewall_rules),
            "fail_count": self.fail_count,
            "warn_count": self.warn_count,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["summary"] = self.summary()
        return payload


def build_packet_review(
    db: Session,
    *,
    window_from: datetime,
    window_to: datetime,
    device_id: str | None = None,
    subject_ip: str | None = None,
) -> PacketReviewReport:
    """``[window_from, window_to)`` 안에서 시작한 분석 Window를 검토한다."""
    if window_from >= window_to:
        raise ValueError("window_from must be before window_to")
    resolver = load_policy_resolver(db)
    report = PacketReviewReport(
        window_from=format_db_utc(window_from),
        window_to=format_db_utc(window_to),
        device_id_filter=device_id,
        subject_ip_filter=subject_ip,
        policy_schema=resolver is not None,
    )

    all_events = _fetch_events_in_range(db, window_from, window_to)
    events_by_id = {int(event["id"]): event for event in all_events}
    packet_events = [
        event for event in all_events
        if str(event["event_type"]) in PACKET_RULE_EVENT_TYPES
        and (device_id is None or event["device_id"] == device_id)
        and (subject_ip is None or event["subject_ip"] == subject_ip)
    ]
    revisions = _fetch_policy_revisions(db) if resolver is not None else {}

    for event in packet_events:
        evidence = _load_evidence(event, report)
        report.events.append(_event_row(event, evidence))
        if evidence is None:
            continue
        if str(event["event_type"]) in RATE_UNITS:
            _check_rate_event(report, event, evidence)
        if resolver is not None:
            _check_policy_revision(report, resolver, revisions, event, evidence)
            _check_response_gate(report, resolver, event)
        elif event["device_id"] is None and event["applied_to_score"] == 1:
            _add(report, FAIL, "RESPONSE_GATE", event,
                 "미등록(device_id 없음) Event가 점수에 반영됨")

    device_ids = {str(e["device_id"]) for e in packet_events if e["device_id"]}
    if device_id is not None:
        device_ids.add(device_id)
    histories = _fetch_trust_history(db, window_from, window_to, device_ids)
    report.trust_history = [dict(row) for row in histories]
    _check_window_history(report, histories, events_by_id)

    if resolver is not None:
        _check_history_gate(report, resolver, histories)

    # 격리 대표가 MQTT Event일 수도 있으므로 구간 안 모든 Event를 차단 요청 후보로 본다.
    trigger_ids = sorted(
        int(e["id"]) for e in all_events
        if (device_id is None or e["device_id"] == device_id)
        and (subject_ip is None or e["subject_ip"] == subject_ip)
    )
    rules = _fetch_firewall_rules(db, trigger_ids)
    report.firewall_rules = [dict(row) for row in rules]
    _check_isolation_link(report, rules, histories)

    unprocessed = [e for e in packet_events if e["processed_at"] is None]
    if unprocessed:
        _add(report, WARN, "UNPROCESSED", None,
             f"Trust 미처리 Packet Event {len(unprocessed)}건: "
             + ", ".join(str(e["id"]) for e in unprocessed[:20]))
    return report


# --- 검사 -----------------------------------------------------------------


def _check_rate_event(
    report: PacketReviewReport, event: dict[str, Any], evidence: dict[str, Any]
) -> None:
    event_type = str(event["event_type"])
    unit, count_key, _ = RATE_UNITS[event_type]
    if evidence.get("unit") != unit:
        _add(report, FAIL, "RATE_UNIT", event,
             f"unit={evidence.get('unit')!r}, 기대값={unit!r}")

    observed = _finite(evidence.get("observed_value"))
    threshold = _finite(evidence.get("threshold"))
    duration = _finite(evidence.get("captured_duration_seconds"))
    raw_count = _finite((evidence.get("raw_counts") or {}).get(count_key))
    if None in (observed, threshold, duration, raw_count) or duration <= 0:
        _add(report, FAIL, "RATE_RECOMPUTE", event,
             "관측값·임계값·captured_duration_seconds·원시 수 중 누락/비정상 값이 있음")
        return
    recomputed = raw_count / duration
    if not math.isclose(observed, recomputed, rel_tol=_REL_TOLERANCE, abs_tol=1e-12):
        _add(report, FAIL, "RATE_RECOMPUTE", event,
             f"observed={observed} ≠ {count_key}/duration={recomputed}")
    if not observed > threshold:
        _add(report, FAIL, "RATE_RECOMPUTE", event,
             f"observed={observed}가 threshold={threshold}를 초과하지 않는데 탐지됨")
    elif math.isclose(observed, threshold, rel_tol=_REL_TOLERANCE, abs_tol=1e-12):
        # 수학적으로 같은 값이 부동소수점 나눗셈 오차로 1ulp 초과한 경우.
        _add(report, WARN, "RATE_RECOMPUTE", event,
             f"observed={observed!r}와 threshold={threshold!r}가 부동소수점 오차 범위에서 같음"
             " (정확한 상한 경계 비탐지 계약 위반 가능)")


def _check_policy_revision(
    report: PacketReviewReport,
    resolver: DevicePolicyResolver,
    revisions: dict[tuple[str, int], dict[str, Any]],
    event: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    device_id = event["device_id"]
    window_start = _event_window_start(event)
    if window_start is None:
        _add(report, FAIL, "POLICY_REVISION", event, "analysis_window_start 없음")
        return
    evidence_revision = evidence.get("device_policy_revision")
    if device_id is None:
        if evidence_revision is not None:
            _add(report, FAIL, "POLICY_REVISION", event,
                 f"미등록 Event에 device_policy_revision={evidence_revision}가 기록됨")
        return

    resolution = _resolve(report, resolver, event, str(device_id), window_start)
    if resolution is None:
        return
    expected_revision = (
        resolution.policy.revision
        if resolution.reason == POLICY_AVAILABLE and resolution.policy is not None
        else None
    )
    if evidence_revision != expected_revision:
        _add(report, FAIL, "POLICY_REVISION", event,
             f"Evidence revision={evidence_revision}, window_start 당시 유효 revision="
             f"{expected_revision} (resolver reason={resolution.reason})")
        return
    if expected_revision is None or str(event["event_type"]) not in RATE_UNITS:
        return
    stored = revisions.get((str(device_id), int(expected_revision)))
    _, _, column = RATE_UNITS[str(event["event_type"])]
    threshold = _finite(evidence.get("threshold"))
    if stored is None or threshold is None or not math.isclose(
        threshold, float(stored[column]), rel_tol=_REL_TOLERANCE, abs_tol=1e-12
    ):
        _add(report, FAIL, "POLICY_REVISION", event,
             f"Evidence threshold={evidence.get('threshold')}가 revision "
             f"{expected_revision}의 {column}="
             f"{None if stored is None else stored[column]}와 다름")


def _check_response_gate(
    report: PacketReviewReport,
    resolver: DevicePolicyResolver,
    event: dict[str, Any],
) -> None:
    if event["applied_to_score"] != 1:
        return
    device_id = event["device_id"]
    window_start = _event_window_start(event)
    if device_id is None or window_start is None:
        _add(report, FAIL, "RESPONSE_GATE", event,
             "기기 귀속·Window가 없는 Event가 점수에 반영됨")
        return
    resolution = _resolve(report, resolver, event, str(device_id), window_start)
    if resolution is None:
        return
    status = resolution.registration.status if resolution.registration else None
    if status != "ACTIVE" or resolution.reason != POLICY_AVAILABLE:
        _add(report, FAIL, "RESPONSE_GATE", event,
             f"당시 등록 상태={status}, 정책={resolution.reason}인데 점수에 반영됨")
        return
    processed_at = event.get("processed_at")
    if processed_at:
        exclusion = resolver.automatic_response_exclusion(
            str(device_id), parse_db_utc(processed_at, "processed_at", allow_subseconds=True)
        )
        if exclusion is not None:
            _add(report, FAIL, "RESPONSE_GATE", event,
                 f"처리 시점 자동 대응 제외 사유={exclusion}인데 점수에 반영됨")


def _check_history_gate(
    report: PacketReviewReport,
    resolver: DevicePolicyResolver,
    histories: list[dict[str, Any]],
) -> None:
    """대표가 MQTT Event인 경우까지 포함해, 감점 이력 자체가 당시 ACTIVE 기기의 것인지 본다."""
    for history in histories:
        window = parse_db_utc(history["analysis_window_start"], "analysis_window_start")
        try:
            resolution = resolver.resolve(str(history["device_id"]), window)
        except ValueError as exc:
            _add_raw(report, FAIL, "RESPONSE_GATE",
                     f"history {history['id']} Window 해석 불가: {exc}",
                     device_id=str(history["device_id"]), window_start=format_db_utc(window))
            continue
        status = resolution.registration.status if resolution.registration else None
        if status != "ACTIVE" or resolution.reason != POLICY_AVAILABLE:
            _add_raw(report, FAIL, "RESPONSE_GATE",
                     f"history {history['id']}: 당시 등록 상태={status}, "
                     f"정책={resolution.reason}인데 감점 이력이 생성됨",
                     device_id=str(history["device_id"]), window_start=format_db_utc(window))


def _check_window_history(
    report: PacketReviewReport,
    histories: list[dict[str, Any]],
    events_by_id: dict[int, dict[str, Any]],
) -> None:
    by_window: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for history in histories:
        window = format_db_utc(parse_db_utc(history["analysis_window_start"]))
        by_window[(str(history["device_id"]), window)].append(history)
        if int(history["capped_delta"]) < WINDOW_DELTA_CAP:
            _add_raw(report, FAIL, "WINDOW_HISTORY",
                     f"history {history['id']} capped_delta={history['capped_delta']} < -30",
                     device_id=str(history["device_id"]), window_start=window)
        try:
            representative_ids = [
                int(value) for value in json.loads(history["representative_event_ids_json"] or "[]")
            ]
        except (TypeError, ValueError):
            _add_raw(report, FAIL, "FAMILY_REPRESENTATIVE",
                     f"history {history['id']} representative_event_ids_json 해석 불가",
                     device_id=str(history["device_id"]), window_start=window)
            continue
        families: dict[str, list[int]] = defaultdict(list)
        for event_id in representative_ids:
            event = events_by_id.get(event_id)
            if event is None:
                continue
            family = event["incident_family"] or incident_family_for_event(str(event["event_type"]))
            families[str(family)].append(event_id)
        for family, ids in families.items():
            if len(ids) > 1:
                _add_raw(report, FAIL, "FAMILY_REPRESENTATIVE",
                         f"history {history['id']}에서 {family} 대표 Event가 {len(ids)}건: {ids}",
                         device_id=str(history["device_id"]), window_start=window)
    for (device_id, window), rows in by_window.items():
        if len(rows) > 1:
            _add_raw(report, FAIL, "WINDOW_HISTORY",
                     f"같은 Window Trust 이력 {len(rows)}건: "
                     + ", ".join(str(row["id"]) for row in rows),
                     device_id=device_id, window_start=window)


def _check_isolation_link(
    report: PacketReviewReport,
    rules: list[dict[str, Any]],
    histories: list[dict[str, Any]],
) -> None:
    isolating: set[int] = set()
    for history in histories:
        if int(history["new_score"]) >= ISOLATION_THRESHOLD:
            continue
        try:
            isolating.update(
                int(value) for value in json.loads(history["representative_event_ids_json"] or "[]")
            )
        except (TypeError, ValueError):
            continue  # FAMILY_REPRESENTATIVE에서 이미 FAIL로 보고된다.
    for rule in rules:
        if int(rule["trigger_event_id"]) not in isolating:
            _add_raw(report, FAIL, "ISOLATION_LINK",
                     f"firewall_rules {rule['id']}의 trigger_event_id={rule['trigger_event_id']}가"
                     " new_score<30 Trust 이력의 대표 Event가 아님",
                     device_id=rule["device_id"])


# --- 조회 -----------------------------------------------------------------


def _fetch_events_in_range(
    db: Session, window_from: datetime, window_to: datetime
) -> list[dict[str, Any]]:
    rows = db.execute(text(
        """
        SELECT id, device_id, detector_type, event_type, severity, score_delta,
               applied_to_score, incident_family, subject_ip, analysis_window_start,
               analysis_window_end, detected_at, processed_at, processing_reason,
               policy_version, evidence_json, packet_feature_log_id
        FROM detection_events
        WHERE analysis_window_start IS NOT NULL
          AND unixepoch(analysis_window_start) >= unixepoch(:window_from)
          AND unixepoch(analysis_window_start) < unixepoch(:window_to)
        ORDER BY analysis_window_start, id
        """
    ), {"window_from": format_db_utc(window_from), "window_to": format_db_utc(window_to)})
    return [dict(row) for row in rows.mappings()]


def _fetch_policy_revisions(db: Session) -> dict[tuple[str, int], dict[str, Any]]:
    rows = db.execute(text(
        """
        SELECT device_id, revision, effective_from, registration_state,
               packet_rate_max_pps, byte_rate_max_bytes_per_second
        FROM device_policy_revisions
        """
    )).mappings()
    return {(str(row["device_id"]), int(row["revision"])): dict(row) for row in rows}


def _fetch_trust_history(
    db: Session, window_from: datetime, window_to: datetime, device_ids: set[str]
) -> list[dict[str, Any]]:
    if not device_ids:
        return []
    params: dict[str, Any] = {
        "window_from": format_db_utc(window_from),
        "window_to": format_db_utc(window_to),
    }
    placeholders = []
    for index, value in enumerate(sorted(device_ids)):
        params[f"d{index}"] = value
        placeholders.append(f":d{index}")
    rows = db.execute(text(
        f"""
        SELECT id, device_id, analysis_window_start, analysis_window_end,
               previous_score, calculated_delta, capped_delta, actual_delta,
               new_score, representative_event_ids_json, policy_version
        FROM trust_score_history
        WHERE device_id IN ({", ".join(placeholders)})
          AND unixepoch(analysis_window_start) >= unixepoch(:window_from)
          AND unixepoch(analysis_window_start) < unixepoch(:window_to)
        ORDER BY analysis_window_start, id
        """
    ), params)
    return [dict(row) for row in rows.mappings()]


def _fetch_firewall_rules(db: Session, trigger_ids: list[int]) -> list[dict[str, Any]]:
    if not trigger_ids:
        return []
    params = {f"e{index}": value for index, value in enumerate(trigger_ids)}
    rows = db.execute(text(
        f"""
        SELECT id, device_id, source_ip, protocol, dest_port, action, status,
               reason, trigger_event_id, created_at
        FROM firewall_rules
        WHERE trigger_event_id IN ({", ".join(':' + key for key in params)})
        ORDER BY id
        """
    ), params)
    return [dict(row) for row in rows.mappings()]


# --- 보조 -----------------------------------------------------------------


def _load_evidence(event: dict[str, Any], report: PacketReviewReport) -> dict[str, Any] | None:
    raw = event.get("evidence_json")
    try:
        evidence = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        evidence = None
    if not isinstance(evidence, dict):
        _add(report, FAIL, "EVIDENCE", event, "evidence_json이 없거나 JSON 객체가 아님")
        return None
    return evidence


def _event_row(event: dict[str, Any], evidence: dict[str, Any] | None) -> dict[str, Any]:
    evidence = evidence or {}
    return {
        "id": int(event["id"]),
        "device_id": event["device_id"],
        "subject_ip": event["subject_ip"],
        "event_type": event["event_type"],
        "window_start": event["analysis_window_start"],
        "observed_value": evidence.get("observed_value"),
        "threshold": evidence.get("threshold"),
        "unit": evidence.get("unit"),
        "device_policy_revision": evidence.get("device_policy_revision"),
        "rule_policy_version": evidence.get("rule_policy_version") or event["policy_version"],
        "captured_duration_seconds": evidence.get("captured_duration_seconds"),
        "score_delta": event["score_delta"],
        "applied_to_score": event["applied_to_score"],
        "processing_reason": event["processing_reason"],
        "processed_at": event["processed_at"],
    }


def _resolve(
    report: PacketReviewReport,
    resolver: DevicePolicyResolver,
    event: dict[str, Any],
    device_id: str,
    window_start: datetime,
) -> PolicyResolution | None:
    """10초 경계가 아닌 과거 Window 등 해석 불가 Event는 전체 중단 대신 FAIL로 남긴다."""
    try:
        return resolver.resolve(device_id, window_start)
    except ValueError as exc:
        _add(report, FAIL, "POLICY_REVISION", event, f"정책 해석 불가: {exc}")
        return None


def _event_window_start(event: dict[str, Any]) -> datetime | None:
    value = event.get("analysis_window_start")
    return parse_db_utc(value, "analysis_window_start") if value else None


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _add(report: PacketReviewReport, level: str, check: str,
         event: dict[str, Any] | None, message: str) -> None:
    report.findings.append(ReviewFinding(
        level=level,
        check=check,
        message=message,
        event_id=int(event["id"]) if event is not None else None,
        device_id=event["device_id"] if event is not None else None,
        window_start=event["analysis_window_start"] if event is not None else None,
    ))


def _add_raw(report: PacketReviewReport, level: str, check: str, message: str, *,
             device_id: str | None = None, window_start: str | None = None) -> None:
    report.findings.append(ReviewFinding(
        level=level, check=check, message=message,
        device_id=device_id, window_start=window_start,
    ))


def _parse_utc_arg(value: str) -> datetime:
    parsed = parse_db_utc(value, "time")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def open_readonly_session(db_path: Path) -> Session:
    if not db_path.is_file():
        raise FileNotFoundError(f"DB 파일이 없습니다: {db_path}")
    uri = db_path.resolve().as_uri() + "?mode=ro"
    engine = create_engine(
        "sqlite://",
        creator=lambda: sqlite3.connect(uri, uri=True, check_same_thread=False),
    )
    return sessionmaker(bind=engine, autoflush=False)()


def print_report(report: PacketReviewReport) -> None:
    summary = report.summary()
    print(f"[PacketReview] {report.window_from} ~ {report.window_to} "
          f"device={report.device_id_filter or '*'} ip={report.subject_ip_filter or '*'} "
          f"policy_schema={report.policy_schema}")
    print(f"  Packet Event {summary['packet_event_count']}건 "
          f"{summary['packet_event_count_by_type']} / 점수 반영 {summary['applied_to_score_count']}건 "
          f"/ Trust 이력 {summary['trust_history_count']}건 / Firewall 요청 {summary['firewall_rule_count']}건")
    for row in report.events:
        print(
            f"  #{row['id']} {row['window_start']} {row['device_id'] or '-'}({row['subject_ip']}) "
            f"{row['event_type']} observed={row['observed_value']} threshold={row['threshold']} "
            f"{row['unit'] or ''} rev={row['device_policy_revision']} "
            f"delta={row['score_delta']} applied={row['applied_to_score']} "
            f"reason={row['processing_reason']}"
        )
    for history in report.trust_history:
        print(
            f"  [Trust] {history['device_id']} {history['analysis_window_start']} "
            f"{history['previous_score']}→{history['new_score']} "
            f"(calc={history['calculated_delta']}, cap={history['capped_delta']}) "
            f"rep={history['representative_event_ids_json']}"
        )
    for rule in report.firewall_rules:
        print(f"  [Firewall] #{rule['id']} {rule['device_id']} {rule['source_ip']} "
              f"{rule['protocol']}/{rule['dest_port']} {rule['action']} {rule['status']}")
    for finding in report.findings:
        target = f" event={finding.event_id}" if finding.event_id is not None else ""
        print(f"  {finding.level} {finding.check}{target}: {finding.message}")
    print(f"  결과: FAIL {summary['fail_count']}건, WARN {summary['warn_count']}건")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 8 Packet Rule·Trust·차단 결과 검토 (읽기 전용, 복사 DB 사용)")
    parser.add_argument("--db", required=True, help="검토할 SQLite 복사본 경로")
    parser.add_argument("--from", dest="window_from", required=True,
                        help="검토 시작 UTC (예: 2026-10-06T01:00:00Z, 포함)")
    parser.add_argument("--to", dest="window_to", required=True,
                        help="검토 끝 UTC (미포함)")
    parser.add_argument("--device-id")
    parser.add_argument("--subject-ip")
    parser.add_argument("--json-out", help="JSON 리포트 저장 경로")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        window_from = _parse_utc_arg(args.window_from)
        window_to = _parse_utc_arg(args.window_to)
        db = open_readonly_session(Path(args.db))
    except (ValueError, FileNotFoundError) as exc:
        print(f"[PacketReview] 입력 오류: {exc}")
        return 2
    try:
        report = build_packet_review(
            db, window_from=window_from, window_to=window_to,
            device_id=args.device_id, subject_ip=args.subject_ip,
        )
    except (ValueError, RuntimeError, OperationalError) as exc:
        print(f"[PacketReview] 검토 실패: {exc}")
        return 2
    finally:
        db.close()

    print_report(report)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"  JSON: {out}")
    return 1 if report.fail_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
