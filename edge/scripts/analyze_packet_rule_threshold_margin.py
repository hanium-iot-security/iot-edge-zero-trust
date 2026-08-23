"""edge/scripts/analyze_packet_rule_threshold_margin.py

세부계획 12.1 / 정선우 담당:
"Packet Rule 임계값은 현재 packet-rule-policy-v2 를 즉시 변경하지 않는다.
 정상·공격 실측 분포의 P95/P99/MAX와 공격 하한을 함께 비교한 뒤 별도
 Calibration에서 v2 유지 또는 새 Policy Version을 결정한다."

이 스크립트는 Threshold를 절대 변경하지 않는다. 실제 DB(packet_feature_logs +
packet_capture_segments)에서 지정한 Capture Session들의 INBOUND Row를 읽어,
Packet Rule과 완전히 동일한 계산 함수(effective_packets_per_second /
effective_bytes_per_second)와 완전히 동일한 적격 판정 함수(is_capture_eligible)
를 재사용해 packets_per_second·bytes_per_second 분포를 만들고, 현재
PacketRulePolicy.from_env() Threshold와의 margin만 리포트로 낸다.

핵심 설계 원칙:
  - Packet Rule Detector(edge/detection/packet_rule_detector.py)와 판정
    로직을 절대 복제하지 않는다. is_capture_eligible / effective_*_per_second
    를 그대로 import해서 쓴다 — 계산식이 둘 사이에서 갈라지지 않게 하기 위함.
  - normal/attack 구분은 Capture Session ID 목록으로 사람이 지정한다
    (Phase 6-B는 Session 단위로 Train/Validation/Holdout을 미리 배정하므로
    그 배정을 그대로 인자로 받는다. 이 스크립트가 자체적으로 정상/공격을
    추정하지 않는다).

사용 예 (정상 3개 Session, 공격 2개 Session):
    PYTHONPATH=. python -m edge.scripts.analyze_packet_rule_threshold_margin \
        --normal-session-id <uuid1> --normal-session-id <uuid2> --normal-session-id <uuid3> \
        --attack-session-id <uuid4> --attack-session-id <uuid5> \
        --metric packet_rate \
        --out-json reports/packet_rule_threshold_margin_2026-08-22.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import SessionLocal
from edge.detection.packet_rule_detector import (
    PacketRulePolicy,
    effective_bytes_per_second,
    effective_packets_per_second,
)
from edge.packet.capture_policy import (
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)

Metric = Literal["packet_rate", "byte_rate"]


@dataclass(frozen=True)
class DistributionSummary:
    count: int
    excluded_ineligible_count: int
    min: float
    p50: float
    p95: float
    p99: float
    max: float


@dataclass(frozen=True)
class ThresholdMarginReport:
    metric: str
    current_threshold: float
    rule_policy_version: str
    capture_policy_version: str
    normal_session_ids: list[str]
    attack_session_ids: list[str]
    normal: DistributionSummary
    attack: DistributionSummary
    normal_p99_below_threshold: bool
    normal_max_below_threshold: bool
    attack_min_above_threshold: bool
    margin_threshold_to_normal_p99: float
    margin_attack_min_to_threshold: float
    recommendation: str
    generated_at: str


def _percentile(sorted_values: list[float], pct: float) -> float:
    """표본이 적은 실측 데이터에서 보간으로 인한 착시를 피하기 위해
    nearest-rank 방식을 쓴다 (선형보간 안 함)."""
    n = len(sorted_values)
    if n == 1:
        return sorted_values[0]
    rank = max(1, math.ceil(pct / 100.0 * n))
    rank = min(rank, n)
    return sorted_values[rank - 1]


def _select_inbound_rows(db: Session, session_ids: list[str]) -> list[dict]:
    """packet_rule_detector._select_packet_feature_rows와 동일한 조인·컬럼을
    사용하되 Cutoff/Checkpoint 없이 지정된 Capture Session ID 목록 전체를
    대상으로 한다 (이 스크립트는 회귀/Checkpoint 처리기가 아니라 사후 분석 도구).

    IN 절은 SQLAlchemy 2.x의 expanding bindparam으로 처리한다 (session_ids
    개수가 가변적이므로 튜플을 그대로 바인딩하지 않는다)."""
    if not session_ids:
        return []

    from sqlalchemy import bindparam

    stmt = text(
        """
        SELECT
            pfl.id,
            pfl.peer_ip,
            pfl.device_id,
            pfl.packet_count,
            pfl.total_bytes,
            pcs.status AS segment_status,
            pcs.error_code AS segment_error_code,
            pcs.start_delay_seconds,
            pcs.captured_duration_seconds,
            pcss.session_id
        FROM packet_feature_logs pfl
        JOIN packet_capture_segments pcs
            ON pcs.id = pfl.capture_segment_id
        JOIN packet_capture_sessions pcss
            ON pcss.id = pcs.capture_session_id
        WHERE pfl.direction = 'INBOUND'
          AND pcss.session_id IN :session_ids
        ORDER BY pfl.id ASC
        """
    ).bindparams(bindparam("session_ids", expanding=True))

    rows = db.execute(stmt, {"session_ids": session_ids})
    return [dict(row._mapping) for row in rows]


def collect_metric_values(
    db: Session,
    *,
    session_ids: list[str],
    metric: Metric,
    capture_policy: CapturePolicy,
) -> tuple[list[float], int]:
    """지정한 Capture Session들의 INBOUND Row에서 metric 값 리스트를 뽑는다.

    Packet Rule Detector와 동일하게 is_capture_eligible()로 거른 Row만 사용한다.
    반환값: (metric 값 리스트, 부적격으로 제외된 Row 수)
    """
    rows = _select_inbound_rows(db, session_ids)
    values: list[float] = []
    excluded = 0

    for row in rows:
        segment = CaptureEligibilitySegment(
            status=str(row["segment_status"]),
            error_code=row["segment_error_code"],
            start_delay_seconds=row["start_delay_seconds"],
            captured_duration_seconds=row["captured_duration_seconds"],
        )
        eligibility = is_capture_eligible(segment, capture_policy)
        if not eligibility.eligible:
            excluded += 1
            continue

        duration = float(row["captured_duration_seconds"])
        if metric == "packet_rate":
            values.append(effective_packets_per_second(float(row["packet_count"]), duration))
        else:
            values.append(effective_bytes_per_second(float(row["total_bytes"]), duration))

    return values, excluded


def summarize(values: list[float], excluded_count: int) -> DistributionSummary:
    if not values:
        raise ValueError(
            "eligible 값이 0개입니다. Capture Session ID가 올바른지, "
            "Segment가 PROCESSED/EMPTY 상태로 처리 완료됐는지 확인하세요."
        )
    values_sorted = sorted(values)
    return DistributionSummary(
        count=len(values_sorted),
        excluded_ineligible_count=excluded_count,
        min=values_sorted[0],
        p50=_percentile(values_sorted, 50),
        p95=_percentile(values_sorted, 95),
        p99=_percentile(values_sorted, 99),
        max=values_sorted[-1],
    )


def build_report(
    *,
    metric: Metric,
    current_threshold: float,
    rule_policy_version: str,
    capture_policy_version: str,
    normal_session_ids: list[str],
    attack_session_ids: list[str],
    normal_values: list[float],
    normal_excluded: int,
    attack_values: list[float],
    attack_excluded: int,
) -> ThresholdMarginReport:
    normal_summary = summarize(normal_values, normal_excluded)
    attack_summary = summarize(attack_values, attack_excluded)

    normal_p99_below = normal_summary.p99 < current_threshold
    normal_max_below = normal_summary.max < current_threshold
    attack_min_above = attack_summary.min > current_threshold

    if normal_max_below and attack_min_above:
        recommendation = (
            "SAFE_MARGIN: 정상 Max와 공격 Min이 Threshold 양쪽에 명확히 분리됨. "
            "v2 유지 근거로 사용 가능 (단, 사람이 최종 Calibration에서 확정할 것)."
        )
    elif normal_p99_below and attack_min_above:
        recommendation = (
            "NARROW_MARGIN: P99 기준으로는 분리되지만 정상 Max가 Threshold를 넘는 outlier가 존재함. "
            "Outlier 원인 조사 후 v2 유지 여부 판단 필요."
        )
    else:
        recommendation = (
            "OVERLAP_DETECTED: 정상 분포와 공격 분포가 Threshold 기준으로 겹침. "
            "즉시 Threshold를 올리지 말고 원인 분석 후 새 Policy Version 필요 여부를 "
            "별도 Calibration에서 결정할 것."
        )

    if attack_summary.count < 5:
        recommendation = (
            f"[표본 n={attack_summary.count}개, 소표본 주의] " + recommendation
        )

    return ThresholdMarginReport(
        metric=metric,
        current_threshold=current_threshold,
        rule_policy_version=rule_policy_version,
        capture_policy_version=capture_policy_version,
        normal_session_ids=normal_session_ids,
        attack_session_ids=attack_session_ids,
        normal=normal_summary,
        attack=attack_summary,
        normal_p99_below_threshold=normal_p99_below,
        normal_max_below_threshold=normal_max_below,
        attack_min_above_threshold=attack_min_above,
        margin_threshold_to_normal_p99=current_threshold - normal_summary.p99,
        margin_attack_min_to_threshold=attack_summary.min - current_threshold,
        recommendation=recommendation,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def print_human_readable(report: ThresholdMarginReport) -> None:
    print(f"=== Packet Rule Threshold Margin Report: {report.metric} ===")
    print(f"rule_policy_version = {report.rule_policy_version}")
    print(f"capture_policy_version = {report.capture_policy_version}")
    print(f"current_threshold = {report.current_threshold}")
    print()
    print(f"Normal Sessions: {report.normal_session_ids}")
    print(f"  n={report.normal.count} (excluded_ineligible={report.normal.excluded_ineligible_count})  "
          f"min={report.normal.min:.2f}  p50={report.normal.p50:.2f}  "
          f"p95={report.normal.p95:.2f}  p99={report.normal.p99:.2f}  max={report.normal.max:.2f}")
    print(f"Attack Sessions: {report.attack_session_ids}")
    print(f"  n={report.attack.count} (excluded_ineligible={report.attack.excluded_ineligible_count})  "
          f"min={report.attack.min:.2f}  p50={report.attack.p50:.2f}  "
          f"p95={report.attack.p95:.2f}  p99={report.attack.p99:.2f}  max={report.attack.max:.2f}")
    print()
    print(f"normal_p99 < threshold : {report.normal_p99_below_threshold}")
    print(f"normal_max < threshold : {report.normal_max_below_threshold}")
    print(f"attack_min > threshold : {report.attack_min_above_threshold}")
    print(f"margin (threshold - normal_p99) = {report.margin_threshold_to_normal_p99:.2f}")
    print(f"margin (attack_min - threshold) = {report.margin_attack_min_to_threshold:.2f}")
    print()
    print(f"RECOMMENDATION: {report.recommendation}")
    print()
    print(
        "NOTE: 이 스크립트는 Threshold를 변경하지 않는다. "
        "v2 유지/새 Policy Version 결정은 이 리포트를 근거로 별도 Calibration에서 사람이 확정한다."
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "실제 DB의 지정 Capture Session들로 Packet Rule Threshold margin을 분석한다. "
            "Threshold는 변경하지 않는다."
        )
    )
    parser.add_argument(
        "--normal-session-id", dest="normal_session_ids", action="append", required=True,
        help="정상 Capture Session ID (UUID). 여러 번 지정 가능.",
    )
    parser.add_argument(
        "--attack-session-id", dest="attack_session_ids", action="append", required=True,
        help="공격 Capture Session ID (UUID). 여러 번 지정 가능.",
    )
    parser.add_argument(
        "--metric", choices=["packet_rate", "byte_rate"], required=True,
        help="packet_rate: packets_per_second, byte_rate: bytes_per_second",
    )
    parser.add_argument("--out-json", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    rule_policy = PacketRulePolicy.from_env()
    capture_policy = CapturePolicy.from_env()
    threshold = (
        rule_policy.packet_rate_threshold
        if args.metric == "packet_rate"
        else rule_policy.byte_rate_threshold
    )

    db = SessionLocal()
    try:
        normal_values, normal_excluded = collect_metric_values(
            db, session_ids=args.normal_session_ids, metric=args.metric, capture_policy=capture_policy
        )
        attack_values, attack_excluded = collect_metric_values(
            db, session_ids=args.attack_session_ids, metric=args.metric, capture_policy=capture_policy
        )
    finally:
        db.close()

    if len(attack_values) < 5:
        print(
            f"[WARNING] 공격 표본 수가 매우 적습니다 (n={len(attack_values)}). "
            "리포트에 표본 수를 반드시 함께 명시하고 일반화된 결론으로 단정하지 마세요.",
            file=sys.stderr,
        )

    try:
        report = build_report(
            metric=args.metric,
            current_threshold=threshold,
            rule_policy_version=rule_policy.version,
            capture_policy_version=capture_policy.version,
            normal_session_ids=args.normal_session_ids,
            attack_session_ids=args.attack_session_ids,
            normal_values=normal_values,
            normal_excluded=normal_excluded,
            attack_values=attack_values,
            attack_excluded=attack_excluded,
        )
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print_human_readable(report)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        with args.out_json.open("w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        print(f"\nJSON report written to {args.out_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())