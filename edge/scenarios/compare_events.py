"""실제 결과와 예상 Packet/MQTT Rule Event 비교표 작성.

``edge/phase5/contracts.py``(PR #45)의 ``RunManifest.from_json``으로
run-manifest.json을 읽고(스키마 검증 포함), 이미 Phase 4부터 존재하는
``detection_events`` 테이블(``backend/app/services/detection_event_query_service.py``)과 대조한다.
evaluation exporter(Trust/Firewall까지 포함하는 정식 산출물)와 달리,
이 스크립트는 **Event Type 일치 여부만** 빠르게 확인하는 스팟체크 도구다.

매칭 기준은 ``detected_at``이 Run의 관찰 구간(``[started_at, observation_deadline_at]``)
안에 있는지로 판정한다. 공식 Evaluator와 동일하게 ``detected_at`` 자체를 기준으로 매칭한다."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from edge.phase5.contracts import RunManifest
from edge.scenarios.run_scenario import DEFAULT_RUNS_ROOT, compare_event_types


@dataclass
class EventComparisonReport:
    run_id: str
    session_id: str | None
    scenario_id: str
    scenario_version: str
    target_device_id: str | None
    source_ip: str | None
    query_window_start: str
    query_window_end: str
    expected_event_types: list[str]
    actual_event_types: list[str]
    actual_events: list[dict[str, Any]]
    comparison: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# detection_event_query_service.list_detection_events는 analysis_window_start/
# analysis_window_end(=window_start_from/window_end_to)만 필터링 인자로 받고
# detected_at으로는 직접 필터링하지 않는다. 그래서 DB 조회 단계에서는 실제
# 관찰 구간보다 앞뒤로 여유를 두어 넓게 가져온 뒤, detected_at 기준 최종
# 매칭은 Python에서 판정한다.
_QUERY_MARGIN = timedelta(minutes=10)


def fetch_actual_events(
    db: Session,
    *,
    target_device_id: str | None,
    source_ip: str | None,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """target_device_id가 있으면 device_id로, 없으면(미매핑 IP) subject_ip로 조회한다.

    최종 매칭 기준은 analysis_window가 아니라 ``detected_at``이 관찰 구간
    ``[window_start, window_end]`` 안에 있는지로 판정한다 (공식 Evaluator와 동일
    기준). DB 조회는 ``_QUERY_MARGIN``만큼 여유를 두어 넓게 가져온 뒤 여기서
    다시 걸러낸다.
    """
    from backend.app.services.detection_event_query_service import list_detection_events

    kwargs: dict[str, Any] = {
        "window_start_from": window_start - _QUERY_MARGIN,
        "window_end_to": window_end + _QUERY_MARGIN,
        "limit": 200,
    }
    if target_device_id:
        kwargs["device_id"] = target_device_id
    elif source_ip:
        kwargs["subject_ip"] = source_ip
    else:
        return []

    result = list_detection_events(db, **kwargs)
    events = list(result["items"])
    return [
        event
        for event in events
        if _matches_detected_at_window(event, window_start, window_end)
    ]


def _matches_detected_at_window(
    event: dict[str, Any], window_start: datetime, window_end: datetime
) -> bool:
    """Event의 ``detected_at``이 관찰 구간 안에 있는지 확인한다 (경계값 포함).

    ``analysis_window_start``가 아니라 실제 탐지 시각(``detected_at``)을 기준으로
    삼아, 집계 Window 중간에 공격이 시작된 경우에도 정상 탐지 Event가 missing으로
    오판되지 않게 한다.
    """
    detected_at = event.get("detected_at")
    if detected_at is None:
        return False
    if isinstance(detected_at, str):
        try:
            detected_at = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        except ValueError:
            # detection_event_query_service가 이미 detected_at을 파싱해 반환하므로
            # 정상 경로에서는 도달하지 않지만, 혹시 형식이 깨진 값이 들어오면
            # "매칭됨"으로 잘못 집계(false positive matched)하는 대신 매칭 실패로
            # 처리해 missing/unexpected 쪽에서 드러나게 한다 (안전한 방향의 보수적 처리).
            return False
    return window_start <= detected_at <= window_end


def build_comparison_report(run_dir: Path, db: Session) -> EventComparisonReport:
    manifest_text = (run_dir / "run-manifest.json").read_text(encoding="utf-8")
    manifest = RunManifest.from_json(manifest_text)  # 스키마 검증 포함

    actual_events = fetch_actual_events(
        db,
        target_device_id=manifest.target_device_id,
        source_ip=manifest.source_ip,
        window_start=manifest.started_at,
        window_end=manifest.observation_deadline_at,
    )
    actual_event_types = sorted({e["event_type"] for e in actual_events})
    expected_event_types = list(manifest.expected_outcome.expected_event_types)

    comparison = compare_event_types(expected_event_types, actual_event_types)

    return EventComparisonReport(
        run_id=manifest.run_id,
        session_id=manifest.session_id,
        scenario_id=manifest.scenario.scenario_id,
        scenario_version=manifest.scenario.scenario_version or "",
        target_device_id=manifest.target_device_id,
        source_ip=manifest.source_ip,
        query_window_start=manifest.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        query_window_end=manifest.observation_deadline_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expected_event_types=expected_event_types,
        actual_event_types=actual_event_types,
        actual_events=[
            {
                "id": e["id"],
                "event_type": e["event_type"],
                "detector_type": e["detector_type"],
                "severity": e["severity"],
                "detected_at": e["detected_at"],
            }
            for e in actual_events
        ],
        comparison=comparison,
    )


def write_report(run_dir: Path, report: EventComparisonReport) -> Path:
    path = run_dir / "event-comparison.json"
    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
    path.write_text(payload, encoding="utf-8")
    sidecar = run_dir / "event-comparison.json.sha256"
    sidecar.write_text(
        hashlib.sha256(payload.encode("utf-8")).hexdigest() + "\n", encoding="utf-8"
    )
    return path


def _print_report(report: EventComparisonReport) -> None:
    print(f"[EventComparison] run_id={report.run_id} scenario_id={report.scenario_id}")
    print(f"  조회 Window: {report.query_window_start} ~ {report.query_window_end}")
    print(f"  expected={report.expected_event_types}")
    print(f"  actual  ={report.actual_event_types}")
    print(f"  matched   ={report.comparison['matched']}")
    print(f"  missing   ={report.comparison['missing']}   (기대했지만 탐지 안 됨)")
    print(f"  unexpected={report.comparison['unexpected']}   (기대하지 않았지만 탐지됨)")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Scenario 실행 결과 vs 실제 detection_events 비교")
    p.add_argument("--run-id", required=True)
    p.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    from backend.app.database import SessionLocal

    run_dir = Path(args.runs_root) / args.run_id
    if not run_dir.exists():
        print(f"[EventComparison] run_dir이 없습니다: {run_dir}")
        return 2

    db = SessionLocal()
    try:
        report = build_comparison_report(run_dir, db)
    finally:
        db.close()

    write_report(run_dir, report)
    _print_report(report)
    return 0 if not report.comparison["missing"] else 1


if __name__ == "__main__":
    raise SystemExit(main())