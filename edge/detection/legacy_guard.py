"""Stop MVP detectors whose event timestamps cannot satisfy the v2 contract."""

from sqlalchemy import text
from sqlalchemy.orm import Session


def reject_v2_database(db: Session, runner_name: str) -> None:
    columns = {
        str(row[1]) for row in db.execute(text("PRAGMA table_info(detection_events)"))
    }
    if {"processed_at", "analysis_window_start", "analysis_window_end"} & columns:
        raise RuntimeError(
            f"{runner_name} is disabled for Phase 4/v2 databases; "
            "run edge.orchestration.run_detection_orchestrator instead"
        )
