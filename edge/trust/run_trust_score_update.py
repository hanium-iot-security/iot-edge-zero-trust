"""Run Trust Score updates from pending detection events."""

from __future__ import annotations

from pathlib import Path
import sys


if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from edge.trust.trust_score_service import DB_PATH, update_trust_scores


def main() -> None:
    result = update_trust_scores(DB_PATH)

    print(f"Trust Score update complete: {DB_PATH}")
    print(f"Candidate events: {result.candidate_event_count}")
    print(f"Processed windows: {result.processed_window_count}")
    print(f"Applied events: {result.applied_event_count}")

    if result.skipped_missing_device_count:
        print(f"Skipped missing devices: {result.skipped_missing_device_count}")
    if result.skipped_no_score_count:
        print(f"Skipped no-score windows: {result.skipped_no_score_count}")

    if not result.changes:
        print("No Trust Score changes.")
        return

    print("Changes:")
    for change in result.changes:
        isolation_note = " isolation_history=created" if change.isolation_recorded else ""
        print(
            "- "
            f"{change.device_id}: "
            f"{change.previous_score}->{change.new_score} "
            f"({change.previous_status}->{change.new_status}), "
            f"event_id={change.event_id}, "
            f"event_type={change.event_type}, "
            f"score_delta={change.score_delta}"
            f"{isolation_note}"
        )


if __name__ == "__main__":
    main()
