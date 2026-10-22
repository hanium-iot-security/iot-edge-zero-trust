"""Read committed runtime evidence without inferring execution from configuration."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.schemas.ai_runtime_schema import (
    AiWarningItem, CompletionEvidence, RuntimeObservation,
)
from backend.app.services.device_policy_service import _connection
from edge.detection.ai_runtime_repository import (
    RuntimeEvidenceUnavailable, list_ai_warnings, read_ai_completions, read_runtime_snapshot,
)


MAX_AGE_SECONDS = 45


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def current_boot_id() -> str | None:
    try:
        return str(UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    except (OSError, ValueError):
        return None


def _utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() != timedelta(0):
            raise ValueError("stored evidence requires UTC")
        return result
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("Invalid runtime evidence timestamp") from exc


def _observation(raw: dict | None) -> dict | None:
    if raw is None:
        return None
    try:
        data = RuntimeObservation.model_validate(raw).model_dump()
        observed = _utc(data["observed_at"])
        if _utc(data["started_at"]) > observed:
            raise ValueError("observation predates runtime start")
        names = [stage["name"] for stage in data["stages"]]
        if len(names) != len(set(names)):
            raise ValueError("duplicate observed Stage")
        for stage in data["stages"]:
            if stage["observed_at"] is not None and _utc(stage["observed_at"]) > observed:
                raise ValueError("Stage observation exceeds snapshot time")
            if stage["last_completed_window_end"] is not None:
                _utc(stage["last_completed_window_end"])
        return data
    except (TypeError, ValueError) as exc:
        raise RuntimeEvidenceUnavailable("Invalid runtime observation") from exc


def _freshness(observed_at: str | None, boot_id: str | None, *, now: datetime, boot: str | None):
    if observed_at is None:
        return "MISSING", None
    age = (now - _utc(observed_at)).total_seconds()
    if age < 0:
        return "FUTURE", age
    if age > MAX_AGE_SECONDS:
        return "STALE", age
    if boot is None or boot_id is None:
        return "BOOT_UNAVAILABLE", age
    if boot_id != boot:
        return "BOOT_MISMATCH", age
    return "FRESH", age


def _reason(freshness: str) -> str | None:
    return None if freshness == "FRESH" else f"RUNTIME_EVIDENCE_{freshness}"


def get_runtime_status(db: Session, *, device_id: str | None = None) -> dict:
    now, boot = utc_now(), current_boot_id()
    # Reuse the existing explicit SQLite read transaction so the publisher and
    # completion rows cannot come from different commits during this response.
    with _connection(db, read=True) as connection:
        snapshot = _observation(read_runtime_snapshot(connection))
        records = read_ai_completions(connection, device_id=device_id)
    observed_at = snapshot["observed_at"] if snapshot else None
    boot_id = snapshot["boot_id"] if snapshot else None
    freshness, age = _freshness(observed_at, boot_id, now=now, boot=boot)
    completions = []
    for record in records:
        try:
            item = CompletionEvidence.model_validate(record).model_dump()
        except ValueError as exc:
            raise RuntimeEvidenceUnavailable("Invalid completion evidence") from exc
        item_freshness, item_age = _freshness(item["observed_at"], item["boot_id"], now=now, boot=boot)
        current = (snapshot is not None and freshness == "FRESH" and item_freshness == "FRESH"
                   and item["run_id"] == snapshot["run_id"])
        completions.append({**item, "evidence_status": "CURRENT" if current else "HISTORICAL",
                            "freshness": item_freshness, "age_seconds": item_age})
    return {
        "server_time": now.isoformat(), "observed_at": observed_at,
        "run_id": snapshot["run_id"] if snapshot else None, "boot_id": boot_id,
        "status": snapshot["status"] if snapshot and freshness == "FRESH" else "UNKNOWN",
        "last_observation_status": snapshot["status"] if snapshot else None,
        "freshness": freshness, "age_seconds": age, "max_age_seconds": MAX_AGE_SECONDS,
        "reason_code": _reason(freshness), "error_code": snapshot["error_code"] if snapshot else None,
        "warning_policy": snapshot["warning_policy"] if snapshot else None,
        "stages": snapshot["stages"] if snapshot else [], "completions": completions,
    }


def _bound(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError(f"{name} is outside the supported UTC range") from exc


def get_ai_warnings(db: Session, *, device_id: str | None = None,
                    from_at: datetime | None = None, to_at: datetime | None = None,
                    limit: int = 100, offset: int = 0) -> dict:
    start, end = _bound(from_at, "from"), _bound(to_at, "to")
    if start is not None and end is not None and start > end:
        raise ValueError("from must be before or equal to to")
    now, boot = utc_now(), current_boot_id()
    with _connection(db, read=True) as connection:
        snapshot = _observation(read_runtime_snapshot(connection))
        result = list_ai_warnings(connection, device_id=device_id, from_at=start, to_at=end,
                                  limit=limit, offset=offset)
    try:
        items = [AiWarningItem.model_validate(item).model_dump() for item in result["items"]]
    except ValueError as exc:
        raise RuntimeEvidenceUnavailable("Invalid AI warning evidence") from exc
    freshness, _ = _freshness(snapshot["observed_at"] if snapshot else None,
                              snapshot["boot_id"] if snapshot else None, now=now, boot=boot)
    source_status, reason = "UNKNOWN", _reason(freshness)
    if snapshot and freshness == "FRESH":
        if snapshot["warning_policy"] is None:
            source_status, reason = "POLICY_UNCONFIGURED", "AI_WARNING_POLICY_UNCONFIGURED"
        elif snapshot["status"] == "RUNNING":
            source_status, reason = "AVAILABLE", None
        else:
            reason = f"RUNTIME_{snapshot['status']}"
    return {"server_time": now.isoformat(), "observed_at": snapshot["observed_at"] if snapshot else None,
            "source_status": source_status, "reason_code": reason,
            "items": items, "total": result["total"]}
