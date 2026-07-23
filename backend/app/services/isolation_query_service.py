"""Isolation history query helpers used by FastAPI routers."""

from sqlalchemy import text
from sqlalchemy.orm import Session


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def list_isolation_history(
    db: Session,
    device_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    params: dict[str, str | int | None] = {
        "device_id": device_id,
        "limit": limit,
        "offset": offset,
    }
    columns = _column_names(db, "isolation_history")
    trust_history_column = (
        "trust_score_history_id"
        if "trust_score_history_id" in columns
        else "NULL AS trust_score_history_id"
    )

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM isolation_history
            WHERE (:device_id IS NULL OR device_id = :device_id)
            """
        ),
        params,
    ).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                device_id,
                action,
                reason,
                trust_score,
                trigger_event_id,
                {trust_history_column},
                created_at
            FROM isolation_history
            WHERE (:device_id IS NULL OR device_id = :device_id)
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "total": int(total)}


def _column_names(db: Session, table_name: str) -> set[str]:
    rows = db.execute(text(f"PRAGMA table_info({table_name})")).mappings().all()
    return {str(row["name"]) for row in rows}
