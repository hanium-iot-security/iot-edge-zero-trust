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
    where_clauses: list[str] = []
    params: dict[str, str | int] = {
        "limit": limit,
        "offset": offset,
    }

    if device_id is not None:
        where_clauses.append("device_id = :device_id")
        params["device_id"] = device_id

    where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    count = db.execute(
        text(f"SELECT COUNT(*) FROM isolation_history{where_sql}"),
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
                created_at
            FROM isolation_history
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "count": int(count)}
