"""Device query helpers used by FastAPI routers."""

from sqlalchemy import text
from sqlalchemy.orm import Session


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def list_devices(
    db: Session,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    where_clauses: list[str] = []
    params: dict[str, str | int] = {
        "limit": limit,
        "offset": offset,
    }

    if status is not None:
        where_clauses.append("status = :status")
        params["status"] = status

    where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    count = db.execute(
        text(f"SELECT COUNT(*) FROM devices{where_sql}"),
        params,
    ).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                device_id,
                ip_address,
                status,
                trust_score,
                last_seen_at,
                created_at
            FROM devices
            {where_sql}
            ORDER BY device_id ASC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "count": int(count)}
