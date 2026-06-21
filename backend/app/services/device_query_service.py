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
    params: dict[str, str | int | None] = {
        "status": status,
        "limit": limit,
        "offset": offset,
    }

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM devices
            WHERE (:status IS NULL OR status = :status)
            """
        ),
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
            WHERE (:status IS NULL OR status = :status)
            ORDER BY device_id ASC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "total": int(total)}


def get_device(db: Session, device_id: str) -> dict | None:
    row = db.execute(
        text(
            """
            SELECT
                device_id,
                ip_address,
                status,
                trust_score,
                last_seen_at,
                created_at
            FROM devices
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).mappings().one_or_none()

    return dict(row) if row is not None else None
