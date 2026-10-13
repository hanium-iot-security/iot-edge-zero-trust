"""Use a real SQLite read snapshot and a global Feature insertion watermark."""

from contextlib import contextmanager

from sqlalchemy import text


SQLITE_MAX_ID = 2**63 - 1


@contextmanager
def feature_read_snapshot(db, table: str, requested: int | None):
    if table not in ("feature_logs", "packet_feature_logs"):
        raise ValueError("unsupported Feature table")
    if requested is not None and (type(requested) is not int or not 0 <= requested <= SQLITE_MAX_ID):
        raise ValueError("snapshot_max_id must be a nonnegative SQLite integer")
    owned = not db.in_transaction()
    try:
        connection = db.connection()
        if connection.dialect.name != "sqlite":
            raise RuntimeError("Feature snapshots require SQLite")
        # Session.begin() alone does not start a physical read transaction with
        # SQLite's legacy driver. Existing caller transactions remain theirs.
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN")
        maximum = int(db.execute(text(f"SELECT COALESCE(MAX(id), 0) FROM {table}")).scalar_one())
        if requested is not None and requested > maximum:
            raise ValueError("snapshot_max_id exceeds the current global maximum")
        yield maximum if requested is None else requested
    finally:
        if owned:
            # Materialized responses must not hold a read transaction while
            # FastAPI serializes/sends them or waits for dependency cleanup.
            db.rollback()
