from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import settings


def _sqlite_connect_args(database_url: str) -> dict[str, bool]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def _ensure_sqlite_parent(database_url: str) -> None:
    if not database_url.startswith("sqlite:///"):
        return

    db_path = database_url.removeprefix("sqlite:///")
    if db_path and db_path != ":memory:":
        Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)


_ensure_sqlite_parent(settings.database_url)
engine = create_engine(settings.database_url, connect_args=_sqlite_connect_args(settings.database_url))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
