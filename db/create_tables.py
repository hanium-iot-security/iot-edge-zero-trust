from pathlib import Path
import sqlite3


DB_PATH = Path("backend/data/iot_security.db")
SCHEMA_PATH = Path("db/migrations/001_init.sql")


def main() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA busy_timeout = 5000;")
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    print(f"SQLite 테이블을 생성했습니다: {DB_PATH}")


if __name__ == "__main__":
    main()
