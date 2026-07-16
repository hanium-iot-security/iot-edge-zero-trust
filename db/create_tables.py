from pathlib import Path

try:
    from db.migration_runner import DB_PATH, apply_migrations
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from migration_runner import DB_PATH, apply_migrations

DEFAULT_DB_PATH = Path("backend/data/iot_security.db")


def main() -> None:
    db_path = DB_PATH if DB_PATH else DEFAULT_DB_PATH
    result = apply_migrations(db_path)
    print(
        f"SQLite migration을 적용했습니다: {db_path} "
        f"(applied={result.applied_versions}, "
        f"skipped={result.skipped_versions}, "
        f"baselined={result.baselined_versions})"
    )


if __name__ == "__main__":
    main()
