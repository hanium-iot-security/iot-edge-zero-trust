from pathlib import Path


DB_PATH = Path("backend/data/iot_security.db")


def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
        print(f"DB 파일을 삭제했습니다: {DB_PATH}")
    else:
        print(f"삭제할 DB 파일이 없습니다: {DB_PATH}")


if __name__ == "__main__":
    main()
