from pathlib import Path
import sqlite3


DB_PATH = Path("backend/data/iot_security.db")
DEFAULT_DEVICE = {
    "device_id": "esp32_01",
    "ip_address": "192.168.0.4",
    "status": "normal",
    "trust_score": 100,
}


def main() -> None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, :ip_address, :status, :trust_score)
            """,
            DEFAULT_DEVICE,
        )
    print(f"기본 기기 {DEFAULT_DEVICE['device_id']}를 seed했습니다: {DB_PATH}")


if __name__ == "__main__":
    main()
