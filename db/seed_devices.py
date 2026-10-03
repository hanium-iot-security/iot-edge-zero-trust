"""개발용 기본 기기를 seed한다.

먼저 `python db/create_tables.py`로 Migration(007 이상)을 적용해야 한다. 기기와 초기 정책
revision을 한 트랜잭션으로 만들어 정책 없는 ACTIVE 기기가 생기지 않게 한다. 다시 실행해도
이미 있는 기기·정책은 덮어쓰지 않는다.

운영 DB의 기존 기기는 이 seed가 아니라 확인된 운영값으로 `db/backfill_device_policies.py`를
실행해 이관한다. 이 파일의 정책 값은 개발 DB용 기존 코드 기본값이다.
"""

from __future__ import annotations

import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:  # `python db/seed_devices.py` 직접 실행 지원
    sys.path.insert(0, str(PROJECT_ROOT))

from db.migration_runner import DB_PATH, connect_database  # noqa: E402
from edge.detection.packet_rule_detector import DEFAULT_PACKET_RULE_POLICY  # noqa: E402
from edge.detection.rule_detector import LARGE_PAYLOAD_BYTES, PUBLISH_COUNT_THRESHOLD  # noqa: E402
from edge.policy.device_policy import (  # noqa: E402
    POLICY_PROFILE,
    STATE_ACTIVE,
    DevicePolicy,
    IpRegistrationPolicy,
    floor_to_window,
    utc_now,
    validate_registration_ip,
)
from edge.policy.device_policy_repository import (  # noqa: E402
    Clock,
    create_device_locked,
    device_exists,
    write_transaction,
)

SEED_ACTOR = "seed_devices"
SEED_REASON = "development seed"

# Broker Principal은 문서로 확인되지 않아 지어내지 않고 비워 둔다(운영값은 backfill에서 기록).
DEFAULT_DEVICES = (
    {"device_id": "esp32_01", "ip_address": "192.168.0.4"},
    {"device_id": "esp32_02", "ip_address": "192.168.0.5"},
)

DEFAULT_POLICY = DevicePolicy(
    policy_profile=POLICY_PROFILE,
    expected_publish_interval_seconds=5.0,
    publish_count_max=PUBLISH_COUNT_THRESHOLD,
    payload_size_max_bytes=LARGE_PAYLOAD_BYTES,
    packet_rate_max_pps=float(DEFAULT_PACKET_RULE_POLICY.packet_rate_threshold),
    byte_rate_max_bytes_per_second=float(DEFAULT_PACKET_RULE_POLICY.byte_rate_threshold),
)


@dataclass(frozen=True)
class SeedResult:
    created: tuple[str, ...]
    already_present: tuple[str, ...]
    #: 기기는 있으나 정책 revision이 없다. 임의 기본값으로 채우지 않고 backfill이 필요하다.
    missing_policy: tuple[str, ...]


def seed_default_devices(connection: sqlite3.Connection, *, clock: Clock = utc_now) -> SeedResult:
    ip_policy = IpRegistrationPolicy()
    created: list[str] = []
    present: list[str] = []
    missing: list[str] = []

    with write_transaction(connection):
        now = clock()
        for spec in DEFAULT_DEVICES:
            device_id = spec["device_id"]
            if device_exists(connection, device_id):
                has_revision = connection.execute(
                    "SELECT 1 FROM device_policy_revisions WHERE device_id = ? LIMIT 1",
                    (device_id,),
                ).fetchone()
                (present if has_revision else missing).append(device_id)
                continue
            create_device_locked(
                connection,
                device_id=device_id,
                ip_address=validate_registration_ip(spec["ip_address"], ip_policy),
                device_type="SENSOR",
                mqtt_principal=None,
                policy=DEFAULT_POLICY,
                reason=SEED_REASON,
                created_by=SEED_ACTOR,
                initial_state=STATE_ACTIVE,
                effective_from=floor_to_window(now),
                now=now,
            )
            created.append(device_id)

    return SeedResult(tuple(created), tuple(present), tuple(missing))


def main() -> None:
    connection = connect_database(DB_PATH)
    try:
        has_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'device_policy_revisions'"
        ).fetchone()
        if has_table is None:
            raise SystemExit(
                "device_policy_revisions 테이블이 없습니다. 먼저 `python db/create_tables.py`로 "
                "Migration을 적용하세요."
            )
        result = seed_default_devices(connection)
    finally:
        connection.close()

    print(
        f"기본 기기 seed 완료: {DB_PATH} "
        f"(created={list(result.created)}, already_present={list(result.already_present)})"
    )
    if result.missing_policy:
        print(
            "정책 revision이 없는 기존 기기가 있습니다: "
            f"{list(result.missing_policy)}. 확인된 운영값으로 "
            "`python -m db.backfill_device_policies`를 실행하세요."
        )


if __name__ == "__main__":
    main()
