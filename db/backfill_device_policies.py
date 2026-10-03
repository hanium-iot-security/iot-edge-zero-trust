"""정책 도입 전부터 있던 기기에 초기 정책 revision을 만든다(P8-03).

기본은 dry-run이다. `--apply`를 줘야 DB를 변경한다. 운영 DB에서 바로 실행하지 말고 먼저
일관된 백업의 복사본으로 dry-run과 `--apply`를 확인한다.

    python -m db.backfill_device_policies --db copy.db --manifest manifest.json
    python -m db.backfill_device_policies --db copy.db --manifest manifest.json --apply

manifest(JSON, 비밀값 없음):

    {
      "schema_version": "device-policy-backfill-v1",
      "effective_from": "2026-10-02T00:00:00Z",   // UTC, 10초 경계
      "reason": "Pi 운영 설정 baseline-manifest <id> 기준 이관",
      "registration_network": "192.168.0.0/24",    // 선택: 실제 LAN
      "excluded_ips": ["192.168.0.1"],             // 선택: 관리/보호/제외 주소
      "devices": [
        {"device_id": "esp32_01", "device_type": "SENSOR",
         "mqtt_principal": "...",                  // 선택: 확인되지 않았으면 생략(NULL로 저장)
         "source": "baseline-manifest:<id>",
         "policy": {"policy_profile": "periodic-sensor-v1", ...네 임계값...}}
      ]
    }

종료 코드: 0 성공(또는 dry-run 문제 없음), 2 입력 오류·사전 조건 미충족.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db.migration_runner import connect_database  # noqa: E402
from edge.policy.device_policy import (  # noqa: E402
    BackfillBlockedError,
    DevicePolicyError,
    DevicePolicyValidationError,
    IpRegistrationPolicy,
    parse_effective_from,
    validate_reason,
)
from edge.policy.device_policy_backfill import (  # noqa: E402
    LegacyDeviceOverride,
    apply_legacy_backfill,
    parse_override,
    plan_legacy_backfill,
)

MANIFEST_SCHEMA_VERSION = "device-policy-backfill-v1"
_MANIFEST_FIELDS = {
    "schema_version",
    "effective_from",
    "reason",
    "registration_network",
    "excluded_ips",
    "devices",
}


def load_manifest(
    path: Path,
) -> tuple[dict[str, LegacyDeviceOverride], Any, IpRegistrationPolicy, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # JSON 오류·인코딩 오류·너무 긴 정수 포함
        raise DevicePolicyValidationError(f"cannot read manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise DevicePolicyValidationError("manifest must be a JSON object")
    unknown = sorted(set(raw) - _MANIFEST_FIELDS)
    if unknown:
        raise DevicePolicyValidationError(f"unsupported manifest fields: {unknown}")
    if raw.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise DevicePolicyValidationError(
            f"schema_version must be {MANIFEST_SCHEMA_VERSION!r}"
        )

    effective_from = parse_effective_from(raw.get("effective_from"))
    reason = validate_reason(raw.get("reason"))  # 누락·null·문자열이 아닌 값은 거부
    devices_raw = raw.get("devices")
    if not isinstance(devices_raw, list) or not devices_raw:
        raise DevicePolicyValidationError("devices must be a non-empty list")

    overrides: dict[str, LegacyDeviceOverride] = {}
    for item in devices_raw:
        override = parse_override(item)
        if override.device_id in overrides:
            raise DevicePolicyValidationError(f"duplicate device in manifest: {override.device_id}")
        overrides[override.device_id] = override

    network_raw = raw.get("registration_network")
    excluded_raw = raw.get("excluded_ips", [])
    if network_raw is not None and type(network_raw) is not str:
        raise DevicePolicyValidationError("registration_network must be a string")
    if not isinstance(excluded_raw, list) or any(type(v) is not str for v in excluded_raw):
        raise DevicePolicyValidationError("excluded_ips must be a list of strings")
    try:
        network = ipaddress.IPv4Network(network_raw) if network_raw is not None else None
        excluded = frozenset(ipaddress.IPv4Address(value) for value in excluded_raw)
    except ValueError as exc:
        raise DevicePolicyValidationError(f"invalid network settings: {exc}") from exc

    return overrides, effective_from, IpRegistrationPolicy(network, excluded), reason


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--db", required=True, type=Path, help="대상 SQLite DB(복사본 권장)")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--apply", action="store_true", help="실제로 변경한다(기본은 dry-run)")
    args = parser.parse_args(argv)

    if not args.db.is_file():
        print(f"DB 파일이 없습니다: {args.db}", file=sys.stderr)
        return 2

    try:
        overrides, effective_from, ip_policy, reason = load_manifest(args.manifest)
    except DevicePolicyError as exc:
        print(f"manifest 오류: {exc.message}", file=sys.stderr)
        return 2

    connection = connect_database(args.db)
    try:
        if args.apply:
            result = apply_legacy_backfill(
                connection,
                overrides,
                effective_from=effective_from,
                ip_policy=ip_policy,
                reason=reason,
            )
            print(f"이관 완료: created={list(result.created)}, "
                  f"already_revised={list(result.already_revised)}")
            return 0
        plan = plan_legacy_backfill(connection, overrides, ip_policy=ip_policy)
    except BackfillBlockedError as exc:
        print(exc.message, file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    except DevicePolicyError as exc:
        print(f"이관 실패: {exc.message}", file=sys.stderr)
        return 2
    finally:
        connection.close()

    print(f"[dry-run] 생성 예정: {list(plan.to_create)}, 이미 있음: {list(plan.already_revised)}")
    for problem in plan.problems:
        print(f"  - {problem}", file=sys.stderr)
    if plan.problems:
        print("[dry-run] 문제가 있어 --apply가 거부됩니다.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
