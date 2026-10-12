"""AI 설정 도입 전부터 있던 기기에 초기 AI 모드 revision을 만든다(P9-03).

기본은 dry-run이다. `--apply`를 줘야 DB를 변경한다. 운영 DB에서 바로 실행하지 말고 먼저
일관된 백업의 복사본으로 dry-run과 `--apply`를 확인한다.

    python -m db.backfill_device_ai_policies --db copy.db --manifest manifest.json
    python -m db.backfill_device_ai_policies --db copy.db --manifest manifest.json --apply

승인 목록(JSON, 비밀값 없음):

    {
      "schema_version": "device-ai-policy-backfill-v1",
      "effective_from": "2026-10-12T00:00:00Z",   // UTC, 10초 경계
      "reason": "AI 설정 이관 승인 <id>",
      "devices": [
        {"device_id": "esp32_01", "mode": "OBSERVE", "source": "approval:<id>"}
      ]
    }

DB의 모든 기기가 목록에 있어야 한다. 하나라도 빠지면 아무것도 변경하지 않는다.
종료 코드: 0 성공(또는 dry-run 문제 없음), 2 입력 오류·사전 조건 미충족.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db.migration_runner import connect_database  # noqa: E402
from edge.policy.device_ai_policy_backfill import (  # noqa: E402
    LegacyAiOverride,
    apply_ai_backfill,
    parse_ai_override,
    plan_ai_backfill,
)
from edge.policy.device_policy import (  # noqa: E402
    BackfillBlockedError,
    DevicePolicyError,
    DevicePolicyValidationError,
    parse_effective_from,
    validate_reason,
)

MANIFEST_SCHEMA_VERSION = "device-ai-policy-backfill-v1"
_MANIFEST_FIELDS = {"schema_version", "effective_from", "reason", "devices"}


def load_manifest(path: Path) -> tuple[dict[str, LegacyAiOverride], datetime, str]:
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
        raise DevicePolicyValidationError(f"schema_version must be {MANIFEST_SCHEMA_VERSION!r}")

    effective_from = parse_effective_from(raw.get("effective_from"))
    reason = validate_reason(raw.get("reason"))
    devices_raw = raw.get("devices")
    if not isinstance(devices_raw, list) or not devices_raw:
        raise DevicePolicyValidationError("devices must be a non-empty list")
    overrides: dict[str, LegacyAiOverride] = {}
    for item in devices_raw:
        override = parse_ai_override(item)
        if override.device_id in overrides:
            raise DevicePolicyValidationError(f"duplicate device in manifest: {override.device_id}")
        overrides[override.device_id] = override
    return overrides, effective_from, reason


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
        overrides, effective_from, reason = load_manifest(args.manifest)
    except DevicePolicyError as exc:
        print(f"manifest 오류: {exc.message}", file=sys.stderr)
        return 2

    connection = connect_database(args.db)
    try:
        if args.apply:
            result = apply_ai_backfill(
                connection, overrides, effective_from=effective_from, reason=reason
            )
            print(f"이관 완료: created={list(result.created)}, "
                  f"already_revised={list(result.already_revised)}")
            return 0
        plan = plan_ai_backfill(connection, overrides)
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
