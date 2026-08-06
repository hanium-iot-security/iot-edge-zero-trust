"""Canonical plan helpers for packet checkpoint gap recovery."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Mapping

from edge.detection.phase4_time import format_db_utc


PLAN_SCHEMA_VERSION = "packet-checkpoint-gap-recovery-plan-v1"
_VOLATILE_PLAN_KEYS = frozenset({
    "plan_sha256", "generated_at", "executed_at", "operation_id", "mode",
    "plan_path", "artifact_dir", "backup_path", "result_path", "backup_sha256",
    "execute_command", "repository_branch", "file_mtime_ns", "data_version",
    "process_id", "lock_acquired_at", "post_commit_verified_at",
})


class PacketCheckpointRecoveryError(Exception):
    """Raised when a packet checkpoint recovery plan is invalid."""


def _without_volatile_fields(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _without_volatile_fields(item)
            for key, item in value.items()
            if key not in _VOLATILE_PLAN_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_without_volatile_fields(item) for item in value]
    return value


def canonical_plan_binding(plan: Mapping[str, object]) -> dict[str, object]:
    binding = _without_volatile_fields(plan)
    if not isinstance(binding, dict):
        raise PacketCheckpointRecoveryError("canonical plan must be an object")
    return binding


def canonical_plan_json(plan: Mapping[str, object]) -> str:
    return json.dumps(
        canonical_plan_binding(plan),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_plan_sha256(plan: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_plan_json(plan).encode("utf-8")).hexdigest()


def attach_plan_sha256(
    payload: Mapping[str, object], *, generated_at: datetime
) -> dict[str, object]:
    plan = {**payload, "generated_at": format_db_utc(generated_at)}
    return {**plan, "plan_sha256": calculate_plan_sha256(plan)}


def verify_plan_sha256(plan: Mapping[str, object]) -> None:
    expected = plan.get("plan_sha256")
    actual = calculate_plan_sha256(plan)
    if not isinstance(expected, str) or not hmac.compare_digest(expected, actual):
        raise PacketCheckpointRecoveryError("plan SHA256 mismatch")
