from datetime import datetime, timezone

import pytest

from edge.detection.packet_checkpoint_recovery import (
    PacketCheckpointRecoveryError,
    attach_plan_sha256,
    verify_plan_sha256,
)


UTC_A = datetime(2026, 8, 6, 10, 0, 0, tzinfo=timezone.utc)
UTC_B = datetime(2026, 8, 6, 11, 0, 0, tzinfo=timezone.utc)
OTHER_UTC = "2026-08-06T12:00:00Z"


def test_canonical_plan_sha_is_independent_of_key_order_and_volatile_fields() -> None:
    payload = {
        "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
        "repository_commit": "a" * 40,
        "repository_root": "/repo",
        "database_path": "/data/iot.db",
        "detector_name": "packet_rule",
        "source_table": "packet_feature_logs",
    }
    first = attach_plan_sha256(payload, generated_at=UTC_A)
    second = attach_plan_sha256(dict(reversed(tuple(payload.items()))), generated_at=UTC_B)

    assert first["plan_sha256"] == second["plan_sha256"]


def test_verify_plan_sha256_rejects_bound_field_tampering() -> None:
    plan = attach_plan_sha256(
        {
            "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
            "repository_commit": "a" * 40,
            "repository_root": "/repo",
            "database_path": "/data/iot.db",
            "detector_name": "packet_rule",
            "source_table": "packet_feature_logs",
            "checkpoint": {
                "before": {"last_completed_window_end": "2026-08-06T10:00:00Z"},
                "after": {"last_completed_window_end": "2026-08-06T11:00:00Z"},
            },
        },
        generated_at=UTC_A,
    )
    plan["checkpoint"]["after"]["last_completed_window_end"] = OTHER_UTC

    with pytest.raises(PacketCheckpointRecoveryError, match="plan SHA256"):
        verify_plan_sha256(plan)
