"""Composition adapter for the Recovery runtime firewall verifier.

The API process stays unprivileged. It reads the short-lived observation file
written by the dedicated firewall runtime snapshot service and delegates the
validation rules to ``edge.trust.firewall_runtime_snapshot``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.app.config import settings
from edge.trust.firewall_runtime_snapshot import verify_firewall_runtime_snapshot


def verify_runtime_firewall(device: Mapping[str, Any]) -> dict[str, Any]:
    return verify_firewall_runtime_snapshot(
        device,
        snapshot_path=settings.firewall_runtime_snapshot_path,
        max_age_seconds=settings.firewall_runtime_snapshot_max_age_seconds,
    )
