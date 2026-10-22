"""Phase 9 per-device AI eligibility at an original UTC analysis window.

Storage is deliberately supplied as an immutable snapshot. The migration owner
defines persistence; this module never treats a missing revision as OFF.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from edge.policy.resolver import POLICY_AVAILABLE, PolicyResolution, require_window_start


AI_OFF = "OFF"
AI_OBSERVE = "OBSERVE"
AI_ALLOWED_MODES = frozenset((AI_OFF, AI_OBSERVE))


def require_observe_trust_mode(trust_ai_mode: str) -> None:
    if trust_ai_mode != "observe":
        raise ValueError("Phase 9 AI activation requires TRUST_AI_MODE=observe")


@dataclass(frozen=True)
class AIRevision:
    device_id: str
    revision: int
    mode: str
    effective_from: datetime


@dataclass(frozen=True)
class AIWindowDecision:
    device_id: str
    window_start: datetime
    mode: str | None
    ai_revision: int | None
    approved_start: datetime | None
    reason: str

    @property
    def infer(self) -> bool:
        return self.reason == "AI_OBSERVE_READY"


def decide_ai_window(
    policy: PolicyResolution,
    revisions: Iterable[AIRevision],
    *,
    stage_activation_from: datetime | None,
) -> AIWindowDecision:
    """Resolve one device without borrowing current registration or another mode."""
    window_start = require_window_start(policy.window_start)

    def result(reason: str, *, mode: str | None = None,
               revision: int | None = None,
               approved_start: datetime | None = None) -> AIWindowDecision:
        return AIWindowDecision(policy.device_id, window_start, mode, revision,
                                approved_start, reason)

    if policy.registration is None:
        return result(policy.reason)
    if policy.registration.status == "DISABLED":
        return result("DISABLED_AT_WINDOW")
    if policy.reason != POLICY_AVAILABLE:
        return result(policy.reason)

    try:
        rows = sorted((row for row in revisions if row.device_id == policy.device_id),
                      key=lambda row: (row.effective_from, row.revision))
        if not rows:
            return result("AI_POLICY_UNAVAILABLE")
        # A scheduled or later corrupt revision cannot change the verdict of an
        # already completed source window. Validate only the historical prefix.
        effective = [row for row in rows if row.effective_from <= window_start]
        if not effective:
            return result("AI_POLICY_NOT_EFFECTIVE")
        for index, row in enumerate(effective, start=1):
            require_window_start(row.effective_from)
            if (type(row.revision) is not int or row.revision != index
                    or row.mode not in AI_ALLOWED_MODES
                    or (index > 1 and row.effective_from <= effective[index - 2].effective_from)):
                return result("INVALID_AI_REVISION")
    except (TypeError, ValueError):
        return result("INVALID_AI_REVISION")
    current = effective[-1]
    if current.mode == AI_OFF:
        return result("AI_OFF_AT_WINDOW", mode=AI_OFF, revision=current.revision)
    if stage_activation_from is None:
        return result("AI_STAGE_NOT_ACTIVATED", mode=AI_OBSERVE,
                      revision=current.revision)
    try:
        activation = require_window_start(stage_activation_from)
    except ValueError:
        return result("INVALID_AI_STAGE_ACTIVATION", mode=AI_OBSERVE,
                      revision=current.revision)
    start = max(policy.registration.effective_from, current.effective_from, activation)
    if window_start < start:
        return result("BEFORE_APPROVED_AI_START", mode=AI_OBSERVE,
                      revision=current.revision, approved_start=start)
    return result("AI_OBSERVE_READY", mode=AI_OBSERVE,
                  revision=current.revision, approved_start=start)
