from datetime import datetime, timedelta, timezone

import pytest

from edge.policy.ai_window_decision import AIRevision, decide_ai_window
from edge.policy.resolver import (
    DevicePolicyResolver,
    DevicePolicyRevision,
    RegistrationRevision,
)


START = datetime(2026, 10, 10, 0, 0, 0, tzinfo=timezone.utc)


def at(seconds: int) -> datetime:
    return START + timedelta(seconds=seconds)


def base_policy(*, registration_state: str = "ACTIVE") -> DevicePolicyResolver:
    return DevicePolicyResolver(
        [RegistrationRevision("esp32_02", registration_state, at(0))],
        [DevicePolicyRevision("esp32_02", 1, at(0), 15, 5120, 10, 2500)],
    )


def decision(window: int, revisions: list[AIRevision], *, activation: int | None = 0,
             state: str = "ACTIVE"):
    return decide_ai_window(
        base_policy(registration_state=state).resolve("esp32_02", at(window)),
        revisions,
        stage_activation_from=at(activation) if activation is not None else None,
    )


def test_off_observe_off_use_original_window_not_processing_time() -> None:
    revisions = [
        AIRevision("esp32_02", 1, "OFF", at(0)),
        AIRevision("esp32_02", 2, "OBSERVE", at(10)),
        AIRevision("esp32_02", 3, "OFF", at(20)),
    ]
    assert decision(0, revisions).reason == "AI_OFF_AT_WINDOW"
    assert decision(10, revisions).infer
    assert decision(20, revisions).reason == "AI_OFF_AT_WINDOW"
    # The delayed 00:00:00 window remains OFF after both later revisions exist.
    assert not decision(0, revisions).infer


def test_latest_approved_registration_mode_and_stage_boundary_wins() -> None:
    revisions = [AIRevision("esp32_02", 1, "OBSERVE", at(0))]
    assert decision(10, revisions, activation=20).reason == "BEFORE_APPROVED_AI_START"
    assert decision(20, revisions, activation=20).approved_start == at(20)
    assert decision(20, revisions, activation=20).infer


@pytest.mark.parametrize("mode", ["ENFORCE", "observe", "", "OFF/OBSERVE", None, ["OBSERVE"]])
def test_unsupported_mode_is_not_silently_interpreted_as_off(mode: str) -> None:
    assert decision(0, [AIRevision("esp32_02", 1, mode, at(0))]).reason == "INVALID_AI_REVISION"


def test_missing_and_corrupt_revision_are_distinct() -> None:
    assert decision(0, []).reason == "AI_POLICY_UNAVAILABLE"
    assert decision(0, [AIRevision("esp32_02", 2, "OBSERVE", at(0))]).reason == "INVALID_AI_REVISION"
    assert decision(0, [AIRevision("esp32_02", 1, "OBSERVE", at(0))], activation=None).reason == "AI_STAGE_NOT_ACTIVATED"


def test_future_corrupt_revision_does_not_change_past_off_window() -> None:
    revisions = [
        AIRevision("esp32_02", 1, "OFF", at(0)),
        AIRevision("esp32_02", 2, "ENFORCE", at(20)),
    ]
    assert decision(0, revisions).reason == "AI_OFF_AT_WINDOW"
    assert decision(10, revisions).reason == "AI_OFF_AT_WINDOW"
    assert decision(20, revisions).reason == "INVALID_AI_REVISION"


def test_disabled_is_excluded_but_pending_can_feed_predictor() -> None:
    revisions = [AIRevision("esp32_02", 1, "OBSERVE", at(0))]
    assert decision(0, revisions, state="DISABLED").reason == "DISABLED_AT_WINDOW"
    assert decision(0, revisions, state="PENDING").infer


@pytest.mark.parametrize("effective_from", [at(20).replace(tzinfo=None), "2026-10-10T00:00:20Z", None])
def test_uncomparable_revision_time_excludes_only_its_device(effective_from) -> None:
    revisions = [
        AIRevision("esp32_02", 1, "OFF", at(0)),
        AIRevision("esp32_02", 2, "OBSERVE", effective_from),
    ]
    assert decision(0, revisions).reason == "INVALID_AI_REVISION"
    revisions[-1] = AIRevision("esp32_03", 2, "OBSERVE", effective_from)
    assert decision(0, revisions).reason == "AI_OFF_AT_WINDOW"


def test_mixed_revision_types_at_same_boundary_are_invalid() -> None:
    revisions = [
        AIRevision("esp32_02", 1, "OFF", at(0)),
        AIRevision("esp32_02", "2", "OBSERVE", at(0)),
    ]
    assert decision(0, revisions).reason == "INVALID_AI_REVISION"
