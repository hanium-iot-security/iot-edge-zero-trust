from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.app.config import Settings
from edge.detection.packet_rule_detector import PacketRulePolicy
from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
from edge.orchestration.stage_registry import PACKET_RULE, build_stage_registry


def _settings(raw_excluded_peer_ips: str) -> SimpleNamespace:
    return SimpleNamespace(
        packet_rule_packet_rate_threshold=50.0,
        packet_rule_byte_rate_threshold=100_000.0,
        packet_rule_port_scan_distinct_port_threshold=15,
        packet_rule_port_scan_syn_threshold=15,
        packet_rule_broker_dos_tcp_syn_threshold=30,
        packet_rule_broker_dos_mqtt_packet_threshold=100,
        packet_rule_policy_version="packet-rule-policy-test-v1",
        packet_rule_excluded_peer_ips=raw_excluded_peer_ips,
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", frozenset()),
        ("   ", frozenset()),
        ("192.168.0.3", frozenset({"192.168.0.3"})),
        (
            " 192.168.0.3, 192.168.0.10 ,192.168.0.3 ",
            frozenset({"192.168.0.3", "192.168.0.10"}),
        ),
    ],
)
def test_from_settings_parses_excluded_peer_ips(
    raw: str,
    expected: frozenset[str],
) -> None:
    policy = PacketRulePolicy.from_settings(_settings(raw))

    assert policy.excluded_peer_ips == expected


@pytest.mark.parametrize(
    "raw",
    [
        "not-an-ip",
        "192.168.0.999",
        "192.168.0.3,invalid",
        "192.168.0.0/24",
    ],
)
def test_from_settings_rejects_invalid_excluded_peer_ip(raw: str) -> None:
    with pytest.raises(ValueError, match="excluded_peer_ips"):
        PacketRulePolicy.from_settings(_settings(raw))


def test_settings_exposes_common_packet_rule_exclusion_name() -> None:
    app_settings = Settings(
        packet_rule_excluded_peer_ips="192.168.0.3",
    )

    assert app_settings.packet_rule_excluded_peer_ips == "192.168.0.3"


def test_orchestrator_packet_rule_stage_receives_common_exclusion() -> None:
    app_settings = Settings(
        orchestrator_enabled_stages=PACKET_RULE,
        orchestrator_required_stages=PACKET_RULE,
        packet_rule_excluded_peer_ips="192.168.0.3",
        packet_rule_policy_version="packet-rule-policy-v2",
    )

    registry = build_stage_registry(
        enabled=(PACKET_RULE,),
        required=(PACKET_RULE,),
        app_settings=app_settings,
    )

    configured = registry.stages[0]
    assert isinstance(configured.stage, PacketFeatureReadyStage)
    assert configured.stage.delegate.rule_policy.excluded_peer_ips == frozenset(
        {"192.168.0.3"}
    )
