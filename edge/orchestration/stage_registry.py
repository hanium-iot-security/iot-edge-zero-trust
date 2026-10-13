"""운영 Stage 구성입니다.

`enabled`/`required` 환경값을 실제 Detector Stage 객체 목록으로 변환합니다.

- `enabled`: 이 Cycle에서 실행할 Stage
- `required`: 완료 Barrier에 포함되는 Stage. 하나라도 cutoff까지 완료되지 않으면
  Trust Score를 호출하지 않는다

Packet Rule은 설정만으로 활성화할 수 있습니다. Packet IF는 배포할 Model Artifact의
경로·Version·SHA256을 모두 설정한 경우에만 활성화하며, 설정이 빠졌거나 Artifact 검증에
실패하면 시작 단계에서 명시적인 구성 오류를 냅니다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from backend.app.config import Settings, settings
from edge.detection.detector_contract import DetectorStage
from edge.detection.mqtt_adapters import (
    MqttFeatureRuleStage,
    MqttIsolationForestStage,
    MqttMessageRuleStage,
)
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.packet_rule_detector import (
    PacketRuleDetectorStage,
    PacketRulePolicy,
)
from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
from edge.packet.capture_policy import CapturePolicy

MQTT_FEATURE_RULE = "mqtt_feature_rule"
MQTT_MESSAGE_RULE = "mqtt_message_rule"
MQTT_IF = "mqtt_if"
PACKET_RULE = "packet_rule"
PACKET_IF = "packet_if"

MQTT_STAGE_NAMES = (MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE, MQTT_IF)
PACKET_STAGE_NAMES = (PACKET_RULE, PACKET_IF)
KNOWN_STAGE_NAMES = MQTT_STAGE_NAMES + PACKET_STAGE_NAMES

StageBuilder = Callable[[Settings], DetectorStage]


def _capture_policy(app_settings: Settings) -> CapturePolicy:
    return CapturePolicy(
        max_start_delay_seconds=app_settings.pcap_max_start_delay_seconds,
        minimum_duration_seconds=app_settings.packet_min_capture_duration_seconds,
        epsilon_seconds=app_settings.capture_time_epsilon_seconds,
        version=app_settings.capture_policy_version,
    )


def _packet_rule_policy(app_settings: Settings) -> PacketRulePolicy:
    return PacketRulePolicy.from_settings(app_settings)


def _build_packet_rule(app_settings: Settings) -> DetectorStage:
    return PacketFeatureReadyStage(
        PacketRuleDetectorStage(
            capture_policy=_capture_policy(app_settings),
            rule_policy=_packet_rule_policy(app_settings),
        )
    )


def _build_packet_if(app_settings: Settings) -> DetectorStage:
    return PacketFeatureReadyStage(
        PacketIsolationForestStage.from_settings(
            app_settings=app_settings,
            capture_policy=_capture_policy(app_settings),
        )
    )


STAGE_BUILDERS: dict[str, StageBuilder] = {
    MQTT_FEATURE_RULE: lambda _settings: MqttFeatureRuleStage(),
    MQTT_MESSAGE_RULE: lambda _settings: MqttMessageRuleStage(),
    MQTT_IF: lambda app_settings: MqttIsolationForestStage.from_settings(app_settings=app_settings),
    PACKET_RULE: _build_packet_rule,
    PACKET_IF: _build_packet_if,
}


class StageConfigurationError(Exception):
    """Stage 설정이 실행 불가능한 상태입니다."""


@dataclass(frozen=True)
class ConfiguredStage:
    name: str
    stage: DetectorStage
    required: bool


@dataclass(frozen=True)
class StageRegistry:
    stages: tuple[ConfiguredStage, ...]

    @property
    def detector_stages(self) -> tuple[DetectorStage, ...]:
        return tuple(configured.stage for configured in self.stages)

    @property
    def required_stages(self) -> tuple[ConfiguredStage, ...]:
        return tuple(configured for configured in self.stages if configured.required)

    @property
    def enabled_names(self) -> tuple[str, ...]:
        return tuple(configured.name for configured in self.stages)

    @property
    def required_names(self) -> tuple[str, ...]:
        return tuple(configured.name for configured in self.required_stages)

    @property
    def packet_layer_enabled(self) -> bool:
        return any(name in PACKET_STAGE_NAMES for name in self.enabled_names)

    @property
    def packet_layer_required(self) -> bool:
        return any(name in PACKET_STAGE_NAMES for name in self.required_names)


def parse_stage_names(raw: str) -> tuple[str, ...]:
    """쉼표 구분 설정값을 순서 유지·중복 제거된 Stage 이름 목록으로 변환합니다."""
    names: list[str] = []
    for part in raw.split(","):
        name = part.strip()
        if not name:
            continue
        if name not in KNOWN_STAGE_NAMES:
            raise StageConfigurationError(
                f"unknown stage name: {name!r} (known={', '.join(KNOWN_STAGE_NAMES)})"
            )
        if name not in names:
            names.append(name)
    return tuple(names)


def build_stage_registry(
    *,
    enabled: Sequence[str],
    required: Sequence[str],
    app_settings: Settings = settings,
) -> StageRegistry:
    enabled_names = tuple(enabled)
    required_names = set(required)

    missing_required = required_names - set(enabled_names)
    if missing_required:
        raise StageConfigurationError(
            "required stages must also be enabled: "
            + ", ".join(sorted(missing_required))
        )

    unavailable = [name for name in enabled_names if name not in STAGE_BUILDERS]
    if unavailable:
        raise StageConfigurationError(
            "stage is not implemented on this revision yet: "
            + ", ".join(unavailable)
        )

    if not enabled_names:
        raise StageConfigurationError("at least one stage must be enabled")

    configured_stages: list[ConfiguredStage] = []
    for name in enabled_names:
        try:
            stage = STAGE_BUILDERS[name](app_settings)
        except (OSError, ValueError) as exc:
            raise StageConfigurationError(
                f"failed to configure stage {name!r}: {exc}"
            ) from exc
        configured_stages.append(
            ConfiguredStage(
                name=name,
                stage=stage,
                required=name in required_names,
            )
        )
    return StageRegistry(stages=tuple(configured_stages))


def load_stage_registry(app_settings: Settings = settings) -> StageRegistry:
    return build_stage_registry(
        enabled=parse_stage_names(app_settings.orchestrator_enabled_stages),
        required=parse_stage_names(app_settings.orchestrator_required_stages),
        app_settings=app_settings,
    )
