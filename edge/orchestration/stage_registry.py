"""운영 Stage 구성입니다.

`enabled`/`required` 환경값을 실제 Detector Stage 객체 목록으로 변환합니다.

- `enabled`: 이 Cycle에서 실행할 Stage
- `required`: 완료 Barrier에 포함되는 Stage. 하나라도 cutoff까지 완료되지 않으면
  Trust Score를 호출하지 않는다

Packet Rule·Packet IF Stage는 아직 `develop`에 없습니다(P4-2-01, P4-3-01). 설정으로
켜려고 하면 조용히 무시하지 않고 즉시 오류를 냅니다. Packet 계층을 Barrier에 넣은 채
Stage가 없으면 Trust가 영구히 호출되지 않기 때문입니다.
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

MQTT_FEATURE_RULE = "mqtt_feature_rule"
MQTT_MESSAGE_RULE = "mqtt_message_rule"
MQTT_IF = "mqtt_if"
PACKET_RULE = "packet_rule"
PACKET_IF = "packet_if"

MQTT_STAGE_NAMES = (MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE, MQTT_IF)
PACKET_STAGE_NAMES = (PACKET_RULE, PACKET_IF)
KNOWN_STAGE_NAMES = MQTT_STAGE_NAMES + PACKET_STAGE_NAMES

STAGE_BUILDERS: dict[str, Callable[[], DetectorStage]] = {
    MQTT_FEATURE_RULE: MqttFeatureRuleStage,
    MQTT_MESSAGE_RULE: MqttMessageRuleStage,
    MQTT_IF: MqttIsolationForestStage,
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
            + " (Packet Rule은 P4-2-01, Packet IF는 P4-3-01 병합 후 사용 가능)"
        )

    if not enabled_names:
        raise StageConfigurationError("at least one stage must be enabled")

    stages = tuple(
        ConfiguredStage(
            name=name,
            stage=STAGE_BUILDERS[name](),
            required=name in required_names,
        )
        for name in enabled_names
    )
    return StageRegistry(stages=stages)


def load_stage_registry(app_settings: Settings = settings) -> StageRegistry:
    return build_stage_registry(
        enabled=parse_stage_names(app_settings.orchestrator_enabled_stages),
        required=parse_stage_names(app_settings.orchestrator_required_stages),
    )
