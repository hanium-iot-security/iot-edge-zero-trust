#!/usr/bin/env bash
set -euo pipefail

# Phase 4 MQTT Feature Producer.
# Feature 저장과 Producer Checkpoint 갱신을 같은 Transaction으로 처리한다.
# 기존 collect_feature_logs CLI는 Checkpoint를 갱신하지 않으므로 함께 실행하지 않는다.
# 신규 DB는 먼저 --bootstrap으로 시작 시점을 정한다:
#   python -m edge.features.run_mqtt_feature_builder \
#     --bootstrap --confirm BOOTSTRAP-MQTT-FEATURE-CHECKPOINT

python -m edge.features.run_mqtt_feature_builder --loop
