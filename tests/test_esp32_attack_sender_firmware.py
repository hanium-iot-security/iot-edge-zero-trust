from pathlib import Path


FIRMWARE = Path("firmware/esp32/attack_sender/attack_sender.ino")
RUNBOOK = Path("docs/phase4-esp32-attack-test-runbook.md")
README = Path("firmware/esp32/README.md")


def _source() -> str:
    return FIRMWARE.read_text(encoding="utf-8")


def test_attack_sender_is_disabled_by_default_and_targets_registered_test_device() -> None:
    source = _source()

    assert "const bool ATTACK_TEST_ENABLED = false;" in source
    assert 'const char* DEVICE_ID = "esp32_02";' in source
    assert 'const char* MQTT_BROKER = "192.168.0.20";' in source
    assert "const int MQTT_PORT = 1883;" in source
    assert 'const char* MQTT_TOPIC = "iot/esp32_02/sensor";' in source


def test_attack_sender_has_bounded_four_window_contract() -> None:
    source = _source()

    assert "const unsigned int MESSAGES_PER_BURST = 40;" in source
    assert "const unsigned int MAX_BURSTS = 4;" in source
    assert "const unsigned long PUBLISH_INTERVAL_MS = 50;" in source
    assert "const unsigned long BURST_START_INTERVAL_MS = 10000;" in source
    assert "const unsigned long MAX_TEST_DURATION_MS = 45000;" in source
    assert "burstIndex < MAX_BURSTS" in source
    assert "messageIndex < MESSAGES_PER_BURST" in source


def test_attack_sender_has_separate_bounded_isolation_observation_contract() -> None:
    source = _source()

    assert "const unsigned long OBSERVATION_TIMEOUT_MS = 45000;" in source
    assert "const unsigned long OBSERVATION_PROBE_INTERVAL_MS = 5000;" in source
    assert "const unsigned int MAX_OBSERVATION_PROBES = 9;" in source
    assert "const unsigned int OBSERVATION_CONNECT_TIMEOUT_SECONDS = 5;" in source
    assert "void runBoundedIsolationObservation()" in source
    assert "observationProbeCount < MAX_OBSERVATION_PROBES" in source
    assert "mqttClient.setSocketTimeout(OBSERVATION_CONNECT_TIMEOUT_SECONDS);" in source
    assert "mqttConnectWithCredentials(\"phase4_observation_esp32_02\")" in source
    assert source.count('mqttConnectWithCredentials("phase4_observation_esp32_02")') == 1
    setup_body = source[source.index("void setup()") : source.index("void loop()")]
    assert setup_body.count("runBoundedFloodTest();") == 1
    assert setup_body.count("runBoundedIsolationObservation();") == 1
    assert setup_body.index("runBoundedFloodTest();") < setup_body.index(
        "runBoundedIsolationObservation();"
    )
    observation_body = source[
        source.index("void runBoundedIsolationObservation()") : source.index("void setup()")
    ]
    assert "runBoundedFloodTest" not in observation_body


def test_attack_sender_rejects_public_broker_and_runs_once_per_boot() -> None:
    source = _source()

    assert "bool isPrivateBrokerAddress()" in source
    assert "isPrivateBrokerAddress()" in source
    assert "bool testExecuted = false;" in source
    assert "testExecuted = true;" in source
    assert "if (testExecuted)" in source


def test_attack_sender_has_bounded_connection_attempts_and_no_restart_loop() -> None:
    source = _source()

    assert "const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;" in source
    assert "const unsigned long MQTT_CONNECT_TIMEOUT_MS = 10000;" in source
    assert "const unsigned int MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS = 3;" in source
    assert "const unsigned int MQTT_CONNECT_MAX_ATTEMPTS = 2;" in source
    connect_body = source[
        source.index("bool connectMqttWithTimeout()") : source.index(
            "String buildCanonicalPayload()"
        )
    ]
    assert connect_body.index(
        "mqttClient.setSocketTimeout(MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS);"
    ) < connect_body.index('mqttConnectWithCredentials("phase4_attack_esp32_02")')
    assert "mqttConnectAttempt < MQTT_CONNECT_MAX_ATTEMPTS" in connect_body
    assert "while (true)" not in source
    assert "ESP.restart()" not in source


def test_attack_sender_uses_the_normal_canonical_payload_schema() -> None:
    source = _source()

    assert "String buildCanonicalPayload()" in source
    assert 'return String("{\\"device_id\\":\\"") + DEVICE_ID + "\\"}";' in source
    for field in ("temperature", "humidity", "sequence", "burst"):
        assert f'\\"{field}\\"' not in source


def test_attack_sender_records_observation_failure_and_disconnects_safely() -> None:
    source = _source()

    assert "first_failure_run_elapsed_ms=" in source
    assert "mqtt_state=" in source
    assert "publish_result=" in source
    assert "reconnect_result=" in source
    assert '"connection_lost"' in source
    assert '"not_attempted"' in source
    assert "run_elapsed_ms=" in source
    assert "observation_elapsed_ms=" in source
    assert "mqttClient.disconnect();" in source
    assert "WiFi.disconnect(false);" in source


def test_runbook_covers_registered_ip_services_and_private_test_scope() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "devices.ip_address" in text
    assert "esp32_02" in text
    assert "192.168.0.20" in text
    assert "사설 테스트 LAN" in text
    assert "packet-capture.service" in text
    assert "mqtt-feature-builder.service" in text
    assert "detection-orchestrator.service" in text
    assert "firewall-worker.service" in text


def test_runbook_covers_four_windows_evidence_and_normal_recovery() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "analysis_window_start" in text
    assert "analysis_window_end" in text
    assert "4회 Burst가 정확히 4개 Window를 보장하지 않습니다" in text
    assert "ABNORMAL_PUBLISH_RATE" in text
    assert "PENDING" in text
    assert "APPLIED" in text
    assert "normal_sender.ino" in text
    assert "정상 Publish 재개" in text
    assert "미검증" in text


def test_runbook_requires_subscriber_and_pipeline_preflight() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "edge/scripts/run_subscriber.sh" in text
    assert "python -m edge.mqtt.subscriber" in text
    assert "Subscriber Gate" in text
    assert "Preflight" in text
    assert "mqtt_logs" in text
    assert "feature_logs" in text
    assert "mqtt_feature_builder+mqtt_logs" in text
    assert "mqtt_feature_rule+feature_logs" in text
    assert "mqtt_message_rule+mqtt_logs" in text
    assert "PREFLIGHT_STARTED_AT_UTC" in text
    assert "PREFLIGHT_MQTT_ID" in text
    assert "PREFLIGHT_FEATURE_ID" in text
    assert "PREFLIGHT_WINDOW_END" in text
    assert "topic = 'iot/esp32_02/sensor'" in text
    assert "payload = '{\\\"device_id\\\":\\\"esp32_02\\\"}'" in text
    assert "last_processed_id >= $PREFLIGHT_MQTT_ID" in text
    assert "last_processed_id >= $PREFLIGHT_FEATURE_ID" in text


def test_runbook_scopes_live_evidence_to_the_current_run() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "RUN_STARTED_AT_UTC" in text
    assert "DETECTION_ID_BEFORE" in text
    assert "TRUST_HISTORY_ID_BEFORE" in text
    assert "FIREWALL_RULE_ID_BEFORE" in text
    assert "id > $DETECTION_ID_BEFORE" in text
    assert "id > $TRUST_HISTORY_ID_BEFORE" in text
    assert "id > $FIREWALL_RULE_ID_BEFORE" in text
    assert "detected_at" in text


def test_runbook_enforces_baseline_and_reset_gates() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "Baseline Gate" in text
    assert "status = 'normal'" in text
    assert "trust_score = 100" in text
    assert "PENDING" in text
    assert "APPLIED" in text
    assert "HOLD" in text
    assert "RESET_FAILED" in text
    assert "승인된 Trust·Device Baseline Reset 절차는 아직 없습니다" in text
    assert "다음 Run을 시작하지 않습니다" in text


def test_firmware_readme_links_attack_sender_and_runbook() -> None:
    text = README.read_text(encoding="utf-8")

    assert "attack_sender/attack_sender.ino" in text
    assert "docs/phase4-esp32-attack-test-runbook.md" in text
