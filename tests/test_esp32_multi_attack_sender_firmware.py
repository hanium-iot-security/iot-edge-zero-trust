from pathlib import Path


FIRMWARE = Path("firmware/esp32/multi_attack_sender/multi_attack_sender.ino")
CONFIG_EXAMPLE = Path(
    "firmware/esp32/multi_attack_sender/multi_attack_firmware_config.example.h"
)
MQTT_CREDENTIALS_EXAMPLE = Path(
    "firmware/esp32/multi_attack_sender/mqtt_credentials.example.h"
)
README = Path("firmware/esp32/multi_attack_sender/README.md")


def _source() -> str:
    return FIRMWARE.read_text(encoding="utf-8")


def _function_body(source: str, start: str, end: str) -> str:
    return source[source.index(start) : source.index(end)]


def test_local_config_requires_explicit_enable_and_only_contains_wifi_secrets() -> None:
    config = CONFIG_EXAMPLE.read_text(encoding="utf-8")

    assert "MULTI_ATTACK_CONFIGURED" in config
    assert "MULTI_ATTACK_TEST_ENABLED" in config
    assert "MULTI_ATTACK_WIFI_SSID" in config
    assert "MULTI_ATTACK_WIFI_PASSWORD" in config

    for forbidden in (
        "MULTI_ATTACK_DEVICE_ID",
        "MULTI_ATTACK_EXPECTED_LOCAL_IP",
        "MULTI_ATTACK_TARGET_IP",
        "MULTI_ATTACK_MQTT_TOPIC",
        "MULTI_ATTACK_TARGET_UDP_PORT",
    ):
        assert forbidden not in config


def test_lab_identity_and_endpoints_are_fixed_in_firmware() -> None:
    source = _source()

    assert 'const char* DEVICE_ID = "esp32_02";' in source
    assert 'const char* SPOOFED_DEVICE_ID = "esp32_01";' in source
    assert 'const char* EXPECTED_LOCAL_IP_TEXT = "192.168.0.5";' in source
    assert 'const char* TARGET_IP_TEXT = "192.168.0.20";' in source
    assert 'const char* MQTT_TOPIC = "iot/esp32_02/sensor";' in source
    assert "const uint16_t MQTT_PORT = 1883U;" in source
    assert "const uint16_t TARGET_UDP_PORT = 19999U;" in source
    assert "const uint16_t LOCAL_UDP_PORT = 42100U;" in source


def test_firmware_never_auto_starts_and_exposes_demo_and_diagnostic_commands() -> None:
    source = _source()

    assert 'Serial.println("auto_start=false");' in source
    assert 'Serial.println("RUN_DEMO");' in source
    assert 'Serial.println("RUN IDENTITY_MISMATCH");' in source
    assert 'Serial.println("RUN MALFORMED_PAYLOAD");' in source
    assert 'Serial.println("RUN PACKET_RATE");' in source
    assert 'Serial.println("RUN MQTT_FLOOD");' in source
    assert 'Serial.println("STATUS");' in source
    assert 'Serial.println("ABORT");' in source

    setup_body = _function_body(source, "void setup()", "void loop()")
    assert "runDemoSequence(" not in setup_body
    assert "runIdentityMismatchAttack(" not in setup_body
    assert "runMalformedPayloadAttack(" not in setup_body
    assert "runPacketRateAttack(" not in setup_body
    assert "runMqttFloodAttack(" not in setup_body


def test_run_demo_executes_four_attacks_once_in_the_approved_order() -> None:
    source = _source()
    demo_body = _function_body(source, "void runDemoSequence()", "void runIndividualAttack")

    calls = (
        "runIdentityMismatchAttack()",
        "runMalformedPayloadAttack()",
        "runPacketRateAttack()",
        "runMqttFloodAttack()",
    )
    for call in calls:
        assert demo_body.count(call) == 1

    positions = [demo_body.index(call) for call in calls]
    assert positions == sorted(positions)
    assert "demoExecuted = true;" in demo_body
    assert 'demo_rejected reason=already_executed_this_boot' in source
    assert "runBoundedIsolationObservation();" in demo_body


def test_demo_aligns_each_attack_to_a_distinct_utc_ten_second_window() -> None:
    source = _source()
    demo_body = _function_body(source, "void runDemoSequence()", "void runIndividualAttack")

    assert "const unsigned long ANALYSIS_WINDOW_SECONDS = 10UL;" in source
    assert "const unsigned long WINDOW_START_OFFSET_SECONDS = 1UL;" in source
    assert "bool syncUtcTimeWithTimeout()" in source
    assert "bool waitForNextAnalysisWindow(" in source
    assert "currentEpoch / ANALYSIS_WINDOW_SECONDS" in source
    assert demo_body.count("waitForNextAnalysisWindow(") == 4
    assert "time_sync_unavailable" in source


def test_identity_and_malformed_attacks_match_detector_contracts() -> None:
    source = _source()
    identity_body = _function_body(
        source,
        "bool runIdentityMismatchAttack()",
        "bool runMalformedPayloadAttack()",
    )
    malformed_body = _function_body(
        source,
        "bool runMalformedPayloadAttack()",
        "bool runPacketRateAttack()",
    )

    assert 'buildDevicePayload(SPOOFED_DEVICE_ID)' in identity_body
    assert "IDENTITY_MISMATCH_MESSAGE_COUNT = 1U" in source
    assert 'const char* MALFORMED_PAYLOAD = "{\\\"device_id\\\":";' in source
    assert "MALFORMED_MESSAGE_COUNT = 3U" in source
    assert "publishMqttMessages(" in malformed_body
    assert "String(MALFORMED_PAYLOAD)" in malformed_body


def test_packet_rate_and_mqtt_flood_are_bounded_to_one_stage_each() -> None:
    source = _source()
    packet_body = _function_body(
        source,
        "bool runPacketRateAttack()",
        "bool runMqttFloodAttack()",
    )
    flood_body = _function_body(
        source,
        "bool runMqttFloodAttack()",
        "void logObservationFailure",
    )

    assert "PACKET_RATE_PPS = 20UL" in source
    assert "PACKET_RATE_DURATION_SECONDS = 6UL" in source
    assert "PACKET_RATE_PAYLOAD_BYTES = 64U" in source
    assert "MAX_PACKET_RATE_PPS = 100UL" in source
    assert "MAX_PACKET_RATE_DURATION_SECONDS = 15UL" in source
    assert "udp.beginPacket(targetIp, TARGET_UDP_PORT)" in packet_body
    assert "nextPacketAtUs = afterSendUs + packetIntervalUs;" in packet_body

    assert "MQTT_FLOOD_MESSAGE_COUNT = 40U" in source
    assert "MQTT_FLOOD_INTERVAL_MS = 50UL" in source
    assert "mqttClient.publish(MQTT_TOPIC" in flood_body
    assert "messageIndex < MQTT_FLOOD_MESSAGE_COUNT" in flood_body
    assert "!abortRequested && published > 15U" in flood_body


def test_abort_and_runtime_failures_stop_the_sequence_without_retry() -> None:
    source = _source()

    assert "bool abortRequested = false;" in source
    assert 'if (command == "ABORT")' in source
    assert "abortRequested = true;" in source
    assert 'demo_aborted reason=operator_request' in source
    assert 'demo_aborted reason=wifi_disconnected' in source
    assert 'demo_aborted reason=local_ip_changed' in source
    assert "while (true)" not in source
    assert "ESP.restart()" not in source


def test_preflight_enforces_private_target_expected_ip_and_mqtt_connection() -> None:
    source = _source()
    preflight_body = _function_body(source, "bool runPreflight()", "bool publishMqttMessages")

    assert "isPrivateIpv4(targetIp)" in preflight_body
    assert "expectedLocalIpMatches()" in preflight_body
    assert "connectMqttWithTimeout()" in preflight_body
    assert "syncUtcTimeWithTimeout()" in preflight_body
    assert 'preflight_result=PASS' in preflight_body


def test_isolation_observation_is_bounded_and_restores_no_state() -> None:
    source = _source()
    observation_body = _function_body(
        source,
        "void runBoundedIsolationObservation()",
        "void runDemoSequence()",
    )

    assert "OBSERVATION_TIMEOUT_MS = 45000UL" in source
    assert "OBSERVATION_PROBE_INTERVAL_MS = 5000UL" in source
    assert "MAX_OBSERVATION_PROBES = 9U" in source
    assert "observationProbeCount < MAX_OBSERVATION_PROBES" in observation_body
    assert "mqttClient.disconnect();" in observation_body
    assert "WiFi.disconnect(false);" in observation_body
    assert "Trust" not in observation_body
    assert "firewall" not in observation_body.lower()


def test_credentials_and_readme_cover_safe_upload_and_demo_contract() -> None:
    credentials = MQTT_CREDENTIALS_EXAMPLE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert '#define MQTT_USERNAME "esp32_02"' in credentials
    assert "REPLACE_WITH_MQTT_PASSWORD" in credentials

    for required in (
        "RUN_DEMO",
        "IDENTITY_MISMATCH",
        "MALFORMED_PAYLOAD",
        "PACKET_RATE",
        "MQTT_FLOOD",
        "100 → 75 → 65 → 45 → 25",
        "10초",
        "192.168.0.5",
        "192.168.0.20",
        "부팅당 한 번",
        "normal_sender",
        "실기기",
    ):
        assert required in readme
