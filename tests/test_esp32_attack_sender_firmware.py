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
    assert "while (true)" not in source
    assert "ESP.restart()" not in source


def test_attack_sender_payload_carries_trace_fields_and_disconnects() -> None:
    source = _source()

    for field in ("device_id", "temperature", "humidity", "sequence", "burst"):
        assert f'\\"{field}\\"' in source
    assert "mqttClient.disconnect();" in source


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

    assert "4개 Window" in text
    assert "ABNORMAL_PUBLISH_RATE" in text
    assert "PENDING" in text
    assert "APPLIED" in text
    assert "normal_sender.ino" in text
    assert "정상 Publish 재개" in text
    assert "미검증" in text


def test_firmware_readme_links_attack_sender_and_runbook() -> None:
    text = README.read_text(encoding="utf-8")

    assert "attack_sender/attack_sender.ino" in text
    assert "docs/phase4-esp32-attack-test-runbook.md" in text
