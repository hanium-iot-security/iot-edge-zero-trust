from pathlib import Path


FIRMWARE_DIR = Path("firmware/esp32/phase5_normal_collector")
SKETCH = FIRMWARE_DIR / "phase5_normal_collector.ino"
EXAMPLE_CONFIG = FIRMWARE_DIR / "phase5_firmware_config.example.h"


def _source() -> str:
    return SKETCH.read_text(encoding="utf-8")


def test_phase5_firmware_has_local_config_gate_and_supported_device_slots() -> None:
    source = _source()
    config = EXAMPLE_CONFIG.read_text(encoding="utf-8")

    assert '#include "phase5_firmware_config.h"' in source
    assert "#if PHASE5_CONFIGURED != 1" in source
    assert "#if PHASE5_DEVICE_SLOT == 1" in source
    assert "#elif PHASE5_DEVICE_SLOT == 2" in source
    assert 'const char* DEVICE_ID = "esp32_01";' in source
    assert 'const char* DEVICE_ID = "esp32_02";' in source
    assert "#define PHASE5_CONFIGURED 0" in config
    assert "#define PHASE5_DEVICE_SLOT 1" in config
    assert "#define PHASE5_NORMAL_PROFILE 0" in config


def test_all_profiles_keep_required_canonical_fields_without_synthetic_sensors() -> None:
    source = _source()

    for field in ("device_id", "sequence", "uptime_s"):
        assert f'\\"{field}\\"' in source
    for forbidden in ("temp", "hum", "bat"):
        assert f'\\"{forbidden}\\"' not in source
    assert "WiFi.RSSI()" in source
    assert "ESP.getFreeHeap()" in source


def test_profiles_isolate_interval_and_payload_variation() -> None:
    source = _source()

    assert "PHASE5_NORMAL_PROFILE == 0 || PHASE5_NORMAL_PROFILE == 2" in source
    assert "random(PHASE5_JITTER_MIN_MS, PHASE5_JITTER_MAX_MS + 1UL)" in source
    assert "PHASE5_NORMAL_PROFILE == 2 || PHASE5_NORMAL_PROFILE == 3" in source
    assert "sequence % 3" in source


def test_topic_and_client_id_are_derived_from_the_selected_device() -> None:
    source = _source()

    assert 'String MQTT_TOPIC = String("iot/") + DEVICE_ID + "/sensor";' in source
    assert 'String MQTT_CLIENT_ID = String("p5-") + DEVICE_ID + "-v1";' in source


def test_publish_rejects_oversize_and_commits_sequence_only_after_success() -> None:
    source = _source()
    publish_body = source[
        source.index("bool publishNormalTelemetry()") : source.index("void setup()")
    ]

    assert "MAX_PAYLOAD_BYTES = PHASE5_PAYLOAD_MAX_BYTES" in source
    assert "payload.length() > MAX_PAYLOAD_BYTES" in publish_body
    assert "packetBytes > mqttClient.getBufferSize()" in publish_body
    assert publish_body.index("packetBytes > mqttClient.getBufferSize()") < publish_body.index("mqttClient.publish")
    assert "return false;" in publish_body
    assert publish_body.index("mqttClient.publish") < publish_body.index(
        "sequenceNumber = nextSequence"
    )


def test_reconnect_path_is_bounded_and_boot_log_identifies_run_contract() -> None:
    source = _source()

    assert "WIFI_CONNECT_TIMEOUT_MS" in source
    assert "MQTT_RETRY_INTERVAL_MS" in source
    assert "while (true)" not in source
    assert "ESP.restart()" not in source
    assert "mqttClient.loop();" in source
    setup_body = source[source.index("void setup()") : source.index("void loop()")]
    assert "mqttBufferReady = mqttClient.setBufferSize(PHASE5_MQTT_BUFFER_BYTES)" in setup_body
    assert "mqttClient.getBufferSize() == PHASE5_MQTT_BUFFER_BYTES" in setup_body
    assert setup_body.index("if (!mqttBufferReady)") < setup_body.index("connectWifiWithTimeout();")
    loop_body = source[source.index("void loop()") :]
    assert loop_body.index("if (!mqttBufferReady)") < loop_body.index("mqttClient.loop();")
    for label in (
        "firmware_version=",
        "payload_schema_version=",
        "firmware_limits_version=",
        "payload_max_bytes=",
        "canonical_payload_max_bytes=",
        "mqtt_buffer_bytes_configured=",
        "mqtt_buffer_bytes_actual=",
        "fixed_publish_interval_ms=",
        "jitter_min_ms=",
        "jitter_max_ms=",
        "device_id=",
        "normal_profile=",
        "mqtt_topic=",
        "mqtt_client_id=",
    ):
        assert label in source
    assert "Serial.println(PHASE5_WIFI_PASSWORD)" not in source
    assert "Serial.println(MQTT_PASSWORD)" not in source
    assert 'FIRMWARE_VERSION = "phase9-normal-pilot-v2"' in source
    assert 'PAYLOAD_SCHEMA_VERSION = "phase5-normal-payload-v1"' in source


def test_profile_three_logs_the_pilot_approval_gate() -> None:
    source = _source()

    assert "PHASE5_NORMAL_PROFILE == 3" in source
    assert "profile_3_requires_profile_1_and_2_pilot_approval" in source


def test_mqtt_username_is_derived_from_device_id_not_separately_configured() -> None:
    # PHASE5_DEVICE_SLOT이 이미 DEVICE_ID(esp32_01/esp32_02)를 결정하므로
    # Username을 별도 Config 값으로 중복 관리하지 않는다.
    source = _source()
    assert "const char* MQTT_USERNAME = DEVICE_ID;" in source


def test_mqtt_password_has_backward_compatible_fallback_default() -> None:
    # 이미 배포된 로컬 phase5_firmware_config.h에 PHASE5_MQTT_PASSWORD가 없어도
    # 컴파일이 깨지지 않아야 한다(기존 실기기 호환).
    source = _source()
    assert "#ifndef PHASE5_MQTT_PASSWORD" in source
    assert '#define PHASE5_MQTT_PASSWORD ""' in source
    for name, default in (
        ("PHASE5_PAYLOAD_MAX_BYTES", "128"),
        ("PHASE5_MQTT_BUFFER_BYTES", "256"),
        ("PHASE5_FIXED_PUBLISH_INTERVAL_MS", "5000UL"),
        ("PHASE5_JITTER_MIN_MS", "4000UL"),
        ("PHASE5_JITTER_MAX_MS", "6000UL"),
    ):
        assert f"#ifndef {name}" in source
        assert f"#define {name} {default}" in source


def test_connect_falls_back_to_anonymous_when_password_not_configured() -> None:
    source = _source()
    connect_body = source[
        source.index("bool connectMqttOnce()") : source.index("bool publishNormalTelemetry()")
    ]
    assert "strlen(MQTT_PASSWORD) > 0" in connect_body
    assert "strlen(MQTT_USERNAME)" not in connect_body
    assert (
        "mqttClient.connect(MQTT_CLIENT_ID.c_str(), MQTT_USERNAME, MQTT_PASSWORD)"
        in connect_body
    )
    # 완전한 익명 연결(Username/Password 없이) 경로도 여전히 남아 있어야 한다.
    assert "mqttClient.connect(MQTT_CLIENT_ID.c_str());" in connect_body


def test_example_config_documents_mqtt_password_with_safe_empty_default() -> None:
    config = EXAMPLE_CONFIG.read_text(encoding="utf-8")
    # 기본값이 비어 있어야 전환 기간에 실수로 잘못된 Credential을 보내지 않는다.
    assert '#define PHASE5_MQTT_PASSWORD ""' in config
    # Username은 예제에서 별도로 정의하지 않는다(DEVICE_ID에서 파생).
    assert "PHASE5_MQTT_USERNAME" not in config
