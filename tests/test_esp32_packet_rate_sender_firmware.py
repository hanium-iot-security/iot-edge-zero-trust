from pathlib import Path


FIRMWARE = Path("firmware/esp32/packet_rate_sender/packet_rate_sender.ino")
CONFIG_EXAMPLE = Path(
    "firmware/esp32/packet_rate_sender/packet_rate_firmware_config.example.h"
)
README = Path("firmware/esp32/packet_rate_sender/README.md")


def _firmware_source() -> str:
    return FIRMWARE.read_text(encoding="utf-8")


def _config_source() -> str:
    return CONFIG_EXAMPLE.read_text(encoding="utf-8")


def test_local_config_contains_only_enable_flag_and_wifi_credentials() -> None:
    config = _config_source()

    assert "PACKET_RATE_CONFIGURED" in config
    assert "PACKET_RATE_WIFI_SSID" in config
    assert "PACKET_RATE_WIFI_PASSWORD" in config

    for forbidden in (
        "PACKET_RATE_DEVICE_SLOT",
        "PACKET_RATE_EXPECTED_LOCAL_IP",
        "PACKET_RATE_TARGET_IP",
        "PACKET_RATE_TARGET_PORT",
        "PACKET_RATE_LOCAL_UDP_PORT",
    ):
        assert forbidden not in config


def test_lab_identity_and_udp_endpoints_are_fixed_in_firmware() -> None:
    source = _firmware_source()

    assert 'const char* DEVICE_ID = "esp32_02";' in source
    assert "const unsigned int DEVICE_SLOT = 2U;" in source
    assert 'const char* EXPECTED_LOCAL_IP_TEXT = "192.168.0.5";' in source
    assert 'const char* TARGET_IP_TEXT = "192.168.0.20";' in source
    assert "const uint16_t TARGET_UDP_PORT = 19999U;" in source
    assert "const uint16_t LOCAL_UDP_PORT = 42100U;" in source

    for configurable_contract in (
        "PACKET_RATE_DEVICE_SLOT",
        "PACKET_RATE_EXPECTED_LOCAL_IP",
        "PACKET_RATE_TARGET_IP",
        "PACKET_RATE_TARGET_PORT",
        "PACKET_RATE_LOCAL_UDP_PORT",
    ):
        assert configurable_contract not in source


def test_packet_rate_sender_is_serial_only_and_bounded() -> None:
    source = _firmware_source()

    assert "const unsigned long MAX_RATE_PPS = 100UL;" in source
    assert "const unsigned long MAX_DURATION_SECONDS = 15UL;" in source
    assert "const unsigned long MAX_PAYLOAD_BYTES = 1400UL;" in source
    assert 'if (verb != "START")' in source
    assert "startAttack(ratePps, durationSeconds, payloadBytes);" in source
    assert 'Serial.println("auto_start=false");' in source

    setup_body = source[source.index("void setup()") : source.index("void loop()")]
    assert "startAttack(" not in setup_body
    assert "sendScheduledPacket(" not in setup_body


def test_packet_rate_sender_enforces_runtime_stop_and_no_catch_up_burst() -> None:
    source = _firmware_source()

    update_body = source[
        source.index("void updateAttack()") : source.index("void processSerialCommand")
    ]
    assert 'finishAttack("wifi_disconnected")' in update_body
    assert 'finishAttack("local_ip_changed")' in update_body
    assert 'finishAttack("duration_completed")' in update_body
    assert "nextPacketAtUs = afterSendUs + attackIntervalUs;" in update_body


def test_readme_states_that_only_wifi_credentials_are_local_configuration() -> None:
    text = README.read_text(encoding="utf-8")

    assert "로컬 설정 파일에는 Wi-Fi SSID와 비밀번호만" in text
    assert "주소·포트·Device 식별 계약은 Firmware 내부에 고정" in text
