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


def _function_body(source: str, start: str, end: str) -> str:
    return source[source.index(start) : source.index(end)]


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

    update_body = _function_body(
        source,
        "void updateAttack()",
        "void processSerialCommand",
    )
    assert 'finishAttack("wifi_disconnected")' in update_body
    assert 'finishAttack("local_ip_changed")' in update_body
    assert 'finishAttack("duration_completed")' in update_body
    assert "nextPacketAtUs = afterSendUs + attackIntervalUs;" in update_body


def test_diagnostic_build_has_distinct_version_and_counters() -> None:
    source = _firmware_source()

    assert (
        'const char* FIRMWARE_VERSION = '
        '"phase6a-packet-rate-sender-diagnostics-v1";'
    ) in source
    assert "unsigned long beginPacketFailCount = 0UL;" in source
    assert "unsigned long shortWriteFailCount = 0UL;" in source
    assert "unsigned long endPacketFailCount = 0UL;" in source
    assert "unsigned long scheduleSkipCount = 0UL;" in source
    assert "int lastEndPacketErrno = 0;" in source


def test_diagnostic_counters_reset_for_each_burst() -> None:
    source = _firmware_source()
    start_body = _function_body(source, "void startAttack(", "void sendScheduledPacket()")

    for reset in (
        "beginPacketFailCount = 0UL;",
        "shortWriteFailCount = 0UL;",
        "endPacketFailCount = 0UL;",
        "scheduleSkipCount = 0UL;",
        "lastEndPacketErrno = 0;",
    ):
        assert reset in start_body


def test_udp_failure_stages_and_errno_are_instrumented_without_retry() -> None:
    source = _firmware_source()
    send_body = _function_body(source, "void sendScheduledPacket()", "void updateAttack()")

    assert "beginPacketFailCount++;" in send_body
    assert "if (written != attackPayloadBytes)" in send_body
    assert "shortWriteFailCount++;" in send_body
    assert "const int endResult = udp.endPacket();\n  const int endErrno = errno;" in send_body
    assert "endPacketFailCount++;" in send_body
    assert "lastEndPacketErrno = endErrno;" in send_body

    # 진단 PR은 송신 재시도를 추가하지 않는다.
    assert send_body.count("udp.beginPacket(targetIp, TARGET_UDP_PORT)") == 1
    assert send_body.count("udp.endPacket()") == 1


def test_scheduler_counts_actual_skipped_slots_and_preserves_no_catch_up() -> None:
    source = _firmware_source()
    update_body = _function_body(
        source,
        "void updateAttack()",
        "void processSerialCommand",
    )

    assert (
        "const unsigned long skippedSlots =\n"
        "        (afterSendUs - nextPacketAtUs) / attackIntervalUs + 1UL;"
    ) in update_body
    assert "scheduleSkipCount += skippedSlots;" in update_body
    assert "nextPacketAtUs = afterSendUs + attackIntervalUs;" in update_body


def test_diagnostic_fields_are_reported_without_per_packet_serial_logging() -> None:
    source = _firmware_source()

    for serial_key in (
        'Serial.print("begin_packet_fail=")',
        'Serial.print("short_write_fail=")',
        'Serial.print("end_packet_fail=")',
        'Serial.print("last_end_packet_errno=")',
        'Serial.print("schedule_skip_count=")',
    ):
        # STATUS + 종료 Summary에서 각각 한 번씩 출력한다.
        assert source.count(serial_key) == 2

    send_body = _function_body(source, "void sendScheduledPacket()", "void updateAttack()")
    assert "Serial.print" not in send_body
    assert "Serial.println" not in send_body


def test_normal_finish_does_not_change_udp_socket_lifecycle() -> None:
    source = _firmware_source()
    finish_body = _function_body(source, "void finishAttack", "bool validateStartArguments")

    assert "udp.stop()" not in finish_body
    assert "stopUdpSocket()" not in finish_body
    assert "startUdpSocket()" not in finish_body


def test_readme_states_that_only_wifi_credentials_are_local_configuration() -> None:
    text = README.read_text(encoding="utf-8")

    assert "로컬 설정 파일에는 Wi-Fi SSID와 비밀번호만" in text
    assert "주소·포트·Device 식별 계약은 Firmware 내부에 고정" in text
