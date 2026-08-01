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
    assert "random(4000, 6001)" in source
    assert "PHASE5_NORMAL_PROFILE == 2 || PHASE5_NORMAL_PROFILE == 3" in source
    assert "sequence % 3" in source
