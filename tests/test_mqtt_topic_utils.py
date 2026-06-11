from edge.mqtt.topic_utils import (
    extract_device_id_candidate_from_topic,
    extract_device_id_from_topic,
    is_telemetry_topic,
)


def test_strict_telemetry_topic_validation() -> None:
    assert is_telemetry_topic("iot/esp32_01/sensor") is True
    assert extract_device_id_from_topic("iot/esp32_01/sensor") == "esp32_01"


def test_abnormal_iot_topic_can_still_expose_device_candidate() -> None:
    assert is_telemetry_topic("iot/esp32_01/control") is False
    assert extract_device_id_from_topic("iot/esp32_01/control") is None
    assert extract_device_id_candidate_from_topic("iot/esp32_01/control") == "esp32_01"
    assert extract_device_id_candidate_from_topic("iot/esp32_01/sensor/debug") == "esp32_01"


def test_non_iot_topic_has_no_device_candidate() -> None:
    assert is_telemetry_topic("admin/system/control") is False
    assert extract_device_id_candidate_from_topic("admin/system/control") is None
