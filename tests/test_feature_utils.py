from edge.features.feature_utils import extract_payload_device_id, is_malformed_json, is_malformed_payload


def test_malformed_payload_requires_valid_json_object_with_device_id() -> None:
    assert is_malformed_json('{"temperature":25.3}') is False
    assert is_malformed_payload('{"temperature":25.3}') is True
    assert is_malformed_payload('{"device_id":"esp32_01"}') is False
    assert is_malformed_payload("{broken-json") is True


class TestExtractPayloadDeviceId:
    def test_valid_device_id(self) -> None:
        assert extract_payload_device_id('{"device_id":"esp32_01"}') == "esp32_01"

    def test_valid_device_id_bytes(self) -> None:
        assert extract_payload_device_id(b'{"device_id":"esp32_02"}') == "esp32_02"

    def test_strips_whitespace(self) -> None:
        assert extract_payload_device_id('{"device_id":"  esp32_01  "}') == "esp32_01"

    def test_empty_string_returns_none(self) -> None:
        assert extract_payload_device_id('{"device_id":""}') is None

    def test_whitespace_only_returns_none(self) -> None:
        assert extract_payload_device_id('{"device_id":"   "}') is None

    def test_missing_field_returns_none(self) -> None:
        assert extract_payload_device_id('{"temperature":25.3}') is None

    def test_broken_json_returns_none(self) -> None:
        assert extract_payload_device_id("{broken-json") is None

    def test_non_string_device_id_returns_none(self) -> None:
        assert extract_payload_device_id('{"device_id":123}') is None
