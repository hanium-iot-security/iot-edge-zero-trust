from edge.features.feature_utils import is_malformed_json, is_malformed_payload


def test_malformed_payload_requires_valid_json_object_with_device_id() -> None:
    assert is_malformed_json('{"temperature":25.3}') is False
    assert is_malformed_payload('{"temperature":25.3}') is True
    assert is_malformed_payload('{"device_id":"esp32_01"}') is False
    assert is_malformed_payload("{broken-json") is True
