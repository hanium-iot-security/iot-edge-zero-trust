"""MQTT topic 파싱 도우미."""


def extract_device_id_from_topic(topic: str) -> str | None:
    """Return device_id only for the strict telemetry topic."""
    parts = topic.split("/")
    if len(parts) == 3 and parts[0] == "iot" and parts[2] == "sensor" and parts[1]:
        return parts[1]
    return None


def extract_device_id_candidate_from_topic(topic: str) -> str | None:
    """Return device_id candidate from iot/{device_id}/... topics."""
    parts = topic.split("/")
    if len(parts) >= 3 and parts[0] == "iot" and parts[1]:
        return parts[1]
    return None


def is_telemetry_topic(topic: str) -> bool:
    return extract_device_id_from_topic(topic) is not None
