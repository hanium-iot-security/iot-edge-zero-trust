"""Explicit INPUT scopes; only absent legacy fields default to MQTT."""
from enum import Enum


class FirewallScope(str, Enum):
    MQTT_IPV4_TCP_1883 = "MQTT_IPV4_TCP_1883"
    PI_INPUT_IPV4_ALL = "PI_INPUT_IPV4_ALL"


MQTT_IPV4_TCP_1883 = FirewallScope.MQTT_IPV4_TCP_1883.value
PI_INPUT_IPV4_ALL = FirewallScope.PI_INPUT_IPV4_ALL.value
SCOPES = frozenset((MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL))


def row_scope(row, field="scope") -> str:
    value = row[field] if field in row.keys() else MQTT_IPV4_TCP_1883
    if not isinstance(value, str) or value not in SCOPES:
        raise ValueError("unknown firewall scope")
    return value
