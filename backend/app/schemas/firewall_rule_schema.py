"""Firewall rule API response schemas."""

from ipaddress import IPv4Address, IPv4Network
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from edge.policy.device_policy import validate_device_id, validate_reason
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883


class FirewallRuleItem(BaseModel):
    id: int
    device_id: str | None = None
    source_ip: str
    scope: Literal["MQTT_IPV4_TCP_1883", "PI_INPUT_IPV4_ALL"] = MQTT_IPV4_TCP_1883
    protocol: str | None
    dest_port: int | None
    action: str
    status: str
    reason: str | None = None
    trigger_event_id: int | None = None
    retry_count: int
    last_error: str | None = None
    last_attempted_at: str | None = None
    next_retry_at: str | None = None
    applied_at: str | None = None
    released_at: str | None = None
    created_at: str
    updated_at: str
    source_rule_id: int | None = None
    approved_policy_revision: int | None = None
    requested_by: str | None = None
    request_id: str | None = None


class FirewallRuleListResponse(BaseModel):
    items: list[FirewallRuleItem]
    total: int


class FirewallScopeExtensionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    device_id: str
    source_ip: str
    approved_policy_revision: int = Field(ge=1, le=2147483647)
    scope: Literal["PI_INPUT_IPV4_ALL"]
    reason: str
    request_id: str
    confirm: str

    _device = field_validator("device_id", mode="before")(validate_device_id)
    _reason = field_validator("reason", mode="before")(validate_reason)

    @field_validator("source_ip")
    @classmethod
    def private_canonical_ipv4(cls, value):
        try:
            address = IPv4Address(value)
            private = any(address in IPv4Network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
            if str(address) != value or not private:
                raise ValueError
        except ValueError:
            raise ValueError("source_ip must be canonical RFC1918 IPv4") from None
        return value

    @field_validator("request_id")
    @classmethod
    def canonical_uuid4(cls, value):
        try:
            parsed = UUID(value)
            if parsed.version != 4 or str(parsed) != value:
                raise ValueError
        except ValueError:
            raise ValueError("request_id must be canonical UUID4") from None
        return value


class FirewallScopeExtensionResponse(BaseModel):
    item: FirewallRuleItem
    created: bool
    replayed: bool
    runtime_verified: Literal[False] = False
