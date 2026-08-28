"""Packet feature log API response schemas."""

from typing import Literal

from pydantic import BaseModel


class PacketFeatureItem(BaseModel):
    id: int
    capture_segment_id: int
    session_id: str
    device_id: str | None = None
    peer_ip: str
    direction: Literal["INBOUND", "OUTBOUND"]
    window_start: str
    window_end: str
    packet_count: int
    total_bytes: int
    avg_packet_size: float
    max_packet_size: int
    mean_inter_arrival_time: float
    distinct_dest_port_count: int
    tcp_syn_count: int
    mqtt_related_packet_count: int
    non_mqtt_tcp_udp_packet_count: int
    packets_per_second: float
    bytes_per_second: float
    nominal_packets_per_second: float
    nominal_bytes_per_second: float
    effective_packets_per_second: float | None = None
    effective_bytes_per_second: float | None = None
    segment_status: Literal["READY", "PROCESSED", "EMPTY", "FAILED"]
    segment_error_code: str | None = None
    start_delay_seconds: float | None = None
    captured_duration_seconds: float | None = None
    coverage_ratio: float | None = None
    capture_eligible: bool
    capture_exclusion_reason: str | None = None
    capture_scope: str | None = None
    created_at: str


class PacketFeatureListResponse(BaseModel):
    items: list[PacketFeatureItem]
    total: int
