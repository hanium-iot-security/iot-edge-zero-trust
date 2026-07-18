"""Gateway metrics API response schemas."""

from pydantic import BaseModel


class GatewayInterfaceMetric(BaseModel):
    interface_name: str
    exists: bool
    is_up: bool
    ip_address: str | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_bytes_per_sec: float | None = None
    tx_bytes_per_sec: float | None = None


class GatewayInterfaceMetrics(BaseModel):
    internal_lan: GatewayInterfaceMetric
    usb_lan: GatewayInterfaceMetric


class GatewayMetricItem(BaseModel):
    id: int
    collected_at: str
    sample_interval_seconds: float | None = None
    cpu_percent: float | None = None
    memory_percent: float
    disk_percent: float
    disk_used_mb: float | None = None
    temperature_c: float | None = None
    interface_metrics: GatewayInterfaceMetrics


class GatewayMetricListResponse(BaseModel):
    items: list[GatewayMetricItem]
    total: int
