from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
import os

from edge.gateway.system_metrics import InterfaceSnapshot, SystemMetricsReader, SystemSnapshot


_NETWORK_RATE_VALID_INTERVAL_MULTIPLIER = 3


@dataclass(frozen=True)
class InterfaceMetrics:
    interface_name: str
    exists: bool
    is_up: bool
    ip_address: str | None
    rx_bytes: int | None
    tx_bytes: int | None
    rx_bytes_per_sec: float | None
    tx_bytes_per_sec: float | None


@dataclass(frozen=True)
class GatewayMetricsSample:
    collected_at: datetime
    sample_interval_seconds: float | None
    cpu_percent: float | None
    memory_percent: float
    disk_percent: float
    disk_total_mb: float
    disk_used_mb: float
    temperature_c: float | None
    interface_metrics: Mapping[str, InterfaceMetrics]


@dataclass(frozen=True)
class GatewayMetricsConfig:
    interval_seconds: float = 10.0
    internal_lan_interface: str = "eth0"
    usb_lan_interface: str = "eth1"

    def __post_init__(self) -> None:
        if not isfinite(self.interval_seconds) or self.interval_seconds <= 0:
            raise ValueError("interval_seconds must be finite and positive")
        if not self.internal_lan_interface.strip():
            raise ValueError("internal_lan_interface must not be empty")
        if not self.usb_lan_interface.strip():
            raise ValueError("usb_lan_interface must not be empty")

    @property
    def interface_names(self) -> dict[str, str]:
        return {
            "internal_lan": self.internal_lan_interface,
            "usb_lan": self.usb_lan_interface,
        }

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "GatewayMetricsConfig":
        values = os.environ if env is None else env
        return cls(
            interval_seconds=float(values.get("GATEWAY_METRICS_INTERVAL_SECONDS", "10")),
            internal_lan_interface=values.get("INTERNAL_LAN_INTERFACE", "eth0"),
            usb_lan_interface=values.get("USB_LAN_INTERFACE", "eth1"),
        )


class GatewayMetricsCollector:
    def __init__(
        self,
        *,
        reader: SystemMetricsReader,
        clock: Callable[[], datetime],
        config: GatewayMetricsConfig,
    ) -> None:
        self._reader = reader
        self._clock = clock
        self._interface_names = config.interface_names
        self._max_valid_interval_seconds = (
            config.interval_seconds * _NETWORK_RATE_VALID_INTERVAL_MULTIPLIER
        )
        self._previous: tuple[datetime, SystemSnapshot] | None = None

    def collect(self) -> GatewayMetricsSample:
        collected_at = self._clock()
        if collected_at.tzinfo is None or collected_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        collected_at = collected_at.astimezone(timezone.utc)

        snapshot = self._reader.read(self._interface_names)
        interval = self._sample_interval(collected_at)
        valid_interval = interval is not None and interval > 0
        valid_network_interval = (
            interval is not None and 0 < interval <= self._max_valid_interval_seconds
        )

        previous_snapshot = self._previous[1] if self._previous is not None else None
        interfaces = {
            role: self._build_interface_metrics(
                current=snapshot.interfaces.get(role) or self._missing_interface(interface_name),
                previous=(previous_snapshot.interfaces.get(role) if previous_snapshot is not None else None),
                interval=interval if valid_network_interval else None,
            )
            for role, interface_name in self._interface_names.items()
        }

        sample = GatewayMetricsSample(
            collected_at=collected_at,
            sample_interval_seconds=interval,
            cpu_percent=self._cpu_percent(snapshot, previous_snapshot, valid_interval),
            memory_percent=self._percent(
                snapshot.memory_total_bytes - snapshot.memory_available_bytes,
                snapshot.memory_total_bytes,
            ),
            disk_percent=self._percent(snapshot.disk_used_bytes, snapshot.disk_total_bytes),
            disk_total_mb=snapshot.disk_total_bytes / (1024 * 1024),
            disk_used_mb=snapshot.disk_used_bytes / (1024 * 1024),
            temperature_c=snapshot.temperature_c,
            interface_metrics=interfaces,
        )
        self._previous = (collected_at, snapshot)
        return sample

    def _sample_interval(self, collected_at: datetime) -> float | None:
        if self._previous is None:
            return None
        interval = (collected_at - self._previous[0]).total_seconds()
        return interval if interval >= 0 else None

    @staticmethod
    def _percent(used: int, total: int) -> float:
        if total <= 0:
            return 0.0
        return max(0.0, min(100.0, used / total * 100.0))

    @staticmethod
    def _cpu_percent(
        current: SystemSnapshot,
        previous: SystemSnapshot | None,
        valid_interval: bool,
    ) -> float | None:
        if previous is None or not valid_interval:
            return None

        total_delta = current.cpu_times.total - previous.cpu_times.total
        idle_delta = current.cpu_times.idle - previous.cpu_times.idle
        if total_delta <= 0 or idle_delta < 0 or idle_delta > total_delta:
            return None
        return (total_delta - idle_delta) / total_delta * 100.0

    @classmethod
    def _build_interface_metrics(
        cls,
        *,
        current: InterfaceSnapshot,
        previous: InterfaceSnapshot | None,
        interval: float | None,
    ) -> InterfaceMetrics:
        rx_rate: float | None = None
        tx_rate: float | None = None
        if cls._can_calculate_rate(current, previous, interval):
            assert previous is not None
            assert interval is not None
            assert current.rx_bytes is not None and previous.rx_bytes is not None
            assert current.tx_bytes is not None and previous.tx_bytes is not None
            rx_rate = (current.rx_bytes - previous.rx_bytes) / interval
            tx_rate = (current.tx_bytes - previous.tx_bytes) / interval

        return InterfaceMetrics(
            interface_name=current.interface_name,
            exists=current.exists,
            is_up=current.is_up,
            ip_address=current.ip_address,
            rx_bytes=current.rx_bytes,
            tx_bytes=current.tx_bytes,
            rx_bytes_per_sec=rx_rate,
            tx_bytes_per_sec=tx_rate,
        )

    @staticmethod
    def _can_calculate_rate(
        current: InterfaceSnapshot,
        previous: InterfaceSnapshot | None,
        interval: float | None,
    ) -> bool:
        if interval is None or interval <= 0 or previous is None:
            return False
        if not current.exists or not previous.exists:
            return False
        if not current.is_up:
            return False
        if None in (current.rx_bytes, current.tx_bytes, previous.rx_bytes, previous.tx_bytes):
            return False
        assert current.rx_bytes is not None and previous.rx_bytes is not None
        assert current.tx_bytes is not None and previous.tx_bytes is not None
        return current.rx_bytes >= previous.rx_bytes and current.tx_bytes >= previous.tx_bytes

    @staticmethod
    def _missing_interface(interface_name: str) -> InterfaceSnapshot:
        return InterfaceSnapshot(
            interface_name=interface_name,
            exists=False,
            is_up=False,
            ip_address=None,
            rx_bytes=None,
            tx_bytes=None,
        )
