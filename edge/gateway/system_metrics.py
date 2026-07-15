from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import shutil
import socket
import struct
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class CpuTimes:
    total: int
    idle: int


@dataclass(frozen=True)
class InterfaceSnapshot:
    interface_name: str
    exists: bool
    is_up: bool
    ip_address: str | None
    rx_bytes: int | None
    tx_bytes: int | None


@dataclass(frozen=True)
class SystemSnapshot:
    cpu_times: CpuTimes
    memory_total_bytes: int
    memory_available_bytes: int
    disk_total_bytes: int
    disk_used_bytes: int
    temperature_c: float | None
    interfaces: Mapping[str, InterfaceSnapshot]


class SystemMetricsReader(Protocol):
    def read(self, interface_names: Mapping[str, str]) -> SystemSnapshot:
        """Read one cumulative system snapshot for the requested interfaces."""


class LinuxSystemMetricsReader:
    def __init__(
        self,
        *,
        proc_root: Path = Path("/proc"),
        sys_root: Path = Path("/sys"),
        disk_path: Path = Path("/"),
        disk_usage: Callable[[Path], Any] = shutil.disk_usage,
        ip_resolver: Callable[[str], str | None] | None = None,
    ) -> None:
        self._proc_root = proc_root
        self._sys_root = sys_root
        self._disk_path = disk_path
        self._disk_usage = disk_usage
        self._ip_resolver = ip_resolver or _resolve_ipv4_address

    def read(self, interface_names: Mapping[str, str]) -> SystemSnapshot:
        disk = self._disk_usage(self._disk_path)
        return SystemSnapshot(
            cpu_times=self._read_cpu_times(),
            memory_total_bytes=self._read_memory_bytes("MemTotal"),
            memory_available_bytes=self._read_memory_bytes("MemAvailable"),
            disk_total_bytes=int(disk.total),
            disk_used_bytes=int(disk.used),
            temperature_c=self._read_temperature_c(),
            interfaces={
                role: self._read_interface_safely(interface_name)
                for role, interface_name in interface_names.items()
            },
        )

    def _read_cpu_times(self) -> CpuTimes:
        for line in (self._proc_root / "stat").read_text(encoding="utf-8").splitlines():
            if not line.startswith("cpu "):
                continue
            values = [int(value) for value in line.split()[1:]]
            if len(values) < 4:
                break
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            # guest and guest_nice are already included in user and nice.
            return CpuTimes(total=sum(values[:8]), idle=idle)
        raise ValueError("/proc/stat does not contain aggregate CPU counters")

    def _read_memory_bytes(self, key: str) -> int:
        for line in (self._proc_root / "meminfo").read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition(":")
            if name != key or not separator:
                continue
            parts = value.split()
            if not parts:
                break
            multiplier = 1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1
            return int(parts[0]) * multiplier
        raise ValueError(f"/proc/meminfo does not contain {key}")

    def _read_temperature_c(self) -> float | None:
        candidates = [
            self._sys_root / "class" / "thermal" / "thermal_zone0" / "temp",
            *sorted((self._sys_root / "class" / "hwmon").glob("hwmon*/temp1_input")),
        ]
        for path in candidates:
            try:
                raw_value = float(path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                continue
            return raw_value / 1000.0 if abs(raw_value) >= 1000 else raw_value
        return None

    def _read_interface_safely(self, interface_name: str) -> InterfaceSnapshot:
        interface_root = self._sys_root / "class" / "net" / interface_name
        try:
            return self._read_interface(interface_name)
        except (OSError, ValueError):
            return InterfaceSnapshot(
                interface_name=interface_name,
                exists=interface_root.exists(),
                is_up=False,
                ip_address=None,
                rx_bytes=None,
                tx_bytes=None,
            )

    def _read_interface(self, interface_name: str) -> InterfaceSnapshot:
        interface_root = self._sys_root / "class" / "net" / interface_name
        is_up = (interface_root / "operstate").read_text(encoding="utf-8").strip() == "up"
        rx_bytes = int((interface_root / "statistics" / "rx_bytes").read_text(encoding="utf-8"))
        tx_bytes = int((interface_root / "statistics" / "tx_bytes").read_text(encoding="utf-8"))
        try:
            ip_address = self._ip_resolver(interface_name)
        except OSError:
            ip_address = None
        return InterfaceSnapshot(
            interface_name=interface_name,
            exists=True,
            is_up=is_up,
            ip_address=ip_address,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
        )


def _resolve_ipv4_address(interface_name: str) -> str | None:
    try:
        import fcntl
    except ImportError:
        return None

    encoded_name = interface_name.encode("utf-8")[:15]
    request = struct.pack("256s", encoded_name)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            response = fcntl.ioctl(sock.fileno(), 0x8915, request)
        except OSError:
            return None
    return socket.inet_ntoa(response[20:24])
