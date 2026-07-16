from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from edge.gateway.metrics_collector import GatewayMetricsCollector, GatewayMetricsConfig
from edge.gateway.system_metrics import (
    CpuTimes,
    InterfaceSnapshot,
    LinuxSystemMetricsReader,
    SystemSnapshot,
)


class SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self._values = iter(values)

    def __call__(self) -> datetime:
        return next(self._values)


class SequenceReader:
    def __init__(self, *snapshots: SystemSnapshot) -> None:
        self._snapshots = iter(snapshots)

    def read(self, interface_names: dict[str, str]) -> SystemSnapshot:
        return next(self._snapshots)


def build_snapshot(
    *,
    cpu_total: int,
    cpu_idle: int,
    internal_rx: int,
    internal_tx: int,
) -> SystemSnapshot:
    return SystemSnapshot(
        cpu_times=CpuTimes(total=cpu_total, idle=cpu_idle),
        memory_total_bytes=1_000,
        memory_available_bytes=600,
        disk_total_bytes=20 * 1024 * 1024,
        disk_used_bytes=5 * 1024 * 1024,
        temperature_c=48.5,
        interfaces={
            "internal_lan": InterfaceSnapshot(
                interface_name="eth0",
                exists=True,
                is_up=True,
                ip_address="192.168.0.20",
                rx_bytes=internal_rx,
                tx_bytes=internal_tx,
            ),
            "usb_lan": InterfaceSnapshot(
                interface_name="eth1",
                exists=False,
                is_up=False,
                ip_address=None,
                rx_bytes=None,
                tx_bytes=None,
            ),
        },
    )


def test_first_sample_keeps_interval_cpu_and_network_rates_unknown() -> None:
    collected_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000)
        ),
        clock=SequenceClock(collected_at),
        config=GatewayMetricsConfig(),
    )

    sample = collector.collect()

    assert sample.collected_at == collected_at
    assert sample.sample_interval_seconds is None
    assert sample.cpu_percent is None
    assert sample.memory_percent == 40.0
    assert sample.disk_percent == 25.0
    assert sample.disk_total_mb == 20.0
    assert sample.disk_used_mb == 5.0
    assert sample.temperature_c == 48.5
    assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None
    assert sample.interface_metrics["usb_lan"].is_up is False


def test_second_sample_uses_actual_elapsed_time_for_cpu_and_network_rates() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000),
            build_snapshot(cpu_total=1_200, cpu_idle=450, internal_rx=2_050, internal_tx=2_525),
        ),
        clock=SequenceClock(started_at, started_at + timedelta(seconds=10.5)),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    sample = collector.collect()

    assert sample.sample_interval_seconds == 10.5
    assert sample.cpu_percent == 75.0
    assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec == pytest.approx(100.0)
    assert sample.interface_metrics["internal_lan"].tx_bytes_per_sec == pytest.approx(50.0)


def test_counter_reset_invalidates_rates_and_becomes_the_next_baseline() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    first = build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=5_000, internal_tx=8_000)
    reset = build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=100, internal_tx=8_500)
    after_reset = build_snapshot(cpu_total=1_400, cpu_idle=600, internal_rx=1_100, internal_tx=9_500)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(first, reset, after_reset),
        clock=SequenceClock(
            started_at,
            started_at + timedelta(seconds=10),
            started_at + timedelta(seconds=20),
        ),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    reset_sample = collector.collect()
    recovered_sample = collector.collect()

    assert reset_sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert reset_sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None
    assert recovered_sample.interface_metrics["internal_lan"].rx_bytes_per_sec == 100.0
    assert recovered_sample.interface_metrics["internal_lan"].tx_bytes_per_sec == 100.0


def test_tx_counter_decrease_invalidates_both_network_rates() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=8_000),
            build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=2_000, internal_tx=100),
        ),
        clock=SequenceClock(started_at, started_at + timedelta(seconds=10)),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    sample = collector.collect()

    assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None


def test_zero_elapsed_time_is_preserved_and_invalidates_cpu_and_network_deltas() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000),
            build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=2_000, internal_tx=3_000),
        ),
        clock=SequenceClock(started_at, started_at),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    sample = collector.collect()

    assert sample.sample_interval_seconds == 0
    assert sample.cpu_percent is None
    assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None


def test_negative_elapsed_time_is_unknown_and_next_sample_recovers() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000),
            build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=2_000, internal_tx=3_000),
            build_snapshot(cpu_total=1_400, cpu_idle=600, internal_rx=3_000, internal_tx=3_500),
        ),
        clock=SequenceClock(
            started_at,
            started_at - timedelta(seconds=1),
            started_at + timedelta(seconds=9),
        ),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    negative_interval_sample = collector.collect()
    recovered_sample = collector.collect()

    assert negative_interval_sample.sample_interval_seconds is None
    assert negative_interval_sample.cpu_percent is None
    assert negative_interval_sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert negative_interval_sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None
    assert recovered_sample.sample_interval_seconds == 10.0
    assert recovered_sample.cpu_percent == 50.0
    assert recovered_sample.interface_metrics["internal_lan"].rx_bytes_per_sec == 100.0
    assert recovered_sample.interface_metrics["internal_lan"].tx_bytes_per_sec == 50.0


def test_down_or_missing_interface_does_not_stop_system_metric_collection() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    first = build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000)
    second = build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=1_500, internal_tx=2_500)
    second_internal = replace(second.interfaces["internal_lan"], is_up=False)
    second = replace(second, interfaces={"internal_lan": second_internal})
    collector = GatewayMetricsCollector(
        reader=SequenceReader(first, second),
        clock=SequenceClock(started_at, started_at + timedelta(seconds=10)),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    sample = collector.collect()

    assert sample.memory_percent == 40.0
    assert sample.interface_metrics["internal_lan"].exists is True
    assert sample.interface_metrics["internal_lan"].is_up is False
    assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert sample.interface_metrics["usb_lan"].interface_name == "eth1"
    assert sample.interface_metrics["usb_lan"].exists is False
    assert sample.interface_metrics["usb_lan"].is_up is False
    assert sample.interface_metrics["usb_lan"].rx_bytes is None


def test_down_interface_counter_becomes_baseline_for_next_up_sample() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    first = build_snapshot(
        cpu_total=1_000,
        cpu_idle=400,
        internal_rx=1_000,
        internal_tx=2_000,
    )
    down = build_snapshot(
        cpu_total=1_200,
        cpu_idle=500,
        internal_rx=1_500,
        internal_tx=2_500,
    )
    down = replace(
        down,
        interfaces={
            **down.interfaces,
            "internal_lan": replace(down.interfaces["internal_lan"], is_up=False),
        },
    )
    recovered = build_snapshot(
        cpu_total=1_400,
        cpu_idle=600,
        internal_rx=2_500,
        internal_tx=3_000,
    )
    collector = GatewayMetricsCollector(
        reader=SequenceReader(first, down, recovered),
        clock=SequenceClock(
            started_at,
            started_at + timedelta(seconds=10),
            started_at + timedelta(seconds=20),
        ),
        config=GatewayMetricsConfig(),
    )

    collector.collect()
    down_sample = collector.collect()
    recovered_sample = collector.collect()

    assert down_sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert down_sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None
    assert recovered_sample.interface_metrics["internal_lan"].rx_bytes_per_sec == 100.0
    assert recovered_sample.interface_metrics["internal_lan"].tx_bytes_per_sec == 50.0


def test_long_interval_invalidates_network_rates_and_next_sample_recovers() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000),
            build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=4_100, internal_tx=3_550),
            build_snapshot(cpu_total=1_400, cpu_idle=600, internal_rx=5_100, internal_tx=4_050),
        ),
        clock=SequenceClock(
            started_at,
            started_at + timedelta(seconds=31),
            started_at + timedelta(seconds=41),
        ),
        config=GatewayMetricsConfig(interval_seconds=10.0),
    )

    collector.collect()
    long_interval_sample = collector.collect()
    recovered_sample = collector.collect()

    assert long_interval_sample.sample_interval_seconds == 31.0
    assert long_interval_sample.cpu_percent == 50.0
    assert long_interval_sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    assert long_interval_sample.interface_metrics["internal_lan"].tx_bytes_per_sec is None
    assert recovered_sample.sample_interval_seconds == 10.0
    assert recovered_sample.interface_metrics["internal_lan"].rx_bytes_per_sec == 100.0
    assert recovered_sample.interface_metrics["internal_lan"].tx_bytes_per_sec == 50.0


def test_network_rates_remain_valid_at_three_times_the_configured_interval() -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000),
            build_snapshot(cpu_total=1_200, cpu_idle=500, internal_rx=4_000, internal_tx=3_500),
        ),
        clock=SequenceClock(started_at, started_at + timedelta(seconds=30)),
        config=GatewayMetricsConfig(interval_seconds=10.0),
    )

    collector.collect()
    sample = collector.collect()

    assert sample.sample_interval_seconds == 30.0
    assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec == 100.0
    assert sample.interface_metrics["internal_lan"].tx_bytes_per_sec == 50.0


@pytest.mark.parametrize(
    ("elapsed_seconds", "expected_rx_rate"),
    [(15.0, 100.0), (15.001, None)],
)
def test_network_rate_limit_scales_with_the_configured_interval(
    elapsed_seconds: float,
    expected_rx_rate: float | None,
) -> None:
    started_at = datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000),
            build_snapshot(
                cpu_total=1_200,
                cpu_idle=500,
                internal_rx=1_000 + int(elapsed_seconds * 100),
                internal_tx=2_000 + int(elapsed_seconds * 50),
            ),
        ),
        clock=SequenceClock(started_at, started_at + timedelta(seconds=elapsed_seconds)),
        config=GatewayMetricsConfig(interval_seconds=5.0),
    )

    collector.collect()
    sample = collector.collect()

    if expected_rx_rate is None:
        assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec is None
    else:
        assert sample.interface_metrics["internal_lan"].rx_bytes_per_sec == pytest.approx(
            expected_rx_rate
        )


def test_collected_at_is_converted_to_utc_and_naive_clock_is_rejected() -> None:
    kst = timezone(timedelta(hours=9))
    collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000)
        ),
        clock=SequenceClock(datetime(2026, 7, 15, 9, 0, 10, tzinfo=kst)),
        config=GatewayMetricsConfig(),
    )
    naive_collector = GatewayMetricsCollector(
        reader=SequenceReader(
            build_snapshot(cpu_total=1_000, cpu_idle=400, internal_rx=1_000, internal_tx=2_000)
        ),
        clock=SequenceClock(datetime(2026, 7, 15, 0, 0, 10)),
        config=GatewayMetricsConfig(),
    )

    assert collector.collect().collected_at == datetime(2026, 7, 15, 0, 0, 10, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="timezone-aware"):
        naive_collector.collect()


def test_gateway_metrics_config_reads_defaults_and_environment_overrides() -> None:
    defaults = GatewayMetricsConfig.from_env({})
    configured = GatewayMetricsConfig.from_env(
        {
            "GATEWAY_METRICS_INTERVAL_SECONDS": "5",
            "INTERNAL_LAN_INTERFACE": "enp1s0",
            "USB_LAN_INTERFACE": "enx001122",
        }
    )

    assert defaults.interval_seconds == 10
    assert defaults.interface_names == {"internal_lan": "eth0", "usb_lan": "eth1"}
    assert configured.interval_seconds == 5
    assert configured.interface_names == {"internal_lan": "enp1s0", "usb_lan": "enx001122"}


@pytest.mark.parametrize("interval_seconds", [float("nan"), float("inf")])
def test_gateway_metrics_config_rejects_non_finite_intervals(
    interval_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        GatewayMetricsConfig(interval_seconds=interval_seconds)


def test_linux_reader_keeps_collecting_when_optional_interface_is_missing(tmp_path) -> None:
    proc_root = tmp_path / "proc"
    sys_root = tmp_path / "sys"
    eth0_root = sys_root / "class" / "net" / "eth0"
    thermal_root = sys_root / "class" / "thermal" / "thermal_zone0"
    proc_root.mkdir()
    (eth0_root / "statistics").mkdir(parents=True)
    thermal_root.mkdir(parents=True)
    (proc_root / "stat").write_text("cpu  100 20 30 400 50 0 0 0 7 3\n", encoding="utf-8")
    (proc_root / "meminfo").write_text(
        "MemTotal:       1000 kB\nMemAvailable:    600 kB\n",
        encoding="utf-8",
    )
    (eth0_root / "operstate").write_text("up\n", encoding="utf-8")
    (eth0_root / "statistics" / "rx_bytes").write_text("12000\n", encoding="utf-8")
    (eth0_root / "statistics" / "tx_bytes").write_text("34000\n", encoding="utf-8")
    (thermal_root / "temp").write_text("48500\n", encoding="utf-8")
    reader = LinuxSystemMetricsReader(
        proc_root=proc_root,
        sys_root=sys_root,
        disk_path=tmp_path,
        disk_usage=lambda _path: SimpleNamespace(total=100_000, used=25_000),
        ip_resolver=lambda interface_name: "192.168.0.20" if interface_name == "eth0" else None,
    )

    snapshot = reader.read({"internal_lan": "eth0", "usb_lan": "eth1"})

    assert snapshot.cpu_times == CpuTimes(total=600, idle=450)
    assert snapshot.memory_total_bytes == 1_024_000
    assert snapshot.memory_available_bytes == 614_400
    assert snapshot.disk_total_bytes == 100_000
    assert snapshot.disk_used_bytes == 25_000
    assert snapshot.temperature_c == 48.5
    assert snapshot.interfaces["internal_lan"].exists is True
    assert snapshot.interfaces["internal_lan"].ip_address == "192.168.0.20"
    assert snapshot.interfaces["internal_lan"].rx_bytes == 12_000
    assert snapshot.interfaces["usb_lan"].exists is False
    assert snapshot.interfaces["usb_lan"].is_up is False
    assert snapshot.interfaces["usb_lan"].rx_bytes is None


def test_linux_reader_keeps_collecting_when_temperature_file_is_missing(tmp_path) -> None:
    proc_root = tmp_path / "proc"
    sys_root = tmp_path / "sys"
    proc_root.mkdir()
    sys_root.mkdir()
    (proc_root / "stat").write_text(
        "cpu  100 20 30 400 50 0 0 0 7 3\n",
        encoding="utf-8",
    )
    (proc_root / "meminfo").write_text(
        "MemTotal:       1000 kB\nMemAvailable:    600 kB\n",
        encoding="utf-8",
    )
    reader = LinuxSystemMetricsReader(
        proc_root=proc_root,
        sys_root=sys_root,
        disk_path=tmp_path,
        disk_usage=lambda _path: SimpleNamespace(total=100_000, used=25_000),
    )

    snapshot = reader.read({})

    assert snapshot.temperature_c is None
    assert snapshot.memory_total_bytes == 1_024_000
