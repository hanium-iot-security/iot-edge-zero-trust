"""Gateway Metrics collection and persistence runtime."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
import logging
import signal
from threading import Event
import time

from sqlalchemy.orm import Session

from backend.app.config import Settings, settings
from backend.app.database import SessionLocal
from edge.gateway.gateway_metrics_repository import insert_gateway_metrics_sample
from edge.gateway.metrics_collector import (
    GatewayMetricsCollector,
    GatewayMetricsConfig,
    GatewayMetricsSample,
)
from edge.gateway.system_metrics import LinuxSystemMetricsReader


logger = logging.getLogger(__name__)


class UtcFormatter(logging.Formatter):
    """Format log timestamps in UTC regardless of the host timezone."""

    converter = time.gmtime


class GracefulShutdown:
    """Signal-backed shutdown state with an interruptible wait."""

    def __init__(self) -> None:
        self._event = Event()

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    def request(self, signum: int, _frame: object | None) -> None:
        logger.info("Shutdown signal received (signum=%s)", signum)
        self._event.set()

    def install(self) -> None:
        signal.signal(signal.SIGTERM, self.request)
        signal.signal(signal.SIGINT, self.request)

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def build_collector(config: GatewayMetricsConfig) -> GatewayMetricsCollector:
    """Build the process-wide Collector with the configured interval contract."""
    return GatewayMetricsCollector(
        reader=LinuxSystemMetricsReader(),
        clock=lambda: datetime.now(timezone.utc),
        config=config,
    )


def load_gateway_metrics_config(
    app_settings: Settings = settings,
) -> GatewayMetricsConfig:
    """Build Collector config from the project's shared `.env`-backed settings."""
    return GatewayMetricsConfig(
        interval_seconds=app_settings.gateway_metrics_interval_seconds,
        internal_lan_interface=app_settings.internal_lan_interface,
        usb_lan_interface=app_settings.usb_lan_interface,
    )


def collect_and_store_sample(
    db: Session,
    collector: GatewayMetricsCollector,
    *,
    shutdown_requested: Callable[[], bool] = lambda: False,
) -> GatewayMetricsSample | None:
    """Collect and commit one sample, rolling back any failure."""
    try:
        sample = collector.collect()
        if shutdown_requested():
            db.rollback()
            return None

        insert_gateway_metrics_sample(db, sample=sample)
        if shutdown_requested():
            db.rollback()
            return None

        db.commit()
        return sample
    except BaseException:
        db.rollback()
        raise


def run_gateway_metrics_loop(
    config: GatewayMetricsConfig,
    collector: GatewayMetricsCollector,
    shutdown: GracefulShutdown,
    *,
    session_factory: Callable[[], Session] = SessionLocal,
    max_samples: int | None = None,
) -> int:
    """Persist samples until shutdown, propagating failures for systemd restart."""
    if max_samples is not None and max_samples <= 0:
        raise ValueError("max_samples must be positive")

    stored_count = 0
    while not shutdown.requested:
        with session_factory() as db:
            sample = collect_and_store_sample(
                db,
                collector,
                shutdown_requested=lambda: shutdown.requested,
            )

        if sample is None:
            break

        stored_count += 1
        if max_samples is not None and stored_count >= max_samples:
            break
        if shutdown.wait(config.interval_seconds):
            break

    return stored_count


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Raspberry Pi Gateway Metrics Collector")
    parser.add_argument(
        "--samples",
        type=_positive_int,
        default=None,
        help="저장할 Sample 수 (미지정 시 종료 Signal까지 반복)",
    )
    return parser.parse_args(argv)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        UtcFormatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    configure_logging()

    config = load_gateway_metrics_config()
    shutdown = GracefulShutdown()
    shutdown.install()
    collector = build_collector(config)

    stored_count = run_gateway_metrics_loop(
        config,
        collector,
        shutdown,
        max_samples=args.samples,
    )
    logger.info("Gateway Metrics collector stopped (stored_samples=%d)", stored_count)


if __name__ == "__main__":
    main()
