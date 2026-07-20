"""Gateway Metrics collection and persistence runtime."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import logging
import signal
from threading import Event

from sqlalchemy.orm import Session

from backend.app.database import SessionLocal
from edge.gateway.gateway_metrics_repository import insert_gateway_metrics_sample
from edge.gateway.metrics_collector import (
    GatewayMetricsCollector,
    GatewayMetricsConfig,
    GatewayMetricsSample,
)
from edge.gateway.system_metrics import LinuxSystemMetricsReader


logger = logging.getLogger(__name__)


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
) -> int:
    """Persist samples until shutdown, propagating failures for systemd restart."""
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
        if shutdown.wait(config.interval_seconds):
            break

    return stored_count


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = GatewayMetricsConfig.from_env()
    shutdown = GracefulShutdown()
    shutdown.install()
    collector = build_collector(config)

    stored_count = run_gateway_metrics_loop(config, collector, shutdown)
    logger.info("Gateway Metrics collector stopped (stored_samples=%d)", stored_count)


if __name__ == "__main__":
    main()
