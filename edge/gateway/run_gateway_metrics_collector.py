"""Gateway Metrics collection and persistence runtime."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from edge.gateway.gateway_metrics_repository import insert_gateway_metrics_sample
from edge.gateway.metrics_collector import GatewayMetricsCollector, GatewayMetricsSample


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
