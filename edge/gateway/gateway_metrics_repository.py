"""Repository helpers for gateway_metrics."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import json
from math import isfinite
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.gateway.metrics_collector import GatewayMetricsSample, InterfaceMetrics
from edge.packet.pcap_naming import format_utc_iso


def insert_gateway_metrics_sample(
    db: Session,
    *,
    sample: GatewayMetricsSample,
) -> int:
    values = _sample_to_db_values(sample)
    result = db.execute(
        text(
            """
            INSERT INTO gateway_metrics (
                collected_at,
                sample_interval_seconds,
                cpu_percent,
                memory_percent,
                disk_percent,
                disk_used_mb,
                network_rx_bytes,
                network_tx_bytes,
                temperature_c,
                interface_metrics_json
            )
            VALUES (
                :collected_at,
                :sample_interval_seconds,
                :cpu_percent,
                :memory_percent,
                :disk_percent,
                :disk_used_mb,
                NULL,
                NULL,
                :temperature_c,
                :interface_metrics_json
            )
            """
        ),
        values,
    )
    return int(result.lastrowid or 0)


def list_gateway_metrics(
    db: Session,
    *,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    where_clause, params = _gateway_metric_filters(from_at=from_at, to_at=to_at)
    params.update({"limit": limit, "offset": offset})
    rows = db.execute(
        text(
            f"""
            SELECT id, collected_at, sample_interval_seconds, cpu_percent,
                   memory_percent, disk_percent, disk_used_mb,
                   network_rx_bytes, network_tx_bytes, temperature_c,
                   interface_metrics_json, created_at
            FROM gateway_metrics
            {where_clause}
            ORDER BY collected_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings()
    return [dict(row) for row in rows]


def count_gateway_metrics(
    db: Session,
    *,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
) -> int:
    where_clause, params = _gateway_metric_filters(from_at=from_at, to_at=to_at)
    row = db.execute(
        text(
            f"""
            SELECT COUNT(*) AS count
            FROM gateway_metrics
            {where_clause}
            """
        ),
        params,
    ).mappings().one()
    return int(row["count"])


def _sample_to_db_values(sample: GatewayMetricsSample) -> dict[str, Any]:
    collected_at = _require_aware_utc(sample.collected_at, "collected_at")
    _validate_optional_non_negative(sample.sample_interval_seconds, "sample_interval_seconds")
    _validate_optional_percent(sample.cpu_percent, "cpu_percent")
    _validate_percent(sample.memory_percent, "memory_percent")
    _validate_percent(sample.disk_percent, "disk_percent")
    _validate_optional_non_negative(sample.disk_used_mb, "disk_used_mb")
    _validate_optional_finite(sample.temperature_c, "temperature_c")
    interface_metrics = _interface_metrics_to_jsonable(sample.interface_metrics)

    return {
        "collected_at": format_utc_iso(collected_at),
        "sample_interval_seconds": sample.sample_interval_seconds,
        "cpu_percent": sample.cpu_percent,
        "memory_percent": sample.memory_percent,
        "disk_percent": sample.disk_percent,
        "disk_used_mb": sample.disk_used_mb,
        "temperature_c": sample.temperature_c,
        "interface_metrics_json": json.dumps(
            interface_metrics,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ),
    }


def _interface_metrics_to_jsonable(
    interface_metrics: dict[str, InterfaceMetrics] | Any,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for role, metrics in interface_metrics.items():
        if is_dataclass(metrics):
            payload = asdict(metrics)
        else:
            payload = dict(metrics)

        _validate_optional_non_negative(payload.get("rx_bytes"), f"{role}.rx_bytes")
        _validate_optional_non_negative(payload.get("tx_bytes"), f"{role}.tx_bytes")
        _validate_optional_non_negative(
            payload.get("rx_bytes_per_sec"),
            f"{role}.rx_bytes_per_sec",
        )
        _validate_optional_non_negative(
            payload.get("tx_bytes_per_sec"),
            f"{role}.tx_bytes_per_sec",
        )
        result[str(role)] = payload
    return result


def _gateway_metric_filters(
    *,
    from_at: datetime | None,
    to_at: datetime | None,
) -> tuple[str, dict[str, Any]]:
    filters: list[str] = []
    params: dict[str, Any] = {}
    if from_at is not None:
        filters.append("collected_at >= :from_at")
        params["from_at"] = format_utc_iso(_require_aware_utc(from_at, "from_at"))
    if to_at is not None:
        filters.append("collected_at <= :to_at")
        params["to_at"] = format_utc_iso(_require_aware_utc(to_at, "to_at"))
    return ("WHERE " + " AND ".join(filters), params) if filters else ("", params)


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate_percent(value: float, field_name: str) -> None:
    _validate_finite(value, field_name)
    if value < 0 or value > 100:
        raise ValueError(f"{field_name} must be between 0 and 100")


def _validate_optional_percent(value: float | None, field_name: str) -> None:
    if value is None:
        return
    _validate_percent(value, field_name)


def _validate_optional_non_negative(value: float | int | None, field_name: str) -> None:
    if value is None:
        return
    _validate_finite(value, field_name)
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")


def _validate_optional_finite(value: float | int | None, field_name: str) -> None:
    if value is None:
        return
    _validate_finite(value, field_name)


def _validate_finite(value: float | int, field_name: str) -> None:
    if not isfinite(float(value)):
        raise ValueError(f"{field_name} must be finite")
