"""Additive raw-log page metadata; payload_size is stored original byte length."""
from typing import Any, Literal, TypedDict


class MqttLogPage(TypedDict):
    items: list[dict[str, Any]]
    total: int
    snapshot_max_id: int
    offset: int
    limit: int
    has_more: bool
    # Scoped to device/valid_only and snapshot, across all times: an unknown
    # timestamp cannot be honestly assigned inside or outside a requested period.
    timestamp_unavailable_count: int | None
    timestamp_unavailable_count_scope: Literal["device_snapshot_first_page", "not_evaluated"]
    # Count every source row between the full range's selected min/max IDs,
    # ignoring valid_only. Equality with total proves no hidden intervening row.
    source_span_count: int | None
    source_span_count_scope: Literal["selected_source_ids_first_page", "not_evaluated"]
    interval_predecessor_policy: Literal["within_range_only"]