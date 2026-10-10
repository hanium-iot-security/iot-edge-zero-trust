"""Pure Phase 9 OBSERVE warning aggregation; persistence is caller-owned.

The caller loads/saves the entire ledger in the detection transaction. A
notification result must be published only after that transaction commits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from edge.policy.resolver import require_window_start


AI_ANOMALY_TYPES = frozenset(("AI_ANOMALY", "AI_PACKET_ANOMALY"))


@dataclass(frozen=True)
class WarningPolicy:
    version: str
    window_seconds: int
    count_threshold: int
    cooldown_seconds: int

    def __post_init__(self) -> None:
        if not self.version or self.window_seconds < 10 or self.window_seconds % 10:
            raise ValueError("warning version and a 10-second-aligned W are required")
        if self.count_threshold < 1 or self.cooldown_seconds < 0:
            raise ValueError("warning N must be positive and C non-negative")


@dataclass(frozen=True)
class AIObservation:
    event_id: int
    device_id: str
    detector_name: str
    event_type: str
    model_version: str
    window_start: datetime
    mode: str = "OBSERVE"
    quality_eligible: bool = True


@dataclass
class WarningAggregate:
    bucket_start: datetime
    event_ids: set[int] = field(default_factory=set)
    analysis_windows: set[datetime] = field(default_factory=set)
    first_window: datetime | None = None
    latest_window: datetime | None = None
    notified_at: datetime | None = None
    suppressed_count: int = 0
    closed: bool = False

    @property
    def count(self) -> int:
        return len(self.analysis_windows)


@dataclass(frozen=True)
class WarningDecision:
    status: str
    aggregate: WarningAggregate | None
    notify: bool = False


class WarningLedger:
    """Serializable state keyed by device, detector, type, model and policy."""

    def __init__(self) -> None:
        self.aggregates: dict[tuple[str, str, str, str, str, datetime], WarningAggregate] = {}
        self.latest_bucket: dict[tuple[str, str, str, str, str], datetime] = {}
        self.last_notification: dict[tuple[str, str, str, str, str], datetime] = {}
        self.seen_event_ids: set[int] = set()

    def ingest(
        self, observation: AIObservation, policy: WarningPolicy, *, received_at: datetime
    ) -> WarningDecision:
        require_window_start(observation.window_start)
        if received_at.tzinfo is None or received_at.utcoffset() != timedelta(0):
            raise ValueError("received_at must be UTC")
        if observation.mode != "OBSERVE":
            return WarningDecision("AI_MODE_EXCLUDED", None)
        if not observation.quality_eligible:
            return WarningDecision("QUALITY_EXCLUDED", None)
        if observation.event_id <= 0 or not all((observation.device_id,
                                                  observation.detector_name,
                                                  observation.model_version)):
            raise ValueError("a saved OBSERVE anomaly and complete warning key are required")
        if observation.event_type not in AI_ANOMALY_TYPES:
            raise ValueError("only saved AI anomaly events are warning inputs")
        key = (observation.device_id, observation.detector_name,
               observation.event_type, observation.model_version, policy.version)
        seconds = int(observation.window_start.timestamp())
        bucket = datetime.fromtimestamp(
            seconds - seconds % policy.window_seconds, tz=timezone.utc
        )
        aggregate_key = (*key, bucket)
        if observation.event_id in self.seen_event_ids:
            return WarningDecision("DUPLICATE", self.aggregates.get(aggregate_key))
        aggregate = self.aggregates.setdefault(aggregate_key, WarningAggregate(bucket))
        if observation.window_start in aggregate.analysis_windows:
            aggregate.event_ids.add(observation.event_id)
            self.seen_event_ids.add(observation.event_id)
            return WarningDecision("DUPLICATE", aggregate)

        latest = self.latest_bucket.get(key)
        late = latest is not None and bucket < latest
        if latest is None or bucket > latest:
            for saved_key, saved in self.aggregates.items():
                if saved_key[:5] == key and saved_key[-1] < bucket:
                    saved.closed = True
            self.latest_bucket[key] = bucket
        aggregate.event_ids.add(observation.event_id)
        aggregate.analysis_windows.add(observation.window_start)
        aggregate.first_window = min(aggregate.analysis_windows)
        aggregate.latest_window = max(aggregate.analysis_windows)
        self.seen_event_ids.add(observation.event_id)
        if late or aggregate.closed:
            aggregate.closed = True
            return WarningDecision("LATE_ATTACHED", aggregate)
        if aggregate.count < policy.count_threshold:
            return WarningDecision("BELOW_THRESHOLD", aggregate)
        if aggregate.notified_at is not None:
            aggregate.suppressed_count += 1
            return WarningDecision("ALREADY_NOTIFIED", aggregate)
        previous = self.last_notification.get(key)
        if previous is not None and received_at < previous + timedelta(seconds=policy.cooldown_seconds):
            aggregate.suppressed_count += 1
            return WarningDecision("COOLDOWN_SUPPRESSED", aggregate)
        aggregate.notified_at = received_at
        self.last_notification[key] = received_at
        return WarningDecision("NOTIFY", aggregate, notify=True)
