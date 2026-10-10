"""Per-device AI Stage completion facts for the runtime-status storage owner."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class AICompletionRecord:
    detector_name: str
    device_id: str | None
    window_start: datetime | None
    completed_window_end: datetime
    input_count: int
    inference_count: int
    normal_count: int
    anomaly_count: int
    exclusion_counts: dict[str, int]
    model_version: str | None
    bundle_sha256: str | None
    ai_revision: int | None


@dataclass
class _Counts:
    inputs: int = 0
    inferred: int = 0
    normal: int = 0
    anomaly: int = 0
    excluded: Counter[str] = field(default_factory=Counter)
    model_version: str | None = None
    bundle_sha256: str | None = None
    ai_revision: int | None = None


class AICompletionCollector:
    def __init__(self, detector_name: str) -> None:
        self.detector_name = detector_name
        self._counts: dict[tuple[str | None, datetime], _Counts] = {}

    def input(self, device_id: str | None, window_start: datetime) -> None:
        self._counts.setdefault((device_id, window_start), _Counts()).inputs += 1

    def exclude(self, device_id: str | None, window_start: datetime, reason: str) -> None:
        self._counts.setdefault((device_id, window_start), _Counts()).excluded[reason] += 1

    def inferred(self, device_id: str | None, window_start: datetime, *,
                 anomaly: bool, model_version: str | None,
                 bundle_sha256: str | None, ai_revision: int | None) -> None:
        row = self._counts.setdefault((device_id, window_start), _Counts())
        row.inferred += 1
        row.anomaly += int(anomaly)
        row.normal += int(not anomaly)
        row.model_version = model_version
        row.bundle_sha256 = bundle_sha256
        row.ai_revision = ai_revision

    def records(self, completed_window_end: datetime) -> tuple[AICompletionRecord, ...]:
        if not self._counts:
            return (AICompletionRecord(self.detector_name, None, None,
                    completed_window_end, 0, 0, 0, 0, {}, None, None, None),)
        return tuple(
            AICompletionRecord(
                self.detector_name, device_id, window_start,
                completed_window_end, value.inputs, value.inferred,
                value.normal, value.anomaly, dict(value.excluded),
                value.model_version, value.bundle_sha256, value.ai_revision,
            )
            for (device_id, window_start), value in sorted(
                self._counts.items(), key=lambda item: (item[0][1], item[0][0] or "")
            )
        )
