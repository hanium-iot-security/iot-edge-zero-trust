"""Small, opt-in observations from the existing Orchestrator process.

Completion storage and successful Stage observations use the caller's transaction.
A fresh observation describes this process's last observation, not a liveness lease.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import logging
from pathlib import Path
from uuid import UUID, uuid4

from backend.app.config import Settings
from edge.detection import ai_runtime_repository as repository
from edge.detection.ai_warning_aggregation import WarningPolicy


logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def current_boot_id() -> str | None:
    try:
        return str(UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
    except (OSError, ValueError):
        return None


def warning_policy_from_settings(app_settings: Settings) -> WarningPolicy | None:
    version = app_settings.ai_warning_policy_version.strip()
    values = (app_settings.ai_warning_window_seconds,
              app_settings.ai_warning_count_threshold,
              app_settings.ai_warning_cooldown_seconds)
    if not version and all(value is None for value in values):
        return None
    if not version or any(value is None for value in values):
        raise ValueError('AI warning version, window, count and cooldown must be configured together')
    return WarningPolicy(version, *values)


class RuntimeEvidence:
    def __init__(self, session_factory, app_settings: Settings, *, clock=utc_now) -> None:
        from edge.orchestration.stage_registry import KNOWN_STAGE_NAMES

        self.session_factory = session_factory
        self.clock = clock
        self.run_id = str(uuid4())
        self.boot_id = current_boot_id()
        self.started_at = clock()
        self.warning_policy: WarningPolicy | None = None
        self.trust_ai_mode: str | None = None
        enabled = {name.strip() for name in app_settings.orchestrator_enabled_stages.split(',') if name.strip()}
        required = {name.strip() for name in app_settings.orchestrator_required_stages.split(',') if name.strip()}
        names = tuple(dict.fromkeys((*KNOWN_STAGE_NAMES, *sorted(enabled | required))))
        self._stage_names: dict[tuple[str, str], str] = {}
        self._initial = {
            'run_id': self.run_id, 'boot_id': self.boot_id,
            'started_at': self.started_at, 'observed_at': self.started_at,
            'status': 'STARTING', 'error_code': None, 'warning_policy': None,
            'stages': [dict(name=name, enabled=name in enabled, required=name in required,
                            status='UNKNOWN' if name in enabled else 'DISABLED',
                            observed_at=None, trust_ai_mode=None, model_version=None,
                            bundle_sha256=None, last_completed_window_end=None,
                            last_processed_id=None, selected_count=None, created_event_count=None,
                            error_code=None) for name in names],
        }

    def _snapshot(self, db, status: str, *, stage_name=None, fields=None, error_code=None):
        stored = repository.read_runtime_snapshot(db)
        snapshot = deepcopy(stored if stored and stored['run_id'] == self.run_id else self._initial)
        snapshot.update(status=status, observed_at=self.clock(), error_code=error_code,
                        warning_policy=asdict(self.warning_policy) if self.warning_policy else None)
        if stage_name is not None:
            stage = next(item for item in snapshot['stages'] if item['name'] == stage_name)
            stage.update(fields or {})
            stage['observed_at'] = snapshot['observed_at']
        failed = next((item for item in snapshot['stages'] if item['status'] == 'FAILED'), None)
        if status == 'RUNNING' and failed is not None:
            snapshot.update(status='FAILED', error_code=failed['error_code'])
        return snapshot

    def publish(self, status: str, *, stage_name=None, fields=None, error_code=None,
                best_effort=False) -> None:
        try:
            with self.session_factory() as db, db.begin():
                repository.save_runtime_snapshot(db, self._snapshot(
                    db, status, stage_name=stage_name, fields=fields, error_code=error_code))
        except Exception:
            if not best_effort:
                raise
            logger.exception('Runtime evidence could not record the existing failure')

    def register_stage(self, name, stage) -> None:
        self._stage_names[(stage.detector_name, stage.source_table)] = name
        delegate = getattr(stage, 'delegate', stage)
        artifact = getattr(delegate, 'artifact', None)
        identity = getattr(artifact, 'inspection', artifact)
        self.publish('STARTING', stage_name=name, fields={
            'status': 'INITIALIZED', 'error_code': None,
            'model_version': getattr(identity, 'model_version', None),
            'bundle_sha256': getattr(identity, 'bundle_sha256', None),
        })
        if hasattr(delegate, 'completion_sink'):
            previous = delegate.completion_sink

            def completion_sink(db, records):
                if previous is not None:
                    previous(db, records)
                repository.store_ai_completions(
                    db, records, run_id=self.run_id, boot_id=self.boot_id,
                    observed_at=self.clock(), warning_policy=self.warning_policy)

            delegate.completion_sink = completion_sink

    def stage_completed(self, db, result) -> None:
        name = self._stage_names[(result.detector_name, result.source_table)]
        fields = {
            'status': 'NO_INPUT' if result.selected_count == 0 else 'COMPLETED',
            'error_code': None,
            'last_completed_window_end': result.completed_window_end_after,
            'last_processed_id': result.last_processed_id_after,
            'selected_count': result.selected_count,
            'created_event_count': result.created_event_count,
            'trust_ai_mode': self.trust_ai_mode if name in ('mqtt_if', 'packet_if') else None,
        }
        snapshot = self._snapshot(db, 'RUNNING', stage_name=name, fields=fields)
        repository.save_runtime_snapshot(db, snapshot)

    def stage_failed(self, name, error_code='STAGE_FAILED') -> None:
        self.publish('FAILED', stage_name=name,
                     fields={'status': 'FAILED', 'error_code': error_code},
                     error_code=error_code, best_effort=True)
