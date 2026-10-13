"""Opt-in runtime observations with real SQLite Stage transactions."""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from backend.app.config import Settings
from edge.detection import ai_runtime_repository as repository
from edge.detection.orchestrator import run_detection_cycle
from edge.orchestration import run_detection_orchestrator as runner
from edge.orchestration.runtime_evidence import RuntimeEvidence, warning_policy_from_settings
from edge.orchestration.stage_registry import StageConfigurationError, load_stage_registry
from edge.runtime_lock import RuntimeLockError
from test_mqtt_if_artifact import _fixture, _write_contract
from test_mqtt_if_runtime import bundle_dir, _settings, _feature
from test_phase8_trust_gates import session_factory, _seed, T0, T1, T2


NOW = datetime(2026, 10, 13, 12, 0, 0, 123456, tzinfo=timezone.utc)


def _setup(factory, app_settings):
    evidence = RuntimeEvidence(factory, app_settings, clock=lambda: NOW)
    evidence.publish('STARTING')
    evidence.warning_policy = warning_policy_from_settings(app_settings)
    registry = load_stage_registry(app_settings, runtime_evidence=evidence)
    return evidence, registry


def _snapshot(factory):
    with factory() as db:
        return repository.read_runtime_snapshot(db)


def _stage(snapshot, name='mqtt_if'):
    return next(item for item in snapshot['stages'] if item['name'] == name)


def _run(factory, registry, start=T0, cutoff=T1):
    return run_detection_cycle(
        session_factory=factory, stages=registry.detector_stages,
        cycle_range_start=start, cycle_cutoff=cutoff,
        stage_completion_sink=registry.runtime_evidence.stage_completed,
    )


def _when(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _main_env(monkeypatch, factory, app_settings):
    original_cycle = runner.run_orchestration_cycle
    monkeypatch.setattr(runner, 'settings', app_settings)
    monkeypatch.setattr(runner, 'SessionLocal', factory)
    monkeypatch.setattr(runner, 'configure_logging', lambda: None)
    monkeypatch.setattr(runner, 'single_instance_lock', lambda *a, **kw: nullcontext())
    monkeypatch.setattr(runner, 'load_stage_registry',
                        lambda **kw: load_stage_registry(app_settings, **kw))
    monkeypatch.setattr(runner, 'run_orchestration_cycle',
                        lambda **kw: original_cycle(session_factory=factory, **kw))
    monkeypatch.setattr(runner, 'resolve_cycle_cutoff', lambda db: T1)
    monkeypatch.setattr(runner, 'resolve_cycle_range_start', lambda db, **kw: T0)
    monkeypatch.setattr(runner, 'resolve_ai_mode', lambda: 'observe')


def test_opt_out_and_no_warning_policy_are_defaults():
    settings = Settings(_env_file=None)
    assert not settings.runtime_evidence_enabled
    assert warning_policy_from_settings(settings) is None


@pytest.mark.parametrize('overrides', [
    {'ai_warning_policy_version': 'v1'},
    {'ai_warning_window_seconds': 60},
    {'ai_warning_count_threshold': 3},
    {'ai_warning_cooldown_seconds': 0},
    {'ai_warning_window_seconds': 60, 'ai_warning_count_threshold': 3,
     'ai_warning_cooldown_seconds': 120},
])
def test_partial_warning_configuration_is_rejected(overrides):
    with pytest.raises(ValueError, match='configured together'):
        warning_policy_from_settings(Settings(_env_file=None, **overrides))


@pytest.mark.parametrize('field,value', [
    ('ai_warning_window_seconds', 11),
    ('ai_warning_count_threshold', 0),
    ('ai_warning_cooldown_seconds', -1),
])
def test_invalid_explicit_warning_configuration_is_rejected(field, value):
    config = dict(ai_warning_policy_version='explicit-test-policy', ai_warning_window_seconds=60,
                  ai_warning_count_threshold=3, ai_warning_cooldown_seconds=0)
    config[field] = value
    with pytest.raises(ValueError):
        warning_policy_from_settings(Settings(_env_file=None, **config))


def test_explicit_zero_cooldown_is_valid():
    policy = warning_policy_from_settings(Settings(
        _env_file=None, ai_warning_policy_version='explicit-test-policy',
        ai_warning_window_seconds=20, ai_warning_count_threshold=2, ai_warning_cooldown_seconds=0))
    assert policy.version == 'explicit-test-policy' and policy.cooldown_seconds == 0


def test_registry_observes_loaded_bundle_not_configured_identity(session_factory, bundle_dir):
    evidence, registry = _setup(session_factory, _settings(bundle_dir))
    snapshot = _snapshot(session_factory)
    stage = _stage(snapshot)
    artifact = registry.detector_stages[0].artifact.inspection
    assert stage['status'] == 'INITIALIZED'
    assert stage['model_version'] == artifact.model_version
    assert stage['bundle_sha256'] == artifact.bundle_sha256
    assert stage['trust_ai_mode'] is None and stage['last_completed_window_end'] is None
    assert _stage(snapshot, 'packet_if')['status'] == 'DISABLED'
    assert snapshot['run_id'] == evidence.run_id and snapshot['warning_policy'] is None
    assert _when(snapshot['observed_at']) == NOW


def test_normal_inference_is_saved_without_anomaly_event(session_factory, tmp_path):
    directory = tmp_path / 'normal-bundle'
    metadata = _fixture(directory)
    metadata['threshold'] = -1.0
    _write_contract(directory, metadata)
    with session_factory() as db, db.begin():
        _seed(db, status='ACTIVE')
        _feature(db)
    evidence, registry = _setup(session_factory, _settings(directory))
    _run(session_factory, registry)
    with session_factory() as db:
        records = repository.read_ai_completions(db, device_id='esp32_01')
        assert db.execute(text('SELECT COUNT(*) FROM detection_events')).scalar_one() == 0
    assert len(records) == 1
    assert records[0]['normal_count'] == records[0]['inference_count'] == 1
    assert records[0]['run_id'] == evidence.run_id
    assert records[0]['ai_mode'] is None  # Publishing never injects or guesses the device policy.
    stage = _stage(_snapshot(session_factory))
    assert stage['status'] == 'COMPLETED' and stage['created_event_count'] == 0
    assert _when(stage['last_completed_window_end']) == T1
    assert _when(stage['observed_at']) == NOW and NOW > T1


def test_empty_stage_is_not_a_normal_device_completion(session_factory, bundle_dir):
    evidence, registry = _setup(session_factory, _settings(bundle_dir))
    _run(session_factory, registry)
    with session_factory() as db:
        assert repository.read_ai_completions(db, device_id='esp32_01') == []
        records = repository.read_ai_completions(db)
    assert len(records) == 1 and records[0]['device_id'] is None
    assert records[0]['normal_count'] == records[0]['inference_count'] == 0
    assert _stage(_snapshot(session_factory))['status'] == 'NO_INPUT'


def test_retry_does_not_duplicate_event_or_refresh_device_evidence(session_factory, bundle_dir):
    with session_factory() as db, db.begin():
        _seed(db, status='ACTIVE')
        _feature(db)
    evidence, registry = _setup(session_factory, _settings(bundle_dir))
    _run(session_factory, registry)
    with session_factory() as db:
        original = repository.read_ai_completions(db)
    evidence.clock = lambda: NOW + timedelta(seconds=10)
    _run(session_factory, registry)
    with session_factory() as db:
        assert repository.read_ai_completions(db) == original
        assert db.execute(text('SELECT COUNT(*) FROM detection_events')).scalar_one() == 1
    assert _when(_stage(_snapshot(session_factory))['observed_at']) == NOW + timedelta(seconds=10)


@pytest.mark.parametrize('failure', ['completion', 'snapshot'])
def test_evidence_failure_rolls_back_event_completion_and_checkpoint(
    session_factory, bundle_dir, monkeypatch, failure,
):
    with session_factory() as db, db.begin():
        _seed(db, status='ACTIVE')
        _feature(db)
    evidence, registry = _setup(session_factory, _settings(bundle_dir))
    original_save = repository.save_runtime_snapshot

    def fail(*args, **kwargs):
        raise RuntimeError('evidence write failed')

    if failure == 'completion':
        monkeypatch.setattr(repository, 'store_ai_completions', fail)
    else:
        def fail_completed(db, snapshot):
            if _stage(snapshot)['status'] == 'COMPLETED':
                fail()
            return original_save(db, snapshot)
        monkeypatch.setattr(repository, 'save_runtime_snapshot', fail_completed)
    with pytest.raises(RuntimeError, match='evidence write failed'):
        _run(session_factory, registry)
    with session_factory() as db:
        assert db.execute(text('SELECT COUNT(*) FROM detection_events')).scalar_one() == 0
        assert repository.read_ai_completions(db) == []
        assert db.execute(text("SELECT COUNT(*) FROM detector_checkpoints WHERE detector_name='mqtt_if'")).scalar_one() == 0
    evidence.stage_failed('mqtt_if')
    stage = _stage(_snapshot(session_factory))
    assert stage['status'] == 'FAILED' and stage['last_completed_window_end'] is None


def test_optional_failure_survives_later_stage_success_and_keeps_last_completion(
    session_factory, bundle_dir, monkeypatch,
):
    settings = _settings(bundle_dir, orchestrator_enabled_stages='mqtt_if,mqtt_feature_rule',
                         orchestrator_required_stages='')
    evidence, registry = _setup(session_factory, settings)
    _run(session_factory, registry)

    def fail(*args, **kwargs):
        raise RuntimeError('inference failed')

    monkeypatch.setattr(registry.detector_stages[0], 'run_until', fail)
    monkeypatch.setattr(runner, 'resolve_cycle_cutoff', lambda db: T2)
    monkeypatch.setattr(runner, 'resolve_cycle_range_start', lambda db, **kw: T1)
    monkeypatch.setattr(runner, 'resolve_ai_mode', lambda: 'observe')
    monkeypatch.setattr(runner, 'single_instance_lock', lambda *a, **kw: nullcontext())
    runner.run_orchestration_cycle(session_factory=session_factory, registry=registry)
    evidence.publish('RUNNING')
    snapshot = _snapshot(session_factory)
    assert snapshot['status'] == 'FAILED'
    assert _stage(snapshot)['status'] == 'FAILED'
    assert _when(_stage(snapshot)['last_completed_window_end']) == T1
    assert _stage(snapshot, 'mqtt_feature_rule')['status'] == 'NO_INPUT'
    assert _when(_stage(snapshot, 'mqtt_feature_rule')['last_completed_window_end']) == T2


def test_main_records_model_initialization_failure_without_configured_model_claim(
    session_factory, bundle_dir, monkeypatch,
):
    settings = _settings(bundle_dir, runtime_evidence_enabled=True,
                         mqtt_if_expected_model_version='wrong-configured-version')
    _main_env(monkeypatch, session_factory, settings)
    with pytest.raises(StageConfigurationError):
        runner.main(['--once'])
    snapshot = _snapshot(session_factory)
    assert snapshot['status'] == 'FAILED'
    stage = _stage(snapshot)
    assert stage['enabled'] and stage['required'] and stage['status'] == 'FAILED'
    assert stage['model_version'] is None and stage['bundle_sha256'] is None
    assert stage['error_code'] == 'STAGE_INITIALIZATION_FAILED'


def test_partial_warning_settings_fail_before_any_stage_runs(session_factory, monkeypatch):
    settings = _settings(runtime_evidence_enabled=True, ai_warning_policy_version='partial')
    _main_env(monkeypatch, session_factory, settings)
    with pytest.raises(ValueError, match='configured together'):
        runner.main(['--once'])
    snapshot = _snapshot(session_factory)
    assert snapshot['status'] == 'FAILED' and snapshot['error_code'] == 'INITIALIZATION_FAILED'
    assert _stage(snapshot)['last_completed_window_end'] is None


def test_main_observes_success_no_input_and_orderly_stop(session_factory, bundle_dir, monkeypatch):
    settings = _settings(bundle_dir, runtime_evidence_enabled=True)
    _main_env(monkeypatch, session_factory, settings)
    assert runner.main(['--once']) == 0
    snapshot = _snapshot(session_factory)
    assert snapshot['status'] == 'STOPPED'
    assert _stage(snapshot)['status'] == 'NO_INPUT'
    assert _stage(snapshot)['trust_ai_mode'] == 'observe'
    assert _when(_stage(snapshot)['last_completed_window_end']) == T1


def test_failed_lock_does_not_replace_another_process_snapshot(session_factory, bundle_dir, monkeypatch):
    settings = _settings(bundle_dir, runtime_evidence_enabled=True)
    evidence, registry = _setup(session_factory, settings)
    evidence.publish('RUNNING')
    before = _snapshot(session_factory)
    _main_env(monkeypatch, session_factory, settings)

    def locked(*args, **kwargs):
        raise RuntimeLockError('already locked')

    monkeypatch.setattr(runner, 'single_instance_lock', locked)
    assert runner.main(['--once']) == 3
    assert _snapshot(session_factory) == before


def test_failure_publication_cannot_hide_original_exception(session_factory, bundle_dir, monkeypatch):
    settings = _settings(bundle_dir, runtime_evidence_enabled=True)
    _main_env(monkeypatch, session_factory, settings)

    def store_failed(*args, **kwargs):
        raise RuntimeError('snapshot storage unavailable')

    def cycle_failed(**kwargs):
        monkeypatch.setattr(repository, 'save_runtime_snapshot', store_failed)
        raise LookupError('original stage error')

    monkeypatch.setattr(runner, 'run_orchestration_cycle', cycle_failed)
    with pytest.raises(LookupError, match='original stage error'):
        runner.main(['--once'])


def test_opt_out_never_touches_runtime_storage(session_factory, monkeypatch):
    settings = _settings(runtime_evidence_enabled=False, orchestrator_enabled_stages='mqtt_message_rule',
                         orchestrator_required_stages='mqtt_message_rule')
    _main_env(monkeypatch, session_factory, settings)

    def forbidden(*args, **kwargs):
        raise AssertionError('opt-out must not query runtime schema')

    monkeypatch.setattr(repository, 'read_runtime_snapshot', forbidden)
    monkeypatch.setattr(repository, 'save_runtime_snapshot', forbidden)
    assert runner.main(['--once']) == 0


def test_skipped_cycle_refreshes_only_runtime_observation(session_factory, bundle_dir, monkeypatch):
    evidence, registry = _setup(session_factory, _settings(bundle_dir))
    monkeypatch.setattr(runner, 'resolve_cycle_cutoff', lambda db: None)
    evidence.clock = lambda: NOW + timedelta(seconds=5)
    runner.run_orchestration_cycle(session_factory=session_factory, registry=registry)
    snapshot = _snapshot(session_factory)
    assert _when(snapshot['observed_at']) == NOW + timedelta(seconds=5)
    assert _stage(snapshot)['status'] == 'INITIALIZED'
    with session_factory() as db:
        assert repository.read_ai_completions(db) == []

def test_unexpected_model_initialization_error_marks_the_failing_stage(
    session_factory, bundle_dir, monkeypatch,
):
    from edge.orchestration.stage_registry import STAGE_BUILDERS
    settings = _settings(bundle_dir, runtime_evidence_enabled=True)
    _main_env(monkeypatch, session_factory, settings)

    def failed_builder(app_settings):
        raise RuntimeError('model initialization interrupted')

    monkeypatch.setitem(STAGE_BUILDERS, 'mqtt_if', failed_builder)
    with pytest.raises(RuntimeError, match='model initialization interrupted'):
        runner.main(['--once'])
    assert _stage(_snapshot(session_factory))['status'] == 'FAILED'

@pytest.mark.parametrize('reject_warning', [False, True])
def test_registry_sink_persists_explicit_observe_warning_in_the_stage_transaction(
    session_factory, bundle_dir, reject_warning,
):
    from edge.policy.ai_window_decision import AIRevision, decide_ai_window
    settings = _settings(bundle_dir, ai_warning_policy_version='synthetic-explicit-v1',
                         ai_warning_window_seconds=20, ai_warning_count_threshold=2,
                         ai_warning_cooldown_seconds=0)
    with session_factory() as db, db.begin():
        _seed(db, status='ACTIVE')
        _feature(db, start=T0)
        _feature(db, start=T1)
        if reject_warning:
            db.execute(text("""CREATE TRIGGER reject_test_warning BEFORE INSERT ON ai_warning_events
                BEGIN SELECT RAISE(ABORT, 'test warning storage failure'); END"""))
    evidence, registry = _setup(session_factory, settings)
    # This explicit synthetic decision is fixture-only; production wiring does
    # not activate a device or substitute a global mode for per-device approval.
    registry.detector_stages[0].ai_window_selector = lambda resolution: decide_ai_window(
        resolution, [AIRevision('esp32_01', 1, 'OBSERVE', T0)], stage_activation_from=T0)
    if reject_warning:
        with pytest.raises(repository.RuntimeEvidenceUnavailable):
            _run(session_factory, registry, cutoff=T2)
        with session_factory() as db:
            assert db.execute(text('SELECT COUNT(*) FROM detection_events')).scalar_one() == 0
            assert repository.read_ai_completions(db) == []
            assert repository.list_ai_warnings(db)['items'] == []
            assert db.execute(text("SELECT COUNT(*) FROM detector_checkpoints WHERE detector_name='mqtt_if'")).scalar_one() == 0
    else:
        _run(session_factory, registry, cutoff=T2)
        with session_factory() as db:
            warnings = repository.list_ai_warnings(db)
        assert warnings['total'] == 1
        warning = warnings['items'][0]
        assert warning['count'] == 2 and len(warning['event_ids']) == 2
        assert warning['last_decision'] == 'NOTIFY'
        evidence.clock = lambda: NOW + timedelta(seconds=5)
        _run(session_factory, registry, cutoff=T2)
        with session_factory() as db:
            assert repository.list_ai_warnings(db) == warnings

def test_pre_012_013_database_keeps_opt_out_startup_and_refuses_enabled_writes(tmp_path, monkeypatch):
    import shutil
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from db.migration_runner import MIGRATIONS_DIR, apply_migrations

    migration_dir = tmp_path / 'legacy-migrations'
    migration_dir.mkdir()
    for migration in MIGRATIONS_DIR.glob('*.sql'):
        if int(migration.name[:3]) <= 11:
            shutil.copyfile(migration, migration_dir / migration.name)
    db_path = tmp_path / 'pre-phase9-runtime.db'
    apply_migrations(db_path, migration_dir)
    engine = create_engine(f'sqlite:///{db_path}', connect_args={'check_same_thread': False})
    factory = sessionmaker(bind=engine)
    settings = _settings(runtime_evidence_enabled=False, orchestrator_enabled_stages='mqtt_message_rule',
                         orchestrator_required_stages='mqtt_message_rule')
    try:
        _main_env(monkeypatch, factory, settings)
        assert runner.main(['--once']) == 0
        with factory() as db:
            before = db.execute(text('SELECT * FROM detector_checkpoints ORDER BY detector_name')).all()
        settings.runtime_evidence_enabled = True
        with pytest.raises(repository.RuntimeEvidenceUnavailable, match='Migration 014'):
            runner.main(['--once'])
        with factory() as db:
            assert db.execute(text('SELECT * FROM detector_checkpoints ORDER BY detector_name')).all() == before
    finally:
        engine.dispose()
