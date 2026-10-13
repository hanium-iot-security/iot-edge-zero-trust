"""The explicit local activation command uses the existing lock and real SQLite."""
from contextlib import closing
from datetime import timedelta
import json
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.migration_runner import apply_migrations
from edge.detection.runtime_checkpoint_repository import upsert_detector_checkpoint
from edge.orchestration import manage_ai_activation as command
from edge.runtime_lock import single_instance_lock
from test_mqtt_if_artifact import _fixture
from test_mqtt_if_runtime import _feature, _settings
from test_phase8_trust_gates import T0, T1, T2, _seed


@pytest.fixture
def activation(tmp_path, monkeypatch):
    path = tmp_path / "activation.db"
    apply_migrations(path)
    directory = tmp_path / "bundle"
    _fixture(directory)
    configured = _settings(directory, ai_device_policy_enabled=True,
                           database_url=f"sqlite:///{path.as_posix()}",
                           orchestrator_enabled_stages="mqtt_feature_rule,mqtt_if",
                           orchestrator_required_stages="mqtt_feature_rule,mqtt_if")
    engine = create_engine(configured.database_url)
    with Session(engine) as db, db.begin():
        _seed(db, status="ACTIVE")
        _feature(db, start=T0)
        _feature(db, start=T1)
        for stage, source, end in (("mqtt_if", "feature_logs", T0),
                                   ("mqtt_feature_rule", "feature_logs", T2),
                                   ("trust_score_v2", "detection_events", T2)):
            upsert_detector_checkpoint(db, detector_name=stage, source_table=source,
                                       last_processed_id=None, last_completed_window_end=end,
                                       updated_at=end)
    engine.dispose()
    monkeypatch.setattr(command, "utc_now", lambda: T2 + timedelta(seconds=10))
    return path, configured, tmp_path / "plan.json"


def dump(path):
    with closing(sqlite3.connect(path)) as db:
        return list(db.iterdump())


def prepare(activation):
    path, configured, plan = activation
    return command.main(["--db", str(path), "prepare", "--stage", "mqtt_if",
                         "--boundary", T2.isoformat().replace("+00:00", "Z"), "--approved-by", "test",
                         "--reason", "explicit synthetic boundary", "--output", str(plan)],
                        app_settings=configured)


def apply(activation, *, configured=None):
    path, default, plan = activation
    return command.main(["--db", str(path), "apply", "--plan", str(plan)],
                        app_settings=configured or default)


def test_prepare_is_read_only_and_apply_is_idempotent(activation):
    path, _, plan = activation
    before = dump(path)
    assert prepare(activation) == 0
    assert dump(path) == before
    payload = json.loads(plan.read_text(encoding="utf-8"))
    assert payload["activation"]["excluded_source"]["row_count"] == 2
    assert apply(activation) == 0
    applied = dump(path)
    assert apply(activation) == 0
    assert dump(path) == applied
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT COUNT(*) FROM ai_stage_activations").fetchone()[0] == 1
        checkpoints = dict(db.execute("SELECT detector_name,last_completed_window_end FROM detector_checkpoints"))
        assert set(checkpoints.values()) == {T2.isoformat().replace("+00:00", "Z")}
        assert db.execute("SELECT COUNT(*) FROM feature_logs").fetchone()[0] == 2


def test_prepare_never_overwrites_reviewed_plan(activation):
    assert prepare(activation) == 0
    path, _, plan = activation
    expected, original = dump(path), plan.read_bytes()
    assert prepare(activation) == 2
    assert plan.read_bytes() == original and dump(path) == expected


def test_apply_uses_orchestrator_lock_before_loading_model(activation, monkeypatch):
    path, configured, _ = activation
    assert prepare(activation) == 0
    before = dump(path)

    def forbidden(*args):
        raise AssertionError("a competing command must not load or change anything")

    monkeypatch.setattr(command, "_runtime_inputs", forbidden)
    with single_instance_lock(command.resolve_lock_path(configured)):
        assert apply(activation) == 3
    assert dump(path) == before


@pytest.mark.parametrize("change", ["config", "source", "model"])
def test_changed_reviewed_state_is_hold_without_checkpoint_change(activation, change):
    path, configured, _ = activation
    assert prepare(activation) == 0
    if change == "config":
        configured = configured.model_copy(update={"orchestrator_required_stages": "mqtt_feature_rule"})
    elif change == "source":
        with closing(sqlite3.connect(path)) as db:
            db.execute("UPDATE feature_logs SET avg_payload_size=avg_payload_size+1")
            db.commit()
    else:
        configured = configured.model_copy(update={"mqtt_if_expected_bundle_sha256": "0" * 64})
    before = dump(path)
    assert apply(activation, configured=configured) == 2
    assert dump(path) == before


def test_plan_cannot_be_applied_to_another_database(activation, tmp_path):
    path, configured, plan = activation
    assert prepare(activation) == 0
    copied = tmp_path / "other.db"
    with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(copied)) as target:
        source.backup(target)
    before = dump(copied)
    assert command.main(["--db", str(copied), "apply", "--plan", str(plan)],
                        app_settings=configured) == 2
    assert dump(copied) == before


def test_lost_output_after_commit_can_be_retried_without_reapplying(activation, monkeypatch):
    assert prepare(activation) == 0

    def lost_output(*args, **kwargs):
        if "file" not in kwargs:
            raise BrokenPipeError("test response lost")

    with monkeypatch.context() as change:
        change.setattr(command, "print", lost_output, raising=False)
        assert apply(activation) == 2
    before = dump(activation[0])
    assert apply(activation) == 0
    assert dump(activation[0]) == before
