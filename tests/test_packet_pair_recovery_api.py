"""Administrator API creates plans and observes real audits without applying."""
import json
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.main import app
from backend.app.services import packet_pair_recovery_service as service
from edge.detection import packet_checkpoint_pair_recovery as pair
from edge.detection import packet_checkpoint_pair_manager as manager
from test_packet_checkpoint_pair_recovery import (
    fixture as recovery_fixture, _audits, _execute, _advance, _finish_replay, _close_target_with_uncaptured_tail,
)
from test_packet_checkpoint_pair_manager import System, Processes, launch, run

PREFIX = "/api/recovery/packet-pair"
HEADERS = {"X-Recovery-Admin-Key": "fixture-admin-key"}


@pytest.fixture
def fixture(recovery_fixture, monkeypatch):
    base = recovery_fixture
    root = base["root"]
    (root / ".git" / "info" / "exclude").write_text("data/\noutput/\n", encoding="utf-8")
    plans = root / "output" / "api-plans"
    artifacts = root / "data" / "recovery" / "packet-pair"
    managers = root / "output" / "manager-plans"
    for directory in (plans, artifacts, managers):
        directory.mkdir(parents=True)
    monkeypatch.setattr(settings, "database_url", "sqlite:///" + str(base["database"]))
    monkeypatch.setattr(settings, "packet_pair_repository_root", str(root))
    monkeypatch.setattr(settings, "packet_pair_plan_dir", str(plans))
    monkeypatch.setattr(settings, "packet_pair_artifact_dir", str(artifacts))
    monkeypatch.setattr(settings, "packet_pair_manager_plan_dir", str(managers))
    monkeypatch.setattr(settings, "recovery_admin_api_key", HEADERS["X-Recovery-Admin-Key"])
    monkeypatch.setattr(settings, "recovery_admin_principal", "server-authorized-principal")
    payload = {"source_session_id": base["plan"]["current_session_id"],
               "target_session_id": base["plan"]["target_session_id"], "reason": "approved API fixture plan"}
    return {"base": base, "client": TestClient(app), "plans": plans, "artifacts": artifacts,
            "managers": managers, "payload": payload}


def create(fixture):
    response = fixture["client"].post(PREFIX + "/plans", json=fixture["payload"], headers=HEADERS)
    assert response.status_code == 201, response.text
    body = response.json()
    plan_id = body["plan_id"]
    files = list(fixture["plans"].rglob("*.json"))
    selected = [path for path in files if json.loads(path.read_text(encoding="utf-8")).get("pair_id") == plan_id]
    assert len(selected) == 1
    path, plan = pair._load_pair(selected[0])
    fixture["base"].update(output=path, plan=plan, artifacts=fixture["artifacts"])
    fixture["plan_id"] = plan_id
    return body


def get(fixture):
    return fixture["client"].get(PREFIX + "/" + fixture["plan_id"], headers=HEADERS)


def verify(fixture):
    return fixture["client"].post(PREFIX + "/" + fixture["plan_id"] + "/verify", headers=HEADERS)


def file_bytes(directory):
    return {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*") if path.is_file()}


@pytest.mark.parametrize("method,suffix", [("post", "/plans"), ("get", "/" + "a" * 36),
                                          ("post", "/" + "a" * 36 + "/verify")])
def test_management_routes_fail_closed_when_auth_not_configured(fixture, monkeypatch, method, suffix):
    monkeypatch.setattr(settings, "recovery_admin_api_key", "")
    monkeypatch.setattr(service, "create_plan", lambda **_: pytest.fail("unauthenticated planner executed"))
    response = getattr(fixture["client"], method)(PREFIX + suffix, **({"json": fixture["payload"]} if suffix == "/plans" else {}))
    assert response.status_code == 503
    assert response.json()["detail"] == "RECOVERY_ADMIN_NOT_CONFIGURED"


@pytest.mark.parametrize("headers", [{}, {"X-Recovery-Admin-Key": "wrong-key"}])
@pytest.mark.parametrize("method,suffix", [("post", "/plans"), ("get", "/" + "a" * 36),
                                          ("post", "/" + "a" * 36 + "/verify")])
def test_management_routes_require_admin_auth(fixture, headers, method, suffix):
    kwargs = {"headers": headers}
    if suffix == "/plans":
        kwargs["json"] = fixture["payload"]
    response = getattr(fixture["client"], method)(PREFIX + suffix, **kwargs)
    assert response.status_code == 401
    assert response.json()["detail"] == "RECOVERY_ADMIN_UNAUTHORIZED"
    assert file_bytes(fixture["plans"]) == {}


@pytest.mark.parametrize("extra", [{"approved_by": "client-principal"}, {"database_path": "other.db"},
                                    {"plan_output": "tracked.txt"}, {"artifact_dir": "other"},
                                    {"allow_failed_current_session": True}, {"allow_failed_target_session": True},
                                    {"mode": "bounded-replay"}, {"confirm": "bypass"}])
def test_plan_body_rejects_principal_paths_or_apply_options(fixture, extra):
    response = fixture["client"].post(PREFIX + "/plans", json=dict(fixture["payload"], **extra), headers=HEADERS)
    assert response.status_code == 422
    assert file_bytes(fixture["plans"]) == {}
    assert _audits(fixture["base"]) == []


@pytest.mark.parametrize("field,value", [("source_session_id", 1), ("target_session_id", False),
                                        ("reason", 5), ("reason", " "), ("source_session_id", "not-a-uuid"),
                                        ("source_session_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")])
def test_plan_body_requires_strict_canonical_values(fixture, field, value):
    payload = dict(fixture["payload"], **{field: value})
    response = fixture["client"].post(PREFIX + "/plans", json=payload, headers=HEADERS)
    assert response.status_code == 422
    assert file_bytes(fixture["plans"]) == {}


def test_identical_source_target_is_rejected(fixture):
    payload = dict(fixture["payload"], target_session_id=fixture["payload"]["source_session_id"])
    assert fixture["client"].post(PREFIX + "/plans", json=payload, headers=HEADERS).status_code == 422


def test_reason_rejects_del_control_character(fixture):
    payload = dict(fixture["payload"], reason="reason\x7f")
    response = fixture["client"].post(PREFIX + "/plans", json=payload, headers=HEADERS)
    assert response.status_code == 422
    assert file_bytes(fixture["plans"]) == {}


def test_plan_is_server_owned_and_does_not_change_database_or_apply(fixture, monkeypatch):
    before = fixture["base"]["database"].read_bytes()
    monkeypatch.setattr(pair, "execute_pair", lambda **_: pytest.fail("API applied checkpoint"))
    body = create(fixture)
    assert body["approved_by"] == "server-authorized-principal"
    assert body["source_session_id"] == fixture["payload"]["source_session_id"]
    assert body["target_session_id"] == fixture["payload"]["target_session_id"]
    assert body["apply_transport"] == "ROOT_CLI"
    assert body["runtime"]["status"] == "UNKNOWN"
    assert body["mode"] == "live-resume" and body["replay_end"] is None
    assert body["can_execute"] is True
    assert str(uuid.UUID(body["plan_id"])) == body["plan_id"]
    assert _audits(fixture["base"]) == []
    assert fixture["base"]["database"].read_bytes() == before
    assert file_bytes(fixture["artifacts"]) == {}


@pytest.mark.parametrize("plan_id", ["not-a-uuid", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "../tracked.txt"])
def test_noncanonical_status_identity_cannot_choose_a_file(fixture, plan_id):
    response = fixture["client"].get(PREFIX + "/" + plan_id, headers=HEADERS)
    assert response.status_code in (404, 422)
    assert file_bytes(fixture["plans"]) == {}


def test_unknown_plan_is_not_found(fixture):
    response = fixture["client"].get(PREFIX + "/" + str(uuid.uuid4()), headers=HEADERS)
    assert response.status_code == 404


def test_api_has_no_apply_route(fixture):
    create(fixture)
    before = fixture["base"]["database"].read_bytes()
    response = fixture["client"].post(PREFIX + "/" + fixture["plan_id"] + "/apply", json={"confirm": "apply"}, headers=HEADERS)
    assert response.status_code in (404, 405)
    assert _audits(fixture["base"]) == []
    assert fixture["base"]["database"].read_bytes() == before


def test_plan_directory_cannot_be_tracked_repository_source(fixture, monkeypatch):
    monkeypatch.setattr(settings, "packet_pair_plan_dir", str(fixture["base"]["root"]))
    original = (fixture["base"]["root"] / "tracked.txt").read_bytes()
    response = fixture["client"].post(PREFIX + "/plans", json=fixture["payload"], headers=HEADERS)
    assert response.status_code == 503
    assert file_bytes(fixture["plans"]) == {}
    assert (fixture["base"]["root"] / "tracked.txt").read_bytes() == original


def test_symlink_plan_directory_is_rejected_without_following(fixture, monkeypatch):
    configured = fixture["plans"]
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == configured or original(path))
    response = fixture["client"].post(PREFIX + "/plans", json=fixture["payload"], headers=HEADERS)
    assert response.status_code == 503
    assert file_bytes(fixture["plans"]) == {}


def test_symlink_leaf_plan_is_sanitized_unavailable_without_writes(fixture, monkeypatch):
    create(fixture)
    selected = fixture["base"]["output"]
    before = file_bytes(fixture["plans"])
    database = fixture["base"]["database"].read_bytes()
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == selected or original(path))
    response = get(fixture)
    assert response.status_code == 503
    assert file_bytes(fixture["plans"]) == before
    assert fixture["base"]["database"].read_bytes() == database


def test_get_does_not_hash_backup_validate_audit_or_write_root_progress(fixture, monkeypatch):
    create(fixture)
    _execute(fixture["base"])
    group = pair._group(fixture["base"]["plan"], fixture["artifacts"])
    (group / "progress.json").write_text('{"untrusted_stdout":"COMPLETE"}', encoding="utf-8")
    before_db = fixture["base"]["database"].read_bytes()
    before = file_bytes(fixture["artifacts"])
    monkeypatch.setattr(pair, "status_pair", lambda **_: pytest.fail("GET wrote root progress"))
    monkeypatch.setattr(pair, "_validate_audit", lambda *_: pytest.fail("GET performed full backup validation"))
    monkeypatch.setattr(pair.core, "file_sha256", lambda *_: pytest.fail("GET hashed backup"))
    response = get(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["operation_status"] == "COMMITTED_UNVERIFIED"
    assert body["database_committed"] is True
    assert body["verification"]["status"] == "NOT_REQUESTED"
    assert body["verification"]["root_progress_verified"] is False
    assert body["runtime"]["status"] == "UNKNOWN"
    assert file_bytes(fixture["artifacts"]) == before
    assert fixture["base"]["database"].read_bytes() == before_db


def test_get_uses_readonly_single_begin_snapshot(fixture, monkeypatch):
    create(fixture)
    original = service.sqlite3.connect
    observed = []

    def connect(database, *args, **kwargs):
        assert "mode=ro" in str(database) and kwargs.get("uri") is True
        db = original(database, *args, **kwargs)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("UPDATE devices SET trust_score=0")
        db.rollback()  # Failed SQLite UPDATE can open an implicit transaction.
        db.set_trace_callback(observed.append)
        return db

    monkeypatch.setattr(service.sqlite3, "connect", connect)
    response = get(fixture)
    assert response.status_code == 200, response.text
    assert sum(statement.strip().upper() == "BEGIN" for statement in observed) == 1
    assert any("QUERY_ONLY" in statement.upper() for statement in observed)


def test_verify_full_audits_does_not_apply_or_write_root_files(fixture, monkeypatch):
    create(fixture)
    _execute(fixture["base"])
    before = file_bytes(fixture["artifacts"])
    database = fixture["base"]["database"].read_bytes()
    monkeypatch.setattr(pair, "status_pair", lambda **_: pytest.fail("API wrote Root progress"))
    monkeypatch.setattr(pair, "execute_pair", lambda **_: pytest.fail("API executed pair"))
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification"]["status"] == "VERIFIED_AUDITS"
    assert body["verification"]["error_code"] == "ROOT_PROGRESS_UNAVAILABLE"
    assert all(child["state"] == "APPLIED" for child in body["children"].values())
    assert body["operation_status"] == "APPLIED_VERIFY_REQUIRED"
    assert body["runtime"]["status"] == "UNKNOWN"
    assert body["verification"]["root_completion_recorded"] is False
    assert file_bytes(fixture["artifacts"]) == before
    assert fixture["base"]["database"].read_bytes() == database


@pytest.mark.parametrize("mutation", ["approval", "operation_id", "before", "backup"])
def test_verify_rejects_audit_mismatch_even_when_child_output_says_complete(fixture, mutation):
    create(fixture)
    _execute(fixture["base"])
    audit = _audits(fixture["base"])[0]
    if mutation == "backup":
        Path(audit["backup_path"]).write_bytes(b"not a verified SQLite backup")
    else:
        field, value = {"approval": ("approved_by", "different-admin"),
                        "operation_id": ("operation_id", str(uuid.uuid4())),
                        "before": ("updated_at_before", "2026-08-01T00:00:00Z")}[mutation]
        with sqlite3.connect(fixture["base"]["database"]) as db:
            db.execute("UPDATE packet_checkpoint_recoveries SET " + field + "=? WHERE id=?", (value, audit["id"]))
    group = pair._group(fixture["base"]["plan"], fixture["artifacts"])
    (group / "result.json").write_text('{"operation_status":"COMPLETE"}', encoding="utf-8")
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification"]["status"] == "HOLD"
    assert body["operation_status"] != "COMPLETE"
    assert body["verification"]["root_progress_verified"] is False
    assert body["runtime"]["status"] == "UNKNOWN"


def test_result_file_alone_cannot_prove_commit(fixture):
    create(fixture)
    group = pair._group(fixture["base"]["plan"], fixture["artifacts"])
    group.mkdir()
    (group / "result.json").write_text('{"operation_status":"COMPLETE","database_committed":true}', encoding="utf-8")
    response = get(fixture)
    assert response.status_code == 200, response.text
    assert response.json()["operation_status"] == "PENDING"
    assert response.json()["database_committed"] is False


def test_partial_rule_audit_is_preserved_without_if_execution(fixture, monkeypatch):
    create(fixture)
    execute = pair.core._execute_locked_recovery

    def fail_if(**kwargs):
        if kwargs["plan"]["detector_name"] == "packet_if":
            raise pair.Error("fixture IF failure")
        return execute(**kwargs)

    monkeypatch.setattr(pair.core, "_execute_locked_recovery", fail_if)
    _execute(fixture["base"])
    before = fixture["base"]["database"].read_bytes()
    assert len(_audits(fixture["base"])) == 1
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["operation_status"] == "PARTIAL_HOLD"
    assert body["children"]["packet_rule"]["state"] == "APPLIED"
    assert body["children"]["packet_if"]["state"] == "PENDING"
    assert fixture["base"]["database"].read_bytes() == before
    assert len(_audits(fixture["base"])) == 1


def test_historical_root_completion_never_becomes_current_api_complete(fixture, monkeypatch):
    create(fixture)
    base = fixture["base"]
    system = System(base)
    managed_path = fixture["managers"] / (fixture["plan_id"] + ".manager.json")
    managed_plan = manager.create_plan(pair_plan_file=base["output"], db_path=base["database"],
                                       artifact_dir=fixture["artifacts"], plan_output=managed_path, system=system)
    managed = {"base": base, "system": system, "path": managed_path, "plan": managed_plan,
               "processes": Processes(lambda: _execute(base))}
    launch(managed)
    assert run(managed, monkeypatch, advance=True)["phase"] == "COMPLETE"
    progress_path = pair._group(base["plan"], fixture["artifacts"]) / "progress.json"
    recorded = json.loads(progress_path.read_text(encoding="utf-8"))

    class LaterDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return base["clock"][0] + timedelta(seconds=100)

    monkeypatch.setattr(service, "datetime", LaterDateTime)
    monkeypatch.setattr(pair, "_runtime_observation", lambda: pytest.fail("API claimed live process attestation"))
    before_db = base["database"].read_bytes()
    before_artifacts = file_bytes(fixture["artifacts"])
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification"]["root_progress_verified"] is True
    assert body["verification"]["root_completion_recorded"] is True
    assert body["verification"]["root_progress_observed_at"] == recorded["observed_at"]
    assert body["verification"]["root_progress_age_seconds"] > 45
    assert body["verification"]["root_progress_fresh"] is False
    assert body["verification"]["root_progress_max_age_seconds"] == 45
    assert body["verification"]["root_progress_status"] == "VERIFIED"
    assert body["verification"]["root_completion_evidence_status"] == "RECORDED"
    assert body["verification"]["historical_completion_status"] == "COMPLETE"
    assert body["verification"]["historical_completion_source"] == "ROOT_MANAGER"
    assert body["operation_status"] == "APPLIED_VERIFY_REQUIRED"
    assert body["runtime"]["status"] == "UNKNOWN"
    assert file_bytes(fixture["artifacts"]) == before_artifacts
    assert base["database"].read_bytes() == before_db


def record_live_progress(fixture, *, observations=3):
    create(fixture)
    base = fixture["base"]
    _execute(base)
    result = None
    for seconds in (10,20,30)[:observations]:
        _advance(base, seconds)
        result = pair.status_pair(plan_file=base["output"], db_path=base["database"], artifact_dir=fixture["artifacts"])
    return result


def test_direct_root_progress_proves_past_complete_without_manager_or_current_runtime(fixture, monkeypatch):
    assert record_live_progress(fixture)["operation_status"] == "COMPLETE"
    before_db, before_files = fixture["base"]["database"].read_bytes(), file_bytes(fixture["artifacts"])
    monkeypatch.setattr(pair, "_runtime_observation", lambda: pytest.fail("API attested current runtime"))
    monkeypatch.setattr(pair, "status_pair", lambda **_: pytest.fail("API wrote Root progress"))
    monkeypatch.setattr(pair, "execute_pair", lambda **_: pytest.fail("API reapplied completed pair"))
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification"]["historical_completion_status"] == "COMPLETE"
    assert body["verification"]["historical_completion_source"] == "ROOT_PROGRESS"
    assert body["verification"]["root_completion_recorded"] is False
    assert body["verification"]["root_completion_evidence_status"] == "UNAVAILABLE"
    assert body["operation_status"] == "APPLIED_VERIFY_REQUIRED"
    assert body["runtime"]["status"] == "UNKNOWN"
    assert file_bytes(fixture["artifacts"]) == before_files and fixture["base"]["database"].read_bytes() == before_db


def test_one_advance_progress_is_not_historical_completion(fixture):
    assert record_live_progress(fixture, observations=2)["operation_status"] != "COMPLETE"
    body = verify(fixture).json()
    assert body["verification"]["root_progress_verified"] is True
    assert body["verification"]["historical_completion_status"] is None
    assert body["verification"]["historical_completion_source"] is None


@pytest.mark.parametrize("mutation", ["ineligible", "future", "inactive", "stale-at-observation", "trust-ahead", "binding", "sha"])
def test_root_progress_cannot_forge_historical_completion(fixture, mutation):
    record_live_progress(fixture)
    progress_path = pair._group(fixture["base"]["plan"], fixture["artifacts"]) / "progress.json"
    progress = json.loads(progress_path.read_text(encoding="utf-8"))
    if mutation == "ineligible": progress["eligible"] = False
    elif mutation == "future": progress["observed_at"] = "2099-01-01T00:00:00Z"
    elif mutation == "inactive": progress["runtime"]["services"][pair.SERVICES[0]] = False
    elif mutation == "stale-at-observation":
        progress["observed_at"] = (pair.core._utc_now()+timedelta(seconds=100)).isoformat()
    elif mutation == "trust-ahead":
        old = progress["checkpoints"]["packet_rule"]
        end = pair.core.parse_db_utc(old["last_completed_window_end"])-timedelta(seconds=10)
        old["last_completed_window_end"] = old["updated_at"] = pair.core.format_db_utc(end)
    elif mutation == "binding": progress["approval_sha256"] = "0"*64
    progress = pair.core.attach_plan_sha256(progress, generated_at=pair.core._utc_now())
    if mutation == "sha": progress["plan_sha256"] = "0"*64
    progress_path.write_text(json.dumps(progress), encoding="utf-8")
    body = verify(fixture).json()
    assert body["verification"]["status"] == "HOLD"
    assert body["verification"]["historical_completion_status"] is None
    assert body["verification"]["root_completion_recorded"] is False


def publish_bounded_plan(fixture, *, failed_target=False):
    base = fixture["base"]
    if failed_target:
        _close_target_with_uncaptured_tail(base)
    else:
        with sqlite3.connect(base["database"]) as db:
            end = base["plan"]["children"][0]["plan"]["target_session"]["packet_feature_ready_through"]
            db.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                       (end, base["plan"]["target_session_id"]))
    temporary = fixture["plans"] / "bounded-pending.json"
    plan = pair.inspect_pair(db_path=base["database"], repository_root=base["root"],
        current_session_id=base["plan"]["current_session_id"], target_session_id=base["plan"]["target_session_id"],
        approved_by="root-fixture", reason="preserved bounded input", plan_output=temporary,
        mode=pair.core.BOUNDED_REPLAY_MODE, allow_failed_target_session=failed_target)
    assert plan["can_execute"], plan["blocking_reasons"]
    destination = fixture["plans"] / (plan["pair_id"] + ".json")
    temporary.rename(destination)
    base.update(output=destination, plan=plan, artifacts=fixture["artifacts"])
    fixture["plan_id"] = plan["pair_id"]


def complete_bounded_manager(fixture):
    base = fixture["base"]
    system = System(base)
    managed_path = fixture["managers"] / (fixture["plan_id"] + ".manager.json")
    managed_plan = manager.create_plan(pair_plan_file=base["output"], db_path=base["database"],
        artifact_dir=fixture["artifacts"], plan_output=managed_path, system=system)
    processes = Processes(lambda: (_execute(base), _finish_replay(base)))
    managed = {"base":base, "system":system, "path":managed_path, "plan":managed_plan, "processes":processes}
    launch(managed)
    elapsed = [0]
    def sleep(seconds): elapsed[0] += seconds
    result = manager.supervise(managed_path, system=system, processes=processes,
        monotonic=lambda:elapsed[0], sleep=sleep)
    assert result["phase"] == "REPLAY_COMPLETE"
    return managed_plan


@pytest.mark.parametrize("failed_target", [False, True])
def test_bounded_manager_completion_needs_no_live_progress_and_does_not_attest_runtime(fixture, monkeypatch, failed_target):
    publish_bounded_plan(fixture, failed_target=failed_target)
    complete_bounded_manager(fixture)
    group = pair._group(fixture["base"]["plan"], fixture["artifacts"])
    assert not (group/"progress.json").exists()
    before_db, before_files = fixture["base"]["database"].read_bytes(), file_bytes(fixture["artifacts"])
    monkeypatch.setattr(pair, "status_pair", lambda **_: pytest.fail("API wrote bounded progress"))
    monkeypatch.setattr(pair, "_runtime_observation", lambda: pytest.fail("API attested live runtime"))
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "bounded-replay"
    assert body["replay_end"] == fixture["base"]["plan"]["bounded_replay"]["replay_end"]
    assert body["verification"]["root_progress_status"] == "NOT_APPLICABLE"
    assert body["verification"]["historical_completion_status"] == "REPLAY_COMPLETE"
    assert body["verification"]["historical_completion_source"] == "ROOT_MANAGER"
    assert body["verification"]["root_completion_recorded"] is True
    assert body["operation_status"] == "APPLIED_VERIFY_REQUIRED" and body["runtime"]["status"] == "UNKNOWN"
    assert file_bytes(fixture["artifacts"]) == before_files and fixture["base"]["database"].read_bytes() == before_db


def test_bounded_applied_audits_without_root_completion_are_not_missing_live_progress(fixture):
    publish_bounded_plan(fixture)
    _execute(fixture["base"])
    _finish_replay(fixture["base"])
    response = verify(fixture)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification"]["status"] == "VERIFIED_AUDITS"
    assert body["verification"]["root_progress_status"] == "NOT_APPLICABLE"
    assert body["verification"]["error_code"] is None
    assert body["verification"]["historical_completion_status"] is None


@pytest.mark.parametrize("mutation", ["live-complete", "end", "tail-live", "trust-cutoff", "restoration", "sha"])
def test_bounded_manager_scope_and_completion_evidence_cannot_be_relabelled(fixture, mutation):
    publish_bounded_plan(fixture, failed_target=True)
    managed_plan = complete_bounded_manager(fixture)
    journal_path = manager._paths(managed_plan)[1]
    journal = manager._journal(managed_plan)
    if mutation == "live-complete": journal["phase"] = journal["verification"]["operation_status"] = "COMPLETE"
    elif mutation == "end": journal["verification"]["replay_end"] = fixture["base"]["plan"]["boundary"]
    elif mutation == "tail-live": journal["verification"]["live_recovery_complete"] = True
    elif mutation == "trust-cutoff": journal["verification"]["checkpoints"]["trust_score_v2"]["last_completed_window_end"] = fixture["base"]["plan"]["boundary"]
    elif mutation == "restoration": journal["restoration_failures"] = [{"unit":manager.UNITS[0],"error":"failed"}]
    manager._save(journal_path, journal)
    if mutation == "sha":
        raw = json.loads(journal_path.read_text(encoding="utf-8"))
        raw["plan_sha256"] = "0"*64
        journal_path.write_text(json.dumps(raw), encoding="utf-8")
    body = verify(fixture).json()
    assert body["verification"]["historical_completion_status"] is None
    assert body["verification"]["root_completion_recorded"] is False


def test_completed_record_cannot_bypass_failed_original_audit_validation(fixture):
    record_live_progress(fixture)
    with sqlite3.connect(fixture["base"]["database"]) as db:
        db.execute("UPDATE packet_checkpoint_recoveries SET approved_by='forged'")
    body = verify(fixture).json()
    assert body["verification"]["status"] == "HOLD"
    assert body["verification"]["historical_completion_status"] is None


@pytest.mark.parametrize("which", ["intent", "progress", "manager"])
def test_private_root_evidence_permission_denied_is_sanitized_unknown_without_writes(fixture, monkeypatch, which):
    if which == "manager":
        publish_bounded_plan(fixture)
        complete_bounded_manager(fixture)
    else:
        record_live_progress(fixture)
    before_db, before_files = fixture["base"]["database"].read_bytes(), file_bytes(fixture["artifacts"])
    original = service._read_json
    def read(path):
        if (which == "intent" and path.name == "intent.json" or which == "progress" and path.name == "progress.json"
                or which == "manager" and path.name.endswith(".manager.json")):
            raise PermissionError("private root path must not be exposed")
        return original(path)
    monkeypatch.setattr(service, "_read_json", read)
    response = verify(fixture)
    assert response.status_code == 503
    assert response.json()["detail"] == {"code":"ROOT_RECOVERY_ARTIFACT_UNAVAILABLE","verification":"UNKNOWN"}
    assert file_bytes(fixture["artifacts"]) == before_files and fixture["base"]["database"].read_bytes() == before_db
