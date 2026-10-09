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
from test_packet_checkpoint_pair_recovery import fixture as recovery_fixture, _audits, _execute
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
                                    {"allow_failed_current_session": True}, {"confirm": "bypass"}])
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
    assert body["operation_status"] == "APPLIED_VERIFY_REQUIRED"
    assert body["runtime"]["status"] == "UNKNOWN"
    assert file_bytes(fixture["artifacts"]) == before_artifacts
    assert base["database"].read_bytes() == before_db
