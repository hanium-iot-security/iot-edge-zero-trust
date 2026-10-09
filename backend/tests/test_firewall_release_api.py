from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.main import app
from backend.app.services.firewall_release_request_service import (
    release_confirmation_for_rule,
)
from db.migration_runner import MIGRATIONS_DIR, apply_migrations


ADMIN_HEADERS = {"X-Recovery-Admin-Key": "release-secret"}


@pytest.fixture
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "firewall-release-api.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    _seed_device(db_path)

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        db.execute(text("PRAGMA foreign_keys = ON"))
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "recovery_admin_api_key", "release-secret")
    monkeypatch.setattr(settings, "recovery_admin_principal", "operator@example")

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), db_path
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_create_release_request_for_applied_rule(api_client) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status="APPLIED")

    response = _post_release_request(client, rule_id, requested_by="spoofed")

    assert response.status_code == 201
    item = response.json()["item"]
    assert item["firewall_rule_id"] == rule_id
    assert item["status"] == "PENDING"
    assert item["requested_by"] == "operator@example"
    assert item["reason"] == "official release approved"
    assert "spoofed" not in str(item)
    assert _rule_status(db_path, rule_id) == "APPLIED"


def test_get_release_request(api_client) -> None:
    client, _ = api_client
    rule_id = _seed_rule(api_client[1], status="APPLIED")
    created = _post_release_request(client, rule_id).json()["item"]

    response = client.get(
        f"/api/firewall-release-requests/{created['id']}",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["item"] == created


def test_release_request_requires_admin(api_client) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status="APPLIED")

    response = client.post(
        f"/api/firewall-rules/{rule_id}/release-requests",
        json={
            "reason": "official release approved",
            "confirm": release_confirmation_for_rule(rule_id),
        },
    )

    assert response.status_code == 401
    assert _release_request_count(db_path) == 0


def test_release_request_requires_rule_bound_confirmation(api_client) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status="APPLIED")

    response = _post_release_request(client, rule_id, confirm="RELEASE-FIREWALL-RULE")

    assert response.status_code == 409
    assert response.json()["detail"]["failure_code"] == "RELEASE_CONFIRMATION_MISMATCH"
    assert _release_request_count(db_path) == 0


def test_release_request_rejects_blank_reason_as_validation_error(api_client) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status="APPLIED")

    response = client.post(
        f"/api/firewall-rules/{rule_id}/release-requests",
        json={
            "reason": "   ",
            "confirm": release_confirmation_for_rule(rule_id),
        },
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 422
    assert _release_request_count(db_path) == 0


@pytest.mark.parametrize("status", ["PENDING", "REMOVED"])
def test_release_request_rejects_non_applied_rule(api_client, status: str) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status=status)

    response = _post_release_request(client, rule_id)

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["failure_code"] == "FIREWALL_RULE_NOT_APPLIED"
    assert detail["current_status"] == status
    assert _release_request_count(db_path) == 0


def test_failed_rule_can_request_exact_audited_cleanup(api_client) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status="FAILED")
    response = _post_release_request(client, rule_id)
    assert response.status_code == 201
    assert response.json()["item"]["firewall_rule_id"] == rule_id
    assert response.json()["item"]["requested_by"] == "operator@example"
    assert _rule_status(db_path, rule_id) == "FAILED"
    assert _release_request_count(db_path) == 1


def test_release_request_returns_404_for_missing_rule(api_client) -> None:
    client, db_path = api_client

    response = _post_release_request(client, 999)

    assert response.status_code == 404
    assert response.json()["detail"]["failure_code"] == "FIREWALL_RULE_NOT_FOUND"
    assert _release_request_count(db_path) == 0


def test_duplicate_pending_release_request_is_rejected(api_client) -> None:
    client, db_path = api_client
    rule_id = _seed_rule(db_path, status="APPLIED")

    first = _post_release_request(client, rule_id)
    second = _post_release_request(client, rule_id)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["detail"]["failure_code"] == "DUPLICATE_PENDING_RELEASE_REQUEST"
    assert _release_request_count(db_path) == 1


def test_get_release_request_returns_404(api_client) -> None:
    client, _ = api_client

    response = client.get("/api/firewall-release-requests/999", headers=ADMIN_HEADERS)

    assert response.status_code == 404
    assert response.json()["detail"]["failure_code"] == "FIREWALL_RELEASE_REQUEST_NOT_FOUND"


def test_db_partial_unique_index_blocks_duplicate_pending_request(api_client) -> None:
    _, db_path = api_client
    rule_id = _seed_rule(db_path, status="APPLIED")

    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO firewall_release_requests (
                firewall_rule_id, requested_by, reason, requested_at
            )
            VALUES (?, 'operator@example', 'first', '2026-08-22T00:00:00Z')
            """,
            (rule_id,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_release_requests (
                    firewall_rule_id, requested_by, reason, requested_at
                )
                VALUES (?, 'operator@example', 'second', '2026-08-22T00:00:01Z')
                """,
                (rule_id,),
            )


def _post_release_request(
    client: TestClient,
    rule_id: int,
    *,
    confirm: str | None = None,
    requested_by: str | None = None,
):
    body = {
        "reason": "official release approved",
        "confirm": confirm or release_confirmation_for_rule(rule_id),
    }
    if requested_by is not None:
        body["requested_by"] = requested_by
    return client.post(
        f"/api/firewall-rules/{rule_id}/release-requests",
        json=body,
        headers=ADMIN_HEADERS,
    )


def _seed_device(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, trust_score, status)
            VALUES ('esp32_01', '192.168.0.21', 20, 'isolated')
            """
        )
        connection.commit()


def _seed_rule(db_path: Path, *, status: str) -> int:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        rule_id = connection.execute(
            """
            INSERT INTO firewall_rules (
                device_id, source_ip, status, applied_at, released_at, reason
            )
            VALUES (
                'esp32_01', '192.168.0.21', ?, '2026-08-22T00:00:00Z',
                CASE WHEN ? = 'REMOVED' THEN '2026-08-22T00:01:00Z' ELSE NULL END,
                'test rule'
            )
            """,
            (status, status),
        ).lastrowid
        connection.commit()
        return int(rule_id)


def _rule_status(db_path: Path, rule_id: int) -> str:
    with sqlite3.connect(db_path) as connection:
        return str(
            connection.execute(
                "SELECT status FROM firewall_rules WHERE id = ?",
                (rule_id,),
            ).fetchone()[0]
        )


def _release_request_count(db_path: Path) -> int:
    with sqlite3.connect(db_path) as connection:
        return int(
            connection.execute("SELECT COUNT(*) FROM firewall_release_requests").fetchone()[0]
        )
