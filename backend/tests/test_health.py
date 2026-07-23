from fastapi.testclient import TestClient

from backend.app.main import app


def test_health_check() -> None:
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["db_connected"] is True
    assert body["server_time"].endswith("Z")
