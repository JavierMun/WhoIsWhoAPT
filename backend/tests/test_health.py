"""Basic API smoke tests."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_check_returns_ok() -> None:
    """The health endpoint should report service liveness."""
    client = TestClient(create_app())
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"

