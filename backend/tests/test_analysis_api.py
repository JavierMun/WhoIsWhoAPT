"""Saved analysis API tests."""

from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.main import create_app
from app.models import entities


def test_save_analysis_returns_summary() -> None:
    """Completed comparison payloads should be persisted as analysis snapshots."""
    client = _client()

    response = client.post("/api/analysis/save", json=_analysis_payload())

    assert response.status_code == 201
    body = response.json()
    assert body["id"]
    assert body["input_type"] == "actor"
    assert body["input_name"] == "APT Alpha"
    assert body["metric"] == "jaccard"
    assert body["top_n"] == 10
    assert body["created_at"]
    assert body["created_at"].endswith("Z")


def test_list_analyses_returns_saved_summaries() -> None:
    """Saved analyses should be listed without full result payloads."""
    client = _client()
    client.post("/api/analysis/save", json=_analysis_payload(input_name="APT Alpha"))
    client.post("/api/analysis/save", json=_analysis_payload(input_name="APT Beta"))

    response = client.get("/api/analysis")

    assert response.status_code == 200
    body = response.json()
    assert [item["input_name"] for item in body] == ["APT Beta", "APT Alpha"]
    assert "results" not in body[0]


def test_get_analysis_returns_detail() -> None:
    """Saved analysis detail should include the stored comparison result payload."""
    client = _client()
    save_response = client.post("/api/analysis/save", json=_analysis_payload())
    analysis_id = save_response.json()["id"]

    response = client.get(f"/api/analysis/{analysis_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == analysis_id
    assert body["results"]["input_name"] == "APT Alpha"
    assert body["results"]["results"][0]["matched_entity_id"] == "actor-b"


def test_delete_analysis_removes_snapshot() -> None:
    """Saved analyses should be removable."""
    client = _client()
    save_response = client.post("/api/analysis/save", json=_analysis_payload())
    analysis_id = save_response.json()["id"]

    delete_response = client.delete(f"/api/analysis/{analysis_id}")
    get_response = client.get(f"/api/analysis/{analysis_id}")

    assert delete_response.status_code == 204
    assert get_response.status_code == 404


def test_get_missing_analysis_returns_not_found() -> None:
    """Unknown analysis IDs should return a clear 404."""
    client = _client()

    response = client.get("/api/analysis/not-a-real-id")

    assert response.status_code == 404
    assert response.json()["error"] == "Analysis not found"


def test_delete_missing_analysis_returns_not_found() -> None:
    """Deleting an unknown analysis should return a clear 404."""
    client = _client()

    response = client.delete("/api/analysis/not-a-real-id")

    assert response.status_code == 404
    assert response.json()["error"] == "Analysis not found"


def test_get_analysis_with_malformed_results_returns_clear_error() -> None:
    """Corrupt stored result JSON should not crash the API."""
    client, session = _client_with_session()
    analysis = entities.Analysis(
        input_type="actor",
        input_id="actor-a",
        input_name="APT Alpha",
        metric="jaccard",
        tactics=["execution"],
        target_ids=["actor-b"],
        top_n=10,
        results_json="{not-json",
    )
    session.add(analysis)
    session.commit()

    response = client.get(f"/api/analysis/{analysis.id}")

    assert response.status_code == 500
    assert response.json()["error"] == "Saved analysis results are invalid"


def _analysis_payload(input_name: str = "APT Alpha") -> dict:
    return {
        "input_type": "actor",
        "input_id": "actor-a",
        "input_name": input_name,
        "metric": "jaccard",
        "tactics": ["execution"],
        "target_ids": ["actor-b"],
        "top_n": 10,
        "results": {
            "input_id": "actor-a",
            "input_name": input_name,
            "input_type": "actor",
            "metric": "jaccard",
            "results": [
                {
                    "matched_entity_id": "actor-b",
                    "matched_entity_name": "APT Beta",
                    "score": 0.5,
                }
            ],
        },
    }


def _client() -> TestClient:
    client, _session = _client_with_session()
    return client


def _client_with_session() -> tuple[TestClient, Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    seed_session = TestingSessionLocal()

    def override_db() -> Generator[Session, None, None]:
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db_session] = override_db
    return TestClient(app), seed_session
