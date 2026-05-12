"""Custom set and technique lookup API tests."""

from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.main import create_app
from app.models.entities import Technique


def test_list_techniques_returns_normalized_rows() -> None:
    """Technique lookup should expose IDs and labels for UI selection."""
    client = _client_with_seeded_techniques()

    response = client.get("/api/techniques")

    assert response.status_code == 200
    assert response.json()[0] == {
        "technique_id": "T1001",
        "name": "Data Obfuscation",
        "tactic": "defense-evasion",
        "is_subtechnique": False,
        "parent_id": None,
    }


def test_get_custom_set_by_id() -> None:
    """Saved custom sets should be retrievable by ID."""
    client = _client_with_seeded_techniques()

    create_response = client.post(
        "/api/custom-sets",
        json={"name": "Navigator Import", "technique_ids": ["T1001", "T1059.001"]},
    )
    assert create_response.status_code == 201

    response = client.get(f"/api/custom-sets/{create_response.json()['id']}")

    assert response.status_code == 200
    assert response.json()["name"] == "Navigator Import"
    assert response.json()["technique_ids"] == ["T1001", "T1059.001"]


def test_create_custom_set_normalizes_technique_ids() -> None:
    """Custom set persistence should tolerate lowercase and duplicate IDs."""
    client = _client_with_seeded_techniques()

    response = client.post(
        "/api/custom-sets",
        json={"name": "Manual Set", "technique_ids": [" t1001 ", "T1001"]},
    )

    assert response.status_code == 201
    assert response.json()["technique_ids"] == ["T1001"]


def test_create_custom_set_rejects_unknown_techniques() -> None:
    """Custom set persistence should validate technique IDs."""
    client = _client_with_seeded_techniques()

    response = client.post(
        "/api/custom-sets",
        json={"name": "Bad Set", "technique_ids": ["T9999"]},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "Unknown technique IDs"


def test_update_custom_set_replaces_metadata_and_techniques() -> None:
    """Saved custom sets should be editable without changing their ID."""
    client = _client_with_seeded_techniques()

    create_response = client.post(
        "/api/custom-sets",
        json={"name": "Draft", "description": "old", "technique_ids": ["T1001"]},
    )
    custom_set_id = create_response.json()["id"]

    response = client.put(
        f"/api/custom-sets/{custom_set_id}",
        json={"name": "Updated", "description": "new", "technique_ids": [" t1059.001 ", "T1001", "T1001"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == custom_set_id
    assert body["name"] == "Updated"
    assert body["description"] == "new"
    assert body["technique_ids"] == ["T1001", "T1059.001"]


def test_update_custom_set_rejects_unknown_techniques() -> None:
    """Custom set updates should validate technique IDs."""
    client = _client_with_seeded_techniques()

    create_response = client.post("/api/custom-sets", json={"name": "Draft", "technique_ids": ["T1001"]})
    response = client.put(
        f"/api/custom-sets/{create_response.json()['id']}",
        json={"name": "Bad Update", "technique_ids": ["T9999"]},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "Unknown technique IDs"


def test_delete_custom_set_removes_saved_profile() -> None:
    """Saved custom sets should be removable."""
    client = _client_with_seeded_techniques()

    create_response = client.post("/api/custom-sets", json={"name": "Delete Me", "technique_ids": ["T1001"]})
    custom_set_id = create_response.json()["id"]

    delete_response = client.delete(f"/api/custom-sets/{custom_set_id}")
    get_response = client.get(f"/api/custom-sets/{custom_set_id}")

    assert delete_response.status_code == 204
    assert get_response.status_code == 404


def _client_with_seeded_techniques() -> TestClient:
    """Create a test client with isolated in-memory technique data."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with TestingSessionLocal() as session:
        session.add_all(
            [
                Technique(
                    technique_id="T1001",
                    name="Data Obfuscation",
                    tactic="defense-evasion",
                    is_subtechnique=False,
                    parent_id=None,
                ),
                Technique(
                    technique_id="T1059.001",
                    name="PowerShell",
                    tactic="execution",
                    is_subtechnique=True,
                    parent_id="T1059",
                ),
            ]
        )
        session.commit()

    def override_db() -> Generator[Session, None, None]:
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db_session] = override_db
    return TestClient(app)
