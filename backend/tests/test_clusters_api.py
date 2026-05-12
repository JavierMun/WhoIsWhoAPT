"""Cluster API tests against the latest similarity matrix."""

from collections.abc import Generator
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.matrix import set_latest_matrix
from app.database import Base, get_db_session
from app.dependencies import get_settings_store
from app.main import create_app
from app.models.entities import Actor, Technique
from app.models.schemas import ApplicationSettings


class FakeSettingsStore:
    """Settings store stub for cluster API tests."""

    def load(self) -> ApplicationSettings:
        """Return default MITRE settings."""
        return ApplicationSettings(active_source="mitre")


def test_clusters_require_existing_matrix() -> None:
    """Cluster endpoint should not compute a matrix implicitly."""
    set_latest_matrix(None)
    client = _client_with_seeded_actors()

    response = client.get("/api/clusters")

    assert response.status_code == 404
    assert response.json()["error"] == "Matrix has not been computed yet"


def test_clusters_return_labels_for_latest_matrix() -> None:
    """Cluster endpoint should label actors from the latest matrix."""
    set_latest_matrix(None)
    client = _client_with_seeded_actors()
    matrix_response = client.post("/api/matrix", json={"metric": "jaccard"})
    assert matrix_response.status_code == 200

    response = client.get("/api/clusters?min_similarity=0.3")

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "mitre"
    assert body["metric"] == "jaccard"
    assert body["actor_count"] == 4
    assert body["cluster_count"] == 3
    assert body["min_similarity"] == 0.3
    labels = {item["actor_id"]: item["cluster_id"] for item in body["labels"]}
    assert labels["actor-a"] == labels["actor-b"]
    assert labels["actor-c"] != labels["actor-a"]
    assert labels["actor-d"] != labels["actor-a"]


def _client_with_seeded_actors() -> TestClient:
    """Create a test client with isolated in-memory actor data."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with TestingSessionLocal() as session:
        now = datetime.now(timezone.utc)  # noqa: UP017 - local dev still supports Python 3.10.
        session.add_all(
            [
                _actor("actor-a", "Alpha", ["T1001", "T1002"], now),
                _actor("actor-b", "Beta", ["T1002", "T1003"], now),
                _actor("actor-c", "Gamma", ["T2001"], now),
                _actor("actor-d", "Delta", [], now),
                _technique("T1001"),
                _technique("T1002"),
                _technique("T1003"),
                _technique("T2001"),
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
    app.dependency_overrides[get_settings_store] = lambda: FakeSettingsStore()
    return TestClient(app)


def _actor(actor_id: str, name: str, technique_ids: list[str], last_updated: datetime) -> Actor:
    """Build a normalized actor row for tests."""
    return Actor(
        id=actor_id,
        source_id=f"source-{actor_id}",
        source="mitre",
        name=name,
        aliases=[],
        description=None,
        last_updated=last_updated,
        techniques=[{"technique_id": technique_id} for technique_id in technique_ids],
        campaigns=[],
        software_used=[],
        cves_exploited=[],
        target_sectors=[],
        target_countries=[],
        motivation=None,
    )


def _technique(technique_id: str) -> Technique:
    """Build a technique row for matrix metadata."""
    return Technique(
        technique_id=technique_id,
        name=f"{technique_id} name",
        tactic="execution",
        is_subtechnique=False,
        parent_id=None,
    )
