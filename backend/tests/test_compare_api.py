"""Comparison API tests against a seeded SQLite database."""

from collections.abc import Generator
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.dependencies import get_settings_store
from app.main import create_app
from app.models.entities import Actor, Technique
from app.models.schemas import ApplicationSettings


class FakeSettingsStore:
    """Settings store stub for API tests."""

    def load(self) -> ApplicationSettings:
        """Return default MITRE settings."""
        return ApplicationSettings(active_source="mitre")


def test_compare_actor_vs_all_returns_ranked_explanation() -> None:
    """Actor comparison should rank candidates and include overlap details."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/compare/actor",
        json={"actor_id": "actor-a", "metric": "jaccard", "top_n": 2},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["input_id"] == "actor-a"
    assert body["results"][0]["matched_entity_id"] == "actor-b"
    assert body["results"][0]["score"] == 1 / 3
    assert body["results"][0]["shared_techniques"] == ["T1002"]
    assert body["results"][0]["unique_to_input"] == ["T1001"]
    assert body["results"][0]["unique_to_matched_entity"] == ["T1003"]


def test_compare_custom_inline_vs_all() -> None:
    """Inline custom TTP sets should compare against all actors."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/compare/custom",
        json={"name": "Incident", "technique_ids": ["T1001", "T1002"], "metric": "jaccard"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["input_name"] == "Incident"
    assert body["results"][0]["matched_entity_id"] == "actor-a"
    assert body["results"][0]["score"] == 1.0


def test_compare_custom_inline_normalizes_technique_ids() -> None:
    """Inline custom comparisons should tolerate lowercase technique IDs."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/compare/custom",
        json={"name": "Incident", "technique_ids": [" t1001 ", "t1002"], "metric": "jaccard"},
    )

    assert response.status_code == 200
    assert response.json()["results"][0]["matched_entity_id"] == "actor-a"


def test_compare_actor_vs_actor() -> None:
    """Direct actor comparison should return one requested match."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/compare/actor",
        json={"actor_id": "actor-a", "target_actor_id": "actor-b", "metric": "jaccard"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 1
    assert body["results"][0]["matched_entity_id"] == "actor-b"
    assert body["results"][0]["score"] == 1 / 3


def test_compare_saved_custom_set_vs_all() -> None:
    """Saved custom TTP sets should be usable by comparison ID."""
    client = _client_with_seeded_actors()

    create_response = client.post(
        "/api/custom-sets",
        json={"name": "Saved Incident", "technique_ids": ["T1001", "T1002"]},
    )
    assert create_response.status_code == 201
    custom_set_id = create_response.json()["id"]

    compare_response = client.post(
        "/api/compare/custom",
        json={"custom_set_id": custom_set_id, "metric": "jaccard"},
    )

    assert compare_response.status_code == 200
    body = compare_response.json()
    assert body["input_id"] == custom_set_id
    assert body["input_name"] == "Saved Incident"
    assert body["results"][0]["matched_entity_id"] == "actor-a"


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
                *[_technique(technique_id) for technique_id in ["T1001", "T1002", "T1003", "T2001"]],
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
    """Build a technique row for custom TTP validation."""
    return Technique(
        technique_id=technique_id,
        name=f"{technique_id} name",
        tactic="execution",
        is_subtechnique="." in technique_id,
        parent_id=technique_id.split(".", maxsplit=1)[0] if "." in technique_id else None,
    )
