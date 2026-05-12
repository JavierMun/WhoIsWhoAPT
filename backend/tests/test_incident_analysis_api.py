"""Incident analysis API tests."""

from collections.abc import Generator
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.dependencies import get_settings_store
from app.main import create_app
from app.models.entities import Actor, Software, Technique
from app.models.schemas import ApplicationSettings


class FakeSettingsStore:
    """Settings store stub for incident API tests."""

    def load(self) -> ApplicationSettings:
        """Return default MITRE settings."""
        return ApplicationSettings(active_source="mitre")


def test_incident_analysis_normalizes_and_ranks_techniques() -> None:
    """Incident analysis should normalize technique IDs and reuse comparison scoring."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/analyze/incident",
        json={
            "incident_name": "Case 42",
            "description": "Observed execution and persistence.",
            "technique_ids": [" t1001 ", "T1002", "t1002"],
            "metric": "jaccard",
            "top_n": 2,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["input_name"] == "Case 42"
    assert body["input_type"] == "incident"
    assert body["metric"] == "jaccard"
    assert body["results"][0]["matched_entity_id"] == "actor-a"
    assert body["results"][0]["score"] == 1.0
    assert body["results"][0]["shared_techniques"] == ["T1001", "T1002"]
    assert body["results"][0]["shared_software"] == []
    assert len(body["results"]) == 2


def test_incident_analysis_rejects_empty_technique_set() -> None:
    """Incident analysis should return a clear validation error for empty input."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/analyze/incident",
        json={"incident_name": "Empty Case", "technique_ids": [" ", ""], "metric": "jaccard"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "Custom comparison must include at least one technique"


def test_incident_analysis_rejects_unknown_technique_ids() -> None:
    """Incident analysis should report unknown normalized technique IDs."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/analyze/incident",
        json={"incident_name": "Unknown Case", "technique_ids": ["t9999"], "metric": "jaccard"},
    )

    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "Unknown technique IDs"
    assert body["detail"]["technique_ids"] == ["T9999"]


def test_incident_analysis_includes_rare_shared_techniques_when_weighted() -> None:
    """Weighted incident analysis should expose rare shared techniques where available."""
    client = _client_with_seeded_actors()

    response = client.post(
        "/api/analyze/incident",
        json={
            "incident_name": "Weighted Case",
            "technique_ids": ["T1001", "T1002"],
            "metric": "jaccard_weighted",
            "top_n": 1,
        },
    )

    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["matched_entity_id"] == "actor-a"
    assert result["rare_shared_techniques"] == ["T1001"]


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
                _software("software-shared", "SharedTool", "tool", ["actor-a", "actor-b"], now),
                _technique("T1001", "execution"),
                _technique("T1002", "persistence"),
                _technique("T1003", "execution"),
                _technique("T2001", "collection"),
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


def _software(
    software_id: str,
    name: str,
    software_type: str,
    actor_ids: list[str],
    last_updated: datetime,
) -> Software:
    """Build a normalized software row for tests."""
    return Software(
        id=software_id,
        source_id=f"source-{software_id}",
        source="mitre",
        name=name,
        aliases=[],
        description=f"{name} description",
        last_updated=last_updated,
        software_type=software_type,
        techniques=[],
        actor_ids=actor_ids,
        campaign_ids=[],
    )


def _technique(technique_id: str, tactic: str) -> Technique:
    """Build a technique row for incident tests."""
    return Technique(
        technique_id=technique_id,
        name=f"{technique_id} name",
        tactic=tactic,
        is_subtechnique="." in technique_id,
        parent_id=technique_id.split(".", maxsplit=1)[0] if "." in technique_id else None,
    )
