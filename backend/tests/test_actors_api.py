"""Minimal actors API tests."""

from collections.abc import Generator
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.dependencies import get_settings_store
from app.main import create_app
from app.models.entities import Actor, Software
from app.models.schemas import ApplicationSettings


class FakeSettingsStore:
    """Settings store stub for API tests."""

    def load(self) -> ApplicationSettings:
        """Return default MITRE settings."""
        return ApplicationSettings(active_source="mitre")


def test_list_actors_returns_selection_fields() -> None:
    """Actor list should include id, name, aliases, and technique count."""
    client = _client_with_seeded_actors()

    response = client.get("/api/actors")

    assert response.status_code == 200
    assert response.json() == [
        {"id": "actor-a", "name": "Alpha", "aliases": ["A-Team"], "technique_count": 2},
        {"id": "actor-b", "name": "Beta", "aliases": [], "technique_count": 1},
    ]


def test_actor_detail_returns_techniques() -> None:
    """Actor detail should expose stored technique references."""
    client = _client_with_seeded_actors()

    response = client.get("/api/actors/actor-a")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "actor-a"
    assert body["name"] == "Alpha"
    assert body["technique_count"] == 2
    assert body["techniques"] == [
        {"technique_id": "T1001", "use_description": None, "detected_in_campaigns": []},
        {"technique_id": "T1002", "use_description": "Observed use.", "detected_in_campaigns": []},
    ]
    assert body["software_count"] == 1
    assert body["software_used"] == [{"id": "software-a", "name": "AlphaTool", "software_type": "tool"}]


def test_actor_detail_returns_404_for_unknown_actor() -> None:
    """Unknown actors should return a clean 404 error."""
    client = _client_with_seeded_actors()

    response = client.get("/api/actors/missing")

    assert response.status_code == 404
    assert response.json()["error"] == "Actor not found"


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
                _actor("actor-a", "Alpha", ["A-Team"], ["T1001", "T1002"], now),
                _actor("actor-b", "Beta", [], ["T2001"], now),
                _actor("actor-c", "Other Source", [], ["T3001"], now, source="opencti"),
                _software("software-a", "AlphaTool", "tool", now),
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


def _actor(
    actor_id: str,
    name: str,
    aliases: list[str],
    technique_ids: list[str],
    last_updated: datetime,
    source: str = "mitre",
) -> Actor:
    """Build a normalized actor row for tests."""
    techniques = [{"technique_id": technique_id} for technique_id in technique_ids]
    if len(techniques) > 1:
        techniques[1]["use_description"] = "Observed use."
    return Actor(
        id=actor_id,
        source_id=f"source-{actor_id}",
        source=source,
        name=name,
        aliases=aliases,
        description=f"{name} description",
        last_updated=last_updated,
        techniques=techniques,
        campaigns=[],
        software_used=["software-a"] if actor_id == "actor-a" else [],
        cves_exploited=[],
        target_sectors=[],
        target_countries=[],
        motivation=None,
    )


def _software(software_id: str, name: str, software_type: str, last_updated: datetime) -> Software:
    """Build a normalized software row for actor detail tests."""
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
        actor_ids=["actor-a"],
        campaign_ids=[],
    )
