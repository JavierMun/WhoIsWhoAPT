"""Actor similarity matrix API tests."""

from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.dependencies import get_settings_store
from app.main import create_app
from app.models.entities import Actor, Software, Technique
from app.models.schemas import ApplicationSettings, SimilarityMetric


class FakeSettingsStore:
    """Settings store stub for matrix API tests."""

    def __init__(self, settings: ApplicationSettings | None = None) -> None:
        self.settings = settings or ApplicationSettings(active_source="mitre")

    def load(self) -> ApplicationSettings:
        """Return configured application settings."""
        return self.settings


def test_matrix_computation_returns_symmetric_frontend_structure() -> None:
    """Matrix computation should return aligned actors and symmetric values."""
    client = _client_with_seeded_actors()

    response = client.post("/api/matrix", json={"metric": "jaccard"})

    assert response.status_code == 200
    body = response.json()
    assert body["metadata"]["source"] == "mitre"
    assert body["metadata"]["metric"] == "jaccard"
    assert body["metadata"]["actor_count"] == 4
    assert [actor["id"] for actor in body["actors"]] == ["actor-a", "actor-b", "actor-empty", "actor-c"]
    assert len(body["matrix"]) == 4
    assert all(len(row) == 4 for row in body["matrix"])
    for row_index, row in enumerate(body["matrix"]):
        for column_index, value in enumerate(row):
            assert 0 <= value <= 1
            assert value == body["matrix"][column_index][row_index]


def test_matrix_diagonal_values_follow_existing_similarity_semantics() -> None:
    """Actors with evidence self-score as 1.0, while empty evidence remains 0.0."""
    client = _client_with_seeded_actors()

    response = client.post("/api/matrix", json={"metric": "jaccard"})

    assert response.status_code == 200
    matrix = response.json()["matrix"]
    assert matrix[0][0] == 1.0
    assert matrix[1][1] == 1.0
    assert matrix[2][2] == 0.0
    assert matrix[3][3] == 1.0


def test_matrix_result_returns_latest_computation() -> None:
    """The result endpoint should return the most recent synchronous computation."""
    client = _client_with_seeded_actors()
    compute_response = client.post("/api/matrix", json={"metric": "jaccard"})

    result_response = client.get("/api/matrix/result")

    assert result_response.status_code == 200
    assert result_response.json() == compute_response.json()


@pytest.mark.parametrize(
    ("metric", "expected_alpha_beta_score"),
    [
        ("jaccard", 1 / 3),
        ("tactic_weighted_jaccard", 3 / 5),
        ("software_weighted_jaccard", 1 / 3),
    ],
)
def test_matrix_metric_selection(metric: SimilarityMetric, expected_alpha_beta_score: float) -> None:
    """The matrix endpoint should select the requested scoring metric."""
    client = _client_with_seeded_actors(
        ApplicationSettings(
            active_source="mitre",
            scoring={
                "tactic_weights": {"execution": 1.0, "persistence": 3.0},
                "technique_score_weight": 0.5,
                "software_score_weight": 0.5,
            },
        )
    )

    response = client.post("/api/matrix", json={"metric": metric})

    assert response.status_code == 200
    body = response.json()
    assert body["metadata"]["metric"] == metric
    assert body["matrix"][0][1] == expected_alpha_beta_score


def test_matrix_supports_rarity_weighted_metric() -> None:
    """Rarity-weighted Jaccard should be accepted and remain normalized."""
    client = _client_with_seeded_actors()

    response = client.post("/api/matrix", json={"metric": "jaccard_weighted"})

    assert response.status_code == 200
    body = response.json()
    assert body["metadata"]["metric"] == "jaccard_weighted"
    assert 0 < body["matrix"][0][1] < 1
    assert body["matrix"][0][1] == body["matrix"][1][0]


def _client_with_seeded_actors(settings: ApplicationSettings | None = None) -> TestClient:
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
                _actor("actor-empty", "Empty", [], now),
                _actor("actor-c", "Gamma", ["T2001"], now),
                _software("software-shared", "SharedTool", "tool", ["actor-a", "actor-b"], now),
                _software("software-alpha", "AlphaMalware", "malware", ["actor-a"], now),
                _software("software-beta", "BetaTool", "tool", ["actor-b"], now),
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
    app.dependency_overrides[get_settings_store] = lambda: FakeSettingsStore(settings)
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
        software_used=_software_ids_for_actor(actor_id),
        cves_exploited=[],
        target_sectors=[],
        target_countries=[],
        motivation=None,
    )


def _software_ids_for_actor(actor_id: str) -> list[str]:
    """Return seeded software relationships for matrix tests."""
    if actor_id == "actor-a":
        return ["software-shared", "software-alpha"]
    if actor_id == "actor-b":
        return ["software-shared", "software-beta"]
    return []


def _software(
    software_id: str,
    name: str,
    software_type: str,
    actor_ids: list[str],
    last_updated: datetime,
) -> Software:
    """Build a normalized software row for matrix tests."""
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


def _technique(technique_id: str, tactic: str = "execution") -> Technique:
    """Build a technique row for tactic metadata."""
    return Technique(
        technique_id=technique_id,
        name=f"{technique_id} name",
        tactic=tactic,
        is_subtechnique="." in technique_id,
        parent_id=technique_id.split(".", maxsplit=1)[0] if "." in technique_id else None,
    )
