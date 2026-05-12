"""Multi-source ingestion and isolation tests.

Covers:
- get_source_adapter() factory: known sources, missing config, unknown source
- _replace_source_data(): MITRE rows survive OpenCTI ingestion and vice-versa
- CustomTTPSet rows are never touched during source replacement
- _technique_has_tactic(): tactic filter works across both normalization formats
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Mock pycti so OpenCTI adapter can be imported without the real package
# ---------------------------------------------------------------------------

_pycti_mock = types.ModuleType("pycti")
_pycti_mock.OpenCTIApiClient = MagicMock  # type: ignore[attr-defined]
sys.modules.setdefault("pycti", _pycti_mock)

from app.api.routes.compare import _technique_has_tactic  # noqa: E402
from app.database import Base  # noqa: E402
from app.errors import AppError  # noqa: E402
from app.ingestion import _replace_source_data, get_source_adapter  # noqa: E402
from app.models import entities  # noqa: E402
from app.models.schemas import Actor as ActorSchema  # noqa: E402
from app.models.schemas import (  # noqa: E402
    ApplicationSettings,
    OpenCTISettings,
    Technique,
    TechniqueRef,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime.now(timezone.utc)  # noqa: UP017


def _make_session() -> tuple[Session, sessionmaker]:  # type: ignore[type-arg]
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return factory(), factory


def _actor_schema(actor_id: str, source: str) -> ActorSchema:
    return ActorSchema(
        id=actor_id,
        source_id=f"src-{actor_id}",
        source=source,
        name=f"Actor {actor_id}",
        aliases=[],
        description=None,
        last_updated=NOW,
        techniques=[TechniqueRef(technique_id="T1059")],
        campaigns=[],
        software_used=[],
        cves_exploited=[],
        target_sectors=[],
        target_countries=[],
        motivation=None,
    )


def _technique_schema(technique_id: str, tactic: str = "execution") -> Technique:
    return Technique(
        technique_id=technique_id,
        name=f"Technique {technique_id}",
        tactic=tactic,
        is_subtechnique="." in technique_id,
        parent_id=technique_id.rsplit(".", 1)[0] if "." in technique_id else None,
    )


# ---------------------------------------------------------------------------
# get_source_adapter()
# ---------------------------------------------------------------------------


def test_factory_returns_mitre_source_for_mitre() -> None:
    from app.sources.mitre import MitreSource

    adapter = get_source_adapter("mitre")
    assert isinstance(adapter, MitreSource)


def test_factory_returns_opencti_adapter_for_opencti() -> None:
    from app.sources.opencti import OpenCTIAdapter

    settings = ApplicationSettings(
        active_source="opencti",
        opencti=OpenCTISettings(url="https://octi.test", api_token="tok"),
    )
    adapter = get_source_adapter("opencti", settings)
    assert isinstance(adapter, OpenCTIAdapter)


def test_factory_raises_apperror_for_opencti_without_credentials() -> None:
    settings = ApplicationSettings(active_source="opencti")
    with pytest.raises(AppError, match="OpenCTI URL and API token are required"):
        get_source_adapter("opencti", settings)


def test_factory_raises_apperror_for_unknown_source() -> None:
    with pytest.raises(AppError, match="not implemented"):
        get_source_adapter("elastic")


# ---------------------------------------------------------------------------
# _replace_source_data(): source isolation
# ---------------------------------------------------------------------------


def test_mitre_actors_survive_opencti_ingestion() -> None:
    """MITRE rows must not be deleted when loading OpenCTI data."""
    session, _ = _make_session()

    # Seed a MITRE actor directly into the DB
    mitre_actor = entities.Actor(
        id="mitre-actor-1",
        source_id="src-1",
        source="mitre",
        name="MITRE Actor",
        aliases=[],
        description=None,
        last_updated=NOW,
        techniques=[],
        campaigns=[],
        software_used=[],
        cves_exploited=[],
        target_sectors=[],
        target_countries=[],
        motivation=None,
    )
    session.add(mitre_actor)
    session.commit()

    # Simulate loading OpenCTI source (replaces opencti rows only)
    _replace_source_data(
        session,
        "opencti",
        actors=[_actor_schema("octi-actor-1", "opencti")],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1059")],
    )
    session.commit()

    # MITRE actor must still be present
    remaining = session.scalars(select(entities.Actor)).all()
    ids = {a.id for a in remaining}
    assert "mitre-actor-1" in ids
    assert "octi-actor-1" in ids


def test_opencti_actors_survive_mitre_ingestion() -> None:
    """OpenCTI rows must not be deleted when loading MITRE data."""
    session, _ = _make_session()

    octi_actor = entities.Actor(
        id="octi-actor-1",
        source_id="octi-src-1",
        source="opencti",
        name="OpenCTI Actor",
        aliases=[],
        description=None,
        last_updated=NOW,
        techniques=[],
        campaigns=[],
        software_used=[],
        cves_exploited=[],
        target_sectors=[],
        target_countries=[],
        motivation=None,
    )
    session.add(octi_actor)
    session.commit()

    _replace_source_data(
        session,
        "mitre",
        actors=[_actor_schema("mitre-actor-1", "mitre")],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1059")],
    )
    session.commit()

    remaining = session.scalars(select(entities.Actor)).all()
    ids = {a.id for a in remaining}
    assert "octi-actor-1" in ids
    assert "mitre-actor-1" in ids


def test_same_source_actors_replaced_on_reload() -> None:
    """Re-loading a source replaces existing rows from that source."""
    session, _ = _make_session()

    # Load mitre with actor-v1
    _replace_source_data(
        session,
        "mitre",
        actors=[_actor_schema("mitre-actor-v1", "mitre")],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1059")],
    )
    session.commit()

    # Reload mitre with actor-v2 (different ID simulates a dataset refresh)
    _replace_source_data(
        session,
        "mitre",
        actors=[_actor_schema("mitre-actor-v2", "mitre")],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1059")],
    )
    session.commit()

    remaining = session.scalars(select(entities.Actor)).all()
    ids = {a.id for a in remaining}
    assert "mitre-actor-v1" not in ids
    assert "mitre-actor-v2" in ids


# ---------------------------------------------------------------------------
# CustomTTPSet survival across source switches
# ---------------------------------------------------------------------------


def test_custom_ttp_sets_survive_source_replacement() -> None:
    """CustomTTPSet rows must never be touched by ingestion."""
    session, _ = _make_session()

    custom_set = entities.CustomTTPSet(
        id="custom-1",
        name="My Red Team Profile",
        description="Custom set for red team ops",
        technique_ids=["T1059", "T1078"],
    )
    session.add(custom_set)
    session.commit()

    _replace_source_data(
        session,
        "mitre",
        actors=[_actor_schema("mitre-actor-1", "mitre")],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1059")],
    )
    session.commit()

    surviving = session.get(entities.CustomTTPSet, "custom-1")
    assert surviving is not None
    assert surviving.name == "My Red Team Profile"
    assert surviving.technique_ids == ["T1059", "T1078"]


# ---------------------------------------------------------------------------
# Techniques table: cleared and replaced on every ingestion
# ---------------------------------------------------------------------------


def test_techniques_fully_replaced_on_every_ingestion() -> None:
    """Technique table is wiped and reloaded regardless of source."""
    session, _ = _make_session()

    _replace_source_data(
        session,
        "mitre",
        actors=[],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1059"), _technique_schema("T1078")],
    )
    session.commit()

    # Reload with a different technique set
    _replace_source_data(
        session,
        "opencti",
        actors=[],
        campaigns=[],
        software=[],
        techniques=[_technique_schema("T1005")],
    )
    session.commit()

    ids = {t.technique_id for t in session.scalars(select(entities.Technique)).all()}
    assert ids == {"T1005"}


# ---------------------------------------------------------------------------
# _technique_has_tactic(): tactic filter regression
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tactic_value, scope, expected",
    [
        # MITRE format: ", " separator, lowercase, sorted
        ("execution", {"execution"}, True),
        ("persistence, privilege-escalation", {"privilege-escalation"}, True),
        ("persistence, privilege-escalation", {"lateral-movement"}, False),
        # OpenCTI pre-fix format: "," separator, may have mixed case — filter must handle it
        ("Execution,Persistence", {"persistence"}, True),
        ("Execution,Persistence", {"lateral-movement"}, False),
        # Single tactic uppercase (edge case)
        ("Discovery", {"discovery"}, True),
        # Empty / unknown
        ("unknown", {"execution"}, False),
        ("", {"execution"}, False),
        # Multiple tactics both formats with whitespace
        ("  Collection ,  Exfiltration  ", {"collection"}, True),
    ],
)
def test_technique_has_tactic(tactic_value: str, scope: set[str], expected: bool) -> None:
    assert _technique_has_tactic(tactic_value, scope) is expected
