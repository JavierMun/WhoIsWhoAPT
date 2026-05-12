"""Settings and source-management API tests.

Covers:
- GET /api/settings  — returns current settings
- PUT /api/settings  — persists and returns updated settings
- GET /api/source/status — returns ingestion status for active source
- POST /api/source/test-connection — tests OpenCTI credentials (mocked adapter)
"""

from __future__ import annotations

import sys
import types
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db_session
from app.dependencies import get_settings_store
from app.errors import AppError
from app.main import create_app
from app.models.schemas import ApplicationSettings, OpenCTISettings

# ---------------------------------------------------------------------------
# Mock pycti so the adapter can be imported without the real package
# ---------------------------------------------------------------------------

_pycti_mock = types.ModuleType("pycti")
_pycti_mock.OpenCTIApiClient = MagicMock  # type: ignore[attr-defined]
sys.modules.setdefault("pycti", _pycti_mock)


# ---------------------------------------------------------------------------
# Fake in-memory settings store
# ---------------------------------------------------------------------------


class FakeSettingsStore:
    """In-memory settings store for tests."""

    def __init__(self, initial: ApplicationSettings | None = None) -> None:
        self._settings = initial or ApplicationSettings()

    def load(self) -> ApplicationSettings:
        return self._settings

    def save(self, settings: ApplicationSettings) -> ApplicationSettings:
        self._settings = settings
        return settings


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------


def _client(store: FakeSettingsStore | None = None) -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_db() -> Generator[Session, None, None]:
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_settings_store] = lambda: (store or FakeSettingsStore())
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /api/settings
# ---------------------------------------------------------------------------


def test_get_settings_returns_defaults() -> None:
    """Default settings should be returned when nothing has been saved."""
    client = _client(FakeSettingsStore())

    response = client.get("/api/settings")

    assert response.status_code == 200
    body = response.json()
    assert body["active_source"] == "mitre"
    assert body["opencti"]["url"] is None
    assert body["opencti"]["api_token"] is None


def test_get_settings_returns_persisted_values() -> None:
    """Persisted settings should be returned as-is."""
    initial = ApplicationSettings(
        active_source="opencti",
        opencti=OpenCTISettings(url="http://octi.test", api_token="tok-123"),
    )
    client = _client(FakeSettingsStore(initial))

    response = client.get("/api/settings")

    assert response.status_code == 200
    body = response.json()
    assert body["active_source"] == "opencti"
    assert body["opencti"]["url"] == "http://octi.test/"
    assert body["opencti"]["api_token"] == "tok-123"


# ---------------------------------------------------------------------------
# PUT /api/settings
# ---------------------------------------------------------------------------


def test_put_settings_switches_to_opencti() -> None:
    """Saving settings with OpenCTI source should persist and return it."""
    store = FakeSettingsStore()
    client = _client(store)

    response = client.put(
        "/api/settings",
        json={
            "active_source": "opencti",
            "mitre": {"auto_update": True, "update_frequency_hours": 168},
            "opencti": {
                "url": "http://opencti.example",
                "api_token": "my-token",
                "auto_update": True,
                "update_frequency_hours": 24,
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["active_source"] == "opencti"
    assert body["opencti"]["api_token"] == "my-token"
    # Verify store was updated
    assert store.load().active_source == "opencti"


def test_put_settings_switches_back_to_mitre() -> None:
    """Switching back to MITRE should persist correctly."""
    store = FakeSettingsStore(
        ApplicationSettings(
            active_source="opencti",
            opencti=OpenCTISettings(url="http://octi.test", api_token="tok"),
        )
    )
    client = _client(store)

    response = client.put(
        "/api/settings",
        json={
            "active_source": "mitre",
            "mitre": {"auto_update": True, "update_frequency_hours": 168},
            "opencti": {"url": "http://octi.test/", "api_token": "tok", "auto_update": True, "update_frequency_hours": 24},
        },
    )

    assert response.status_code == 200
    assert response.json()["active_source"] == "mitre"
    assert store.load().active_source == "mitre"


def test_put_settings_returns_full_settings_object() -> None:
    """PUT should echo back the full settings schema including defaults."""
    client = _client()

    response = client.put(
        "/api/settings",
        json={
            "active_source": "mitre",
            "mitre": {"auto_update": True, "update_frequency_hours": 72},
            "opencti": {"url": None, "api_token": None, "auto_update": True, "update_frequency_hours": 24},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert "mitre" in body
    assert "opencti" in body
    assert body["mitre"]["update_frequency_hours"] == 72


# ---------------------------------------------------------------------------
# GET /api/source/status
# ---------------------------------------------------------------------------


def test_get_source_status_returns_never_loaded_for_fresh_db() -> None:
    """A clean database should return 'never_loaded' status."""
    client = _client(FakeSettingsStore())

    response = client.get("/api/source/status")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "never_loaded"
    assert body["source"] == "mitre"
    assert body["last_loaded_at"] is None
    assert body["actor_count"] == 0
    assert body["technique_count"] == 0


def test_get_source_status_reflects_active_source() -> None:
    """Status endpoint should use the active source from settings."""
    store = FakeSettingsStore(
        ApplicationSettings(
            active_source="opencti",
            opencti=OpenCTISettings(url="http://octi.test", api_token="tok"),
        )
    )
    client = _client(store)

    response = client.get("/api/source/status")

    assert response.status_code == 200
    assert response.json()["source"] == "opencti"


# ---------------------------------------------------------------------------
# POST /api/source/test-connection
# ---------------------------------------------------------------------------


def test_test_connection_returns_ok_when_health_check_passes() -> None:
    """A passing health_check() should yield ok=True."""
    client = _client()

    with patch("app.sources.opencti.OpenCTIAdapter._get_client") as mock_get:
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_get.return_value = mock_client

        response = client.post(
            "/api/source/test-connection",
            json={"url": "http://octi.test", "api_token": "valid-token"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["detail"] is None


def test_test_connection_returns_failure_when_health_check_false() -> None:
    """A failing health_check() should yield ok=False with detail."""
    client = _client()

    with patch("app.sources.opencti.OpenCTIAdapter._get_client") as mock_get:
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get.return_value = mock_client

        response = client.post(
            "/api/source/test-connection",
            json={"url": "http://octi.test", "api_token": "bad-token"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["detail"] is not None


def test_test_connection_returns_failure_on_exception() -> None:
    """A connection error should yield ok=False, never raise HTTP 5xx."""
    client = _client()

    with patch("app.sources.opencti.OpenCTIAdapter._get_client") as mock_get:
        mock_get.side_effect = RuntimeError("refused")

        response = client.post(
            "/api/source/test-connection",
            json={"url": "http://bad.host", "api_token": "tok"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False


def test_test_connection_always_returns_http_200() -> None:
    """The endpoint must always return 200 regardless of outcome."""
    client = _client()

    with patch("app.sources.opencti.OpenCTIAdapter._get_client") as mock_get:
        mock_get.side_effect = Exception("catastrophic failure")

        response = client.post(
            "/api/source/test-connection",
            json={"url": "http://octi.test", "api_token": "tok"},
        )

    assert response.status_code == 200
