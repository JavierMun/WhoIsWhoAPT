"""Unit tests for the OpenCTI source adapter.

pycti is not installed in the local dev environment; we mock the entire
module via sys.modules before importing the adapter so tests run without it.
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Mock pycti before any import of opencti.py touches it
# ---------------------------------------------------------------------------

_pycti_mock = types.ModuleType("pycti")
_pycti_mock.OpenCTIApiClient = MagicMock  # type: ignore[attr-defined]
sys.modules.setdefault("pycti", _pycti_mock)

from app.sources.opencti import (  # noqa: E402
    OpenCTIAdapter,
    _aliases,
    _build_ap_mitre_map,
    _build_technique_refs,
    _internal_id,
    _tactic_from_item,
)

# ---------------------------------------------------------------------------
# Helper: build a fake OpenCTI attack-pattern dict
# ---------------------------------------------------------------------------


def _ap(
    octi_id: str,
    mitre_id: str,
    name: str,
    *,
    tactics: list[str] | None = None,
    kill_chain_key: str = "killChainPhases",
) -> dict[str, Any]:
    phases = [{"kill_chain_name": "mitre-attack", "phase_name": tactic} for tactic in (tactics or ["execution"])]
    return {
        "id": octi_id,
        "x_mitre_id": mitre_id,
        "name": name,
        kill_chain_key: phases,
    }


def _rel(from_id: str, to_id: str, description: str | None = None) -> dict[str, Any]:
    return {
        "from": {"id": from_id},
        "to": {"id": to_id},
        "description": description,
    }


# ---------------------------------------------------------------------------
# _tactic_from_item
# ---------------------------------------------------------------------------


def test_tactic_from_item_single() -> None:
    item = {"killChainPhases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]}
    assert _tactic_from_item(item) == "execution"


def test_tactic_from_item_multiple_sorted_deduped() -> None:
    item = {
        "killChainPhases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "Persistence"},
            {"kill_chain_name": "mitre-attack", "phase_name": "Execution"},
            {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},  # dup
        ]
    }
    assert _tactic_from_item(item) == "execution, persistence"


def test_tactic_from_item_strips_whitespace() -> None:
    item = {
        "killChainPhases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "  Discovery  "},
        ]
    }
    assert _tactic_from_item(item) == "discovery"


def test_tactic_from_item_ignores_non_mitre_chains() -> None:
    item = {
        "killChainPhases": [
            {"kill_chain_name": "lockheed-martin", "phase_name": "recon"},
            {"kill_chain_name": "mitre-attack", "phase_name": "collection"},
        ]
    }
    assert _tactic_from_item(item) == "collection"


def test_tactic_from_item_versioned_chain_deduped() -> None:
    """pycti 6.x returns both 'mitre-attack' and 'mitre-attack-v19' for same phase."""
    item = {
        "killChainPhases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "resource-development"},
            {"kill_chain_name": "mitre-attack-v19", "phase_name": "resource-development"},
        ]
    }
    assert _tactic_from_item(item) == "resource-development"


def test_tactic_from_item_fallback_key() -> None:
    item = {"kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]}
    assert _tactic_from_item(item) == "defense-evasion"


def test_tactic_from_item_empty_returns_unknown() -> None:
    assert _tactic_from_item({}) == "unknown"
    assert _tactic_from_item({"killChainPhases": []}) == "unknown"


def test_tactic_format_matches_mitre_source() -> None:
    """Verify the separator and casing match MitreSource output exactly."""
    item = {
        "killChainPhases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "Privilege-Escalation"},
            {"kill_chain_name": "mitre-attack", "phase_name": "Persistence"},
        ]
    }
    tactic = _tactic_from_item(item)
    # Must use ", " (comma-space), lowercase, alphabetically sorted
    assert tactic == "persistence, privilege-escalation"
    assert ", " in tactic
    parts = tactic.split(", ")
    assert parts == sorted(parts)
    assert all(p == p.lower() for p in parts)


# ---------------------------------------------------------------------------
# _internal_id
# ---------------------------------------------------------------------------


def test_internal_id_is_deterministic() -> None:
    octi_id = "7e65e3f5-aa6c-4f6c-97f0-000000000001"
    assert _internal_id(octi_id) == _internal_id(octi_id)


def test_internal_id_differs_per_opencti_id() -> None:
    a = _internal_id("aaa")
    b = _internal_id("bbb")
    assert a != b


# ---------------------------------------------------------------------------
# _aliases
# ---------------------------------------------------------------------------


def test_aliases_prefers_aliases_key() -> None:
    item = {"aliases": ["APT1", "Comment Crew"], "x_opencti_aliases": ["other"]}
    assert _aliases(item) == ["APT1", "Comment Crew"]


def test_aliases_falls_back_to_opencti_aliases() -> None:
    item = {"x_opencti_aliases": ["Fancy Bear"]}
    assert _aliases(item) == ["Fancy Bear"]


def test_aliases_empty_when_missing() -> None:
    assert _aliases({}) == []


# ---------------------------------------------------------------------------
# _build_ap_mitre_map
# ---------------------------------------------------------------------------


def test_build_ap_mitre_map_includes_only_t_ids() -> None:
    ap_list = [
        {"id": "ap-1", "x_mitre_id": "T1059"},
        {"id": "ap-2", "x_mitre_id": "T1059.001"},
        {"id": "ap-3", "x_mitre_id": "S0001"},  # software, not T-number
        {"id": "ap-4"},  # no x_mitre_id
    ]
    result = _build_ap_mitre_map(ap_list)
    assert result == {"ap-1": "T1059", "ap-2": "T1059.001"}


# ---------------------------------------------------------------------------
# _build_technique_refs
# ---------------------------------------------------------------------------


def test_build_technique_refs_maps_matching_rels() -> None:
    ap_mitre_map = {"ap-1": "T1059", "ap-2": "T1059.001"}
    rels = [
        _rel("actor-A", "ap-1", "uses powershell"),
        _rel("actor-A", "ap-2"),
        _rel("actor-B", "ap-1"),  # different actor — should be ignored
    ]
    refs = _build_technique_refs(rels, ap_mitre_map, "actor-A")
    assert {r.technique_id for r in refs} == {"T1059", "T1059.001"}
    descriptions = {r.technique_id: r.use_description for r in refs}
    assert descriptions["T1059"] == "uses powershell"
    assert descriptions["T1059.001"] is None


def test_build_technique_refs_skips_unmapped_aps() -> None:
    ap_mitre_map = {"ap-1": "T1059"}
    rels = [_rel("actor-A", "ap-9999")]  # not in map
    refs = _build_technique_refs(rels, ap_mitre_map, "actor-A")
    assert refs == []


# ---------------------------------------------------------------------------
# OpenCTIAdapter.fetch_techniques
# ---------------------------------------------------------------------------


def _make_adapter_with_client(ap_list: list[dict[str, Any]]) -> OpenCTIAdapter:
    """Return an OpenCTIAdapter whose internal client returns the given ap list."""
    adapter = OpenCTIAdapter("https://octi.example", "fake-token")
    mock_client = MagicMock()
    mock_client.attack_pattern.list.return_value = ap_list
    adapter._client = mock_client
    return adapter


def test_fetch_techniques_returns_only_t_ids() -> None:
    ap_list = [
        _ap("ap-1", "T1059", "Command and Scripting Interpreter"),
        _ap("ap-2", "T1059.001", "PowerShell", tactics=["execution"]),
        _ap("ap-3", "S0001", "SomeSoftware"),  # not a T-number — must be excluded
    ]
    adapter = _make_adapter_with_client(ap_list)
    techniques = adapter.fetch_techniques()
    ids = {t.technique_id for t in techniques}
    assert ids == {"T1059", "T1059.001"}


def test_fetch_techniques_subtechnique_detection() -> None:
    ap_list = [
        _ap("ap-1", "T1059", "Parent"),
        _ap("ap-2", "T1059.001", "Child"),
    ]
    adapter = _make_adapter_with_client(ap_list)
    techniques = {t.technique_id: t for t in adapter.fetch_techniques()}
    assert techniques["T1059"].is_subtechnique is False
    assert techniques["T1059"].parent_id is None
    assert techniques["T1059.001"].is_subtechnique is True
    assert techniques["T1059.001"].parent_id == "T1059"


def test_fetch_techniques_tactic_normalized() -> None:
    ap_list = [_ap("ap-1", "T1059", "Exec", tactics=["Execution", "execution"])]
    adapter = _make_adapter_with_client(ap_list)
    techniques = adapter.fetch_techniques()
    assert techniques[0].tactic == "execution"


def test_fetch_techniques_multi_tactic_sorted() -> None:
    ap_list = [_ap("ap-1", "T1005", "Data", tactics=["Persistence", "Collection"])]
    adapter = _make_adapter_with_client(ap_list)
    techniques = adapter.fetch_techniques()
    assert techniques[0].tactic == "collection, persistence"


# ---------------------------------------------------------------------------
# OpenCTIAdapter.test_connection
# ---------------------------------------------------------------------------


def test_test_connection_calls_health_check() -> None:
    adapter = OpenCTIAdapter("https://octi.example", "fake-token")
    mock_client = MagicMock()
    mock_client.health_check.return_value = True
    adapter._client = mock_client
    adapter.test_connection()  # should not raise
    mock_client.health_check.assert_called_once()


def test_test_connection_raises_apperror_when_unhealthy() -> None:
    from app.errors import AppError

    adapter = OpenCTIAdapter("https://octi.example", "fake-token")
    mock_client = MagicMock()
    mock_client.health_check.return_value = False
    adapter._client = mock_client
    with pytest.raises(AppError):
        adapter.test_connection()


def test_test_connection_raises_apperror_on_exception() -> None:
    from app.errors import AppError

    adapter = OpenCTIAdapter("https://octi.example", "fake-token")
    mock_client = MagicMock()
    mock_client.health_check.side_effect = RuntimeError("refused")
    adapter._client = mock_client
    with pytest.raises(AppError):
        adapter.test_connection()


# ---------------------------------------------------------------------------
# OpenCTIAdapter.get_source_version
# ---------------------------------------------------------------------------


def test_get_source_version_returns_string() -> None:
    adapter = OpenCTIAdapter("https://octi.example", "fake-token")
    mock_client = MagicMock()
    mock_client.query.return_value = {"data": {"about": {"version": "7.260423.0"}}}
    adapter._client = mock_client
    assert adapter.get_source_version() == "7.260423.0"


def test_get_source_version_returns_unknown_on_error() -> None:
    adapter = OpenCTIAdapter("https://octi.example", "fake-token")
    mock_client = MagicMock()
    mock_client.query.side_effect = Exception("network error")
    adapter._client = mock_client
    assert adapter.get_source_version() == "unknown"
