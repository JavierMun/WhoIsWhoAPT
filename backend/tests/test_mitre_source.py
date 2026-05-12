"""MITRE ATT&CK source normalization tests."""

from typing import Any

from app.sources.mitre import MitreSource


def test_mitre_source_normalizes_core_entities() -> None:
    """Groups, campaigns, software, techniques, and relationships are normalized."""
    source = MitreSource(bundle=_fixture_bundle())

    actors = source.fetch_actors()
    campaigns = source.fetch_campaigns()
    software = source.fetch_software()
    techniques = source.fetch_techniques()

    assert source.get_source_version() == "16.1"
    assert [actor.name for actor in actors] == ["Example Group"]
    assert actors[0].aliases == ["Example Alias"]
    assert [ref.technique_id for ref in actors[0].techniques] == ["T1059.001"]
    assert len(actors[0].software_used) == 1
    assert len(actors[0].campaigns) == 1

    assert [campaign.name for campaign in campaigns] == ["Example Campaign"]
    assert campaigns[0].actor_ids == [actors[0].id]
    assert [ref.technique_id for ref in campaigns[0].techniques] == ["T1059.001"]
    assert campaigns[0].software_used == [software[0].id]

    assert [item.name for item in software] == ["Example Malware"]
    assert software[0].software_type == "malware"
    assert software[0].actor_ids == [actors[0].id]
    assert software[0].campaign_ids == [campaigns[0].id]
    assert [ref.technique_id for ref in software[0].techniques] == ["T1059"]

    technique_by_id = {technique.technique_id: technique for technique in techniques}
    assert technique_by_id["T1059"].is_subtechnique is False
    assert technique_by_id["T1059.001"].is_subtechnique is True
    assert technique_by_id["T1059.001"].parent_id == "T1059"
    assert technique_by_id["T1059.001"].tactic == "execution"


def test_mitre_source_filters_revoked_and_deprecated_objects() -> None:
    """Revoked or deprecated objects should not enter the normalized dataset."""
    source = MitreSource(
        bundle={
            "objects": [
                _attack_pattern("attack-pattern--active", "T1000", "Active"),
                _attack_pattern("attack-pattern--revoked", "T1001", "Revoked", revoked=True),
                _attack_pattern("attack-pattern--deprecated", "T1002", "Deprecated", deprecated=True),
            ]
        }
    )

    assert [technique.technique_id for technique in source.fetch_techniques()] == ["T1000"]


def _fixture_bundle() -> dict[str, Any]:
    """Return a compact STIX fixture with the relationships the adapter maps."""
    return {
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--enterprise",
                "x_mitre_version": "16.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--11111111-1111-1111-1111-111111111111",
                "name": "Example Group",
                "aliases": ["Example Group", "Example Alias"],
                "description": "A fixture actor.",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-02-01T00:00:00.000Z",
            },
            {
                "type": "campaign",
                "id": "campaign--22222222-2222-2222-2222-222222222222",
                "name": "Example Campaign",
                "description": "A fixture campaign.",
                "first_seen": "2023-01-01T00:00:00.000Z",
                "last_seen": "2023-02-01T00:00:00.000Z",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-02-01T00:00:00.000Z",
            },
            {
                "type": "malware",
                "id": "malware--33333333-3333-3333-3333-333333333333",
                "name": "Example Malware",
                "description": "A fixture malware family.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}],
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-02-01T00:00:00.000Z",
            },
            _attack_pattern(
                "attack-pattern--44444444-4444-4444-4444-444444444444",
                "T1059",
                "Command and Scripting Interpreter",
            ),
            _attack_pattern(
                "attack-pattern--55555555-5555-5555-5555-555555555555",
                "T1059.001",
                "PowerShell",
                is_subtechnique=True,
            ),
            _relationship(
                "relationship--1",
                "uses",
                "intrusion-set--11111111-1111-1111-1111-111111111111",
                "attack-pattern--55555555-5555-5555-5555-555555555555",
                "Actor uses PowerShell.",
            ),
            _relationship(
                "relationship--2",
                "uses",
                "intrusion-set--11111111-1111-1111-1111-111111111111",
                "malware--33333333-3333-3333-3333-333333333333",
            ),
            _relationship(
                "relationship--3",
                "attributed-to",
                "campaign--22222222-2222-2222-2222-222222222222",
                "intrusion-set--11111111-1111-1111-1111-111111111111",
            ),
            _relationship(
                "relationship--4",
                "uses",
                "campaign--22222222-2222-2222-2222-222222222222",
                "attack-pattern--55555555-5555-5555-5555-555555555555",
            ),
            _relationship(
                "relationship--5",
                "uses",
                "malware--33333333-3333-3333-3333-333333333333",
                "attack-pattern--44444444-4444-4444-4444-444444444444",
            ),
            _relationship(
                "relationship--6",
                "uses",
                "campaign--22222222-2222-2222-2222-222222222222",
                "malware--33333333-3333-3333-3333-333333333333",
            ),
        ]
    }


def _attack_pattern(
    stix_id: str,
    external_id: str,
    name: str,
    *,
    is_subtechnique: bool = False,
    revoked: bool = False,
    deprecated: bool = False,
) -> dict[str, Any]:
    """Build a compact attack-pattern STIX object."""
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": external_id}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        "x_mitre_is_subtechnique": is_subtechnique,
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-02-01T00:00:00.000Z",
    }


def _relationship(
    stix_id: str,
    relationship_type: str,
    source_ref: str,
    target_ref: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a compact STIX relationship object."""
    return {
        "type": "relationship",
        "id": stix_id,
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": description,
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-02-01T00:00:00.000Z",
    }
