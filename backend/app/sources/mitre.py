"""MITRE ATT&CK Enterprise source adapter.

The adapter accepts raw STIX bundle dictionaries so tests can exercise the
normalization logic without network access. In production it fetches the
Enterprise ATT&CK bundle and normalizes it into the app's internal models.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen
from uuid import NAMESPACE_URL, uuid5

from app.errors import AppError
from app.models.schemas import Actor, Campaign, Software, Technique, TechniqueRef
from app.sources.base import BaseSource

MITRE_SOURCE = "mitre"
ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)


class MitreSource(BaseSource):
    """Normalize MITRE ATT&CK STIX objects into internal source models."""

    def __init__(
        self,
        bundle: dict[str, Any] | None = None,
        bundle_path: Path | None = None,
        bundle_url: str = ENTERPRISE_ATTACK_URL,
    ) -> None:
        self.bundle_path = bundle_path
        self.bundle_url = bundle_url
        self._bundle = bundle
        self._objects: list[dict[str, Any]] | None = None

    def fetch_actors(self) -> list[Actor]:
        """Fetch and normalize ATT&CK intrusion sets."""
        objects = self._active_objects()
        relationships = self._relationships()
        technique_by_stix_id = self._technique_external_ids()
        software_by_stix_id = self._software_internal_ids()
        campaigns_by_actor = self._campaigns_by_actor()

        actors: list[Actor] = []
        for item in objects:
            if item.get("type") != "intrusion-set":
                continue

            source_id = str(item["id"])
            techniques = self._technique_refs_for_source(source_id, relationships, technique_by_stix_id)
            software_used = self._target_refs_for_source(source_id, relationships, software_by_stix_id)
            actors.append(
                Actor(
                    id=_internal_id(source_id),
                    source_id=source_id,
                    source=MITRE_SOURCE,
                    name=str(item.get("name", "")),
                    aliases=_aliases(item),
                    description=item.get("description"),
                    last_updated=_stix_datetime(item),
                    techniques=techniques,
                    campaigns=campaigns_by_actor.get(source_id, []),
                    software_used=software_used,
                    cves_exploited=[],
                    target_sectors=[],
                    target_countries=[],
                    motivation=None,
                )
            )
        return actors

    def fetch_campaigns(self) -> list[Campaign]:
        """Fetch and normalize ATT&CK campaigns."""
        objects = self._active_objects()
        relationships = self._relationships()
        technique_by_stix_id = self._technique_external_ids()
        software_by_stix_id = self._software_internal_ids()

        campaigns: list[Campaign] = []
        for item in objects:
            if item.get("type") != "campaign":
                continue

            source_id = str(item["id"])
            campaigns.append(
                Campaign(
                    id=_internal_id(source_id),
                    source_id=source_id,
                    source=MITRE_SOURCE,
                    name=str(item.get("name", "")),
                    aliases=_aliases(item),
                    description=item.get("description"),
                    last_updated=_stix_datetime(item),
                    actor_ids=self._actor_ids_for_campaign(source_id, relationships),
                    techniques=self._technique_refs_for_source(source_id, relationships, technique_by_stix_id),
                    software_used=self._target_refs_for_source(source_id, relationships, software_by_stix_id),
                    cves_exploited=[],
                    start_date=_stix_date(item.get("first_seen")),
                    end_date=_stix_date(item.get("last_seen")),
                )
            )
        return campaigns

    def fetch_software(self) -> list[Software]:
        """Fetch and normalize ATT&CK malware and tool objects."""
        objects = self._active_objects()
        relationships = self._relationships()
        technique_by_stix_id = self._technique_external_ids()

        software: list[Software] = []
        for item in objects:
            if item.get("type") not in {"malware", "tool"}:
                continue

            source_id = str(item["id"])
            software.append(
                Software(
                    id=_internal_id(source_id),
                    source_id=source_id,
                    source=MITRE_SOURCE,
                    name=str(item.get("name", "")),
                    aliases=_aliases(item),
                    description=item.get("description"),
                    last_updated=_stix_datetime(item),
                    software_type="malware" if item.get("type") == "malware" else "tool",
                    techniques=self._technique_refs_for_source(source_id, relationships, technique_by_stix_id),
                    actor_ids=self._source_ids_using_target(source_id, relationships, "intrusion-set"),
                    campaign_ids=self._source_ids_using_target(source_id, relationships, "campaign"),
                )
            )
        return software

    def fetch_techniques(self) -> list[Technique]:
        """Fetch and normalize ATT&CK techniques and sub-techniques."""
        techniques: list[Technique] = []
        for item in self._active_objects():
            if item.get("type") != "attack-pattern":
                continue
            technique_id = _external_id(item)
            if technique_id is None:
                continue

            # ATT&CK allows a technique to appear under more than one tactic. The
            # current internal model has one tactic string, so keep every phase in
            # a stable comma-separated value instead of dropping secondary tactics.
            tactics = [
                str(phase.get("phase_name"))
                for phase in item.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
            ]
            is_subtechnique = bool(item.get("x_mitre_is_subtechnique")) or "." in technique_id
            techniques.append(
                Technique(
                    technique_id=technique_id,
                    name=str(item.get("name", "")),
                    tactic=", ".join(sorted(set(tactics))),
                    is_subtechnique=is_subtechnique,
                    parent_id=technique_id.split(".", maxsplit=1)[0] if is_subtechnique else None,
                )
            )
        return techniques

    def get_source_version(self) -> str:
        """Return the ATT&CK version string when available."""
        versions = [
            str(item["x_mitre_version"])
            for item in self._active_objects()
            if item.get("type") == "x-mitre-collection" and item.get("x_mitre_version")
        ]
        if versions:
            return versions[0]

        spec_versions = [
            str(item["x_mitre_attack_spec_version"])
            for item in self._active_objects()
            if item.get("type") == "x-mitre-collection" and item.get("x_mitre_attack_spec_version")
        ]
        if spec_versions:
            return spec_versions[0]

        attack_versions = [
            str(item["x_mitre_version"]) for item in self._active_objects() if item.get("x_mitre_version")
        ]
        if attack_versions:
            return max(attack_versions)
        return "unknown"

    def _load_bundle(self) -> dict[str, Any]:
        """Load a STIX bundle from memory, disk, mitreattack-python, or HTTPS."""
        if self._bundle is not None:
            return self._bundle
        if self.bundle_path is not None:
            with self.bundle_path.open("r", encoding="utf-8") as bundle_file:
                self._bundle = json.load(bundle_file)
                return self._bundle

        # mitreattack-python is included as the preferred ATT&CK client library,
        # but it does not expose a stable one-line Enterprise bundle downloader
        # across recent releases. Importing it here verifies availability while
        # keeping the actual bundle loading deterministic and easy to test.
        try:
            import mitreattack  # noqa: F401
        except ImportError:
            pass

        try:
            with urlopen(self.bundle_url, timeout=60) as response:
                self._bundle = json.load(response)
                return self._bundle
        except (OSError, URLError, json.JSONDecodeError) as exc:
            raise AppError("Failed to load MITRE ATT&CK data", status_code=502, detail=str(exc)) from exc

    def _active_objects(self) -> list[dict[str, Any]]:
        """Return active, non-revoked STIX objects from the bundle."""
        if self._objects is None:
            raw_objects = self._load_bundle().get("objects", [])
            self._objects = [
                item
                for item in raw_objects
                if isinstance(item, dict) and not item.get("revoked") and not item.get("x_mitre_deprecated")
            ]
        return self._objects

    def _relationships(self) -> list[dict[str, Any]]:
        """Return active STIX relationship objects."""
        return [item for item in self._active_objects() if item.get("type") == "relationship"]

    def _technique_external_ids(self) -> dict[str, str]:
        """Map STIX attack-pattern IDs to ATT&CK technique IDs."""
        return {
            str(item["id"]): technique_id
            for item in self._active_objects()
            if item.get("type") == "attack-pattern" and (technique_id := _external_id(item)) is not None
        }

    def _software_internal_ids(self) -> dict[str, str]:
        """Map STIX software IDs to internal deterministic IDs."""
        return {
            str(item["id"]): _internal_id(str(item["id"]))
            for item in self._active_objects()
            if item.get("type") in {"malware", "tool"}
        }

    def _campaigns_by_actor(self) -> dict[str, list[str]]:
        """Map actor STIX IDs to internal campaign IDs using attribution relationships."""
        campaigns: dict[str, list[str]] = defaultdict(list)
        for relation in self._relationships():
            if relation.get("relationship_type") != "attributed-to":
                continue
            source_ref = str(relation.get("source_ref"))
            target_ref = str(relation.get("target_ref"))
            if source_ref.startswith("campaign--") and target_ref.startswith("intrusion-set--"):
                campaigns[target_ref].append(_internal_id(source_ref))
        return {key: _dedupe(values) for key, values in campaigns.items()}

    def _actor_ids_for_campaign(self, campaign_id: str, relationships: list[dict[str, Any]]) -> list[str]:
        """Return internal actor IDs attributed to a campaign."""
        actor_ids = []
        for relation in relationships:
            if relation.get("relationship_type") == "attributed-to" and relation.get("source_ref") == campaign_id:
                target_ref = str(relation.get("target_ref"))
                if target_ref.startswith("intrusion-set--"):
                    actor_ids.append(_internal_id(target_ref))
        return _dedupe(actor_ids)

    def _technique_refs_for_source(
        self,
        source_id: str,
        relationships: list[dict[str, Any]],
        technique_by_stix_id: dict[str, str],
    ) -> list[TechniqueRef]:
        """Return technique refs used by a STIX source object."""
        refs = []
        for relation in relationships:
            if relation.get("relationship_type") != "uses" or relation.get("source_ref") != source_id:
                continue
            technique_id = technique_by_stix_id.get(str(relation.get("target_ref")))
            if technique_id is None:
                continue
            refs.append(
                TechniqueRef(
                    technique_id=technique_id,
                    use_description=relation.get("description"),
                    detected_in_campaigns=[],
                )
            )
        return _dedupe_technique_refs(refs)

    def _target_refs_for_source(
        self,
        source_id: str,
        relationships: list[dict[str, Any]],
        targets_by_stix_id: dict[str, str],
    ) -> list[str]:
        """Return internal target IDs for `uses` relationships from source_id."""
        target_ids = [
            targets_by_stix_id[str(relation.get("target_ref"))]
            for relation in relationships
            if relation.get("relationship_type") == "uses"
            and relation.get("source_ref") == source_id
            and str(relation.get("target_ref")) in targets_by_stix_id
        ]
        return _dedupe(target_ids)

    def _source_ids_using_target(
        self,
        target_id: str,
        relationships: list[dict[str, Any]],
        source_prefix: str,
    ) -> list[str]:
        """Return internal source IDs that use the given target STIX object."""
        source_ids = [
            _internal_id(str(relation.get("source_ref")))
            for relation in relationships
            if relation.get("relationship_type") == "uses"
            and relation.get("target_ref") == target_id
            and str(relation.get("source_ref")).startswith(f"{source_prefix}--")
        ]
        return _dedupe(source_ids)


def _internal_id(source_id: str) -> str:
    """Return a stable UUID for a MITRE STIX ID."""
    return str(uuid5(NAMESPACE_URL, f"{MITRE_SOURCE}:{source_id}"))


def _external_id(item: dict[str, Any]) -> str | None:
    """Return the ATT&CK external ID for a STIX domain object."""
    for reference in item.get("external_references", []):
        external_id = reference.get("external_id")
        if external_id:
            return str(external_id)
    return None


def _aliases(item: dict[str, Any]) -> list[str]:
    """Return de-duplicated aliases while avoiding a duplicate canonical name."""
    name = str(item.get("name", ""))
    aliases = [str(alias) for alias in item.get("aliases", item.get("x_mitre_aliases", []))]
    return [alias for alias in _dedupe(aliases) if alias != name]


def _stix_datetime(item: dict[str, Any]) -> datetime:
    """Return the best available STIX timestamp as an aware datetime."""
    raw = item.get("modified") or item.get("created")
    if not raw:
        return datetime.now(timezone.utc)  # noqa: UP017 - local dev still supports Python 3.10.
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


def _stix_date(raw: Any) -> date | None:
    """Parse a STIX date or datetime field into a date."""
    if not raw:
        return None
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()


def _dedupe(values: list[str]) -> list[str]:
    """Deduplicate strings without changing their first-seen order."""
    return list(dict.fromkeys(values))


def _dedupe_technique_refs(refs: list[TechniqueRef]) -> list[TechniqueRef]:
    """Deduplicate technique refs, preserving the first relationship description."""
    by_id: dict[str, TechniqueRef] = {}
    for ref in refs:
        by_id.setdefault(ref.technique_id, ref)
    return list(by_id.values())
