"""OpenCTI source adapter using pycti.

Normalizes OpenCTI entities (Intrusion-Set, Campaign, Malware, Tool,
Attack-Pattern) into the application's internal source models.

Requires an OpenCTI instance with the MITRE ATT&CK dataset imported so
that Attack-Pattern objects carry an x_mitre_id field (e.g. "T1059.001").
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pycti import OpenCTIApiClient

from app.errors import AppError
from app.models.schemas import Actor, Campaign, Software, Technique, TechniqueRef
from app.sources.base import BaseSource

OPENCTI_SOURCE = "opencti"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _internal_id(opencti_id: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"opencti:{opencti_id}"))


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except (ValueError, AttributeError):
        return None


def _tactic_from_item(item: dict[str, Any]) -> str:
    """Extract tactic(s) from kill_chain_phases / killChainPhases.

    Returns lowercase, sorted, deduplicated tactics joined by ", " — matching
    the format produced by MitreSource so tactic filtering works across sources.

    Matches both "mitre-attack" and "mitre-attack-v<N>" kill chain names so
    versioned chains (pycti 6.x enriches objects with both) don't produce
    duplicate entries after dedup.
    """
    phases = item.get("killChainPhases") or item.get("kill_chain_phases") or []
    tactics = sorted({
        p["phase_name"].strip().lower()
        for p in phases
        if isinstance(p, dict)
        and (p.get("kill_chain_name") or "").startswith("mitre-attack")
        and p.get("phase_name")
    })
    return ", ".join(tactics) if tactics else "unknown"


def _aliases(item: dict[str, Any]) -> list[str]:
    return item.get("aliases") or item.get("x_opencti_aliases") or []


# ---------------------------------------------------------------------------
# Relationship helpers
# ---------------------------------------------------------------------------


def _uses_rels(
    client: OpenCTIApiClient,
    from_types: list[str],
    to_types: list[str],
) -> list[dict[str, Any]]:
    """Fetch 'uses' relationships between the given entity types."""
    try:
        result = client.stix_core_relationship.list(
            relationship_type="uses",
            fromTypes=from_types,
            toTypes=to_types,
            getAll=True,
        )
        return result or []
    except Exception:
        return []


def _attributed_to_rels(client: OpenCTIApiClient) -> list[dict[str, Any]]:
    """Fetch 'attributed-to' relationships (Campaign → Intrusion-Set)."""
    try:
        result = client.stix_core_relationship.list(
            relationship_type="attributed-to",
            fromTypes=["Campaign"],
            toTypes=["Intrusion-Set"],
            getAll=True,
        )
        return result or []
    except Exception:
        return []


def _targets_rels(client: OpenCTIApiClient) -> list[dict[str, Any]]:
    """Fetch all 'targets' relationships from Intrusion-Set to any entity.

    Returns a flat list; callers filter by `to.entity_type` to distinguish
    countries (Country), sectors (Sector), and vulnerabilities (Vulnerability).
    """
    try:
        result = client.stix_core_relationship.list(
            relationship_type="targets",
            fromTypes=["Intrusion-Set"],
            getAll=True,
        )
        return result or []
    except Exception:
        return []


def _build_ap_mitre_map(ap_list: list[dict[str, Any]]) -> dict[str, str]:
    """Map OpenCTI attack-pattern ID → ATT&CK technique ID (T-numbers only)."""
    return {
        item["id"]: item["x_mitre_id"]
        for item in ap_list
        if (item.get("x_mitre_id") or "").startswith("T")
    }


def _build_technique_refs(
    rels: list[dict[str, Any]],
    ap_mitre_map: dict[str, str],
    from_id: str,
) -> list[TechniqueRef]:
    """Return TechniqueRef list for a given entity ID from pre-fetched rels."""
    refs: list[TechniqueRef] = []
    for rel in rels:
        if (rel.get("from") or {}).get("id") != from_id:
            continue
        to_id = (rel.get("to") or {}).get("id", "")
        mitre_id = ap_mitre_map.get(to_id)
        if mitre_id:
            refs.append(
                TechniqueRef(
                    technique_id=mitre_id,
                    use_description=rel.get("description"),
                )
            )
    return refs


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class OpenCTIAdapter(BaseSource):
    """Normalize OpenCTI entities into internal source models via pycti."""

    def __init__(self, url: str, api_token: str) -> None:
        self._url = url
        self._api_token = api_token
        self._client: OpenCTIApiClient | None = None

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    def _get_client(self) -> OpenCTIApiClient:
        if self._client is None:
            try:
                self._client = OpenCTIApiClient(
                    url=self._url,
                    token=self._api_token,
                    log_level="ERROR",
                    ssl_verify=True,
                )
            except Exception as exc:
                raise AppError(
                    f"Failed to initialise OpenCTI client: {exc}", status_code=400
                ) from exc
        return self._client

    # ------------------------------------------------------------------
    # BaseSource interface
    # ------------------------------------------------------------------

    def test_connection(self) -> None:
        """Verify OpenCTI is reachable and the API token is valid."""
        try:
            result = self._get_client().health_check()
            if not result:
                raise AppError("OpenCTI health check returned unhealthy", status_code=400)
        except AppError:
            raise
        except Exception as exc:
            raise AppError(f"OpenCTI connection failed: {exc}", status_code=400) from exc

    def get_source_version(self) -> str:
        try:
            result = self._get_client().query("{about{version}}")
            return str(result["data"]["about"]["version"])
        except Exception:
            return "unknown"

    # ------------------------------------------------------------------
    # Techniques
    # ------------------------------------------------------------------

    def fetch_techniques(self) -> list[Technique]:
        try:
            raw: list[dict[str, Any]] = self._get_client().attack_pattern.list(getAll=True) or []
        except Exception as exc:
            raise AppError(
                f"Failed to fetch attack patterns from OpenCTI: {exc}", status_code=500
            ) from exc

        techniques: list[Technique] = []
        for item in raw:
            mitre_id: str = (item.get("x_mitre_id") or "")
            if not mitre_id.startswith("T"):
                continue
            is_sub = "." in mitre_id
            techniques.append(
                Technique(
                    technique_id=mitre_id,
                    name=item.get("name", ""),
                    tactic=_tactic_from_item(item),
                    is_subtechnique=is_sub,
                    parent_id=mitre_id.rsplit(".", 1)[0] if is_sub else None,
                )
            )
        return techniques

    # ------------------------------------------------------------------
    # Actors
    # ------------------------------------------------------------------

    def fetch_actors(self) -> list[Actor]:
        client = self._get_client()

        # Attack-Pattern map (needed for technique resolution)
        try:
            ap_list: list[dict[str, Any]] = client.attack_pattern.list(getAll=True) or []
        except Exception as exc:
            raise AppError(
                f"Failed to fetch attack patterns from OpenCTI: {exc}", status_code=500
            ) from exc
        ap_mitre_map = _build_ap_mitre_map(ap_list)

        # Relationships used by actors
        actor_ap_rels = _uses_rels(client, ["Intrusion-Set"], ["Attack-Pattern"])
        actor_sw_rels = _uses_rels(client, ["Intrusion-Set"], ["Malware", "Tool"])
        attr_rels = _attributed_to_rels(client)
        target_rels = _targets_rels(client)

        # Build lookup: actor opencti-id → software internal ids
        actor_software: dict[str, list[str]] = {}
        for rel in actor_sw_rels:
            from_id = (rel.get("from") or {}).get("id", "")
            to_id = (rel.get("to") or {}).get("id", "")
            if from_id and to_id:
                actor_software.setdefault(from_id, []).append(_internal_id(to_id))

        # Build lookup: actor opencti-id → campaign internal ids
        campaigns_by_actor: dict[str, list[str]] = {}
        for rel in attr_rels:
            actor_id = (rel.get("to") or {}).get("id", "")
            campaign_id = (rel.get("from") or {}).get("id", "")
            if actor_id and campaign_id:
                campaigns_by_actor.setdefault(actor_id, []).append(_internal_id(campaign_id))

        # Build lookups from targets relationships: sectors, countries, CVEs
        actor_sectors: dict[str, list[str]] = {}
        actor_countries: dict[str, list[str]] = {}
        actor_cves: dict[str, list[str]] = {}
        for rel in target_rels:
            from_id = (rel.get("from") or {}).get("id", "")
            to_obj = rel.get("to") or {}
            to_type = to_obj.get("entity_type", "")
            to_name: str = to_obj.get("name", "")
            if not from_id or not to_name:
                continue
            if to_type == "Sector":
                actor_sectors.setdefault(from_id, [])
                if to_name not in actor_sectors[from_id]:
                    actor_sectors[from_id].append(to_name)
            elif to_type == "Country":
                actor_countries.setdefault(from_id, [])
                if to_name not in actor_countries[from_id]:
                    actor_countries[from_id].append(to_name)
            elif to_type == "Vulnerability":
                actor_cves.setdefault(from_id, [])
                if to_name not in actor_cves[from_id]:
                    actor_cves[from_id].append(to_name)

        try:
            raw: list[dict[str, Any]] = client.intrusion_set.list(getAll=True) or []
        except Exception as exc:
            raise AppError(
                f"Failed to fetch actors from OpenCTI: {exc}", status_code=500
            ) from exc

        actors: list[Actor] = []
        for item in raw:
            opencti_id: str = item.get("id", "")
            if not opencti_id:
                continue
            actors.append(
                Actor(
                    id=_internal_id(opencti_id),
                    source_id=opencti_id,
                    source=OPENCTI_SOURCE,
                    name=item.get("name", ""),
                    aliases=_aliases(item),
                    description=item.get("description"),
                    last_updated=_parse_datetime(
                        item.get("updated_at") or item.get("modified")
                    ),
                    techniques=_build_technique_refs(actor_ap_rels, ap_mitre_map, opencti_id),
                    campaigns=campaigns_by_actor.get(opencti_id, []),
                    software_used=actor_software.get(opencti_id, []),
                    cves_exploited=actor_cves.get(opencti_id, []),
                    target_sectors=actor_sectors.get(opencti_id, []),
                    target_countries=actor_countries.get(opencti_id, []),
                    motivation=item.get("primary_motivation"),
                )
            )
        return actors

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def fetch_campaigns(self) -> list[Campaign]:
        client = self._get_client()

        try:
            ap_list: list[dict[str, Any]] = client.attack_pattern.list(getAll=True) or []
        except Exception:
            ap_list = []
        ap_mitre_map = _build_ap_mitre_map(ap_list)

        campaign_ap_rels = _uses_rels(client, ["Campaign"], ["Attack-Pattern"])
        attr_rels = _attributed_to_rels(client)

        # campaign opencti-id → actor internal ids
        campaign_actors: dict[str, list[str]] = {}
        for rel in attr_rels:
            campaign_id = (rel.get("from") or {}).get("id", "")
            actor_id = (rel.get("to") or {}).get("id", "")
            if campaign_id and actor_id:
                campaign_actors.setdefault(campaign_id, []).append(_internal_id(actor_id))

        try:
            raw: list[dict[str, Any]] = client.campaign.list(getAll=True) or []
        except Exception as exc:
            raise AppError(
                f"Failed to fetch campaigns from OpenCTI: {exc}", status_code=500
            ) from exc

        campaigns: list[Campaign] = []
        for item in raw:
            opencti_id: str = item.get("id", "")
            if not opencti_id:
                continue
            campaigns.append(
                Campaign(
                    id=_internal_id(opencti_id),
                    source_id=opencti_id,
                    source=OPENCTI_SOURCE,
                    name=item.get("name", ""),
                    aliases=_aliases(item),
                    description=item.get("description"),
                    last_updated=_parse_datetime(
                        item.get("updated_at") or item.get("modified")
                    ),
                    actor_ids=campaign_actors.get(opencti_id, []),
                    techniques=_build_technique_refs(campaign_ap_rels, ap_mitre_map, opencti_id),
                    software_used=[],
                    cves_exploited=[],
                    start_date=_parse_date(item.get("first_seen")),
                    end_date=_parse_date(item.get("last_seen")),
                )
            )
        return campaigns

    # ------------------------------------------------------------------
    # Software
    # ------------------------------------------------------------------

    def fetch_software(self) -> list[Software]:
        client = self._get_client()

        try:
            ap_list: list[dict[str, Any]] = client.attack_pattern.list(getAll=True) or []
        except Exception:
            ap_list = []
        ap_mitre_map = _build_ap_mitre_map(ap_list)

        sw_ap_rels = _uses_rels(client, ["Malware", "Tool"], ["Attack-Pattern"])
        actor_sw_rels = _uses_rels(client, ["Intrusion-Set"], ["Malware", "Tool"])

        # software opencti-id → actor internal ids
        sw_actors: dict[str, list[str]] = {}
        for rel in actor_sw_rels:
            sw_id = (rel.get("to") or {}).get("id", "")
            actor_id = (rel.get("from") or {}).get("id", "")
            if sw_id and actor_id:
                sw_actors.setdefault(sw_id, []).append(_internal_id(actor_id))

        software_items: list[Software] = []

        def _normalize(items: list[dict[str, Any]], sw_type: str) -> None:
            for item in items:
                opencti_id: str = item.get("id", "")
                if not opencti_id:
                    continue
                software_items.append(
                    Software(
                        id=_internal_id(opencti_id),
                        source_id=opencti_id,
                        source=OPENCTI_SOURCE,
                        name=item.get("name", ""),
                        aliases=_aliases(item),
                        description=item.get("description"),
                        last_updated=_parse_datetime(
                            item.get("updated_at") or item.get("modified")
                        ),
                        software_type=sw_type,  # type: ignore[arg-type]
                        techniques=_build_technique_refs(sw_ap_rels, ap_mitre_map, opencti_id),
                        actor_ids=sw_actors.get(opencti_id, []),
                        campaign_ids=[],
                    )
                )

        try:
            _normalize(client.malware.list(getAll=True) or [], "malware")
        except Exception as exc:
            raise AppError(
                f"Failed to fetch malware from OpenCTI: {exc}", status_code=500
            ) from exc

        try:
            _normalize(client.tool.list(getAll=True) or [], "tool")
        except Exception as exc:
            raise AppError(
                f"Failed to fetch tools from OpenCTI: {exc}", status_code=500
            ) from exc

        return software_items

    # ------------------------------------------------------------------
    # Report ingestion (custom TTP set import)
    # ------------------------------------------------------------------

    def search_reports(self, query: str) -> list[dict[str, str | None]]:
        """Search OpenCTI reports by name. Returns up to 25 matches."""
        client = self._get_client()
        try:
            raw = client.report.list(search=query, first=25) or []
        except Exception as exc:
            raise AppError(
                f"Failed to search OpenCTI reports: {exc}", status_code=500
            ) from exc
        return [
            {
                "id": r.get("id", ""),
                "name": r.get("name", ""),
                "published": r.get("published"),
                "description": r.get("description"),
            }
            for r in raw
            if r.get("id")
        ]

    def fetch_report_technique_ids(self, report_id: str) -> tuple[str, list[str]]:
        """Return (report_name, deduplicated ATT&CK technique IDs) for a report.

        Tries two strategies:
        1. Read the report and extract x_mitre_id from embedded objects.
        2. Fall back to querying attack patterns by report membership filter.
        """
        client = self._get_client()
        try:
            report = client.report.read(id=report_id)
        except Exception as exc:
            raise AppError(f"Failed to fetch report: {exc}", status_code=500) from exc

        if not report:
            raise AppError(f"Report not found: {report_id}", status_code=404)

        report_name: str = report.get("name", "")
        technique_ids: list[str] = []

        # Strategy 1: embedded objects (available when pycti populates the objects field)
        for obj in report.get("objects", []) or []:
            if isinstance(obj, dict):
                mitre_id: str = obj.get("x_mitre_id", "")
                if mitre_id.startswith("T"):
                    technique_ids.append(mitre_id)

        # Strategy 2: filter attack-patterns by report membership
        if not technique_ids:
            try:
                aps = client.attack_pattern.list(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "containedBy", "values": [report_id]}],
                        "filterGroups": [],
                    },
                    getAll=True,
                ) or []
                technique_ids = [
                    ap.get("x_mitre_id", "")
                    for ap in aps
                    if ap.get("x_mitre_id", "").startswith("T")
                ]
            except Exception:
                pass  # return whatever we have

        # Deduplicate preserving first-seen order
        seen: set[str] = set()
        unique: list[str] = []
        for tid in technique_ids:
            if tid not in seen:
                seen.add(tid)
                unique.append(tid)

        return report_name, unique
