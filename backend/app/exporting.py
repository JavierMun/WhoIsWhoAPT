"""Format already-computed comparison results for export."""

from __future__ import annotations

import csv
import json
from io import StringIO

from app.models.schemas import ComparisonExportRequest, ComparisonResult


def comparison_export_json(payload: ComparisonExportRequest) -> str:
    """Return a pretty JSON export with metadata and comparison results."""
    return payload.model_dump_json(indent=2)


def comparison_export_csv(payload: ComparisonExportRequest) -> str:
    """Return comparison results as CSV with metadata repeated per row."""
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "source",
            "metric",
            "generated_at",
            "input_id",
            "input_name",
            "input_type",
            "top_n",
            "rank",
            "matched_entity_id",
            "matched_entity_name",
            "matched_entity_source",
            "score",
            "technique_score",
            "software_score",
            "shared_techniques",
            "shared_software",
        ],
        lineterminator="\n",
    )
    writer.writeheader()

    metadata = payload.metadata
    for rank, result in enumerate(payload.comparison.results, start=1):
        writer.writerow(
            {
                "source": metadata.source,
                "metric": metadata.metric,
                "generated_at": metadata.generated_at.isoformat(),
                "input_id": metadata.input_id or "",
                "input_name": metadata.input_name,
                "input_type": metadata.input_type,
                "top_n": metadata.top_n if metadata.top_n is not None else "",
                "rank": rank,
                "matched_entity_id": result.matched_entity_id,
                "matched_entity_name": result.matched_entity_name,
                "matched_entity_source": result.matched_entity_source,
                "score": _score(result.score),
                "technique_score": _score(result.technique_score),
                "software_score": _score(result.software_score),
                "shared_techniques": ";".join(result.shared_techniques),
                "shared_software": ";".join(item.name for item in result.shared_software),
            }
        )

    return output.getvalue()


def comparison_export_navigator(payload: ComparisonExportRequest) -> str:
    """Return an ATT&CK Navigator layer containing shared techniques."""
    metadata = payload.metadata
    techniques = _navigator_techniques(payload.comparison.results)
    layer = {
        "version": "4.5",
        "name": f"{metadata.input_name} shared techniques",
        "domain": "enterprise-attack",
        "description": (
            f"Shared techniques exported from WhoIsWhoAPT comparison. "
            f"Source: {metadata.source}. Metric: {metadata.metric}."
        ),
        "filters": {"platforms": ["Windows", "macOS", "Linux"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": False, "showName": True},
        "hideDisabled": False,
        "metadata": [
            {"name": "source", "value": str(metadata.source)},
            {"name": "metric", "value": str(metadata.metric)},
            {"name": "generated_at", "value": metadata.generated_at.isoformat()},
            {"name": "input_name", "value": metadata.input_name},
            {"name": "input_type", "value": metadata.input_type},
            {"name": "top_n", "value": "" if metadata.top_n is None else str(metadata.top_n)},
        ],
        "techniques": techniques,
    }
    return json.dumps(layer, indent=2)


def _navigator_techniques(results: list[ComparisonResult]) -> list[dict[str, object]]:
    """Collect shared techniques from exported results for Navigator."""
    matched_names_by_technique: dict[str, list[str]] = {}
    for result in results:
        for technique_id in result.shared_techniques:
            matched_names_by_technique.setdefault(technique_id, []).append(result.matched_entity_name)

    return [
        {
            "techniqueID": technique_id,
            "score": min(100, len(matched_names)),
            "enabled": True,
            "comment": f"Shared with: {', '.join(sorted(matched_names))}",
        }
        for technique_id, matched_names in sorted(matched_names_by_technique.items())
    ]


def _score(value: float) -> str:
    """Format normalized scores for stable CSV output."""
    return f"{value:.6f}"
