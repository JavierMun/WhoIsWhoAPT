"""Export formatting tests for comparison results."""

import csv
import json
from datetime import datetime, timezone
from io import StringIO

from fastapi.testclient import TestClient

from app.exporting import comparison_export_csv, comparison_export_json, comparison_export_navigator
from app.main import create_app
from app.models.schemas import (
    ComparisonExportRequest,
    ComparisonResponse,
    ComparisonResult,
    ExportMetadata,
    SoftwareSummary,
)


def test_comparison_export_json_includes_metadata_and_results() -> None:
    """JSON export should preserve metadata and full comparison payload."""
    exported = json.loads(comparison_export_json(_export_payload()))

    assert exported["metadata"]["source"] == "mitre"
    assert exported["metadata"]["metric"] == "jaccard"
    assert exported["comparison"]["input_name"] == "Alpha"
    assert exported["comparison"]["results"][0]["shared_techniques"] == ["T1001", "T1002"]


def test_comparison_export_csv_flattens_rows_with_metadata() -> None:
    """CSV export should be valid tabular output with metadata columns."""
    rows = list(csv.DictReader(StringIO(comparison_export_csv(_export_payload()))))

    assert rows[0]["source"] == "mitre"
    assert rows[0]["metric"] == "jaccard"
    assert rows[0]["top_n"] == "10"
    assert rows[0]["rank"] == "1"
    assert rows[0]["matched_entity_name"] == "Beta"
    assert rows[0]["score"] == "0.500000"
    assert rows[0]["shared_techniques"] == "T1001;T1002"
    assert rows[0]["shared_software"] == "SharedTool"


def test_comparison_export_navigator_contains_unique_shared_techniques() -> None:
    """Navigator export should include shared techniques from comparison results."""
    layer = json.loads(comparison_export_navigator(_export_payload()))

    assert layer["domain"] == "enterprise-attack"
    assert layer["metadata"][0] == {"name": "source", "value": "mitre"}
    assert [item["techniqueID"] for item in layer["techniques"]] == ["T1001", "T1002"]
    assert layer["techniques"][0]["comment"] == "Shared with: Beta"


def test_export_endpoints_return_downloadable_content() -> None:
    """Export endpoints should format posted results without recomputation."""
    client = TestClient(create_app())

    response = client.post("/api/export/csv", json=json.loads(_export_payload().model_dump_json()))

    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="whoiswhoapt-comparison.csv"'
    assert "matched_entity_name" in response.text


def _export_payload() -> ComparisonExportRequest:
    """Build a compact export payload fixture."""
    generated_at = datetime(2026, 4, 24, 10, 0, tzinfo=timezone.utc)  # noqa: UP017 - local dev supports 3.10.
    return ComparisonExportRequest(
        metadata=ExportMetadata(
            source="mitre",
            metric="jaccard",
            generated_at=generated_at,
            input_id="actor-a",
            input_name="Alpha",
            input_type="actor",
            top_n=10,
        ),
        comparison=ComparisonResponse(
            input_id="actor-a",
            input_name="Alpha",
            input_type="actor",
            metric="jaccard",
            results=[
                ComparisonResult(
                    matched_entity_id="actor-b",
                    matched_entity_name="Beta",
                    matched_entity_source="mitre",
                    score=0.5,
                    technique_score=0.5,
                    software_score=1.0,
                    shared_techniques=["T1001", "T1002"],
                    unique_to_input=["T1003"],
                    unique_to_matched_entity=["T1004"],
                    shared_software=[
                        SoftwareSummary(id="software-a", name="SharedTool", software_type="tool"),
                    ],
                )
            ],
        ),
    )
