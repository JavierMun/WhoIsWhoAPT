"""Export endpoints for already-computed comparison results."""

from fastapi import APIRouter
from fastapi.responses import Response

from app.exporting import comparison_export_csv, comparison_export_json, comparison_export_navigator
from app.models.schemas import ComparisonExportRequest

router = APIRouter()


@router.post("/json")
def export_json(payload: ComparisonExportRequest) -> Response:
    """Export comparison results as JSON without recomputing them."""
    return _download_response(
        comparison_export_json(payload),
        media_type="application/json",
        filename="whoiswhoapt-comparison.json",
    )


@router.post("/csv")
def export_csv(payload: ComparisonExportRequest) -> Response:
    """Export comparison results as CSV without recomputing them."""
    return _download_response(
        comparison_export_csv(payload),
        media_type="text/csv",
        filename="whoiswhoapt-comparison.csv",
    )


@router.post("/navigator")
def export_navigator(payload: ComparisonExportRequest) -> Response:
    """Export shared techniques as an ATT&CK Navigator layer."""
    return _download_response(
        comparison_export_navigator(payload),
        media_type="application/json",
        filename="whoiswhoapt-shared-techniques-navigator.json",
    )


def _download_response(content: str, media_type: str, filename: str) -> Response:
    """Return a downloadable response for browser and API clients."""
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
