"""Persisted comparison analysis endpoints."""

import json
from datetime import datetime, timezone
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.errors import AppError
from app.models import entities
from app.models.schemas import AnalysisCreateRequest, AnalysisDetail, AnalysisResponse

router = APIRouter()


@router.post("/save", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
def save_analysis(
    request: AnalysisCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> AnalysisResponse:
    """Persist a completed analysis without recomputing results."""
    analysis = entities.Analysis(
        input_type=request.input_type,
        input_id=request.input_id,
        input_name=request.input_name,
        metric=request.metric,
        tactics=request.tactics,
        target_ids=request.target_ids,
        filter_sectors=request.filter_sectors or None,
        filter_countries=request.filter_countries or None,
        top_n=request.top_n,
        results_json=json.dumps(request.results, separators=(",", ":"), ensure_ascii=False),
        created_at=datetime.now(timezone.utc),
    )
    session.add(analysis)
    session.commit()
    session.refresh(analysis)
    return _analysis_response(analysis)


@router.get("", response_model=list[AnalysisResponse])
def list_analyses(session: Annotated[Session, Depends(get_db_session)]) -> list[AnalysisResponse]:
    """Return saved analysis summaries newest first."""
    rows = session.scalars(select(entities.Analysis).order_by(entities.Analysis.created_at.desc())).all()
    return [_analysis_response(row) for row in rows]


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(
    analysis_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> AnalysisDetail:
    """Return one saved analysis with its stored result payload."""
    analysis = session.get(entities.Analysis, analysis_id)
    if analysis is None:
        raise AppError("Analysis not found", status_code=404)
    return _analysis_detail(analysis)


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> None:
    """Delete a saved analysis."""
    analysis = session.get(entities.Analysis, analysis_id)
    if analysis is None:
        raise AppError("Analysis not found", status_code=404)

    session.delete(analysis)
    session.commit()
    return None


def _analysis_response(analysis: entities.Analysis) -> AnalysisResponse:
    """Convert an analysis row to its summary schema."""
    return AnalysisResponse(
        id=analysis.id,
        input_type=cast(Any, analysis.input_type),
        input_id=analysis.input_id,
        input_name=analysis.input_name,
        metric=analysis.metric,
        tactics=analysis.tactics,
        target_ids=analysis.target_ids,
        filter_sectors=analysis.filter_sectors,
        filter_countries=analysis.filter_countries,
        top_n=analysis.top_n,
        created_at=_utc_datetime(analysis.created_at),
    )


def _analysis_detail(analysis: entities.Analysis) -> AnalysisDetail:
    """Convert an analysis row to its full detail schema."""
    try:
        results = json.loads(analysis.results_json)
    except json.JSONDecodeError as exc:
        raise AppError("Saved analysis results are invalid", status_code=500) from exc

    return AnalysisDetail(
        **_analysis_response(analysis).model_dump(),
        results=results,
    )


def _utc_datetime(value: datetime) -> datetime:
    """Return stored datetimes as timezone-aware UTC values."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
