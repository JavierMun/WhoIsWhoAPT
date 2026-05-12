"""SQLAlchemy entities for the normalized local data model."""

from datetime import date, datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import Date, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.database import Base


def new_id() -> str:
    """Generate an internal entity identifier."""
    return str(uuid4())


class EntityMixin:
    """Shared columns for source-backed entities."""

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Actor(EntityMixin, Base):
    """APT group or threat actor."""

    __tablename__ = "actors"

    techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    campaigns: Mapped[list[str]] = mapped_column(JSON, default=list)
    software_used: Mapped[list[str]] = mapped_column(JSON, default=list)
    cves_exploited: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_sectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_countries: Mapped[list[str]] = mapped_column(JSON, default=list)
    motivation: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Campaign(EntityMixin, Base):
    """Named operation attributed to one or more actors."""

    __tablename__ = "campaigns"

    actor_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    software_used: Mapped[list[str]] = mapped_column(JSON, default=list)
    cves_exploited: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_sectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_countries: Mapped[list[str]] = mapped_column(JSON, default=list)
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)


class Software(EntityMixin, Base):
    """Malware or tool."""

    __tablename__ = "software"

    software_type: Mapped[str] = mapped_column(String(32))
    techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    actor_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    campaign_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class Technique(Base):
    """ATT&CK technique or sub-technique."""

    __tablename__ = "techniques"

    technique_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    tactic: Mapped[str] = mapped_column(String(128), index=True)
    is_subtechnique: Mapped[bool] = mapped_column(default=False)
    parent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class CVE(Base):
    """Common Vulnerabilities and Exposures record."""

    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    exploited_by: Mapped[list[str]] = mapped_column(JSON, default=list)


class SourceLoadStatus(Base):
    """Status and summary counts for a primary source ingestion run."""

    __tablename__ = "source_load_status"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="never_loaded")
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_loaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_count: Mapped[int] = mapped_column(Integer, default=0)
    campaign_count: Mapped[int] = mapped_column(Integer, default=0)
    software_count: Mapped[int] = mapped_column(Integer, default=0)
    technique_count: Mapped[int] = mapped_column(Integer, default=0)


class CustomTTPSet(Base):
    """Saved user-defined TTP set for actor comparisons."""

    __tablename__ = "custom_ttp_sets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_sectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_countries: Mapped[list[str]] = mapped_column(JSON, default=list)
    cves_exploited: Mapped[list[str]] = mapped_column(JSON, default=list)
    motivation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class Analysis(Base):
    """Persisted comparison analysis snapshot."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    input_type: Mapped[str] = mapped_column(String(32), index=True)
    input_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    input_name: Mapped[str] = mapped_column(String(255), index=True)
    metric: Mapped[str] = mapped_column(String(64), index=True)
    tactics: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    target_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    filter_sectors: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    filter_countries: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    top_n: Mapped[int] = mapped_column(Integer)
    results_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
