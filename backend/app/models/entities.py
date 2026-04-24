"""SQLAlchemy entities for the normalized local data model."""

from datetime import date, datetime
from uuid import uuid4

from sqlalchemy import Date, DateTime, Float, String, Text, func
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

    techniques: Mapped[list[dict]] = mapped_column(JSON, default=list)
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
    techniques: Mapped[list[dict]] = mapped_column(JSON, default=list)
    software_used: Mapped[list[str]] = mapped_column(JSON, default=list)
    cves_exploited: Mapped[list[str]] = mapped_column(JSON, default=list)
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)


class Software(EntityMixin, Base):
    """Malware or tool."""

    __tablename__ = "software"

    software_type: Mapped[str] = mapped_column(String(32))
    techniques: Mapped[list[dict]] = mapped_column(JSON, default=list)
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

