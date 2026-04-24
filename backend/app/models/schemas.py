"""Pydantic schemas for API and normalized domain data."""

from datetime import date, datetime
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, Field

SourceName = Literal["mitre", "opencti", "navigator"]
PrimarySourceName = Literal["mitre", "opencti"]


class TechniqueRef(BaseModel):
    """Reference to a technique used by an entity."""

    technique_id: str
    use_description: str | None = None
    detected_in_campaigns: list[str] = Field(default_factory=list)


class BaseEntity(BaseModel):
    """Common normalized entity fields."""

    id: str
    source_id: str
    source: SourceName
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str | None = None
    last_updated: datetime


class Actor(BaseEntity):
    """APT group or threat actor."""

    techniques: list[TechniqueRef] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    software_used: list[str] = Field(default_factory=list)
    cves_exploited: list[str] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    motivation: str | None = None


class Campaign(BaseEntity):
    """Named operation attributed to one or more actors."""

    actor_ids: list[str] = Field(default_factory=list)
    techniques: list[TechniqueRef] = Field(default_factory=list)
    software_used: list[str] = Field(default_factory=list)
    cves_exploited: list[str] = Field(default_factory=list)
    start_date: date | None = None
    end_date: date | None = None


class Software(BaseEntity):
    """Malware or tool."""

    software_type: Literal["malware", "tool"]
    techniques: list[TechniqueRef] = Field(default_factory=list)
    actor_ids: list[str] = Field(default_factory=list)
    campaign_ids: list[str] = Field(default_factory=list)


class Technique(BaseModel):
    """ATT&CK technique or sub-technique."""

    technique_id: str
    name: str
    tactic: str
    is_subtechnique: bool = False
    parent_id: str | None = None


class CVE(BaseModel):
    """Common Vulnerabilities and Exposures record."""

    id: str
    cvss_score: float | None = None
    affected_products: list[str] = Field(default_factory=list)
    exploited_by: list[str] = Field(default_factory=list)


class MitreSettings(BaseModel):
    """Settings for the MITRE ATT&CK source."""

    auto_update: bool = True
    update_frequency_hours: int = Field(default=168, ge=1)


class OpenCTISettings(BaseModel):
    """Settings for the OpenCTI source."""

    url: AnyHttpUrl | None = None
    api_token: str | None = None
    auto_update: bool = True
    update_frequency_hours: int = Field(default=24, ge=1)


class UISettings(BaseModel):
    """Frontend behavior settings."""

    default_top_n: int = Field(default=10, ge=1, le=100)
    default_similarity_metric: str = "jaccard_weighted"


class ApplicationSettings(BaseModel):
    """User-editable application settings."""

    active_source: PrimarySourceName = "mitre"
    mitre: MitreSettings = Field(default_factory=MitreSettings)
    opencti: OpenCTISettings = Field(default_factory=OpenCTISettings)
    ui: UISettings = Field(default_factory=UISettings)


class SourceLoadStatus(BaseModel):
    """Status and summary counts for source ingestion."""

    source: PrimarySourceName
    status: str
    version: str | None = None
    last_loaded_at: datetime | None = None
    error: str | None = None
    actor_count: int = 0
    campaign_count: int = 0
    software_count: int = 0
    technique_count: int = 0
