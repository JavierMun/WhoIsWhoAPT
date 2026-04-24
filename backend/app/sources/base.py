"""Abstract interface for primary actor data sources."""

from abc import ABC, abstractmethod

from app.models.schemas import Actor, Campaign, Software, Technique


class BaseSource(ABC):
    """Contract implemented by normalized data source adapters."""

    @abstractmethod
    def fetch_actors(self) -> list[Actor]:
        """Fetch and normalize threat actors."""
        raise NotImplementedError

    @abstractmethod
    def fetch_campaigns(self) -> list[Campaign]:
        """Fetch and normalize campaigns."""
        raise NotImplementedError

    @abstractmethod
    def fetch_software(self) -> list[Software]:
        """Fetch and normalize software."""
        raise NotImplementedError

    @abstractmethod
    def fetch_techniques(self) -> list[Technique]:
        """Fetch and normalize techniques."""
        raise NotImplementedError

    @abstractmethod
    def get_source_version(self) -> str:
        """Return a source version string used for change detection."""
        raise NotImplementedError
