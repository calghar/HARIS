"""OWASP mapping data model."""

from pydantic import BaseModel, ConfigDict

from .enums import OwaspCategory


class OwaspMapping(BaseModel):
    """Maps a CWE or vulnerability keyword to an OWASP 2025 category."""

    model_config = ConfigDict(frozen=True)

    category: OwaspCategory
    description: str
    typical_cwes: tuple[str, ...]
