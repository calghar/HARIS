"""Business impact data model."""

from pydantic import BaseModel, ConfigDict


class BusinessImpact(BaseModel):
    """Plain-language explanation of a finding's business impact."""

    model_config = ConfigDict(frozen=True)

    headline: str
    explanation: str
    who_is_affected: str
    worst_case: str
