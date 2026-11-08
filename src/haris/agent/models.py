from typing import Literal

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    tool: str = ""
    arguments: dict[str, str] = Field(default_factory=dict)
    claim: str = ""
    done: bool = False


class PoCRequest(BaseModel):
    method: str = "GET"
    url: str
    body: str = ""


class PoC(BaseModel):
    requests: list[PoCRequest] = Field(default_factory=list)
    oracle: str = ""
    expected_span: str = ""


class JobResult(BaseModel):
    job_id: str
    status: Literal["completed", "aborted"] = "completed"
    annotation: str = ""
    poc: PoC | None = None


class ProxyEvent(BaseModel):
    method: str
    url: str
    outcome: Literal["forwards", "rejects"]
    reason: str = ""
    status: int = 0
    body: str = ""


class Review(BaseModel):
    notes: str = ""
    agrees: bool = False
