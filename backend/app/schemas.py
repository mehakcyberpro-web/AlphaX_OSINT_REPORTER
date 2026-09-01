from typing import Any, Literal
from pydantic import BaseModel, Field

TargetType = Literal['Domain', 'Organization', 'Username', 'Public Email']

class InvestigationRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: TargetType = 'Domain'
    authorized_lab: bool = False

class AgentResult(BaseModel):
    agent: str
    status: Literal['completed', 'skipped', 'needs_review']
    confidence: Literal['HIGH', 'MEDIUM', 'LOW', 'UNVERIFIED']
    findings: list[dict[str, Any]] = []
    sources: list[str] = []

class InvestigationResponse(BaseModel):
    target: str
    agents: list[AgentResult]
    risk: dict[str, Any]
    safety_note: str
