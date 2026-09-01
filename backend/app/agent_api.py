from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any
from .agents import osint_agent, vulnerability_agent, risk_agent, validation_agent
from .schemas import AgentResult

router = APIRouter(prefix='/api/agents', tags=['independent agents'])

class TargetInput(BaseModel):
    target: str = Field(min_length=1, max_length=253)

class VulnerabilityInput(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    osint_findings: list[dict[str, Any]] = []
    osint_sources: list[str] = []

class RiskInput(BaseModel):
    osint: dict[str, Any] = {}
    vulnerability: dict[str, Any] = {}

class ValidationInput(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    authorized_lab: bool = False
    lab_scope: str | None = None

@router.post('/1/osint', response_model=AgentResult)
def run_agent_1(req: TargetInput):
    return osint_agent(req.target)

@router.post('/2/vulnerability', response_model=AgentResult)
def run_agent_2(req: VulnerabilityInput):
    osint = AgentResult(agent='OSINT', status='completed', confidence='UNVERIFIED', findings=req.osint_findings, sources=req.osint_sources)
    return vulnerability_agent(req.target, osint)

@router.post('/3/risk', response_model=AgentResult)
def run_agent_3(req: RiskInput):
    try:
        osint = AgentResult(**req.osint)
        vuln = AgentResult(**req.vulnerability)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Provide valid Agent 1 and Agent 2 results: {exc}')
    return risk_agent(osint, vuln)

@router.post('/4/validation', response_model=AgentResult)
def run_agent_4(req: ValidationInput):
    if not req.authorized_lab:
        return validation_agent(req.target, False)
    if not req.lab_scope or len(req.lab_scope.strip()) < 10:
        raise HTTPException(status_code=400, detail='Explicit authorized lab scope is required.')
    return validation_agent(req.target, True)

@router.get('/status')
def agent_status():
    return {'agents': [
        {'id': 1, 'name': 'OSINT', 'mode': 'independent', 'status': 'ready'},
        {'id': 2, 'name': 'Vulnerability + CTI', 'mode': 'independent', 'status': 'ready'},
        {'id': 3, 'name': 'Risk', 'mode': 'independent', 'status': 'ready'},
        {'id': 4, 'name': 'Validation', 'mode': 'independent', 'status': 'guarded'}
    ]}
