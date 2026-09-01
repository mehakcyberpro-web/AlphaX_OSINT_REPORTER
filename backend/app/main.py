from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .schemas import InvestigationRequest, InvestigationResponse
from .agents import osint_agent, vulnerability_agent, risk_agent, validation_agent
from .agent_api import router as agent_router

app = FastAPI(title='ALPHAX OSINT REPORTER API', version='0.3.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])
app.include_router(agent_router)

@app.get('/health')
def health():
    return {'status': 'online', 'mode': 'public/passive intelligence', 'agents': 4}

@app.post('/api/investigate', response_model=InvestigationResponse)
def investigate(req: InvestigationRequest):
    a1 = osint_agent(req.target)
    a2 = vulnerability_agent(req.target, a1)
    a3 = risk_agent(a1, a2)
    a4 = validation_agent(req.target, req.authorized_lab)
    risk_finding = next((x for x in a3.findings if x.get('type') == 'risk_assessment'), {})
    return InvestigationResponse(
        target=req.target,
        agents=[a1, a2, a3, a4],
        risk={'severity': risk_finding.get('severity', 'INFORMATIONAL'), 'score': risk_finding.get('exposure_score'), 'reason': risk_finding.get('reason', 'Evidence-weighted assessment')},
        safety_note='Agent 4 is guarded and performs no exploitation of public targets. Validation requires an explicitly authorized lab scope.'
    )
