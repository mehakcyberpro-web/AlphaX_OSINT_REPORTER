from fastapi import FastAPI
from .schemas import InvestigationRequest, InvestigationResponse
from .agents import osint_agent, vulnerability_agent, risk_agent, validation_agent
from .agent_api import router as agent_router

app = FastAPI(title='ALPHAX OSINT REPORTER API', version='0.2.0')
app.include_router(agent_router)

@app.get('/health')
def health():
    return {'status': 'online', 'mode': 'public/passive intelligence'}

@app.post('/api/investigate', response_model=InvestigationResponse)
def investigate(req: InvestigationRequest):
    a1 = osint_agent(req.target)
    a2 = vulnerability_agent(req.target, a1)
    a3 = risk_agent(a1, a2)
    a4 = validation_agent(req.target, req.authorized_lab)
    return InvestigationResponse(
        target=req.target,
        agents=[a1, a2, a3, a4],
        risk={'severity': 'INFORMATIONAL', 'score': None, 'reason': 'No confirmed evidence-backed vulnerability score yet'},
        safety_note='Agent 4 is skipped unless an explicitly authorized lab scope is supplied. No exploitation is performed.'
    )
