# AlphaX Multi-Agent Backend

The backend separates the investigation into four independent agents:

1. **OSINT Agent** — passive/public collection and provenance.
2. **Vulnerability + CTI Agent** — public CVE, advisory and threat-intelligence correlation.
3. **Risk Agent** — evidence-backed aggregation and confidence handling.
4. **Validation Agent** — skipped by default; reserved for non-destructive checks in explicitly authorized labs/sandboxes.

## Run

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Windows PowerShell activation:

```powershell
.venv\Scripts\Activate.ps1
```

API: `POST /api/investigate`

The current agents are safe orchestration stubs. Connect approved public intelligence providers next; preserve source URLs, timestamps, evidence classification and confidence for every finding.
