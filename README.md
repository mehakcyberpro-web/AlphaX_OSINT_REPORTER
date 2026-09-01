# ALPHAX OSINT REPORTER

AI-powered ethical OSINT, Cyber Threat Intelligence, risk assessment and authorized security-validation platform.

## Current prototype

- Animated web dashboard
- Agent 1 — Public OSINT intelligence
- Agent 2 — Vulnerability + CTI correlation
- Agent 3 — Risk/exposure dashboard
- Agent 4 — LAB/SIMULATION validation gate
- Linux-friendly architecture

## Run locally

```bash
cd frontend
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://127.0.0.1:8080`.

## Safety

AlphaX is designed for public/lawful intelligence. Do not use it to access private data, bypass controls, perform unauthorized scanning, exploit systems, deploy malware, or obtain stolen credentials. Agent 4 is intended for explicitly authorized labs/sandboxes and non-destructive validation.

## Roadmap

FastAPI backend → agent orchestration → PostgreSQL → public OSINT/CVE/CTI integrations → evidence graph → PDF reporting → authorized lab validation.
