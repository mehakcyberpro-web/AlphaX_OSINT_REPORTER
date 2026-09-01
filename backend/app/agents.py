from .schemas import AgentResult


def osint_agent(target: str) -> AgentResult:
    """Agent 1: passive/public OSINT collection placeholder.
    Real integrations should use lawful public sources and retain provenance.
    """
    return AgentResult(
        agent='OSINT', status='completed', confidence='UNVERIFIED',
        findings=[{'type': 'target', 'value': target, 'classification': 'FACT'}],
        sources=[]
    )


def vulnerability_agent(target: str, osint: AgentResult) -> AgentResult:
    """Agent 2: correlate public advisories/CVEs/CTI; never infer a CVE from a name alone."""
    return AgentResult(
        agent='VULNERABILITY_CTI', status='completed', confidence='UNVERIFIED',
        findings=[], sources=[]
    )


def risk_agent(osint: AgentResult, vuln: AgentResult) -> AgentResult:
    """Agent 3: evidence-based risk aggregation. No evidence means no confirmed vulnerability."""
    return AgentResult(
        agent='RISK', status='completed', confidence='UNVERIFIED',
        findings=[], sources=[]
    )


def validation_agent(target: str, authorized_lab: bool) -> AgentResult:
    """Agent 4: reserved for non-destructive validation in explicitly authorized labs."""
    if not authorized_lab:
        return AgentResult(
            agent='VALIDATION', status='skipped', confidence='UNVERIFIED',
            findings=[{'classification': 'UNVERIFIED', 'reason': 'No authorized lab scope supplied'}],
            sources=[]
        )
    return AgentResult(
        agent='VALIDATION', status='needs_review', confidence='UNVERIFIED',
        findings=[{'classification': 'UNVERIFIED', 'reason': 'Authorized lab validation requires an explicit test plan'}],
        sources=[]
    )
