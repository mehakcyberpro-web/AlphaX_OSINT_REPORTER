from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx

from .schemas import AgentResult

UA = 'AlphaX-OSINT-Reporter/1.0 (public-passive-intelligence)'
TIMEOUT = httpx.Timeout(7.0, connect=4.0)


def _get_json(url: str) -> dict[str, Any]:
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True, headers={'User-Agent': UA}) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.json()


def _get_web(url: str) -> tuple[int, dict[str, str], str]:
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True, headers={'User-Agent': UA}) as client:
        r = client.get(url)
        return r.status_code, dict(r.headers), r.text[:120000]


def osint_agent(target: str) -> AgentResult:
    """Agent 1: public/passive OSINT only. No scanning or authentication bypass."""
    target = target.strip().lower().rstrip('.')
    findings: list[dict[str, Any]] = [{'classification': 'FACT', 'type': 'target', 'value': target}]
    sources: list[str] = []

    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', target) or '.' not in target:
        return AgentResult(agent='OSINT', status='failed', confidence='LOW', findings=[{'classification': 'UNVERIFIED', 'reason': 'Expected a public domain such as example.com'}], sources=[])

    try:
        data = _get_json(f'https://rdap.org/domain/{quote(target)}')
        findings.append({'classification': 'FACT', 'type': 'rdap', 'name': data.get('ldhName', target), 'status': data.get('status', []), 'nameservers': [x.get('ldhName') for x in data.get('nameservers', []) if x.get('ldhName')]})
        sources.append(f'https://rdap.org/domain/{target}')
    except Exception as exc:
        findings.append({'classification': 'UNVERIFIED', 'type': 'rdap', 'error': str(exc)[:120]})

    try:
        for rr in ('A', 'AAAA', 'MX', 'NS'):
            data = _get_json(f'https://dns.google/resolve?name={quote(target)}&type={rr}')
            answers = [a.get('data') for a in data.get('Answer', []) if a.get('data')]
            if answers:
                findings.append({'classification': 'FACT', 'type': 'dns', 'record': rr, 'answers': answers[:20]})
        sources.append('https://dns.google/')
    except Exception as exc:
        findings.append({'classification': 'UNVERIFIED', 'type': 'dns', 'error': str(exc)[:120]})

    try:
        data = _get_json(f'https://crt.sh/?q=%25.{quote(target)}&output=json')
        names = sorted({n.strip().lower() for row in data for n in str(row.get('name_value', '')).splitlines() if n.strip()})
        names = [n for n in names if n == target or n.endswith('.' + target)]
        findings.append({'classification': 'FACT', 'type': 'certificate_transparency', 'subdomains': names[:100], 'count': len(names)})
        sources.append(f'https://crt.sh/?q=%25.{target}&output=json')
    except Exception as exc:
        findings.append({'classification': 'UNVERIFIED', 'type': 'certificate_transparency', 'error': str(exc)[:120]})

    try:
        code, headers, html = _get_web('https://' + target)
        generator = None
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
        if m:
            generator = m.group(1)[:120]
        findings.append({'classification': 'FACT', 'type': 'web', 'https_status': code, 'server': headers.get('server'), 'x_powered_by': headers.get('x-powered-by'), 'generator': generator})
        sources.append('https://' + target)
    except Exception as exc:
        findings.append({'classification': 'UNVERIFIED', 'type': 'web', 'error': str(exc)[:120]})

    confidence = 'HIGH' if len(sources) >= 3 else 'MEDIUM' if sources else 'LOW'
    return AgentResult(agent='OSINT', status='completed', confidence=confidence, findings=findings, sources=list(dict.fromkeys(sources)))


def vulnerability_agent(target: str, osint: AgentResult) -> AgentResult:
    """Agent 2: public CVE/CTI correlation. A keyword hit is never treated as proof of exposure."""
    technologies: list[str] = []
    for finding in osint.findings:
        if finding.get('type') == 'web':
            for key in ('server', 'x_powered_by', 'generator'):
                value = finding.get(key)
                if value:
                    technologies.append(str(value))
    technologies = list(dict.fromkeys(technologies))[:3]
    findings: list[dict[str, Any]] = []
    sources: list[str] = []

    for technology in technologies:
        keyword = re.sub(r'[^A-Za-z0-9._ -]', ' ', technology)[:80].strip()
        if not keyword:
            continue
        try:
            data = _get_json(f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(keyword)}&resultsPerPage=5')
            for item in data.get('vulnerabilities', [])[:5]:
                cve = item.get('cve', {})
                cid = cve.get('id')
                description = next((x.get('value') for x in cve.get('descriptions', []) if x.get('lang') == 'en'), '')
                if cid:
                    findings.append({'classification': 'POSSIBLE', 'type': 'cve_candidate', 'technology': technology, 'cve': cid, 'description': description[:300], 'note': 'Public keyword correlation only; affected version/configuration must be verified.'})
            sources.append('https://nvd.nist.gov/')
        except Exception as exc:
            findings.append({'classification': 'UNVERIFIED', 'type': 'nvd_query', 'technology': technology, 'error': str(exc)[:120]})

    confidence = 'MEDIUM' if findings else 'LOW'
    return AgentResult(agent='VULNERABILITY_CTI', status='completed', confidence=confidence, findings=findings, sources=list(dict.fromkeys(sources)))


def risk_agent(osint: AgentResult, vuln: AgentResult) -> AgentResult:
    """Agent 3: evidence-weighted exposure posture, not compromise probability."""
    factual = sum(1 for x in osint.findings if x.get('classification') == 'FACT')
    possible = sum(1 for x in vuln.findings if x.get('classification') == 'POSSIBLE')
    reported = sum(1 for x in vuln.findings if x.get('classification') == 'REPORTED')
    unverified = sum(1 for x in osint.findings + vuln.findings if x.get('classification') == 'UNVERIFIED')
    source_count = len(set(osint.sources + vuln.sources))

    osint_score = min(100, factual * 16 + min(20, source_count * 5))
    vuln_score = min(100, possible * 7 + reported * 10)
    score = min(100, round(osint_score * 0.45 + vuln_score * 0.55))
    severity = 'CRITICAL' if score >= 90 else 'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW' if score >= 15 else 'INFORMATIONAL'
    confidence = 'HIGH' if source_count >= 4 and unverified <= 2 else 'MEDIUM' if source_count else 'LOW'

    return AgentResult(agent='RISK', status='completed', confidence=confidence, findings=[{
        'classification': 'FACT', 'type': 'risk_assessment', 'severity': severity,
        'exposure_score': score, 'osint_coverage': osint_score, 'vulnerability_intel': vuln_score,
        'reason': 'Evidence-weighted aggregation of Agents 1 and 2.'
    }], sources=list(dict.fromkeys(osint.sources + vuln.sources)))


def validation_agent(target: str, authorized_lab: bool) -> AgentResult:
    """Agent 4: guarded validation gate; no exploitation of public targets."""
    if not authorized_lab:
        return AgentResult(agent='VALIDATION', status='skipped', confidence='UNVERIFIED', findings=[{
            'classification': 'UNVERIFIED', 'type': 'validation_gate',
            'reason': 'No explicit authorized lab scope supplied. No attack or exploitation performed.'
        }], sources=[])
    return AgentResult(agent='VALIDATION', status='needs_review', confidence='UNVERIFIED', findings=[{
        'classification': 'UNVERIFIED', 'type': 'validation_plan',
        'reason': 'Authorized lab validation requires a human-reviewed, non-destructive test plan.'
    }], sources=[])
