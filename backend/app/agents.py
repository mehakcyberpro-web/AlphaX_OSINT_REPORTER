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
        r = client.get(url); r.raise_for_status(); return r.json()


def _get_web(url: str) -> tuple[int, dict[str, str], str]:
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True, headers={'User-Agent': UA}) as client:
        r = client.get(url); return r.status_code, dict(r.headers), r.text[:120000]


def osint_agent(target: str) -> AgentResult:
    target = target.strip().lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', target) or '.' not in target:
        return AgentResult(agent='OSINT', status='skipped', confidence='LOW', findings=[{'classification': 'UNVERIFIED', 'reason': 'Expected a public domain such as example.com'}], sources=[])
    findings=[{'classification':'FACT','type':'target','value':target}]; sources=[]
    try:
        d=_get_json(f'https://rdap.org/domain/{quote(target)}'); findings.append({'classification':'FACT','type':'rdap','name':d.get('ldhName',target),'status':d.get('status',[]),'nameservers':[x.get('ldhName') for x in d.get('nameservers',[]) if x.get('ldhName')]}); sources.append(f'https://rdap.org/domain/{target}')
    except Exception as e: findings.append({'classification':'UNVERIFIED','type':'rdap','error':str(e)[:120]})
    try:
        for rr in ('A','AAAA','MX','NS'):
            d=_get_json(f'https://dns.google/resolve?name={quote(target)}&type={rr}'); a=[x.get('data') for x in d.get('Answer',[]) if x.get('data')]
            if a: findings.append({'classification':'FACT','type':'dns','record':rr,'answers':a[:20]})
        sources.append('https://dns.google/')
    except Exception as e: findings.append({'classification':'UNVERIFIED','type':'dns','error':str(e)[:120]})
    try:
        d=_get_json(f'https://crt.sh/?q=%25.{quote(target)}&output=json'); names=sorted({n.strip().lower() for row in d for n in str(row.get('name_value','')).splitlines() if n.strip()}); names=[n for n in names if n==target or n.endswith('.'+target)]; findings.append({'classification':'FACT','type':'certificate_transparency','subdomains':names[:100],'count':len(names)}); sources.append(f'https://crt.sh/?q=%25.{target}&output=json')
    except Exception as e: findings.append({'classification':'UNVERIFIED','type':'certificate_transparency','error':str(e)[:120]})
    try:
        code,h,html=_get_web('https://'+target); generator=None; m=re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',html,re.I)
        if m: generator=m.group(1)[:120]
        findings.append({'classification':'FACT','type':'web','https_status':code,'server':h.get('server'),'x_powered_by':h.get('x-powered-by'),'generator':generator}); sources.append('https://'+target)
    except Exception as e: findings.append({'classification':'UNVERIFIED','type':'web','error':str(e)[:120]})
    return AgentResult(agent='OSINT',status='completed',confidence='HIGH' if len(sources)>=3 else 'MEDIUM' if sources else 'LOW',findings=findings,sources=list(dict.fromkeys(sources)))


def vulnerability_agent(target: str, osint: AgentResult) -> AgentResult:
    technologies=[]
    for f in osint.findings:
        if f.get('type')=='web':
            for k in ('server','x_powered_by','generator'):
                if f.get(k): technologies.append(str(f[k]))
    technologies=list(dict.fromkeys(technologies))[:3]; findings=[]; sources=[]
    for tech in technologies:
        keyword=re.sub(r'[^A-Za-z0-9._ -]',' ',tech)[:80].strip()
        if not keyword: continue
        try:
            d=_get_json(f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(keyword)}&resultsPerPage=5')
            for item in d.get('vulnerabilities',[])[:5]:
                c=item.get('cve',{}); cid=c.get('id'); desc=next((x.get('value') for x in c.get('descriptions',[]) if x.get('lang')=='en'),'')
                if cid: findings.append({'classification':'POSSIBLE','type':'cve_candidate','technology':tech,'cve':cid,'description':desc[:300],'note':'Keyword correlation only; affected version/configuration must be verified.'})
            sources.append('https://nvd.nist.gov/')
        except Exception as e: findings.append({'classification':'UNVERIFIED','type':'nvd_query','technology':tech,'error':str(e)[:120]})
    return AgentResult(agent='VULNERABILITY_CTI',status='completed',confidence='MEDIUM' if findings else 'LOW',findings=findings,sources=list(dict.fromkeys(sources)))


def risk_agent(osint: AgentResult, vuln: AgentResult) -> AgentResult:
    factual=sum(1 for x in osint.findings if x.get('classification')=='FACT'); possible=len({x.get('cve') for x in vuln.findings if x.get('classification')=='POSSIBLE' and x.get('cve')}); reported=len({x.get('cve') for x in vuln.findings if x.get('classification')=='REPORTED' and x.get('cve')}); unverified=sum(1 for x in osint.findings+vuln.findings if x.get('classification')=='UNVERIFIED'); source_count=len(set(osint.sources+vuln.sources))
    osint_score=min(60,factual*10+min(20,source_count*4)); vuln_score=min(60,possible*3+reported*10); score=min(100,round(osint_score*.4+vuln_score*.6)); severity='CRITICAL' if score>=90 else 'HIGH' if score>=70 else 'MEDIUM' if score>=40 else 'LOW' if score>=15 else 'INFORMATIONAL'; confidence='HIGH' if source_count>=4 and unverified<=2 else 'MEDIUM' if source_count else 'LOW'
    return AgentResult(agent='RISK',status='completed',confidence=confidence,findings=[{'classification':'FACT','type':'risk_assessment','severity':severity,'exposure_score':score,'osint_coverage':osint_score,'vulnerability_intel':vuln_score,'reason':'Conservative evidence-weighted aggregation. POSSIBLE CVEs do not prove target exposure.'}],sources=list(dict.fromkeys(osint.sources+vuln.sources)))


def validation_agent(target: str, authorized_lab: bool) -> AgentResult:
    if not authorized_lab: return AgentResult(agent='VALIDATION',status='skipped',confidence='UNVERIFIED',findings=[{'classification':'UNVERIFIED','type':'validation_gate','reason':'No explicit authorized lab scope supplied. No attack or exploitation performed.'}],sources=[])
    return AgentResult(agent='VALIDATION',status='needs_review',confidence='UNVERIFIED',findings=[{'classification':'UNVERIFIED','type':'validation_plan','reason':'Authorized lab validation requires a human-reviewed, non-destructive test plan.'}],sources=[])
