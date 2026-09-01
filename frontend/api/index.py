import json, re, urllib.request, urllib.parse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title='ALPHAX OSINT REPORTER API', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])

class TargetInput(BaseModel):
    target: str = Field(min_length=1, max_length=253)

class VulnerabilityInput(BaseModel):
    target: str
    osint: dict = {}
    osint_findings: list[dict] = []
    osint_sources: list[str] = []

class RiskInput(BaseModel):
    osint: dict = {}
    vulnerability: dict = {}

class ValidationInput(BaseModel):
    target: str
    authorized_lab: bool = False
    lab_scope: str | None = None

def clean_domain(value):
    value = value.strip().lower()
    value = re.sub(r'^https?://', '', value).split('/')[0].split(':')[0]
    if not re.fullmatch(r'[a-z0-9.-]+', value) or '.' not in value:
        raise ValueError('Enter a valid public domain, e.g. example.com')
    return value

def get_json(url, timeout=8):
    req = urllib.request.Request(url, headers={'User-Agent':'AlphaX-OSINT-Reporter/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', errors='replace'))

def agent1(target):
    d = clean_domain(target); findings=[]; sources=[]
    # RDAP
    try:
        rdap_url=f'https://rdap.org/domain/{urllib.parse.quote(d)}'
        rdap=get_json(rdap_url); sources.append(rdap_url)
        names=[x.get('ldhName') for x in rdap.get('nameservers',[]) if x.get('ldhName')]
        findings.append({'type':'domain_rdap','classification':'CONFIRMED','domain':d,'status':rdap.get('status',[]),'nameservers':names,'events':rdap.get('events',[])})
    except Exception as e:
        findings.append({'type':'rdap','classification':'UNVERIFIED','error':str(e)})
    # Certificate Transparency
    try:
        ct_url='https://crt.sh/?q='+urllib.parse.quote('%.'+d)+'&output=json'
        rows=get_json(ct_url); names=set()
        for row in rows[:500]:
            for n in str(row.get('name_value','')).splitlines():
                n=n.strip().lower()
                if n and '*' not in n and (n==d or n.endswith('.'+d)): names.add(n)
        sources.append(ct_url)
        findings.append({'type':'certificate_transparency','classification':'CONFIRMED','count':len(names),'names':sorted(names)[:100]})
    except Exception as e:
        findings.append({'type':'certificate_transparency','classification':'UNVERIFIED','error':str(e)})
    # Public HTTP metadata only; no port scanning/exploitation
    try:
        url='https://'+d+'/'
        req=urllib.request.Request(url,headers={'User-Agent':'AlphaX-OSINT-Reporter/1.0'})
        with urllib.request.urlopen(req,timeout=8) as r:
            headers={k.lower():v for k,v in r.headers.items()}
            findings.append({'type':'web','classification':'CONFIRMED','https_status':r.status,'server':headers.get('server'),'powered_by':headers.get('x-powered-by'),'content_type':headers.get('content-type')})
        sources.append(url)
    except Exception as e:
        findings.append({'type':'web','classification':'UNVERIFIED','error':str(e)})
    coverage=min(100, 25*sum(1 for f in findings if f.get('classification')=='CONFIRMED')+10*sum(1 for f in findings if f.get('classification')=='UNVERIFIED'))
    return {'agent':'OSINT','status':'completed','confidence':'MEDIUM' if any(f.get('classification')=='CONFIRMED' for f in findings) else 'LOW','findings':findings,'sources':sources,'coverage':coverage,'target':d}

def agent2(target, osint):
    d=clean_domain(target); tech=[]; findings=[]; sources=[]
    for f in osint.get('findings',[]):
        for k in ('server','powered_by'):
            if f.get(k): tech.append(str(f[k]))
    # Public NVD search using observed web header technology terms only.
    for t in list(dict.fromkeys(tech))[:3]:
        try:
            url='https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch='+urllib.parse.quote(t)+'&resultsPerPage=5'
            data=get_json(url); sources.append(url)
            for item in data.get('vulnerabilities',[])[:5]:
                c=item.get('cve',{}); cid=c.get('id'); desc=next((x.get('value') for x in c.get('descriptions',[]) if x.get('lang')=='en'),'')
                findings.append({'type':'cve_candidate','classification':'REPORTED','cve':cid,'technology':t,'description':desc[:500],'reason':'Public NVD match for observed technology header; target version/affected component is not established.'})
        except Exception as e:
            findings.append({'type':'cti_lookup','classification':'UNVERIFIED','technology':t,'error':str(e)})
    return {'agent':'VULNERABILITY + CTI','status':'completed','confidence':'MEDIUM' if findings else 'LOW','findings':findings,'sources':sources,'target':d,'note':'CVE candidates are intelligence leads, not proof that the target is vulnerable.'}

def agent3(osint, vuln):
    confirmed=sum(1 for f in osint.get('findings',[]) if f.get('classification')=='CONFIRMED')
    candidates=sum(1 for f in vuln.get('findings',[]) if f.get('type')=='cve_candidate')
    coverage=int(osint.get('coverage',0) or 0)
    vuln_intel=min(100,candidates*12)
    score=min(100, int(coverage*0.45 + vuln_intel*0.35 + confirmed*5))
    sev='CRITICAL' if score>=90 else 'HIGH' if score>=70 else 'MEDIUM' if score>=40 else 'LOW' if score>=15 else 'INFORMATIONAL'
    confidence='HIGH' if confirmed>=2 and candidates==0 else 'MEDIUM' if confirmed else 'LOW'
    finding={'type':'risk_assessment','classification':'INFERENCE','exposure_score':score,'osint_coverage':coverage,'vulnerability_intel':vuln_intel,'severity':sev,'reason':'Evidence-weighted exposure posture. CVE candidates are not treated as confirmed target vulnerabilities.'}
    return {'agent':'RISK','status':'completed','confidence':confidence,'findings':[finding],'sources':list(dict.fromkeys(osint.get('sources',[])+vuln.get('sources',[]))),'counts':{'informational':1 if sev=='INFORMATIONAL' else 0,'low':1 if sev=='LOW' else 0,'medium':1 if sev=='MEDIUM' else 0,'high':1 if sev=='HIGH' else 0,'critical':1 if sev=='CRITICAL' else 0}}

def agent4(target, authorized=False, scope=None):
    if not authorized:
        return {'agent':'VALIDATION','status':'guarded','confidence':'HIGH','findings':[{'type':'validation_gate','classification':'CONFIRMED','result':'SKIPPED','reason':'Public-target exploitation is disabled. Provide an explicitly authorized lab scope for controlled validation.'}],'sources':[]}
    if not scope or len(scope.strip())<10:
        return {'agent':'VALIDATION','status':'blocked','confidence':'HIGH','findings':[{'type':'validation_gate','classification':'CONFIRMED','result':'BLOCKED','reason':'Explicit authorized lab scope is required.'}],'sources':[]}
    return {'agent':'VALIDATION','status':'ready','confidence':'HIGH','findings':[{'type':'validation_gate','classification':'CONFIRMED','result':'AUTHORIZED_LAB_READY','scope':scope[:300]}],'sources':[]}

@app.get('/health')
def health(): return {'status':'online','mode':'public/passive intelligence','agents':4}
@app.get('/api/health')
def api_health(): return health()
@app.post('/api/agents/1/osint')
def a1(req:TargetInput): return agent1(req.target)
@app.post('/api/agents/2/vulnerability')
def a2(req:VulnerabilityInput): return agent2(req.target, req.osint or {'findings':req.osint_findings,'sources':req.osint_sources})
@app.post('/api/agents/3/risk')
def a3(req:RiskInput): return agent3(req.osint, req.vulnerability)
@app.post('/api/agents/4/validation')
def a4(req:ValidationInput): return agent4(req.target, req.authorized_lab, req.lab_scope)
