import json, re
from urllib.request import Request, urlopen
from urllib.parse import quote


def send(data, status=200):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type"}, "body": json.dumps(data)}


def get_json(url, timeout=10):
    req = Request(url, headers={"User-Agent": "AlphaX-OSINT-Reporter/1.0"})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def handler(request):
    if getattr(request, "method", "POST") == "OPTIONS": return send({"ok": True})
    try:
        body = request.get_json() if hasattr(request, "get_json") else json.loads(request.body or "{}")
        target = str(body.get("target", "")).strip().lower()
        osint = body.get("osint", {}) or {}
        if not target or not isinstance(osint, dict): return send({"error": "target and Agent 1 OSINT JSON are required."}, 400)

        tech = []
        for f in osint.get("findings", []):
            if f.get("type") == "web":
                for k in ("server", "x_powered_by", "generator"):
                    v = f.get(k)
                    if v: tech.append(str(v))
        tech = list(dict.fromkeys(tech))[:5]
        findings, sources = [], []

        for item in tech:
            keyword = re.sub(r"[^A-Za-z0-9._ -]", " ", item)[:80].strip()
            if not keyword: continue
            try:
                data = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + quote(keyword) + "&resultsPerPage=5")
                vulns = data.get("vulnerabilities", [])
                for v in vulns[:5]:
                    c = v.get("cve", {})
                    cid = c.get("id")
                    desc = next((x.get("value") for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
                    metrics = c.get("metrics", {})
                    cvss = None
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metrics.get(key):
                            cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                            break
                    if cid:
                        findings.append({"classification": "POSSIBLE", "type": "cve_candidate", "technology": item, "cve": cid, "cvss": cvss, "description": desc[:300], "note": "Keyword correlation only; affected-version match must be verified."})
                sources.append("https://nvd.nist.gov/")
            except Exception as e:
                findings.append({"classification": "UNVERIFIED", "type": "nvd_query", "technology": item, "error": str(e)[:120]})

        # CISA KEV is used only as public threat context; no claim is made that target is affected.
        try:
            kev = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            matches = []
            for x in kev.get("vulnerabilities", []):
                text = (str(x.get("product", "")) + " " + str(x.get("vendorProject", ""))).lower()
                if any(t.lower().split("/")[0] in text for t in tech if len(t) > 3): matches.append({"cve": x.get("cveID"), "product": x.get("product"), "vendor": x.get("vendorProject"), "dueDate": x.get("dueDate")})
            for m in matches[:10]: findings.append({"classification": "REPORTED", "type": "cisa_kev_context", **m, "note": "Threat context only; target exposure is not established."})
            sources.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        except Exception:
            pass

        confidence = "MEDIUM" if findings else "LOW"
        return send({"agent": "VULNERABILITY_CTI", "status": "completed", "confidence": confidence, "technologies_reviewed": tech, "findings": findings, "sources": list(dict.fromkeys(sources))})
    except Exception as e:
        return send({"error": "Agent 2 failed safely: " + str(e)[:180]}, 500)
