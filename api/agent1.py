import json, re
from urllib.request import Request, urlopen
from urllib.parse import quote


def send(data, status=200):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type"}, "body": json.dumps(data)}


def get_json(url, timeout=8):
    req = Request(url, headers={"User-Agent": "AlphaX-OSINT-Reporter/1.0"})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def get_text(url, timeout=8):
    req = Request(url, headers={"User-Agent": "AlphaX-OSINT-Reporter/1.0"})
    with urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read(120000).decode("utf-8", "replace")


def handler(request):
    if getattr(request, "method", "POST") == "OPTIONS":
        return send({"ok": True})
    try:
        body = request.get_json() if hasattr(request, "get_json") else json.loads(request.body or "{}")
        target = str(body.get("target", "")).strip().lower().rstrip(".")
        target_type = str(body.get("type", "Domain"))
        if not target or len(target) > 253:
            return send({"error": "A valid public target is required."}, 400)
        if target_type != "Domain":
            return send({"agent": "OSINT", "status": "completed", "confidence": "LOW", "findings": [{"classification": "UNVERIFIED", "type": target_type, "value": target, "note": "This passive domain collector currently supports Domain targets."}], "sources": []})
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", target) or "." not in target:
            return send({"error": "Enter a public domain such as example.com."}, 400)

        findings, sources = [{"classification": "FACT", "type": "target", "value": target}], []
        # RDAP / registration metadata
        try:
            rdap = get_json("https://rdap.org/domain/" + quote(target))
            findings.append({"classification": "FACT", "type": "rdap", "name": rdap.get("ldhName", target), "status": rdap.get("status", []), "nameservers": [x.get("ldhName") for x in rdap.get("nameservers", []) if x.get("ldhName")]})
            sources.append("https://rdap.org/domain/" + target)
        except Exception as e:
            findings.append({"classification": "UNVERIFIED", "type": "rdap", "error": str(e)[:120]})

        # DNS-over-HTTPS, public resolver
        try:
            for rr in ("A", "AAAA", "MX", "NS"):
                d = get_json("https://dns.google/resolve?name=" + quote(target) + "&type=" + rr)
                answers = [a.get("data") for a in d.get("Answer", []) if a.get("data")]
                if answers:
                    findings.append({"classification": "FACT", "type": "dns", "record": rr, "answers": answers[:20]})
            sources.append("https://dns.google/")
        except Exception as e:
            findings.append({"classification": "UNVERIFIED", "type": "dns", "error": str(e)[:120]})

        # Certificate Transparency
        try:
            certs = get_json("https://crt.sh/?q=%25." + quote(target) + "&output=json")
            names = sorted({n.strip().lower() for row in certs for n in str(row.get("name_value", "")).splitlines() if n.strip()})
            names = [n for n in names if n == target or n.endswith("." + target)]
            findings.append({"classification": "FACT", "type": "certificate_transparency", "subdomains": names[:100], "count": len(names)})
            sources.append("https://crt.sh/?q=%25." + target + "&output=json")
        except Exception as e:
            findings.append({"classification": "UNVERIFIED", "type": "certificate_transparency", "error": str(e)[:120]})

        # One normal public homepage request; not a scan.
        try:
            code, headers, html = get_text("https://" + target)
            server = headers.get("Server")
            powered = headers.get("X-Powered-By")
            generator = None
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
            if m: generator = m.group(1)[:120]
            findings.append({"classification": "FACT", "type": "web", "https_status": code, "server": server, "x_powered_by": powered, "generator": generator})
            sources.append("https://" + target)
        except Exception as e:
            findings.append({"classification": "UNVERIFIED", "type": "web", "error": str(e)[:120]})

        confidence = "HIGH" if len(sources) >= 3 else "MEDIUM" if sources else "LOW"
        return send({"agent": "OSINT", "status": "completed", "confidence": confidence, "findings": findings, "sources": sources})
    except Exception as e:
        return send({"error": "Agent 1 failed safely: " + str(e)[:180]}, 500)
