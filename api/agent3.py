import json


def send(data, status=200):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type"}, "body": json.dumps(data)}


def handler(request):
    if getattr(request, "method", "POST") == "OPTIONS": return send({"ok": True})
    try:
        body = request.get_json() if hasattr(request, "get_json") else json.loads(request.body or "{}")
        osint = body.get("osint", {}) or {}
        vuln = body.get("vulnerability", {}) or {}
        if not isinstance(osint, dict) or not isinstance(vuln, dict): return send({"error": "Valid Agent 1 and Agent 2 JSON is required."}, 400)

        of = osint.get("findings", [])
        vf = vuln.get("findings", [])
        sources = set(osint.get("sources", []) + vuln.get("sources", []))
        factual = sum(1 for x in of if x.get("classification") == "FACT")
        possible = sum(1 for x in vf if x.get("classification") == "POSSIBLE")
        reported = sum(1 for x in vf if x.get("classification") == "REPORTED")
        unverified = sum(1 for x in of + vf if x.get("classification") == "UNVERIFIED")

        # Exposure posture, not probability of compromise.
        osint_score = min(100, factual * 16 + min(20, len(sources) * 5))
        vuln_score = min(100, possible * 7 + reported * 10)
        score = min(100, round(osint_score * 0.45 + vuln_score * 0.55))
        confidence = "HIGH" if len(sources) >= 4 and unverified <= 2 else "MEDIUM" if sources else "LOW"
        severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "INFORMATIONAL"
        return send({"agent": "RISK", "status": "completed", "confidence": confidence, "exposure_score": score, "osint_coverage": osint_score, "vulnerability_intel": vuln_score, "severity": severity, "counts": {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "possible": possible, "reported": reported, "unverified": unverified}, "findings": [{"classification": "FACT", "type": "risk_assessment", "severity": severity, "reason": "Evidence-weighted aggregation of Agent 1 and Agent 2 results."}], "sources": sorted(sources)})
    except Exception as e:
        return send({"error": "Agent 3 failed safely: " + str(e)[:180]}, 500)
