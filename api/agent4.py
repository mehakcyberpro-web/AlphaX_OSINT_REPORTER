import json


def send(data, status=200):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type"}, "body": json.dumps(data)}


def handler(request):
    if getattr(request, "method", "POST") == "OPTIONS": return send({"ok": True})
    try:
        body = request.get_json() if hasattr(request, "get_json") else json.loads(request.body or "{}")
        target = str(body.get("target", "")).strip()
        authorized = bool(body.get("authorized_lab", False))
        scope = str(body.get("lab_scope", "")).strip()
        if not target: return send({"error": "target is required."}, 400)
        if not authorized:
            return send({"agent": "VALIDATION", "status": "skipped", "confidence": "UNVERIFIED", "mode": "guarded", "findings": [{"classification": "UNVERIFIED", "type": "validation_gate", "reason": "No explicit authorized lab scope supplied. No attack or exploitation performed."}], "sources": []})
        if len(scope) < 10:
            return send({"error": "Explicit authorized lab scope is required."}, 400)
        return send({"agent": "VALIDATION", "status": "needs_review", "confidence": "UNVERIFIED", "mode": "authorized_lab_only", "findings": [{"classification": "UNVERIFIED", "type": "validation_plan", "reason": "A human-reviewed, non-destructive lab test plan is required before validation."}], "sources": []})
    except Exception as e:
        return send({"error": "Agent 4 failed safely: " + str(e)[:180]}, 500)
