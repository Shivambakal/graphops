"""Supabase persistence for GraphOps — hunt history + containment decision audit trail.

Reads SUPABASE_URL and SUPABASE_SECRET_KEY from the environment.
If either is missing, every function degrades gracefully (returns None/[])
and the app runs fully without persistence. No exceptions ever escape.
Uses stdlib urllib only (no extra dependency); honors proxy env vars.
"""
import json
import os
import urllib.request

_TIMEOUT = 10


def _cfg():
    url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SECRET_KEY", "")
    if url and key:
        return url, key
    return None


def is_configured():
    return _cfg() is not None


def _insert(table, row):
    cfg = _cfg()
    if not cfg:
        return None
    url, key = cfg
    req = urllib.request.Request(
        f"{url}/rest/v1/{table}",
        data=json.dumps(row).encode(),
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode() or "[]")
    except Exception:
        return None


def _select(table, order="created_at.desc", limit=50):
    cfg = _cfg()
    if not cfg:
        return []
    url, key = cfg
    req = urllib.request.Request(
        f"{url}/rest/v1/{table}?order={order}&limit={int(limit)}",
        headers={"apikey": key, "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode() or "[]")
    except Exception:
        return []


def record_hunt_run(node_count, edge_count, findings, engine_source="generator"):
    """Persist a hunt run + its findings. Returns run id or None."""
    run = _insert("hunt_runs", {
        "engine_source": engine_source,
        "node_count": node_count,
        "edge_count": edge_count,
        "finding_count": len(findings or []),
    })
    run_id = (run or [{}])[0].get("id")
    if run_id:
        for f in findings or []:
            _insert("findings", {
                "hunt_run_id": run_id,
                "title": str(f.get("title", ""))[:500],
                "severity": str(f.get("severity", ""))[:50],
                "evidence": f.get("evidence", []),
                "nodes": f.get("nodes", []),
            })
    return run_id


def record_decision(node_id, action, target, decision, rationale="", decided_by="analyst"):
    """Record an analyst approve/reject on a containment action."""
    rows = _insert("containment_decisions", {
        "node_id": node_id,
        "action": action,
        "target": target,
        "decision": decision,
        "decided_by": decided_by,
        "rationale": rationale,
    })
    return (rows or [{}])[0].get("id")


def list_decisions(limit=50):
    return _select("containment_decisions", limit=limit)


def list_hunt_runs(limit=20):
    return _select("hunt_runs", limit=limit)


def record_queued_action(rec):
    """Queue an irreversible containment action behind the analyst gate."""
    rows = _insert("containment_queue", {
        "node_id": str(rec.get("node_id", "")),
        "action": str(rec.get("action", "")),
        "target": str(rec.get("target", "")),
        "reversibility": rec.get("reversibility_score"),
        "impact_tier": str(rec.get("impact_tier", "")),
        "est_cost_usd": rec.get("est_cost_usd"),
        "status": str(rec.get("status", "queued_for_approval")),
        "context": rec.get("context") or {},
        "requested_by": str(rec.get("requested_by", "analyst")),
    })
    return (rows or [{}])[0].get("id")


def list_queued_actions(limit=100):
    """List queued containment actions, newest first."""
    return _select("containment_queue", limit=limit)
