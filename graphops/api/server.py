"""GraphOps API server — hunt + blast-radius + graph summary over a synthetic SOC graph.

Engine source priority:
  1. graphops.intel.generator.generate(seed=42)  (sibling module)
  2. Tiny built-in demo engine (3 hosts + 1 alert) so the server ALWAYS starts.

All sibling imports are wrapped in try/except with duck-typed fallbacks.
"""

import sys
import time
import traceback
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

# Make the build dir importable so sibling graphops.* modules resolve.
_BUILD_DIR = Path(__file__).resolve().parents[2]
if str(_BUILD_DIR) not in sys.path:
    sys.path.insert(0, str(_BUILD_DIR))

try:
    from graphops.api import ratelimit as _ratelimit
except Exception:  # pragma: no cover
    _ratelimit = None


# ---------------------------------------------------------------------------
# Fallback demo engine (used only when graphops.intel.generator is missing)
# ---------------------------------------------------------------------------
class DemoEngine:
    """Minimal duck-typed stand-in for graphops.graph.engine.GraphEngine."""

    def __init__(self):
        self._nodes = [
            {"id": "host:web-01", "etype": "host", "label": "web-01"},
            {"id": "host:db-01", "etype": "host", "label": "db-01"},
            {"id": "host:wkst-07", "etype": "host", "label": "wkst-07"},
            {"id": "alert:ALT-2026-0042", "etype": "alert", "label": "Suspicious PowerShell"},
        ]
        self._edges = [
            {"src": "host:wkst-07", "dst": "host:web-01", "etype": "smb"},
            {"src": "host:web-01", "dst": "host:db-01", "etype": "mssql"},
            {"src": "alert:ALT-2026-0042", "dst": "host:wkst-07", "etype": "indicates"},
        ]

    def nodes(self):
        return list(self._nodes)

    def edges(self):
        return list(self._edges)


def _demo_engine():
    return DemoEngine()


# ---------------------------------------------------------------------------
# Normalization helpers (duck-type whatever engine we get)
# ---------------------------------------------------------------------------
try:
    from graphops.graph.classification import classify_node as _classify_node
except Exception:  # pragma: no cover
    def _classify_node(_engine, _node_id):  # type: ignore[misc]
        return "internal"


def _node_classification(engine, node_id):
    try:
        return _classify_node(engine, node_id)
    except Exception:
        return "internal"
def _normalize_nodes(engine):
    nodes = []
    getter = getattr(engine, "nodes", None)
    if callable(getter):
        try:
            raw = getter()
        except Exception:
            raw = []
        for n in raw or []:
            if isinstance(n, dict):
                nodes.append({
                    "id": str(n.get("id")),
                    "etype": str(n.get("etype", "unknown")),
                    "label": str(n.get("label", n.get("id"))),
                    "data_classification": _node_classification(
                        engine, n.get("id")),
                })
            elif isinstance(n, (tuple, list)) and len(n) == 2:
                nid, attrs = n
                attrs = attrs or {}
                if isinstance(attrs, dict):
                    nodes.append({
                        "id": str(nid),
                        "etype": str(attrs.get("etype", "unknown")),
                        "label": str(attrs.get("label", nid)),
                        "data_classification": _node_classification(
                            engine, nid),
                    })
                else:
                    nodes.append({"id": str(nid), "etype": "unknown",
                                  "label": str(nid),
                                  "data_classification": _node_classification(
                                      engine, nid)})
            else:
                nodes.append({"id": str(n), "etype": "unknown", "label": str(n),
                              "data_classification": _node_classification(
                                  engine, n)})
    # networkx-graph fallback (engine.graph)
    if not nodes:
        g = getattr(engine, "graph", None)
        try:
            for nid, attrs in list(g.nodes(data=True)):  # type: ignore[union-attr]
                attrs = attrs or {}
                nodes.append({
                    "id": str(nid),
                    "etype": str(attrs.get("etype", "unknown")),
                    "label": str(attrs.get("label", nid)),
                    "data_classification": _node_classification(engine, nid),
                })
        except Exception:
            pass
    return nodes


def _normalize_edges(engine):
    edges = []
    getter = getattr(engine, "edges", None)
    if callable(getter):
        try:
            raw = getter()
        except Exception:
            raw = []
        for e in raw or []:
            if isinstance(e, dict):
                edges.append({
                    "src": str(e.get("src")),
                    "dst": str(e.get("dst")),
                    "etype": str(e.get("etype", "unknown")),
                })
            elif isinstance(e, (tuple, list)) and len(e) in (2, 3):
                src, dst = e[0], e[1]
                attrs = e[2] if len(e) == 3 and isinstance(e[2], dict) else {}
                edges.append({
                    "src": str(src),
                    "dst": str(dst),
                    "etype": str(attrs.get("etype", "unknown")),
                })
    # networkx-graph fallback (engine.graph)
    if not edges:
        g = getattr(engine, "graph", None)
        try:
            for src, dst, attrs in list(g.edges(data=True)):  # type: ignore[union-attr]
                attrs = attrs or {}
                edges.append({
                    "src": str(src),
                    "dst": str(dst),
                    "etype": str(attrs.get("etype", "unknown")),
                })
        except Exception:
            pass
    return edges


# ---------------------------------------------------------------------------
# Fallback containment (used only when graphops.response.contain is missing)
# ---------------------------------------------------------------------------
def _fallback_containment(engine, node_id):
    # Same response SHAPE as graphops.response.contain.recommend_containment:
    # blast_radius is a dict keyed by node id with distance +
    # data_classification per node. (Used only if the contain module import
    # fails; kept schema-identical so the frontend never has to branch.)
    edges = _normalize_edges(engine)
    adj = {}
    for e in edges:
        adj.setdefault(e["src"], []).append(e["dst"])
        adj.setdefault(e["dst"], []).append(e["src"])
    seen = {node_id}
    dist = {node_id: 0}
    frontier = [node_id]
    while frontier:
        cur = frontier.pop(0)
        if dist[cur] >= 4:  # same BFS depth as recommend_containment
            continue
        for nb in adj.get(cur, []):
            if nb not in seen:
                seen.add(nb)
                dist[nb] = dist[cur] + 1
                frontier.append(nb)
    radius = {
        n: {"distance": dist[n],
            "data_classification": _node_classification(engine, n)}
        for n in sorted(seen)  # seed included at distance 0, like the real one
    }
    affected = sorted(n for n in seen if n != node_id)
    return {
        "node_id": node_id,
        "blast_radius": radius,
        "blast_radius_size": len(radius),
        "actions": [
            {"action": "isolate_host", "target": node_id, "priority": "P1",
             "detail": "Quarantine the node from the network immediately."},
            *({"action": "isolate_host", "target": n, "priority": "P2",
                "detail": "Proactive isolation of blast-radius host."} for n in affected),
            {"action": "collect_artifacts", "target": node_id, "priority": "P1",
             "detail": "Snapshot memory/disk and export telemetry before remediation."},
            {"action": "reset_credentials", "target": node_id, "priority": "P2",
             "detail": "Rotate credentials used on the node and any shared service accounts."},
        ],
        "source": "fallback",
    }


# ---------------------------------------------------------------------------
# Engine built ONCE at startup
# ---------------------------------------------------------------------------
def _build_engine():
    try:
        from graphops.intel.generator import generate
        engine, _ground_truth = generate(seed=42)
        return engine, "generator"
    except Exception:
        traceback.print_exc()
        return _demo_engine(), "fallback"


engine, ENGINE_SOURCE = _build_engine()
_NODE_INDEX = {n["id"]: n for n in _normalize_nodes(engine)}
N_NODES = len(_NODE_INDEX)
N_EDGES = len(_normalize_edges(engine))

app = FastAPI(title="GraphOps API", version="0.1.0")


# ---------------------------------------------------------------------------
# /api prefix tolerance. On Vercel the function receives the original path
# (/api/hunt); locally (uvicorn) there is no prefix. Strip it when present.
# ---------------------------------------------------------------------------
try:
    from starlette.middleware.base import BaseHTTPMiddleware

    class _StripApiPrefix(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            p = request.scope.get("path", "")
            if p in ("/api", "/api/"):
                request.scope["path"] = "/"
            elif p.startswith("/api/"):
                request.scope["path"] = p[4:]
            return await call_next(request)

    app.add_middleware(_StripApiPrefix)
except Exception:
    traceback.print_exc()


# ---------------------------------------------------------------------------
# Supabase persistence (optional). If SUPABASE_URL / SUPABASE_SECRET_KEY are
# not set, the app runs fully without persistence — nothing here raises.
# ---------------------------------------------------------------------------
try:
    from graphops.store import supabase_client as _store
except Exception:
    _store = None


class BlastRadiusRequest(BaseModel):
    node_id: str = Field(min_length=1, max_length=256)


@app.get("/health")
def health():
    diag = {
        "status": "ok",
        "nodes": N_NODES,
        "edges": N_EDGES,
        "synthetic": True,
        "engine_source": ENGINE_SOURCE,
        "ingested": _INGESTED_GRAPH is not None,
    }
    # Persistence backend for the containment queue + analyst decisions.
    supabase_up = _store is not None and _store.is_configured()
    diag["persistence"] = "supabase" if supabase_up else "local"
    diag["supabase_configured"] = bool(supabase_up)
    # Analyst-gate queue depth (guarded; never breaks /health).
    try:
        from graphops.response.gate import list_queued as _lq
        diag["queue_depth"] = len(_lq(limit=1000))
    except Exception:
        diag["queue_depth"] = None
    # Neo4j liveness (short timeout, never raises, never leaks creds).
    try:
        from graphops.store import neo4j_client as _neo
        diag["neo4j"] = _neo.ping(timeout=4.0)
    except Exception:
        diag["neo4j"] = {"reachable": False, "latency_ms": None,
                         "error": "client unavailable"}
    return diag


# Finding caps: a single noisy query must not blow up the payload.
MAX_FINDINGS_PER_QUERY = 100
MAX_FINDINGS_TOTAL = 500


@app.post("/hunt")
def hunt(max_findings: int = Query(default=MAX_FINDINGS_TOTAL, ge=1,
                                   le=1000)):
    queries = []
    try:
        from graphops.hunt.queries import (
            hunt_lateral_movement,
            hunt_beaconing,
            hunt_impossible_travel,
            hunt_oauth_scope_creep,
        )
        queries = [
            ("lateral_movement", hunt_lateral_movement),
            ("beaconing", hunt_beaconing),
            ("impossible_travel", hunt_impossible_travel),
            ("oauth_scope_creep", hunt_oauth_scope_creep),
        ]
    except Exception:
        traceback.print_exc()

    findings = []
    for _name, fn in queries:
        try:
            res = fn(engine)
            if res:
                items = res if isinstance(res, list) else [res]
                findings.extend(items[:MAX_FINDINGS_PER_QUERY])
        except Exception:
            traceback.print_exc()  # a failing query contributes nothing, never a 500
    findings = findings[: max(1, min(int(max_findings), 1000))]
    # Every finding ships its evidence chain (signals + subgraph + recommendation).
    try:
        from graphops.hunt.evidence import attach_evidence_chains
        findings = attach_evidence_chains(engine, findings)
    except Exception:
        traceback.print_exc()
    if _store is not None:
        try:
            _store.record_hunt_run(N_NODES, N_EDGES, findings, ENGINE_SOURCE)
        except Exception:
            traceback.print_exc()
    return {"findings": findings}


@app.post("/hunt/privilege-escalation")
def hunt_privilege_escalation():
    findings = []
    try:
        from graphops.hunt.queries import hunt_privilege_escalation as _h
        res = _h(engine)
        if res:
            findings.extend(res if isinstance(res, list) else [res])
    except Exception:
        traceback.print_exc()
    # same evidence-chain contract as /hunt: every finding ships one
    try:
        from graphops.hunt.evidence import attach_evidence_chains
        findings = attach_evidence_chains(engine, findings)
    except Exception:
        traceback.print_exc()
    return {"findings": findings}


@app.post("/hunt/data-staging")
def hunt_data_staging():
    findings = []
    try:
        from graphops.hunt.queries import hunt_data_staging as _h
        res = _h(engine)
        if res:
            findings.extend(res if isinstance(res, list) else [res])
    except Exception:
        traceback.print_exc()
    # same evidence-chain contract as /hunt: every finding ships one
    try:
        from graphops.hunt.evidence import attach_evidence_chains
        findings = attach_evidence_chains(engine, findings)
    except Exception:
        traceback.print_exc()
    return {"findings": findings}


class RedteamRequest(BaseModel):
    seed: int = 42


@app.post("/redteam/replay")
def redteam_replay(req: RedteamRequest):
    try:
        from graphops.redteam.replay import replay
        return replay(seed=int(req.seed))
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="redteam replay failed")


@app.get("/redteam/scenarios")
def redteam_scenarios():
    """Catalog of the scripted end-to-end red-team demo scenarios."""
    try:
        from graphops.redteam.scenarios import list_scenarios
        catalog = list_scenarios()
        return {"scenarios": catalog, "count": len(catalog),
                "synthetic": True}
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="scenarios unavailable")


@app.post("/redteam/run/{scenario_id}")
def redteam_run_scenario(scenario_id: str, seed: int = 42):
    """Replay one scripted scenario against the synthetic seeded graph.

    Returns per-stage detection results plus MTTD, MTTC (detection delay +
    a synthetic analyst-response SLA — containment is recommendations-only
    and never auto-executes), detections fired per hunt, and blast-radius
    precision/recall. NO real system access, NO execution of anything.
    """
    try:
        from graphops.redteam.scenarios import run_scenario, get_scenario
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="scenarios unavailable")
    if get_scenario(scenario_id) is None:
        raise HTTPException(status_code=404,
                            detail=f"unknown scenario {scenario_id!r}")
    return run_scenario(scenario_id, seed=int(seed))


# Cross-scenario metrics rollup: per-hunt-method MTTD + firings plus the
# per-scenario coverage/precision/recall table. Deterministic; cached for
# METRICS_TTL_S so the 7-scenario replay (~4 s) is not paid per request.
_METRICS_CACHE: dict = {"at": 0.0, "seed": None, "payload": None}
METRICS_TTL_S = 300.0


@app.get("/redteam/metrics")
def redteam_metrics(seed: int = Query(default=42, ge=0, le=10 ** 9)):
    now = time.time()
    cached = _METRICS_CACHE
    if (cached["payload"] is not None and cached["seed"] == seed
            and now - cached["at"] < METRICS_TTL_S):
        return cached["payload"]
    try:
        from graphops.redteam.scenarios import rollup_metrics
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="metrics unavailable")
    payload = rollup_metrics(seed=seed)
    cached.update(at=now, seed=seed, payload=payload)
    return payload


@app.post("/blast-radius")
def blast_radius(req: BlastRadiusRequest):
    if req.node_id not in _NODE_INDEX:
        raise HTTPException(status_code=404, detail="unknown node (empty blast radius)")
    try:
        from graphops.response.contain import recommend_containment
        return recommend_containment(engine, req.node_id)
    except ImportError:
        return _fallback_containment(engine, req.node_id)


MAX_GRAPH_NODES = 500
MAX_GRAPH_EDGES = 1500


@app.get("/graph")
def graph_summary():
    nodes = _normalize_nodes(engine)
    edges = _normalize_edges(engine)
    truncated = len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES
    return {
        "nodes": nodes[:MAX_GRAPH_NODES],
        "edges": edges[:MAX_GRAPH_EDGES],
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# Analyst decision gate — the human-in-the-loop audit trail.
# Every containment action an analyst approves/rejects is recorded (Supabase
# when configured). Nothing auto-executes, ever.
# NOTE: these routes must be registered BEFORE the static "/" mount below,
# otherwise the mount shadows them.
# ---------------------------------------------------------------------------
class DecisionRequest(BaseModel):
    node_id: str
    action: str
    target: str = ""
    decision: str  # approved | rejected
    rationale: str = ""


@app.post("/decisions")
def record_decision(req: DecisionRequest):
    if req.decision not in ("approved", "rejected"):
        raise HTTPException(status_code=400, detail="decision must be 'approved' or 'rejected'")
    try:
        from graphops.response.gate import record_analyst_decision
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="decision store unavailable")
    record, store = record_analyst_decision(
        req.node_id, req.action, req.target, req.decision, req.rationale)
    # the queue is the pending work list: a decided action leaves it.
    # resolution failure must never break the audit write above.
    try:
        from graphops.response.gate import resolve_queued_action
        resolve_queued_action(req.node_id, req.action, req.target,
                              req.decision)
    except Exception:
        traceback.print_exc()
    return {"ok": True, "id": record.get("id"), "stored": True,
            "persistence": store}


@app.get("/decisions")
def list_decisions(
        limit: int = Query(default=50, ge=1, le=200),
        status: Optional[str] = Query(default=None, max_length=64),
        action: Optional[str] = Query(default=None, max_length=64),
        min_reversibility: Optional[float] = Query(default=None, ge=0.0,
                                                  le=1.0),
        sort: str = Query(default="newest", pattern="^(newest|oldest)$")):
    """Analyst decision audit trail + approval queue, filterable.

    Filters: ``status`` (decisions: approved|rejected; queue:
    queued_for_approval), ``action`` (exact action name),
    ``min_reversibility`` (queue records only), ``sort`` newest|oldest.
    """
    lim = min(max(limit, 1), 200)
    items, store = [], "local"
    try:
        from graphops.response.gate import list_analyst_decisions
        items, store = list_analyst_decisions(limit=lim)
    except Exception:
        traceback.print_exc()
    # Approval queue: irreversible actions waiting on an analyst, enriched
    # with reversibility scores + business-impact cost. Never auto-executes.
    queue = []
    try:
        from graphops.response.gate import list_queued
        queue = list_queued(limit=lim)
    except Exception:
        traceback.print_exc()

    def _matches_decision(d):
        if status is not None and d.get("decision") != status:
            return False
        if action is not None and d.get("action") != action:
            return False
        return True

    def _matches_queue(q):
        if status is not None and q.get("status") != status:
            return False
        if action is not None and q.get("action") != action:
            return False
        if min_reversibility is not None:
            try:
                if float(q.get("reversibility_score", 0.0)) < min_reversibility:
                    return False
            except (TypeError, ValueError):
                return False
        return True

    items = [d for d in items if _matches_decision(d)]
    queue = [q for q in queue if _matches_queue(q)]
    if sort == "oldest":
        items.reverse()
        queue.reverse()
    return {"decisions": items, "queue": queue,
            "persisted": store == "supabase",
            "persistence": store,
            "queue_persisted": bool(queue)}


# ---------------------------------------------------------------------------
# Reversibility-gated containment proposals.
# POST /contain NEVER executes anything: reversible actions are auto-approved
# as recommendations; irreversible ones are queued behind analyst approval.
# ---------------------------------------------------------------------------
class ContainRequest(BaseModel):
    node_id: str = Field(min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=64)
    target: str = Field(default="", max_length=256)
    context: dict = Field(default_factory=dict)
    requested_by: str = Field(default="analyst", min_length=1, max_length=64)

    @field_validator("context")
    @classmethod
    def _cap_context(cls, v):
        if len(v) > 50:
            raise ValueError("context: at most 50 keys")
        for k, val in v.items():
            if len(str(val)) > 2048:
                raise ValueError(f"context[{k!r}]: value too large")
        return v


def _client_ip(request: Request) -> str:
    try:
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


def _enforce_rate_limit(request: Request, route: str) -> None:
    if _ratelimit is None:
        return
    allowed, retry_after = _ratelimit.check(route, _client_ip(request))
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"rate limit exceeded for /{route}; retry in "
                   f"{int(retry_after)}s",
            headers={"Retry-After": str(int(retry_after))})


@app.post("/contain")
def propose_containment(req: ContainRequest, request: Request):
    _enforce_rate_limit(request, "contain")
    try:
        from graphops.response.gate import evaluate_action, queue_action
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="containment gate unavailable")
    try:
        decision = evaluate_action(req.action, req.node_id, req.target, req.context)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    queued_record, store = None, None
    if decision["status"] == "queued_for_approval":
        try:
            queued_record, store = queue_action(decision, requested_by=req.requested_by)
        except Exception:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail="failed to queue action")
    return {"ok": True, "gate": decision, "queued": queued_record, "store": store}


@app.get("/contain/actions")
def list_containment_actions():
    try:
        from graphops.response.gate import ACTION_CATALOG, AUTO_APPROVE_MIN_REVERSIBILITY
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="containment gate unavailable")
    return {"actions": ACTION_CATALOG,
            "auto_approve_min_reversibility": AUTO_APPROVE_MIN_REVERSIBILITY}


@app.get("/hunt-runs")
def list_hunt_runs(limit: int = 20):
    items = []
    if _store is not None:
        try:
            items = _store.list_hunt_runs(limit=min(max(limit, 1), 100))
        except Exception:
            traceback.print_exc()
    return {"hunt_runs": items, "persisted": _store is not None and _store.is_configured()}


# ---------------------------------------------------------------------------
# Real telemetry ingestion — raw logs in, dynamic graph out.
# POST /ingest accepts CSV or JSON log telemetry (Sysmon / 4624 style),
# builds the graph from the logs alone (zero hardcoded topology), and
# stores it for the telemetry hunts below.
# ---------------------------------------------------------------------------
_INGESTED_GRAPH = None
_INGESTED_META = {}


class IngestRequest(BaseModel):
    logs: str = Field(min_length=1, max_length=5_000_000)  # 5 MB cap
    format: Literal["csv", "json", "auto"] = "auto"


@app.post("/ingest")
def ingest_logs(req: IngestRequest, request: Request):
    _enforce_rate_limit(request, "ingest")
    global _INGESTED_GRAPH, _INGESTED_META
    try:
        from graphops.engine.parser import ingest as _ingest, build_graph as _build
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="ingestion engine unavailable")
    fmt = req.format if req.format in ("csv", "json") else None
    try:
        events = _ingest(req.logs, fmt=fmt)
        G = _build(events)
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail="failed to parse logs")
    _INGESTED_GRAPH = G
    _INGESTED_META = {"events": len(events), "nodes": G.number_of_nodes(),
                      "edges": G.number_of_edges()}
    return {"ok": True, **_INGESTED_META}


def _telemetry_graph():
    # ingested telemetry wins; fall back to the demo engine graph
    if _INGESTED_GRAPH is not None:
        return _INGESTED_GRAPH
    try:
        g = getattr(engine, "graph", None)
        if callable(g):
            g = g()
        return g
    except Exception:
        return None


@app.post("/hunt/beaconing")
def hunt_beaconing():
    try:
        from graphops.engine.beaconing import detect_beaconing as _detect
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="beaconing engine unavailable")
    G = _telemetry_graph()
    if G is None:
        raise HTTPException(status_code=400, detail="no graph: POST /ingest first")
    findings = _detect(G)
    # evidence-chain contract: every finding ships one, like /hunt
    try:
        from graphops.hunt.evidence import attach_evidence_chains
        findings = attach_evidence_chains(G, findings)
    except Exception:
        traceback.print_exc()
    return {"findings": findings, "ingested": _INGESTED_GRAPH is not None}


@app.post("/hunt/lateral")
def hunt_lateral():
    try:
        from graphops.hunt.queries import hunt_lateral_movement_telemetry as _hunt
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="lateral-movement engine unavailable")
    G = _telemetry_graph()
    if G is None:
        raise HTTPException(status_code=400, detail="no graph: POST /ingest first")
    findings = _hunt(G)
    # evidence-chain contract: every finding ships one, like /hunt
    try:
        from graphops.hunt.evidence import attach_evidence_chains
        findings = attach_evidence_chains(G, findings)
    except Exception:
        traceback.print_exc()
    return {"findings": findings, "ingested": _INGESTED_GRAPH is not None}


class PrivilegePathRequest(BaseModel):
    source: str  # e.g. "host:ws-107"


@app.post("/hunt/privilege-paths")
def hunt_privilege_paths(req: PrivilegePathRequest):
    try:
        from graphops.engine.privilege import privilege_weighted_paths as _paths
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="privilege engine unavailable")
    G = _telemetry_graph()
    if G is None:
        raise HTTPException(status_code=400, detail="no graph: POST /ingest first")
    return {"paths": _paths(G, req.source), "ingested": _INGESTED_GRAPH is not None}


# ---------------------------------------------------------------------------
# Serve the dashboard UI from the same process (Docker / Render / Fly /
# Hugging Face single-container deploys). API routes registered above take
# precedence; this mount is the LAST route and only a fallback for "/".
# ---------------------------------------------------------------------------
try:
    from fastapi.staticfiles import StaticFiles

    _DASHBOARD_DIR = _BUILD_DIR / "dashboard"
    if _DASHBOARD_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(_DASHBOARD_DIR), html=True), name="dashboard")
except Exception:
    traceback.print_exc()
