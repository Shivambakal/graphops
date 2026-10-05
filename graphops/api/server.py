"""GraphOps API server — hunt + blast-radius + graph summary over a synthetic SOC graph.

Engine source priority:
  1. graphops.intel.generator.generate(seed=42)  (sibling module)
  2. Tiny built-in demo engine (3 hosts + 1 alert) so the server ALWAYS starts.

All sibling imports are wrapped in try/except with duck-typed fallbacks.
"""

import sys
import traceback
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Make the build dir importable so sibling graphops.* modules resolve.
_BUILD_DIR = Path(__file__).resolve().parents[2]
if str(_BUILD_DIR) not in sys.path:
    sys.path.insert(0, str(_BUILD_DIR))


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
                })
            elif isinstance(n, (tuple, list)) and len(n) == 2:
                nid, attrs = n
                attrs = attrs or {}
                if isinstance(attrs, dict):
                    nodes.append({
                        "id": str(nid),
                        "etype": str(attrs.get("etype", "unknown")),
                        "label": str(attrs.get("label", nid)),
                    })
                else:
                    nodes.append({"id": str(nid), "etype": "unknown", "label": str(nid)})
            else:
                nodes.append({"id": str(n), "etype": "unknown", "label": str(n)})
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
    edges = _normalize_edges(engine)
    adj = {}
    for e in edges:
        adj.setdefault(e["src"], []).append(e["dst"])
        adj.setdefault(e["dst"], []).append(e["src"])
    seen = {node_id}
    frontier = [node_id]
    while frontier:
        cur = frontier.pop()
        for nb in adj.get(cur, []):
            if nb not in seen:
                seen.add(nb)
                frontier.append(nb)
    affected = sorted(seen - {node_id})
    return {
        "node_id": node_id,
        "blast_radius": [{"id": n} for n in affected],
        "blast_radius_size": len(affected),
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


class BlastRadiusRequest(BaseModel):
    node_id: str


@app.get("/health")
def health():
    return {"status": "ok", "nodes": N_NODES, "edges": N_EDGES, "synthetic": True}


@app.post("/hunt")
def hunt():
    queries = []
    try:
        from graphops.hunt.queries import (
            hunt_lateral_movement,
            hunt_beaconing,
            hunt_impossible_travel,
        )
        queries = [
            ("lateral_movement", hunt_lateral_movement),
            ("beaconing", hunt_beaconing),
            ("impossible_travel", hunt_impossible_travel),
        ]
    except Exception:
        traceback.print_exc()

    findings = []
    for _name, fn in queries:
        try:
            res = fn(engine)
            if res:
                findings.extend(res if isinstance(res, list) else [res])
        except Exception:
            traceback.print_exc()  # a failing query contributes nothing, never a 500
    return {"findings": findings}


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
