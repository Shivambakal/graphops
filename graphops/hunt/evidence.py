"""Evidence chains for GraphOps hunt findings.

Every finding ships an evidence chain: which signals fired, the local
subgraph the finding rests on, and a recommended containment action.
RECOMMENDATIONS ONLY — nothing here executes anything.
"""

from __future__ import annotations

from typing import Any, Dict, List

MAX_SUBGRAPH_NODES = 100
MAX_SUBGRAPH_EDGES = 200

# Severity -> recommended containment template. "requires_approval" marks
# irreversible actions that must sit behind the analyst gate; nothing here
# executes — the response layer only recommends or queues.
_SEVERITY_ACTION = {
    "critical": {"action": "isolate_host", "requires_approval": True,
                 "reversibility": 0.70},
    "high": {"action": "flag_account", "requires_approval": False,
             "reversibility": 0.95},
    "medium": {"action": "observe", "requires_approval": False,
               "reversibility": 1.00},
    "low": {"action": "enrich_alert", "requires_approval": False,
            "reversibility": 1.00},
}


def _get_graph(engine: Any):
    g = getattr(engine, "graph", None)
    if g is None:
        return None
    if callable(g):
        try:
            g = g()
        except Exception:
            return None
    return g


def _subgraph_slice(engine: Any, seed_nodes: List[Any],
                    max_hops: int = 1) -> Dict[str, Any]:
    """1-hop (default) slice around the finding's nodes.

    Returns {"nodes": [ids], "edges": [{src, dst, etype, ts}]} capped at
    MAX_SUBGRAPH_NODES / MAX_SUBGRAPH_EDGES. Defensive: returns empty slice
    when the graph is unavailable.
    """
    G = _get_graph(engine)
    if G is None:
        return {"nodes": [], "edges": []}
    seeds = [s for s in (seed_nodes or []) if s]
    seen: List[Any] = []
    seen_set = set()
    for s in seeds:
        if s not in seen_set:
            seen.append(s)
            seen_set.add(s)
    try:
        for _ in range(max_hops):
            frontier = list(seen)
            for n in frontier:
                try:
                    nbrs = list(G.successors(n)) + list(G.predecessors(n))
                except Exception:
                    continue
                for m in nbrs:
                    if m not in seen_set and len(seen) < MAX_SUBGRAPH_NODES:
                        seen.append(m)
                        seen_set.add(m)
    except Exception:
        pass
    nodes = [str(n) for n in seen]
    edges: List[Dict[str, Any]] = []
    try:
        for u, v, attrs in G.edges(data=True):
            if len(edges) >= MAX_SUBGRAPH_EDGES:
                break
            if u in seen_set and v in seen_set:
                attrs = attrs if isinstance(attrs, dict) else {}
                edges.append({
                    "src": str(u),
                    "dst": str(v),
                    "etype": str(attrs.get("etype", "unknown")),
                    "ts": attrs.get("ts"),
                })
    except Exception:
        pass
    return {"nodes": nodes, "edges": edges}


def _detection_method(title: str) -> str:
    t = str(title or "").lower()
    if "impossible travel" in t:
        return "impossible_travel"
    if "beacon" in t:
        return "beaconing"
    if "lateral" in t:
        return "lateral_movement"
    if "privilege" in t:
        return "privilege_escalation"
    if "staging" in t:
        return "data_staging"
    if "scope" in t or "oauth" in t:
        return "oauth_scope_creep"
    return "heuristic"


def _recommended_action(finding: Dict[str, Any]) -> Dict[str, Any]:
    severity = str(finding.get("severity", "medium")).lower()
    template = _SEVERITY_ACTION.get(severity, _SEVERITY_ACTION["medium"])
    nodes = finding.get("nodes") or []
    target = str(nodes[0]) if nodes else ""
    return {
        "action": template["action"],
        "target": target,
        "requires_approval": template["requires_approval"],
        "reversibility": template["reversibility"],
        "executed": False,
        "note": ("recommendation only — queued for analyst approval" if
                 template["requires_approval"] else
                 "recommendation only — reversible, no auto-execution"),
    }


def build_evidence_chain(engine: Any, finding: Dict[str, Any]) -> Dict[str, Any]:
    """Build the evidence chain for one finding dict.

    Never raises: on any failure returns a minimal chain with the finding's
    own evidence text and an empty subgraph.
    """
    try:
        evidence = finding.get("evidence") or []
        nodes = finding.get("nodes") or []
        chain = {
            "detection_method": _detection_method(finding.get("title", "")),
            "signals": list(evidence),
            "signal_count": len(evidence),
            "subgraph": _subgraph_slice(engine, nodes),
            "recommended_action": _recommended_action(finding),
            "synthetic": True,
        }
        return chain
    except Exception:
        return {
            "detection_method": "unknown",
            "signals": list(finding.get("evidence") or []),
            "signal_count": len(finding.get("evidence") or []),
            "subgraph": {"nodes": [], "edges": []},
            "recommended_action": _recommended_action(finding),
            "synthetic": True,
        }


def attach_evidence_chains(engine: Any,
                           findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach an evidence_chain to each finding (in place, returns findings).

    Never raises and never drops a finding: if chain building fails the
    finding is returned unchanged.
    """
    out = []
    for f in findings or []:
        try:
            f = dict(f)
            f["evidence_chain"] = build_evidence_chain(engine, f)
        except Exception:
            pass
        out.append(f)
    return out
