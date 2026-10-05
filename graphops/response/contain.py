"""Blast radius containment recommendations for the GraphOps MVP.

RECOMMENDATIONS ONLY: this module never executes anything. It inspects the
graph, computes who is in the blast radius of a compromised node, and returns
a prioritized list of recommended containment actions for a human analyst.

Contract:
    recommend_containment(engine, compromised_node) -> {
        "blast_radius": {node_id: {"distance": int, "risk_score": float}},
        "actions": [ {action, target, priority, rationale, status} ]
    }
where blast_radius comes from engine.blast_radius(compromised_node, max_hops=4).
"""

from __future__ import annotations

from typing import Any, Dict, List

MAX_ACTIONS = 25
STATUS_RECOMMENDED = "recommended"

# Canonical node-type categories we act on, with the raw attribute spellings
# that map into each category.
_HOST_TYPES = {"host", "asset", "machine", "endpoint", "server", "workstation"}
_USER_TYPES = {"user", "account", "identity", "principal"}
_IP_TYPES = {"ip", "external_ip", "external", "attacker_ip", "c2", "c2_ip", "exfil_ip"}


def _node_type(engine: Any, node_id: str) -> str | None:
    """Best-effort node type lookup: attribute first, id-prefix heuristic second.

    The sibling graph-engine worker stores node metadata on the underlying
    networkx graph (engine.graph). Known conventions tried:
      1. node attribute "type" or "node_type" (e.g. "host", "user", "external_ip")
      2. id prefix heuristic ("host-01", "user-jdoe", "ip-8.8.8.8", "ext-...")
    Returns one of "host" / "user" / "ip", or None if it cannot be determined.
    """
    graph = getattr(engine, "graph", None)
    attrs: Dict[str, Any] = {}
    if graph is not None:
        try:
            if node_id in graph:
                attrs = dict(graph.nodes[node_id])
        except Exception:
            attrs = {}

    raw = attrs.get("type", attrs.get("node_type", attrs.get("etype", "")))
    t = str(raw).strip().lower()
    if t in _HOST_TYPES:
        return "host"
    if t in _USER_TYPES:
        return "user"
    if t in _IP_TYPES:
        return "ip"

    # Engine convention: node ids are "<etype>:<eid>" (e.g. "host:ws-007").
    # Try the colon prefix before the dash-style heuristic below.
    colon_prefix = str(node_id).split(":", 1)[0].strip().lower()
    if colon_prefix in _HOST_TYPES:
        return "host"
    if colon_prefix in _USER_TYPES:
        return "user"
    if colon_prefix in _IP_TYPES:
        return "ip"

    # Fallback: id prefix heuristic (e.g. "host-01", "user-2", "ip-203.0.113.7").
    name = str(node_id).lower().split(":", 1)[-1]
    for prefix, cat in (("host", "host"), ("user", "user"), ("ip", "ip"),
                        ("ext", "ip"), ("asset", "host")):
        if name == prefix or name.startswith(prefix + "-") \
                or name.startswith(prefix + "_") or name.startswith(prefix + "."):
            return cat
    return None


def _has_node(engine: Any, node_id: str) -> bool:
    """True if the node exists; conservative True when we cannot tell."""
    graph = getattr(engine, "graph", None)
    if graph is not None:
        try:
            return node_id in graph
        except Exception:
            return True
    return True


def _make_action(action: str, target: str, priority: str, rationale: str) -> Dict[str, Any]:
    return {
        "action": action,
        "target": target,
        "priority": priority,
        "rationale": rationale,
        "status": STATUS_RECOMMENDED,
    }


def recommend_containment(engine: Any, compromised_node: str) -> Dict[str, Any]:
    """Recommend containment actions for a confirmed-compromised node.

    Pure function: reads from the engine, never mutates the graph and never
    executes any containment. Every returned action carries status="recommended".
    """
    if not _has_node(engine, compromised_node):
        return {"blast_radius": {}, "actions": []}

    try:
        radius = engine.blast_radius(compromised_node, max_hops=4)
    except (KeyError, ValueError):
        return {"blast_radius": {}, "actions": []}

    if not isinstance(radius, dict):
        return {"blast_radius": {}, "actions": []}

    p1: List[Dict[str, Any]] = []
    p2: List[Dict[str, Any]] = []

    for node_id, info in radius.items():
        info = info or {}
        distance = int(info.get("distance", 0))
        kind = _node_type(engine, node_id)
        if kind is None:
            continue

        if kind == "host":
            if distance <= 2:
                (p1 if distance == 0 else p2).append(_make_action(
                    "isolate host",
                    node_id,
                    "P1" if distance == 0 else "P2",
                    f"within {distance} hops of confirmed compromise {compromised_node}",
                ))
        elif kind == "user":
            for action, verb in (
                ("revoke user sessions", "revoke"),
                ("force password reset", "reset"),
            ):
                p2.append(_make_action(
                    action,
                    node_id,
                    "P2",
                    f"{verb} credentials in blast radius of confirmed compromise "
                    f"{compromised_node} (distance {distance})",
                ))
        elif kind == "ip":
            p1.append(_make_action(
                "block IP at firewall",
                node_id,
                "P1",
                "suspected C2/exfiltration endpoint",
            ))

    actions = p1 + p2
    return {"blast_radius": radius, "actions": actions[:MAX_ACTIONS]}
