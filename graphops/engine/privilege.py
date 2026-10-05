"""Privilege-weighted graph traversal — blast radius that respects privilege.

Enterprise reality: network reachability is not exploitability.  A path that
climbs toward Domain Admin is far more dangerous than a flat path across
workstations, even at the same hop count.  This module tiers assets and runs
Dijkstra/A* where the edge cost *decreases* as the traversal moves toward
higher privilege — modelling how cheap escalation is for an attacker who
already holds credentials (MITRE T1134, Access Token Manipulation).

Tiers
----
- Tier 0: domain controllers / AD / identity plane. Detected from hostname
  patterns (``dc``, ``ad``, ``domaincontroller``) or an explicit ``tier`` /
  ``role`` attribute on the node or in the logs.
- Tier 1: servers, databases, infrastructure.
- Tier 2: endpoints / workstations (default).

No hostname is hardcoded: tiers come from patterns and log attributes.
"""

from __future__ import annotations

import itertools
import re
from typing import Any, Dict, List, Tuple

import networkx as nx


TIER_DC_PATTERNS = (
    re.compile(r"(^|[^a-z])dcs?([^a-z]|$)", re.IGNORECASE),       # dc, dc01, dcs
    re.compile(r"domain[_-]?controller", re.IGNORECASE),
    re.compile(r"(^|[^a-z])ads?([^a-z]|$)", re.IGNORECASE),        # ad, ad01
    re.compile(r"active[_-]?directory", re.IGNORECASE),
    re.compile(r"identity", re.IGNORECASE),
    re.compile(r"krb|kdc", re.IGNORECASE),
)

TIER_SERVER_PATTERNS = (
    re.compile(r"(^|[^a-z])srv([^a-z]|$)", re.IGNORECASE),         # srv, srv01
    re.compile(r"server", re.IGNORECASE),
    re.compile(r"\bdb\b|database|sql|postgres|mysql|mongo", re.IGNORECASE),
    re.compile(r"file[_-]?share|nas\b", re.IGNORECASE),
    re.compile(r"backup", re.IGNORECASE),
    re.compile(r"exchange|mail", re.IGNORECASE),
    re.compile(r"web[_-]?(srv|server)?", re.IGNORECASE),
)

TIER_WORKSTATION_PATTERNS = (
    re.compile(r"(^|[^a-z])ws([^a-z]|$)", re.IGNORECASE),          # ws, ws-007
    re.compile(r"wkstn|workstation|laptop|desktop|pc\d", re.IGNORECASE),
)


def _node_eid(node_id: Any) -> str:
    try:
        return str(node_id).split(":", 1)[-1].lower()
    except Exception:
        return ""


def _node_attrs(G: Any, node_id: Any) -> Dict[str, Any]:
    try:
        data = G.nodes[node_id]
    except Exception:
        return {}
    return dict(data) if isinstance(data, dict) else {}


def asset_tier(G: Any, node_id: Any) -> int:
    """Return 0, 1, or 2 for a host node. Non-hosts return 2 (least privileged).

    Explicit ``tier``/``role`` attributes from the logs win; otherwise
    hostname patterns decide. Nothing host-specific is hardcoded.
    """
    attrs = _node_attrs(G, node_id)
    try:
        explicit = attrs.get("tier")
        if explicit is not None and str(explicit).strip() != "":
            t = int(float(str(explicit).strip()))
            if t in (0, 1, 2):
                return t
    except (TypeError, ValueError):
        pass
    role = str(attrs.get("role", "")).lower()
    if any(k in role for k in ("domain_controller", "domaincontroller", "ad ", " active directory", "identity", "kdc")):
        return 0
    if any(k in role for k in ("server", "database", "db", "file", "backup", "mail")):
        return 1
    eid = _node_eid(node_id)
    if any(p.search(eid) for p in TIER_DC_PATTERNS):
        return 0
    if any(p.search(eid) for p in TIER_SERVER_PATTERNS):
        return 1
    if any(p.search(eid) for p in TIER_WORKSTATION_PATTERNS):
        return 2
    # unknown hosts default to endpoint tier; servers are never assumed
    return 2


def privilege_edge_cost(G: Any, u: Any, v: Any, base: float = 1.0) -> float:
    """Edge cost for privilege-weighted traversal.

    Moving *up* in privilege (toward tier 0) is cheap for an attacker with
    stolen credentials; moving laterally or down is full price.  This makes
    Dijkstra prefer paths that escalate — the paths defenders fear most.
    """
    tu = asset_tier(G, u)
    tv = asset_tier(G, v)
    if tv < tu:
        # escalation: each tier climbed multiplies cost down
        return base * (0.25 ** (tu - tv))
    if tv > tu:
        # moving down-privilege is uninteresting for escalation paths
        return base * (1.5 ** (tv - tu))
    return base


def tier0_targets(G: Any) -> List[Any]:
    """All Tier-0 (crown jewel) nodes in the graph."""
    targets = []
    try:
        nodes = list(G.nodes())
    except Exception:
        return []
    for n in nodes:
        try:
            ntype = str(n).split(":", 1)[0].lower()
        except Exception:
            continue
        if ntype == "host" and asset_tier(G, n) == 0:
            targets.append(n)
    return targets


def privilege_weighted_paths(
    G: Any,
    source: Any,
    max_paths: int = 5,
) -> List[Dict[str, Any]]:
    """Rank privilege-escalation paths from ``source`` to Tier-0 assets.

    Uses Dijkstra with privilege-weighted costs, then enumerates the
    cheapest simple paths (up to ``max_paths``).  Each result carries the
    path, its weighted cost, the tier transitions, and MITRE T1134 tags
    wherever the path climbs privilege.
    """
    if G is None or not hasattr(G, "nodes"):
        return []
    try:
        if source not in G:
            return []
    except Exception:
        return []
    targets = [t for t in tier0_targets(G) if t != source]
    if not targets:
        return []

    def weight(u: Any, v: Any, _d: Any) -> float:
        return privilege_edge_cost(G, u, v)

    results: List[Dict[str, Any]] = []
    for target in targets:
        try:
            # cheapest path first via Dijkstra
            primary = nx.dijkstra_path(G, source, target, weight=weight)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        except Exception:
            continue
        # a few alternates: k shortest simple paths by the same weight
        try:
            paths = list(itertools.islice(
                nx.shortest_simple_paths(G, source, target, weight=weight),
                max_paths,
            ))
        except Exception:
            paths = [primary]
        for path in paths:
            cost = 0.0
            climbs = []
            for a, b in zip(path, path[1:]):
                c = privilege_edge_cost(G, a, b)
                cost += c
                ta, tb = asset_tier(G, a), asset_tier(G, b)
                if tb < ta:
                    climbs.append(f"{a}(T{ta}) -> {b}(T{tb})")
            results.append(
                {
                    "target": target,
                    "path": list(path),
                    "weighted_cost": round(cost, 4),
                    "hops": len(path) - 1,
                    "privilege_climbs": climbs,
                    "mitre": ["T1134"] if climbs else [],
                }
            )
    results.sort(key=lambda r: (r["weighted_cost"], r["hops"]))
    return results[: max_paths * max(len(targets), 1)][: max_paths * 3]
