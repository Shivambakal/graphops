"""C2 beaconing detector — pure mathematics, no hardcoded indicators.

For every host -> external-IP egress edge set, the detector computes the
inter-arrival times between consecutive connections and derives:

- ``mean``   : average seconds between connections
- ``stdev``  : sample standard deviation of the inter-arrival times
- ``cv``     : coefficient of variation (stdev / mean)

A human browsing the web produces irregular intervals (high CV).  Automated
command-and-control beacons fire on a timer, so the deltas cluster tightly
around the mean (CV near zero).  A finding is raised when at least
``MIN_BEACONS`` connections are observed spanning several expected periods
and the timing is periodic (MITRE T1071).

No IP address, hostname, or interval is hardcoded: periodicity is derived
entirely from the observed timestamps.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List

import networkx as nx


MIN_BEACONS = 6          # minimum connections before timing math is meaningful
MAX_CV = 0.35            # coefficient of variation below this => periodic
MIN_PERIODS_SPANNED = 3  # total span must cover this many mean-intervals


def _node_type(node_id: Any) -> str:
    try:
        return str(node_id).split(":", 1)[0].lower()
    except Exception:
        return ""


def _edge_timestamps(G: nx.DiGraph, src: Any, dst: Any) -> List[float]:
    try:
        data = G.edges[src, dst]
    except Exception:
        return []
    tss = data.get("timestamps") or []
    out = []
    for t in tss:
        try:
            out.append(float(t))
        except (TypeError, ValueError):
            continue
    single = data.get("ts")
    if single is not None:
        try:
            out.append(float(single))
        except (TypeError, ValueError):
            pass
    return sorted(set(out))


def _is_external(G: nx.DiGraph, node_id: Any) -> bool:
    try:
        data = G.nodes[node_id]
    except Exception:
        return False
    val = data.get("external")
    if val is not None:
        return bool(val)
    # fallback: classify from the id itself
    import ipaddress

    eid = str(node_id).split(":", 1)[-1]
    try:
        addr = ipaddress.ip_address(eid)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


def inter_arrival_stats(timestamps: List[float]) -> Dict[str, float]:
    """Compute mean / stdev / CV of inter-arrival times.

    Returns {} when fewer than 2 distinct timestamps exist.
    """
    tss = sorted(set(float(t) for t in timestamps))
    if len(tss) < 2:
        return {}
    deltas = [b - a for a, b in zip(tss, tss[1:])]
    deltas = [d for d in deltas if d >= 0]
    if len(deltas) < 2:
        return {}
    n = len(deltas)
    mean = sum(deltas) / n
    if mean <= 0:
        return {}
    var = sum((d - mean) ** 2 for d in deltas) / (n - 1) if n > 1 else 0.0
    stdev = math.sqrt(var)
    return {
        "count": float(len(tss)),
        "mean_interval": mean,
        "stdev": stdev,
        "cv": stdev / mean,
        "span": tss[-1] - tss[0],
        "min_interval": min(deltas),
        "max_interval": max(deltas),
    }


def is_periodic(stats: Dict[str, float]) -> bool:
    """Decide periodicity purely from the computed statistics."""
    if not stats:
        return False
    if stats.get("count", 0) < MIN_BEACONS:
        return False
    mean = stats.get("mean_interval", 0)
    if mean <= 0:
        return False
    # the observation window must actually span multiple beacon periods;
    # a tight burst of back-to-back connections is not beaconing
    if stats.get("span", 0) < MIN_PERIODS_SPANNED * mean:
        return False
    return stats.get("cv", float("inf")) < MAX_CV


def detect_beaconing(G: Any) -> List[Dict[str, Any]]:
    """Flag host -> external-IP pairs with periodic egress timing.

    Returns findings shaped like the rest of GraphOps:
    {"title", "severity", "evidence", "nodes"} with the computed
    statistics embedded in the evidence strings.
    """
    if G is None or not hasattr(G, "edges"):
        return []
    findings: List[Dict[str, Any]] = []
    try:
        edges = list(G.edges())
    except Exception:
        return []
    seen = set()
    for src, dst in edges:
        if (src, dst) in seen:
            continue
        seen.add((src, dst))
        if _node_type(src) != "host" or _node_type(dst) != "ip":
            continue
        if not _is_external(G, dst):
            continue
        tss = _edge_timestamps(G, src, dst)
        stats = inter_arrival_stats(tss)
        if not is_periodic(stats):
            continue
        evidence = [
            f"{src} -> {dst}: {int(stats['count'])} egress connections over "
            f"{stats['span']:.0f}s",
            f"inter-arrival mean={stats['mean_interval']:.1f}s "
            f"stdev={stats['stdev']:.1f}s cv={stats['cv']:.3f} "
            f"(periodic beaconing threshold cv<{MAX_CV})",
            "MITRE T1071: automated C2-style beaconing — timing too regular "
            "for human activity",
        ]
        findings.append(
            {
                "title": f"C2 beaconing (T1071): {src} -> {dst}",
                "severity": "critical",
                "evidence": evidence,
                "nodes": [src, dst],
                "stats": {
                    "count": int(stats["count"]),
                    "mean_interval": stats["mean_interval"],
                    "stdev": stats["stdev"],
                    "cv": stats["cv"],
                },
            }
        )
    return findings
