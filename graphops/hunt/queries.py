"""GraphOps hunt queries for proactive threat hunting.

Each function takes a ``GraphEngine`` (contract: wraps a networkx.DiGraph as
``engine.graph``; node ids are ``f"{etype}:{eid}"``; edges carry
``etype``/``ts``/``attrs``) and returns a list of findings.  A finding is::

    {"title": str,
     "severity": "low|medium|high|critical",
     "evidence": [human-readable strings],
     "nodes": [node ids involved]}

All functions are defensive: they tolerate missing engine/graph attributes,
missing node/edge fields, and always return [] (never crash) on an empty or
unusable engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# defensive access helpers
# ---------------------------------------------------------------------------

def _get_graph(engine: Any):
    """Return the underlying networkx DiGraph or None."""
    g = getattr(engine, "graph", None)
    if g is None:
        return None
    if callable(g):  # tolerate a graph() accessor instead of an attribute
        try:
            g = g()
        except Exception:
            return None
    return g


def _node_type(node_id: Any) -> str:
    try:
        return str(node_id).split(":", 1)[0].lower()
    except Exception:
        return ""


def _node_attrs(G: Any, node_id: Any) -> Dict[str, Any]:
    try:
        data = G.nodes[node_id]
    except Exception:
        return {}
    if isinstance(data, dict):
        attrs = data.get("attrs")
        merged = dict(data)
        if isinstance(attrs, dict):
            for k, v in attrs.items():
                merged.setdefault(k, v)
        return merged
    return {}


def _edge_info(G: Any, src: Any, dst: Any) -> Dict[str, Any]:
    """Merged edge payload: top-level keys win, nested 'attrs' fills gaps."""
    try:
        raw = G.edges[src, dst]
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    merged: Dict[str, Any] = {}
    nested = raw.get("attrs")
    if isinstance(nested, dict):
        merged.update(nested)
    merged.update(raw)
    return merged


def _edge_etype(info: Dict[str, Any]) -> str:
    return str(info.get("etype") or "").lower()


def _is_truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        s = value.strip().lower()
        return bool(s) and s not in {"false", "no", "0", "none", "null", "unknown"}
    return bool(value)


def _alert_detail(G: Any, node_id: Any) -> Optional[Dict[str, Any]]:
    """Describe an alert attached to a node, or None.

    Supports: node attrs (alert/alert_id/alerts), and alert neighbours
    (node with etype 'alert' or an edge with etype 'alert').
    """
    attrs = _node_attrs(G, node_id)
    aid = attrs.get("alert_id") or attrs.get("alert")
    if _is_truthy(aid):
        return {
            "id": str(aid),
            "severity": str(attrs.get("alert_severity", "unknown")),
        }
    alerts = attrs.get("alerts")
    if isinstance(alerts, (list, tuple)) and alerts:
        first = alerts[0]
        if isinstance(first, dict):
            return {
                "id": str(first.get("id", first.get("alert_id", "ALERT-unknown"))),
                "severity": str(first.get("severity", "unknown")),
            }
        return {"id": str(first), "severity": "unknown"}
    try:
        nbrs = list(G.successors(node_id)) + list(G.predecessors(node_id))
    except Exception:
        nbrs = []
    for n in nbrs:
        if _node_type(n) == "alert":
            na = _node_attrs(G, n)
            return {
                "id": str(na.get("alert_id", n)),
                "severity": str(na.get("severity", "unknown")),
            }
        try:
            for (s, d) in ((node_id, n), (n, node_id)):
                if G.has_edge(s, d) and _edge_etype(_edge_info(G, s, d)) == "alert":
                    return {"id": str(n), "severity": str(_edge_info(G, s, d).get("severity", "unknown"))}
        except Exception:
            continue
    return None


def _fmt_ts(ts: Any) -> str:
    if ts is None:
        return "unknown time"
    return str(ts)


def _is_external_ip(eid: str) -> bool:
    """RFC-1918 + loopback/link-local check."""
    e = eid.strip().lower()
    if e in {"localhost", "::1"}:
        return False
    if e.startswith("10."):
        return False
    if e.startswith("192.168."):
        return False
    if e.startswith("172."):
        try:
            second = int(e.split(".")[1])
            if 16 <= second <= 31:
                return False
        except (IndexError, ValueError):
            pass
    if e.startswith("127.") or e.startswith("169.254."):
        return False
    return True


def _suspicious_path(G: Any, src: Any, dst: Any) -> List[Any]:
    """Shortest path src->dst using only suspicious lateral edges; [] if none."""
    try:
        import networkx as nx

        def lateral(u, v):
            t = {_node_type(u), _node_type(v)}
            et = _edge_etype(_edge_info(G, u, v))
            return (
                ("host" in t)
                and et in {"network", "smb", "winrm", "lateral"}
                and _is_truthy(_edge_info(G, u, v).get("suspicious"))
            )

        sub = nx.subgraph_view(G, filter_edge=lateral)
        return list(nx.shortest_path(sub, src, dst))
    except Exception:
        return []


# ---------------------------------------------------------------------------
# hunt: lateral movement
# ---------------------------------------------------------------------------

_LATERAL_ETYPES = {"network", "smb", "winrm", "lateral"}


def hunt_lateral_movement(engine: Any) -> List[Dict[str, Any]]:
    """Find host->host lateral-movement edges with suspicious signal.

    An edge qualifies when it is a network/smb/winrm/lateral edge AND
    (the source host has an alert attached OR the edge is marked
    suspicious=True in its attrs).
    """
    G = _get_graph(engine)
    if G is None:
        return []
    findings: List[Dict[str, Any]] = []
    try:
        edges = list(G.edges())
    except Exception:
        return []
    for src, dst in edges:
        if _node_type(src) != "host" or _node_type(dst) != "host":
            continue
        info = _edge_info(G, src, dst)
        if _edge_etype(info) not in _LATERAL_ETYPES:
            continue
        suspicious_edge = _is_truthy(info.get("suspicious"))
        alert = _alert_detail(G, src)
        if not suspicious_edge and alert is None:
            continue
        ts = info.get("ts") or info.get("timestamp")
        etype = _edge_etype(info)
        evidence: List[str] = []
        if alert is not None:
            evidence.append(
                f"{src} -> {dst} via {etype} at {_fmt_ts(ts)}: "
                f"source host has {alert['severity']} alert {alert['id']}"
            )
        if suspicious_edge:
            evidence.append(
                f"{src} -> {dst} via {etype} at {_fmt_ts(ts)}: "
                "edge flagged suspicious=True"
            )
        path = _suspicious_path(G, src, dst)
        if len(path) > 2:
            evidence.append(
                f"path of length {len(path) - 1} from {src} reaches "
                f"{path[-1]} via {' -> '.join(str(p) for p in path)}"
            )
        elif len(path) == 2:
            evidence.append(f"path of length 1 from {src} reaches {dst}")
        findings.append(
            {
                "title": f"Lateral movement: {src} -> {dst} via {etype}",
                "severity": "high",
                "evidence": evidence,
                "nodes": [src, dst],
            }
        )
    return findings


# ---------------------------------------------------------------------------
# hunt: beaconing / C2-style exfiltration
# ---------------------------------------------------------------------------

def hunt_beaconing(engine: Any) -> List[Dict[str, Any]]:
    """Find host->external-ip edges with suspicious outbound activity.

    Flags any host->ip edge marked suspicious=True where the ip is external
    (not RFC-1918/loopback/link-local).  Severity is critical when the ip node
    carries an alert or an edge is labeled exfiltration, else high.
    """
    G = _get_graph(engine)
    if G is None:
        return []
    findings: List[Dict[str, Any]] = []
    try:
        edges = list(G.edges())
    except Exception:
        return []
    for src, dst in edges:
        if _node_type(src) != "host" or _node_type(dst) != "ip":
            continue
        eid = str(dst).split(":", 1)[-1]
        if not _is_external_ip(eid):
            continue
        info = _edge_info(G, src, dst)
        if not _is_truthy(info.get("suspicious")):
            continue
        ts = info.get("ts") or info.get("timestamp")
        # aggregate parallel edges between the same host/ip pair
        pairs = [(u, v) for u, v in edges if u == src and v == dst]
        tss = [
            _edge_info(G, u, v).get("ts") or _edge_info(G, u, v).get("timestamp")
            for u, v in pairs
        ]
        tss = [t for t in tss if t is not None]
        first, last = (min(tss), max(tss)) if tss else (ts, ts)
        ip_alert = _alert_detail(G, dst)
        et = _edge_etype(info)
        exfil = (
            et == "exfiltration"
            or _is_truthy(info.get("exfiltration"))
            or str(info.get("action", "")).lower() == "exfiltration"
        )
        severity = "critical" if (ip_alert is not None or exfil) else "high"
        evidence = [
            f"{src} -> {dst}: {len(pairs)} suspicious outbound connection(s), "
            f"first {_fmt_ts(first)} last {_fmt_ts(last)}"
        ]
        if ip_alert is not None:
            evidence.append(
                f"destination {dst} has {ip_alert['severity']} alert {ip_alert['id']}"
            )
        if exfil:
            evidence.append(f"{src} -> {dst} labeled exfiltration")
        findings.append(
            {
                "title": f"Possible beaconing: {src} -> {dst}",
                "severity": severity,
                "evidence": evidence,
                "nodes": [src, dst],
            }
        )
    return findings


# ---------------------------------------------------------------------------
# hunt: impossible travel
# ---------------------------------------------------------------------------

_AUTH_ETYPES = {"auth", "login", "logon", "session", "auth_event", "authentication"}


def hunt_impossible_travel(engine: Any) -> List[Dict[str, Any]]:
    """Find users authenticating from two distinct geos within 3600 seconds.

    Auth events are edges with an auth-like etype from a user node to an
    ip/host node; the target's geo attr is used.  Generic: any two distinct
    geo values inside the window flag a finding.
    """
    G = _get_graph(engine)
    if G is None:
        return []
    try:
        edges = list(G.edges())
    except Exception:
        return []
    # user -> [(geo, ts, src, dst)]
    logins: Dict[Any, List[Any]] = {}
    for src, dst in edges:
        if _node_type(src) != "user":
            continue
        et = _edge_etype(_edge_info(G, src, dst))
        if not any(k in et for k in ("auth", "login", "logon", "session")):
            continue
        if _node_type(dst) not in {"ip", "host"}:
            continue
        geo = _node_attrs(G, dst).get("geo")
        if geo is None:
            continue
        info = _edge_info(G, src, dst)
        ts = info.get("ts") or info.get("timestamp")
        if ts is None:
            continue
        try:
            ts_f = float(ts)
        except (TypeError, ValueError):
            continue
        logins.setdefault(src, []).append((str(geo), ts_f, dst))
    findings: List[Dict[str, Any]] = []
    for user, events in logins.items():
        events.sort(key=lambda e: e[1])
        best = None  # (geo_a, geo_b, dt, a_dst, b_dst)
        for i in range(len(events)):
            for j in range(i + 1, len(events)):
                geo_a, ts_a, dst_a = events[i]
                geo_b, ts_b, dst_b = events[j]
                if geo_a == geo_b:
                    continue
                dt = ts_b - ts_a
                if dt < 0 or dt >= 3600:
                    continue
                if best is None or dt < best[2]:
                    best = (geo_a, geo_b, dt, dst_a, dst_b)
        if best is None:
            continue
        geo_a, geo_b, dt, dst_a, dst_b = best
        minutes = int(dt // 60)
        evidence = [
            f"{user} authenticated from geo {geo_a} and geo {geo_b} "
            f"within {minutes} minutes"
        ]
        severity = "high" if dt < 900 else "medium"
        findings.append(
            {
                "title": f"Impossible travel: {user} ({geo_a} -> {geo_b})",
                "severity": severity,
                "evidence": evidence,
                "nodes": [user, dst_a, dst_b],
            }
        )
    return findings
