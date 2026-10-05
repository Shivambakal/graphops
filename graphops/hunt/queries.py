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
    # tolerate a raw networkx graph passed directly (parser-built telemetry)
    try:
        import networkx as _nx

        if isinstance(engine, _nx.Graph):
            return engine
    except Exception:
        pass
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
# hunt: privilege escalation (user -> admin via group nesting or token theft)
# ---------------------------------------------------------------------------

_PRIV_VALUES = {"admin", "administrator", "root", "system", "domain admin",
                "enterprise admin", "da"}
_PRIVESC_TECHNIQUES = {"T1134", "T1068", "T1055", "T1548", "T1134.001",
                       "T1134.002", "T1078"}
_MEMBERSHIP_ETYPES = {"member_of", "member", "in_group", "belongs_to", "nested_in"}
_STAGING_TOOLS = {"7z.exe", "7za.exe", "rar.exe", "winrar.exe", "tar",
                  "zip", "unzip"}


def _is_priv_grant(info: Dict[str, Any]) -> bool:
    """True when an edge payload signals privilege acquisition."""
    priv = str(info.get("priv", "") or "").strip().lower()
    if priv in _PRIV_VALUES:
        return True
    note = str(info.get("note", "") or "").lower()
    if "privileg" in note and ("escalat" in note or "elevation" in note):
        return True
    tech = str(info.get("technique", "") or "").upper().strip()
    if tech in _PRIVESC_TECHNIQUES:
        return True
    return False


def _is_privileged_group(G: Any, node_id: Any) -> bool:
    """True when a group-ish node looks administratively privileged."""
    if _node_type(node_id) not in {"group", "role"}:
        return False
    attrs = _node_attrs(G, node_id)
    if _is_truthy(attrs.get("admin")) or _is_truthy(attrs.get("privileged")):
        return True
    eid = str(node_id).split(":", 1)[-1].lower()
    name = str(attrs.get("name", "") or "").lower()
    return "admin" in eid or "admin" in name or "domain admins" in name


def _origin_user(G: Any, node_id: Any, max_hops: int = 6) -> List[Any]:
    """Path from an originating user to node_id; [] if none.

    Prefers paths that traverse suspicious edges (the attack chain) over
    incidental background logons: candidates are scored by (#suspicious
    edges, -length) so the campaign path wins ties.
    """
    try:
        import networkx as nx

        def edge_suspicious(u, v):
            return _is_truthy(_edge_info(G, u, v).get("suspicious"))

        users = [n for n in G.nodes() if _node_type(n) == "user"]
        scored = []
        for u in users:
            try:
                for path in nx.all_shortest_paths(G, u, node_id):
                    if len(path) - 1 > max_hops:
                        continue
                    susp = sum(
                        1 for a, b in zip(path, path[1:]) if edge_suspicious(a, b)
                    )
                    scored.append((susp, -len(path), path))
            except Exception:
                continue
        if not scored:
            return []
        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        return scored[0][2]
    except Exception:
        return []


def hunt_privilege_escalation(engine: Any) -> List[Dict[str, Any]]:
    """Find privilege-escalation signals: admin-grant edges and nested groups.

    Flags (a) edges whose attrs grant admin-level privilege (priv=admin,
    privilege-escalation notes, MITRE privesc techniques), and (b) group
    nesting chains user -> group -> ... -> privileged group. Each finding
    traces the path back to the originating user.
    """
    G = _get_graph(engine)
    if G is None:
        return []
    findings: List[Dict[str, Any]] = []
    try:
        edges = list(G.edges())
    except Exception:
        return []

    # (a) direct privilege-grant edges
    for src, dst in edges:
        info = _edge_info(G, src, dst)
        if not _is_priv_grant(info):
            continue
        ts = info.get("ts") or info.get("timestamp")
        path = _origin_user(G, src)
        origin = path[0] if path else src
        tech = str(info.get("technique", "") or "").upper().strip()
        priv = str(info.get("priv", "") or "").strip()
        evidence = [
            f"{src} -> {dst} at {_fmt_ts(ts)}: privilege grant "
            f"(priv={priv or 'n/a'}, technique={tech or 'n/a'})"
        ]
        if path and len(path) > 1:
            evidence.append(
                f"escalation path: {' -> '.join(str(p) for p in path)} -> {dst}"
            )
        severity = "critical" if (tech or "lsass" in str(dst).lower()) else "high"
        findings.append(
            {
                "title": f"Privilege escalation: {origin} reached admin via {dst}",
                "severity": severity,
                "evidence": evidence,
                "nodes": list(dict.fromkeys([origin, src, dst])),
            }
        )

    # (b) group nesting: user -> group+ -> privileged group
    try:
        import networkx as nx
        membership = [
            (u, v) for u, v in edges
            if _edge_etype(_edge_info(G, u, v)) in _MEMBERSHIP_ETYPES
        ]
        if membership:
            sub = nx.DiGraph()
            sub.add_edges_from(membership)
            for node in list(sub.nodes()):
                if not _is_privileged_group(G, node):
                    continue
                for user in [n for n in sub.nodes() if _node_type(n) == "user"]:
                    try:
                        path = nx.shortest_path(sub, user, node)
                    except Exception:
                        continue
                    if len(path) < 3:  # need real nesting, not direct membership
                        continue
                    findings.append(
                        {
                            "title": f"Privilege escalation: {user} nested into "
                                     f"privileged group {node}",
                            "severity": "high",
                            "evidence": [
                                f"group nesting path: "
                                f"{' -> '.join(str(p) for p in path)}"
                            ],
                            "nodes": path,
                        }
                    )
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# hunt: data staging (archive/collect before exfiltration)
# ---------------------------------------------------------------------------

def _is_staging_edge(G: Any, src: Any, dst: Any, info: Dict[str, Any]) -> bool:
    if _node_type(src) != "host" or _node_type(dst) != "process":
        return False
    eid = str(dst).split(":", 1)[-1].lower()
    if eid in _STAGING_TOOLS:
        return True
    note = str(info.get("note", "") or "").lower()
    if "stag" in note:
        return True
    cmdline = str(info.get("cmdline", "") or "").lower()
    if any(t in cmdline for t in ("7z", ".rar", ".zip", "compress", "archive")):
        return True
    return False


def _is_exfil_edge(G: Any, src: Any, dst: Any, info: Dict[str, Any]) -> bool:
    if _node_type(src) != "host" or _node_type(dst) != "ip":
        return False
    if not _is_external_ip(str(dst).split(":", 1)[-1]):
        return False
    note = str(info.get("note", "") or "").lower()
    if "exfil" in note:
        return True
    try:
        if float(info.get("bytes") or 0) >= 100_000_000:
            return True
    except (TypeError, ValueError):
        pass
    return _is_truthy(info.get("suspicious")) and _edge_etype(info) == "network"


def hunt_data_staging(engine: Any) -> List[Dict[str, Any]]:
    """Find data-staging activity and correlate it with later exfiltration.

    Flags host -> archiving-process edges (7z/rar/zip, staging notes,
    archive cmdlines). When the same host later talks to an external IP
    with exfiltration signals, the finding is critical and links both.
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
        info = _edge_info(G, src, dst)
        if not _is_staging_edge(G, src, dst, info):
            continue
        ts = info.get("ts") or info.get("timestamp")
        try:
            ts_f = float(ts) if ts is not None else None
        except (TypeError, ValueError):
            ts_f = None
        # correlate: same host -> external ip with exfil signals afterwards
        exfil_evidence: List[str] = []
        exfil_dst = None
        for s2, d2 in edges:
            if s2 != src:
                continue
            info2 = _edge_info(G, s2, d2)
            if not _is_exfil_edge(G, s2, d2, info2):
                continue
            ts2 = info2.get("ts") or info2.get("timestamp")
            try:
                ts2_f = float(ts2) if ts2 is not None else None
            except (TypeError, ValueError):
                ts2_f = None
            if ts_f is not None and ts2_f is not None and ts2_f < ts_f:
                continue  # exfil before staging: not this pattern
            exfil_dst = d2
            exfil_evidence.append(
                f"{s2} -> {d2} at {_fmt_ts(ts2)}: exfiltration signal after staging"
            )
            break
        evidence = [
            f"{src} -> {dst} at {_fmt_ts(ts)}: data staging "
            f"(cmdline={str(info.get('cmdline', 'n/a'))[:80]})"
        ]
        evidence.extend(exfil_evidence)
        severity = "critical" if exfil_dst else "high"
        nodes = [src, dst] + ([exfil_dst] if exfil_dst else [])
        findings.append(
            {
                "title": f"Data staging: {src} archived data via {dst}"
                         + (f" before exfiltration to {exfil_dst}" if exfil_dst else ""),
                "severity": severity,
                "evidence": evidence,
                "nodes": nodes,
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


# ---------------------------------------------------------------------------
# hunt: lateral movement from raw telemetry (parser-built graphs)
# ---------------------------------------------------------------------------

_ADMIN_SHARES = {"C$", "ADMIN$", "IPC$"}


def _edge_share(info: Dict[str, Any]) -> Optional[str]:
    share = info.get("share")
    if share is None:
        return None
    s = str(share).strip().upper()
    return s or None


def hunt_lateral_movement_telemetry(engine: Any) -> List[Dict[str, Any]]:
    """Detect lateral movement from raw log telemetry.

    Works on parser-built graphs (edges carry ``logon_type`` / ``share`` /
    ``etype="logon"`` from Windows 4624 / Sysmon events).  Flags:

    - Logon Type 3 (network logon) between two workstations/endpoints.
      Admins log on to servers, not workstation-to-workstation — a Type 3
      hop between endpoints is a classic lateral-movement signal.
    - Any edge involving administrative shares (C$, ADMIN$, IPC$).

    Tagged MITRE T1021.002 (SMB/Windows Admin Shares).  No hostnames,
    users, or shares are hardcoded; everything derives from edge attrs.
    """
    G = _get_graph(engine)
    if G is None:
        return []
    try:
        from graphops.engine.privilege import asset_tier
    except Exception:
        asset_tier = None  # type: ignore

    def _tier(n: Any) -> int:
        if asset_tier is not None:
            try:
                return asset_tier(G, n)
            except Exception:
                pass
        return 2

    findings: List[Dict[str, Any]] = []
    try:
        edges = list(G.edges())
    except Exception:
        return []
    for src, dst in edges:
        if _node_type(src) != "host" or _node_type(dst) != "host":
            continue
        info = _edge_info(G, src, dst)
        logon_type = info.get("logon_type")
        try:
            logon_type = int(str(logon_type)) if logon_type is not None else None
        except (TypeError, ValueError):
            logon_type = None
        share = _edge_share(info)
        admin_share = share in _ADMIN_SHARES

        ws_to_ws_type3 = (
            logon_type == 3 and _tier(src) == 2 and _tier(dst) == 2
        )
        if not ws_to_ws_type3 and not admin_share:
            continue

        ts = info.get("ts") or info.get("timestamp")
        evidence: List[str] = []
        if ws_to_ws_type3:
            evidence.append(
                f"{src} -> {dst} at {_fmt_ts(ts)}: network logon (Type 3) "
                f"between two workstations — atypical for legitimate "
                f"administration (MITRE T1021.002)"
            )
        if admin_share:
            evidence.append(
                f"{src} -> {dst} at {_fmt_ts(ts)}: administrative share "
                f"{share} accessed (MITRE T1021.002)"
            )
        severity = "critical" if (ws_to_ws_type3 and admin_share) else "high"
        findings.append(
            {
                "title": f"Lateral movement (T1021.002): {src} -> {dst}",
                "severity": severity,
                "evidence": evidence,
                "nodes": [src, dst],
                "mitre": ["T1021.002"],
            }
        )
    return findings
