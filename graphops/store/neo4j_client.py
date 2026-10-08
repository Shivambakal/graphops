"""Neo4j Aura sync for GraphOps — HTTPS Query API client.

AuraDB Free exposes the Query API v2
(https://<instance>.databases.neo4j.io/db/<database>/query/v2); Bolt is
unreachable from sandboxed networks, so every operation here goes over HTTPS
with Basic auth. Credentials resolve in this order:

  1. NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD / NEO4J_DATABASE env vars
  2. .neo4j-credentials.txt next to the build root (chmod 600, gitignored)

If no credentials resolve, every function degrades gracefully (None/False)
and nothing raises. The password is NEVER logged.

Uses stdlib urllib only (no extra dependency); honors proxy env vars.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict

_TIMEOUT = 60
_BATCH = 500

_CREDS_FILE = Path(__file__).resolve().parents[2] / ".neo4j-credentials.txt"


def _cfg():
    """Return (base_url, username, password, database) or None."""
    uri = os.environ.get("NEO4J_URI", "").strip()
    user = os.environ.get("NEO4J_USERNAME", "").strip()
    pw = os.environ.get("NEO4J_PASSWORD", "")
    db = os.environ.get("NEO4J_DATABASE", "").strip()
    if uri and user and pw:
        instance = uri.split("://", 1)[-1]
        return f"https://{instance}/db/{db or 'neo4j'}/query/v2", user, pw, db or "neo4j"
    try:
        file_creds: dict = {}
        with open(_CREDS_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    file_creds[k.strip()] = v.strip()
        f_uri = file_creds.get("NEO4J_URI", "")
        f_user = file_creds.get("NEO4J_USERNAME", "")
        f_pw = file_creds.get("NEO4J_PASSWORD", "")
        f_db = file_creds.get("NEO4J_DATABASE", "") or "neo4j"
        if f_uri and f_user and f_pw:
            instance = f_uri.split("://", 1)[-1]
            return f"https://{instance}/db/{f_db}/query/v2", f_user, f_pw, f_db
    except OSError:
        pass
    return None


def is_configured() -> bool:
    return _cfg() is not None


def _redact(msg: str) -> str:
    """Strip anything credential-shaped from an error message."""
    cfg = _cfg()
    if cfg:
        _, user, pw, _ = cfg
        for secret in (pw, user):
            if secret and len(secret) >= 4:
                msg = msg.replace(secret, "<redacted>")
    return msg


def run_cypher(statement: str, params: dict | None = None):
    """Run one Cypher statement. Returns list of row-dicts, or None on failure.

    Never raises, never logs credentials.
    """
    cfg = _cfg()
    if not cfg:
        return None
    url, user, pw, _db = cfg
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    payload = {"statement": statement, "parameters": params or {}}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            body = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:300]
        except Exception:
            detail = ""
        print(f"[neo4j] HTTP {e.code}: {_redact(detail)}")
        return None
    except Exception as e:  # network / timeout / TLS
        print(f"[neo4j] request failed: {_redact(str(e))[:200]}")
        return None
    errors = body.get("errors")
    if errors:
        print(f"[neo4j] cypher errors: {_redact(json.dumps(errors)[:300])}")
        return None
    data = body.get("data") or {}
    fields = data.get("fields") or []
    values = data.get("values") or []
    return [dict(zip(fields, row)) for row in values]


def ping(timeout: float = 5.0) -> Dict[str, Any]:
    """Liveness check against the Neo4j HTTPS Query API.

    Returns {"reachable": bool, "latency_ms": int|None, "error": str|None}.
    Never raises, never logs credentials. Uses its own short timeout so a
    health endpoint can call it safely.
    """
    import time as _time

    if not is_configured():
        return {"reachable": False, "latency_ms": None,
                "error": "neo4j not configured"}
    cfg = _cfg()
    if not cfg:
        return {"reachable": False, "latency_ms": None,
                "error": "neo4j credentials unresolved"}
    url, user, pw, _db = cfg
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=json.dumps({"statement": "RETURN 1 AS ok"}).encode(),
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    started = _time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return {"reachable": False, "latency_ms": None,
                "error": f"http {e.code}"}
    except Exception as e:
        return {"reachable": False, "latency_ms": None,
                "error": _redact(str(e))[:120]}
    latency = int((_time.time() - started) * 1000)
    if body.get("errors"):
        return {"reachable": False, "latency_ms": latency,
                "error": _redact(json.dumps(body["errors"])[:120])}
    return {"reachable": True, "latency_ms": latency, "error": None}


def _scalar(v):
    """Keep only Neo4j-safe scalar property values."""
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)[:500]


def _iter_nodes(engine):
    g = getattr(engine, "graph", None)
    if g is None:
        return
    # DPDP overlay: keep the graph layer's classification attribute in sync
    # with what the API serves (graphops.graph.classification). Computed,
    # never raises; skipped silently if the classifier is unavailable.
    try:
        from graphops.graph.classification import (
            classify_node as _classify_node)
    except Exception:
        _classify_node = None  # type: ignore[assignment]
    try:
        items = list(g.nodes(data=True))
    except Exception:
        return
    for nid, attrs in items:
        attrs = attrs if isinstance(attrs, dict) else {}
        etype = str(attrs.get("etype", "unknown"))
        props = {k: _scalar(v) for k, v in attrs.items() if k != "etype"}
        if _classify_node is not None and "data_classification" not in props:
            try:
                props["data_classification"] = _classify_node(engine, str(nid))
            except Exception:
                pass
        yield {"id": str(nid), "etype": etype, "props": props}


def _iter_edges(engine):
    g = getattr(engine, "graph", None)
    if g is None:
        return
    try:
        items = list(g.edges(data=True))
    except Exception:
        return
    for src, dst, attrs in items:
        attrs = attrs if isinstance(attrs, dict) else {}
        etype = str(attrs.get("etype", "unknown"))
        props = {k: _scalar(v) for k, v in attrs.items() if k != "etype"}
        yield {"src": str(src), "dst": str(dst), "etype": etype, "props": props}


def _chunks(items, n):
    items = list(items)
    for i in range(0, len(items), n):
        yield items[i:i + n]


_NODE_SYNC = """\
UNWIND $batch AS row
MERGE (n:GraphOpsEntity {id: row.id})
SET n.etype = row.etype, n += row.props
"""

_EDGE_SYNC = """\
UNWIND $batch AS row
MATCH (a:GraphOpsEntity {id: row.src}), (b:GraphOpsEntity {id: row.dst})
MERGE (a)-[r:GraphOpsEvent {src: row.src, dst: row.dst}]->(b)
SET r.etype = row.etype, r += row.props
"""


def sync_graph(engine) -> dict | None:
    """Idempotently sync the NetworkX graph into Neo4j Aura.

    Returns {"nodes": N, "edges": M, "ms": t} or None when not configured
    or any batch fails. Safe to re-run: MERGE keeps it idempotent.
    """
    if not is_configured():
        return None
    t0 = time.time()
    node_batches = list(_chunks(_iter_nodes(engine), _BATCH))
    edge_batches = list(_chunks(_iter_edges(engine), _BATCH))
    nodes = edges = 0
    for batch in node_batches:
        if run_cypher(_NODE_SYNC, {"batch": batch}) is None:
            return None
        nodes += len(batch)
    for batch in edge_batches:
        if run_cypher(_EDGE_SYNC, {"batch": batch}) is None:
            return None
        edges += len(batch)
    return {"nodes": nodes, "edges": edges, "ms": int((time.time() - t0) * 1000)}


def clear_graph() -> bool:
    """Delete all GraphOpsEntity nodes/relationships. Returns success."""
    if not is_configured():
        return False
    ok = run_cypher(
        "MATCH (n:GraphOpsEntity) DETACH DELETE n"
    )
    return ok is not None


def count_by_etype():
    """Return [{etype, n}] node counts grouped by etype, or None."""
    return run_cypher(
        "MATCH (n:GraphOpsEntity) RETURN n.etype AS etype, count(*) AS n "
        "ORDER BY n DESC"
    )
