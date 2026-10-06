"""GraphOps identity-trust graph layer.

Models the identity attack surface the SIEM-alert graph misses:

    user --grants--> oauth_token --authorizes--> oauth_app
        --has_scope--> oauth_scope --accesses--> dataset

Edges are weighted by privilege depth + behavioral anomaly so the blast
radius and hunt layers can rank identity paths. All helpers are duck-typed
against GraphEngine (add_entity/add_event; node ids "etype:eid") and never
raise on a partial engine.

SYNTHETIC DATA: seed_identity_layer() fabricates clearly-labeled synthetic
OAuth apps/tokens/scopes/datasets for demo/evaluation. Nothing here is real.
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Model constants
# ---------------------------------------------------------------------------

IDENTITY_NODE_TYPES = ("oauth_token", "oauth_app", "oauth_scope", "dataset")

EDGE_GRANTS = "grants"
EDGE_AUTHORIZES = "authorizes"
EDGE_HAS_SCOPE = "has_scope"
EDGE_ACCESSES = "accesses"

IDENTITY_EDGE_ETYPES = {EDGE_GRANTS, EDGE_AUTHORIZES, EDGE_HAS_SCOPE, EDGE_ACCESSES}

# Scope-name fragments that imply elevated privilege.
ADMIN_SCOPE_HINTS = ("admin", "write", "delete", "impersonate", "full_access")

# Edge base weights by relationship type (privilege depth grows along the chain).
_EDGE_BASE_WEIGHT = {
    EDGE_GRANTS: 0.30,
    EDGE_AUTHORIZES: 0.35,
    EDGE_HAS_SCOPE: 0.45,
    EDGE_ACCESSES: 0.55,
}

# Anomaly weight bumps.
_W_SCOPE_CREEP = 0.25
_W_ADMIN_SCOPE = 0.15
_W_REGULATED_DATASET = 0.10


def identity_edge_weight(src_etype: str, dst_etype: str, edge_attrs: Dict[str, Any] | None) -> float:
    """Risk weight in [0, 1] for an identity-layer edge.

    Base weight comes from the relationship type (deeper privilege = higher
    weight); anomaly signals add bumps: scope creep (+0.25), admin-level
    scopes (+0.15), regulated dataset touched (+0.10). Clamped to [0, 1].
    """
    attrs = edge_attrs or {}
    etype = str(attrs.get("etype", "")).lower()
    w = _EDGE_BASE_WEIGHT.get(etype, 0.40)
    if str(attrs.get("scope_creep", "")).lower() == "true" or attrs.get("scope_creep") is True:
        w += _W_SCOPE_CREEP
    scopes = attrs.get("scopes") or []
    if isinstance(scopes, (list, tuple)):
        if any(any(h in str(s).lower() for h in ADMIN_SCOPE_HINTS) for s in scopes):
            w += _W_ADMIN_SCOPE
    if attrs.get("regulated") is True:
        w += _W_REGULATED_DATASET
    return round(min(max(w, 0.0), 1.0), 3)


# ---------------------------------------------------------------------------
# Synthetic seeding (clearly labeled synthetic data)
# ---------------------------------------------------------------------------

# Baseline scopes per third-party app (minimum-necessary grants).
DEFAULT_APPS = {
    "github-ci": {"baseline_scopes": ["repo:read", "actions:read", "offline_access"]},
    "slack-bot": {"baseline_scopes": ["chat:write", "channels:read", "offline_access"]},
    "salesforce-sync": {"baseline_scopes": ["data:read", "offline_access"]},
    "data-pipeline": {"baseline_scopes": ["datasets:read", "offline_access"]},
}

# Regulated datasets (DPDP-relevant personal data).
DEFAULT_DATASETS = {
    "customer-pii": {"regulated": True, "dpdp": True, "kind": "personal"},
    "finance-ledger": {"regulated": True, "dpdp": True, "kind": "financial"},
    "public-assets": {"regulated": False, "dpdp": False, "kind": "public"},
}

# Which datasets a scope unlocks.
SCOPE_DATASETS = {
    "repo:read": ["public-assets"],
    "actions:read": [],
    "chat:write": [],
    "channels:read": [],
    "channels:history:read": [],
    "data:read": ["customer-pii"],
    "datasets:read": ["customer-pii", "finance-ledger", "public-assets"],
    "offline_access": [],
    "admin:users:write": ["customer-pii", "finance-ledger"],
}


def _syn(**kw) -> Dict[str, Any]:
    """Tag synthetic attrs so synthetic data is never mistaken for real."""
    kw.setdefault("synthetic", True)
    return kw


def seed_identity_layer(
    engine: Any,
    rng: "random.Random | None" = None,
    user_ids: List[str] | None = None,
    anomaly_user: str | None = None,
) -> Dict[str, int]:
    """Seed the identity-trust layer onto a GraphEngine.

    Creates oauth_app / oauth_scope / dataset entities, wires app->scope->
    dataset edges, and issues oauth tokens for a subset of users (one token
    per user, baseline scopes). When anomaly_user is given, that user gets a
    deliberately over-scoped token (scope creep) for the OAuth scope-creep
    hunt to find.

    Returns counts {"apps", "scopes", "datasets", "tokens"}.
    Deterministic given rng. All nodes/edges tagged synthetic=True.
    """
    rng = rng or random.Random(42)

    if user_ids is None:
        g = getattr(engine, "graph", None)
        try:
            user_ids = sorted(
                str(n) for n in g.nodes() if str(n).startswith("user:")
            )
        except Exception:
            user_ids = []

    # -- apps, scopes, datasets -------------------------------------------
    apps = list(DEFAULT_APPS)
    for app in apps:
        engine.add_entity("oauth_app", app, _syn(
            name=app, baseline_scopes=list(DEFAULT_APPS[app]["baseline_scopes"])))
    seen_scopes: set = set()
    for app in apps:
        for scope in DEFAULT_APPS[app]["baseline_scopes"]:
            seen_scopes.add(scope)
            engine.add_entity("oauth_scope", scope, _syn(name=scope))
            engine.add_event(f"oauth_app:{app}", f"oauth_scope:{scope}",
                             EDGE_HAS_SCOPE, 0.0, _syn(baseline=True))
    for ds, attrs in DEFAULT_DATASETS.items():
        engine.add_entity("dataset", ds, _syn(**attrs))
    for scope, datasets in SCOPE_DATASETS.items():
        if scope not in seen_scopes:
            continue
        for ds in datasets:
            reg = bool(DEFAULT_DATASETS.get(ds, {}).get("regulated"))
            engine.add_event(f"oauth_scope:{scope}", f"dataset:{ds}",
                             EDGE_ACCESSES, 0.0,
                             _syn(regulated=reg,
                                   weight=identity_edge_weight(
                                       "oauth_scope", "dataset",
                                       {"etype": EDGE_ACCESSES, "regulated": reg})))

    # -- tokens: one per user, baseline scopes -----------------------------
    tokens = 0
    for i, user in enumerate(user_ids[:40]):
        app = apps[i % len(apps)]
        baseline = list(DEFAULT_APPS[app]["baseline_scopes"])
        tok = f"tok-{i:04d}"
        engine.add_entity("oauth_token", tok, _syn(
            app=app, scopes=baseline, granted_by=user))
        engine.add_event(user, f"oauth_token:{tok}", EDGE_GRANTS, 0.0,
                         _syn(scopes=baseline, scope_creep=False,
                               weight=identity_edge_weight(
                                   "user", "oauth_token",
                                   {"etype": EDGE_GRANTS, "scopes": baseline})))
        engine.add_event(f"oauth_token:{tok}", f"oauth_app:{app}",
                         EDGE_AUTHORIZES, 0.0, _syn())
        tokens += 1

    # -- embedded scope-creep anomaly ---------------------------------------
    if anomaly_user:
        app = "slack-bot"
        baseline = list(DEFAULT_APPS[app]["baseline_scopes"])
        creep_scopes = ["admin:users:write", "channels:history:read"]
        granted = baseline + creep_scopes
        engine.add_entity("oauth_token", "tok-campaign-01", _syn(
            app=app, scopes=granted, granted_by=anomaly_user,
            note="scope creep: admin scopes granted beyond app baseline"))
        for scope in creep_scopes:
            engine.add_entity("oauth_scope", scope, _syn(name=scope))
            engine.add_event(f"oauth_app:{app}", f"oauth_scope:{scope}",
                             EDGE_HAS_SCOPE, 0.0, _syn(baseline=False))
            for ds in SCOPE_DATASETS.get(scope, []):
                reg = bool(DEFAULT_DATASETS.get(ds, {}).get("regulated"))
                engine.add_event(f"oauth_scope:{scope}", f"dataset:{ds}",
                                 EDGE_ACCESSES, 0.0,
                                 _syn(regulated=reg,
                                       weight=identity_edge_weight(
                                           "oauth_scope", "dataset",
                                           {"etype": EDGE_ACCESSES, "regulated": reg})))
        engine.add_event(anomaly_user, "oauth_token:tok-campaign-01",
                         EDGE_GRANTS, 0.0,
                         _syn(scopes=granted, scope_creep=True,
                               note="scope creep: admin scopes granted beyond app baseline",
                               weight=identity_edge_weight(
                                   "user", "oauth_token",
                                   {"etype": EDGE_GRANTS, "scopes": granted,
                                    "scope_creep": True})))
        engine.add_event("oauth_token:tok-campaign-01", f"oauth_app:{app}",
                         EDGE_AUTHORIZES, 0.0, _syn())
        tokens += 1

    return {"apps": len(apps), "scopes": len(seen_scopes),
            "datasets": len(DEFAULT_DATASETS), "tokens": tokens}


# ---------------------------------------------------------------------------
# Neo4j Aura sync for the identity layer
# ---------------------------------------------------------------------------

def sync_identity_layer(engine: Any) -> Optional[Dict[str, Any]]:
    """Sync identity-layer nodes/edges into Neo4j Aura (HTTPS Query API).

    Returns {"nodes": N, "edges": M} or None when Neo4j is not configured or
    unreachable. Never raises. Uses graphops.store.neo4j_client.
    """
    try:
        from graphops.store import neo4j_client as n4
    except Exception:
        return None
    if not n4.is_configured():
        return None

    g = getattr(engine, "graph", None)
    if g is None:
        return None
    try:
        id_nodes = [n for n in g.nodes()
                    if str(n).split(":", 1)[0] in IDENTITY_NODE_TYPES]
        id_set = set(id_nodes)
        id_edges = [(u, v) for u, v in g.edges()
                    if u in id_set and v in id_set]
    except Exception:
        return None

    node_batch = []
    for n in id_nodes:
        try:
            attrs = dict(g.nodes[n])
        except Exception:
            attrs = {}
        etype = str(attrs.pop("etype", str(n).split(":", 1)[0]))
        node_batch.append({"id": str(n), "etype": etype,
                           "props": {k: v for k, v in attrs.items()
                                     if isinstance(v, (str, int, float, bool))
                                     or v is None}})
    edge_batch = []
    for u, v in id_edges:
        try:
            attrs = dict(g.edges[u, v])
        except Exception:
            attrs = {}
        etype = str(attrs.pop("etype", "unknown"))
        edge_batch.append({"src": str(u), "dst": str(v), "etype": etype,
                           "props": {k: v for k, v in attrs.items()
                                     if isinstance(v, (str, int, float, bool))
                                     or v is None}})

    node_cypher = ("UNWIND $batch AS row MERGE (n:GraphOpsEntity {id: row.id}) "
                   "SET n.etype = row.etype, n += row.props")
    edge_cypher = ("UNWIND $batch AS row "
                   "MATCH (a:GraphOpsEntity {id: row.src}), (b:GraphOpsEntity {id: row.dst}) "
                   "MERGE (a)-[r:GraphOpsEvent {src: row.src, dst: row.dst}]->(b) "
                   "SET r.etype = row.etype, r += row.props")
    if n4.run_cypher(node_cypher, {"batch": node_batch}) is None:
        return None
    if edge_batch and n4.run_cypher(edge_cypher, {"batch": edge_batch}) is None:
        return None
    return {"nodes": len(node_batch), "edges": len(edge_batch)}
