"""DPDP data-classification overlay for GraphOps nodes.

Every node carries a ``data_classification``: one of
  ``regulated`` | ``personal`` | ``internal`` | ``public``

- Dataset nodes are classified from their own attributes
  (``regulated``/``dpdp`` flags, ``kind``).
- Every other node inherits the highest classification of any dataset
  reachable through the identity graph (user -> token -> app -> scope ->
  dataset, directed BFS up to 5 hops).
- Nodes with no dataset linkage default to ``internal`` — the safe
  default: never assume public.

Ranking: regulated (4) > personal (3) > internal (2) > public (1).

All classifications derive from the synthetic seeded graph (synthetic=True
is set by the generator); nothing here is real data.
"""

from __future__ import annotations

from typing import Any, Dict

CLASSIFICATIONS = ("regulated", "personal", "internal", "public")
_RANK = {"public": 1, "internal": 2, "personal": 3, "regulated": 4}
_DATASET_ETYPES = {"dataset", "data_set", "dataasset", "data_asset"}

# Directed BFS depth: user -> token -> app -> scope -> dataset is 4 hops.
_MAX_HOPS = 5


def _dataset_class(attrs: Dict[str, Any]) -> str:
    """Classify a dataset node from its own attributes."""
    if bool(attrs.get("regulated")) or bool(attrs.get("dpdp")):
        return "regulated"
    kind = str(attrs.get("kind", "")).strip().lower()
    if kind in ("personal", "pii", "sensitive"):
        return "personal"
    if kind in ("financial", "phi", "health"):
        # Financial/health data is regulated personal data.
        return "personal"
    if kind == "public":
        return "public"
    return "internal"


def _is_dataset(node_id: str, attrs: Dict[str, Any]) -> bool:
    etype = str(attrs.get("etype", "")).strip().lower()
    if etype in _DATASET_ETYPES:
        return True
    return str(node_id).split(":", 1)[0].strip().lower() in _DATASET_ETYPES


def classify_node(engine: Any, node_id: str) -> str:
    """Return the DPDP data classification for a node.

    Dataset nodes: classified from their own attributes. All other nodes:
    the highest classification of any dataset reachable via directed
    out-edges (identity-graph linkage), else "internal" (safe default).
    Never raises: any failure degrades to "internal".
    """
    try:
        graph = getattr(engine, "graph", None)
        if graph is None:
            return "internal"
        try:
            attrs = dict(graph.nodes[node_id])
        except Exception:
            return "internal"

        if _is_dataset(node_id, attrs):
            return _dataset_class(attrs)

        # BFS over directed out-edges toward dataset nodes.
        best = "internal"
        seen = {node_id}
        frontier = [node_id]
        for _ in range(_MAX_HOPS):
            nxt = []
            for cur in frontier:
                try:
                    succ = list(graph.successors(cur))
                except Exception:
                    succ = []
                for s in succ:
                    if s in seen:
                        continue
                    seen.add(s)
                    try:
                        sattrs = dict(graph.nodes[s])
                    except Exception:
                        sattrs = {}
                    if _is_dataset(s, sattrs):
                        cand = _dataset_class(sattrs)
                        if _RANK[cand] > _RANK[best]:
                            best = cand
                            if best == "regulated":
                                return best
                    else:
                        nxt.append(s)
            frontier = nxt
            if not frontier:
                break
        return best
    except Exception:
        return "internal"
