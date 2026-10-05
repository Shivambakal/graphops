"""GraphOps MVP — graph engine.

GraphEngine wraps networkx.DiGraph and exposes the blast-radius and
attack-path primitives used by proactive threat hunting and containment.
"""

from __future__ import annotations

import networkx as nx

_NODE_ID_SEPARATOR = ":"


class GraphEngine:
    """Directed entity/relationship graph for SOC threat hunting.

    Node ids are strings of the form "<etype>:<eid>", e.g. "host:web-01".
    """

    ENTITY_TYPES = ("host", "user", "ip", "process", "alert")

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------ #
    # builders
    # ------------------------------------------------------------------ #
    def add_entity(self, etype: str, eid: str, attrs: dict | None = None) -> str:
        """Add (or update) an entity node. Idempotent.

        Returns the node id.
        """
        node_id = f"{etype}{_NODE_ID_SEPARATOR}{eid}"
        data = dict(attrs or {})
        data["etype"] = etype
        if node_id in self.graph:
            self.graph.nodes[node_id].update(data)
        else:
            self.graph.add_node(node_id, **data)
        return node_id

    def _infer_etype(self, node_id: str) -> str:
        prefix = node_id.split(_NODE_ID_SEPARATOR, 1)[0]
        return prefix if prefix in self.ENTITY_TYPES else "unknown"

    def _ensure_node(self, node_id: str) -> None:
        if node_id not in self.graph:
            etype = self._infer_etype(node_id)
            self.graph.add_node(node_id, etype=etype)

    def add_event(
        self,
        src: str,
        dst: str,
        etype: str,
        ts: float,
        attrs: dict | None = None,
    ) -> tuple[str, str]:
        """Add a directed event edge between two node-id strings.

        Endpoints are auto-created with etype inferred from the id prefix
        when missing. Returns (src, dst).
        """
        self._ensure_node(src)
        self._ensure_node(dst)
        data = dict(attrs or {})
        data["etype"] = etype
        data["ts"] = float(ts)
        self.graph.add_edge(src, dst, **data)
        return src, dst

    # ------------------------------------------------------------------ #
    # analysis
    # ------------------------------------------------------------------ #
    def blast_radius(self, node_id: str, max_hops: int = 4) -> dict:
        """BFS over the undirected view from node_id up to max_hops.

        Returns {node_id: {"distance": int, "risk_score": float}}.
        risk_score = 100.0 * 0.6^distance (+25.0 if the node carries a
        "severity" attribute), clamped to 100.0.
        """
        if node_id not in self.graph:
            return {}

        undirected = self.graph.to_undirected()
        distances = nx.single_source_shortest_path_length(
            undirected, node_id, cutoff=max_hops
        )

        result = {}
        for nid, distance in distances.items():
            risk = 100.0 * (0.6 ** distance)
            if "severity" in self.graph.nodes[nid]:
                risk += 25.0
            result[nid] = {"distance": distance, "risk_score": min(risk, 100.0)}
        return result

    def shortest_attack_path(self, src: str, dst: str) -> list:
        """Directed shortest path from src to dst, or [] if none exists."""
        if src not in self.graph or dst not in self.graph:
            return []
        try:
            return list(nx.shortest_path(self.graph, src, dst))
        except nx.NetworkXNoPath:
            return []

    def neighbors(self, node_id: str) -> list:
        """List of (neighbor_id, edge_attrs) for in- and out-neighbors."""
        if node_id not in self.graph:
            return []
        out = [
            (nbr, dict(self.graph.edges[node_id, nbr])) for nbr in self.graph.successors(node_id)
        ]
        inb = [
            (nbr, dict(self.graph.edges[nbr, node_id])) for nbr in self.graph.predecessors(node_id)
        ]
        return out + inb
