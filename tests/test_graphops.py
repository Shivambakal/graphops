"""GraphOps MVP test suite.

Runs against the REAL modules in graphops/ — no mocks of the system under
test, no weakened assertions. Each test asserts observable behaviour of the
actual code.
"""

from __future__ import annotations

import pytest

from graphops.graph.engine import GraphEngine
from graphops.intel.generator import generate
from graphops.hunt.queries import (
    hunt_beaconing,
    hunt_impossible_travel,
    hunt_lateral_movement,
)
from graphops.response.contain import recommend_containment


# ---------------------------------------------------------------------------
# 1. Engine correctness on a tiny hand-built graph
# ---------------------------------------------------------------------------

def _tiny_graph() -> GraphEngine:
    eng = GraphEngine()
    eng.add_entity("host", "web-01")
    eng.add_entity("host", "db-01")
    eng.add_entity("user", "u1")
    eng.add_event("host:web-01", "host:db-01", "network", 1.0)
    eng.add_event("user:u1", "host:web-01", "auth", 1.0)
    return eng


def test_engine_blast_radius_distances_on_tiny_graph():
    eng = _tiny_graph()
    radius = eng.blast_radius("host:web-01", max_hops=2)
    distances = {nid: info["distance"] for nid, info in radius.items()}
    assert distances == {
        "host:web-01": 0,
        "host:db-01": 1,
        "user:u1": 1,
    }


def test_engine_blast_radius_risk_scores_decay_with_distance():
    eng = _tiny_graph()
    radius = eng.blast_radius("host:web-01", max_hops=2)
    assert radius["host:web-01"]["risk_score"] == pytest.approx(100.0)
    assert radius["host:db-01"]["risk_score"] == pytest.approx(60.0)
    assert radius["user:u1"]["risk_score"] == pytest.approx(60.0)


def test_engine_shortest_attack_path_follows_directed_edges():
    eng = _tiny_graph()
    assert eng.shortest_attack_path("user:u1", "host:db-01") == [
        "user:u1",
        "host:web-01",
        "host:db-01",
    ]


def test_engine_shortest_attack_path_respects_direction():
    eng = _tiny_graph()
    # No directed path from db-01 back to web-01 or to the user.
    assert eng.shortest_attack_path("host:db-01", "user:u1") == []
    assert eng.shortest_attack_path("host:db-01", "host:web-01") == []


def test_engine_unknown_node_returns_empty():
    eng = _tiny_graph()
    assert eng.blast_radius("host:nope") == {}
    assert eng.shortest_attack_path("host:web-01", "host:nope") == []
    assert eng.shortest_attack_path("host:nope", "host:web-01") == []


# ---------------------------------------------------------------------------
# 2. Generator determinism
# ---------------------------------------------------------------------------

def _edge_signature(engine: GraphEngine):
    """Sorted (src, dst, sorted-attrs) tuples — a canonical edge list."""
    return sorted(
        (src, dst, tuple(sorted(attrs.items())))
        for src, dst, attrs in engine.graph.edges(data=True)
    )


def test_generator_deterministic_seed_42():
    engine_a, gt_a = generate(42)
    engine_b, gt_b = generate(42)

    assert engine_a.graph.number_of_nodes() == engine_b.graph.number_of_nodes()
    assert engine_a.graph.number_of_edges() == engine_b.graph.number_of_edges()

    edges_a = sorted(engine_a.graph.edges(data=True), key=lambda e: (e[0], e[1]))
    edges_b = sorted(engine_b.graph.edges(data=True), key=lambda e: (e[0], e[1]))
    assert len(edges_a) == len(edges_b)
    assert _edge_signature(engine_a) == _edge_signature(engine_b)
    assert [gt_a] == [gt_b]


def test_generator_graph_is_nontrivial():
    engine, gt = generate(42)
    assert engine.graph.number_of_nodes() > 100
    assert engine.graph.number_of_edges() > 1000
    assert gt["compromised_hosts"]
    assert gt["attack_path"]
    assert gt["seed"] == 42


# ---------------------------------------------------------------------------
# 3. Ground-truth hunt
# ---------------------------------------------------------------------------

def _finding_nodes(findings) -> list:
    """Union of every finding's nodes list."""
    seen = set()
    for f in findings:
        assert isinstance(f.get("nodes"), list)
        seen.update(f["nodes"])
    return seen


def test_hunt_lateral_movement_covers_all_compromised_hosts():
    engine, gt = generate(42)
    findings = hunt_lateral_movement(engine)
    assert findings, "expected at least one lateral-movement finding"
    hit_nodes = _finding_nodes(findings)
    for host in gt["compromised_hosts"]:
        assert host in hit_nodes, f"compromised host {host} not in any finding"


def test_hunt_beaconing_finds_exfiltration_ip():
    engine, gt = generate(42)
    exfil_ip = gt["attack_path"][-1]
    assert exfil_ip == "ip:203.0.113.9"
    findings = hunt_beaconing(engine)
    assert findings, "expected at least one beaconing finding"
    hit_nodes = _finding_nodes(findings)
    assert exfil_ip in hit_nodes, f"exfil ip {exfil_ip} not in any finding"


def test_hunt_functions_are_defensive_on_empty_engine():
    empty = GraphEngine()
    assert hunt_lateral_movement(empty) == []
    assert hunt_beaconing(empty) == []
    assert hunt_impossible_travel(empty) == []


# ---------------------------------------------------------------------------
# 4. Containment
# ---------------------------------------------------------------------------

_ACTION_KEYS = {"action", "target", "priority", "rationale", "status"}


def test_containment_recommends_actions_for_compromised_host():
    engine, gt = generate(42)
    host = gt["compromised_hosts"][0]
    result = recommend_containment(engine, host)

    assert result["blast_radius"], "blast radius must be non-empty"
    assert host in result["blast_radius"]
    assert result["blast_radius"][host]["distance"] == 0

    actions = result["actions"]
    assert actions, "expected at least one containment action"
    for a in actions:
        assert set(a.keys()) == _ACTION_KEYS, f"bad action keys: {set(a.keys())}"
        assert a["status"] == "recommended"
        assert a["priority"] in ("P1", "P2")
        assert a["target"] in result["blast_radius"] or a["target"] == host


def test_containment_p1_actions_precede_p2():
    engine, gt = generate(42)
    actions = recommend_containment(engine, gt["compromised_hosts"][0])["actions"]
    priorities = [a["priority"] for a in actions]
    # No P2 may appear before a P1: the sequence must be P1* P2*.
    seen_p2 = False
    for p in priorities:
        if p == "P2":
            seen_p2 = True
        assert not (p == "P1" and seen_p2), f"ordering violated: {priorities}"


def test_containment_unknown_node_is_empty():
    engine, _gt = generate(42)
    result = recommend_containment(engine, "host:nope")
    assert result == {"blast_radius": {}, "actions": []}


# ---------------------------------------------------------------------------
# 5. API smoke (real FastAPI app, real generated engine)
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient

from graphops.api.server import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_api_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["nodes"] > 0
    assert body["edges"] > 0


def test_api_hunt_returns_findings(client):
    r = client.post("/hunt")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert isinstance(findings, list)
    assert len(findings) >= 1


def test_api_blast_radius_for_real_node(client):
    node_id = client.get("/graph").json()["nodes"][0]["id"]
    r = client.post("/blast-radius", json={"node_id": node_id})
    assert r.status_code == 200
    body = r.json()
    assert "actions" in body
    assert "blast_radius" in body


def test_api_blast_radius_unknown_node_is_404(client):
    r = client.post("/blast-radius", json={"node_id": "host:nope"})
    assert r.status_code == 404
