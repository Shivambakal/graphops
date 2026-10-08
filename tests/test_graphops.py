"""GraphOps MVP test suite.

Runs against the REAL modules in graphops/ — no mocks of the system under
test, no weakened assertions. Each test asserts observable behaviour of the
actual code.
"""

from __future__ import annotations

import os

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


# ---------------------------------------------------------------------------
# 6. Analyst decision gate (graceful when Supabase is not configured)
# ---------------------------------------------------------------------------

def test_decision_endpoint_validates_input(client):
    r = client.post("/decisions", json={
        "node_id": "host:ws-007", "action": "isolate_host",
        "target": "host:ws-007", "decision": "maybe",
    })
    assert r.status_code == 400


def test_decision_endpoint_accepts_approve_and_reject(client, tmp_path):
    # Redirect the local decisions store so the test never touches the repo.
    os.environ["GRAPHOPS_DECISIONS_PATH"] = str(tmp_path / "decisions.json")
    try:
        for d in ("approved", "rejected"):
            r = client.post("/decisions", json={
                "node_id": "host:ws-007", "action": "isolate_host",
                "target": "host:ws-007", "decision": d,
                "rationale": "test",
            })
            assert r.status_code == 200
            body = r.json()
            assert body["ok"] is True
            # no SUPABASE_URL in test env -> gitignored local JSON fallback
            assert body["stored"] is True
            assert body["persistence"] == "local"
            assert body["id"]
        # both decisions are listed back, newest first
        r = client.get("/decisions")
        assert r.status_code == 200
        body = r.json()
        assert len(body["decisions"]) == 2
        assert body["persistence"] == "local"
        assert body["persisted"] is False
        assert {x["decision"] for x in body["decisions"]} == {
            "approved", "rejected"}
        assert all(x["executed"] is False for x in body["decisions"])
    finally:
        del os.environ["GRAPHOPS_DECISIONS_PATH"]


def test_decisions_list_degrades_gracefully(client, tmp_path):
    os.environ["GRAPHOPS_DECISIONS_PATH"] = str(tmp_path / "decisions2.json")
    try:
        r = client.get("/decisions")
        assert r.status_code == 200
        body = r.json()
        assert body["decisions"] == []
        assert body["persisted"] is False
        assert body["persistence"] == "local"
    finally:
        del os.environ["GRAPHOPS_DECISIONS_PATH"]


def test_hunt_runs_list_degrades_gracefully(client):
    r = client.get("/hunt-runs")
    assert r.status_code == 200
    assert r.json()["hunt_runs"] == []


# ---------------------------------------------------------------------------
# 7. Edge cases: blast-radius scoring boundaries (QA specialist additions)
# ---------------------------------------------------------------------------

def _chain_graph(n: int = 6) -> GraphEngine:
    """Linear chain host:h0 -> host:h1 -> ... -> host:h{n-1}."""
    eng = GraphEngine()
    for i in range(n):
        eng.add_entity("host", f"h{i}")
    for i in range(n - 1):
        eng.add_event(f"host:h{i}", f"host:h{i+1}", "network", float(i))
    return eng


def test_blast_radius_max_hops_cutoff_excludes_distant_nodes():
    eng = _chain_graph(6)
    radius = eng.blast_radius("host:h0", max_hops=2)
    distances = {nid: info["distance"] for nid, info in radius.items()}
    assert distances == {"host:h0": 0, "host:h1": 1, "host:h2": 2}
    assert "host:h3" not in radius  # beyond cutoff must be absent, not just far


def test_blast_radius_severity_boost_clamped_at_100():
    eng = _chain_graph(3)
    eng.graph.nodes["host:h0"]["severity"] = "critical"  # 100 + 25 -> clamp 100
    eng.graph.nodes["host:h1"]["severity"] = "high"      # 60 + 25 = 85
    radius = eng.blast_radius("host:h0", max_hops=2)
    assert radius["host:h0"]["risk_score"] == pytest.approx(100.0)
    assert radius["host:h1"]["risk_score"] == pytest.approx(85.0)
    assert radius["host:h2"]["risk_score"] == pytest.approx(36.0)  # 100*0.6^2, no boost


def test_blast_radius_isolated_node_returns_only_itself():
    eng = GraphEngine()
    eng.add_entity("host", "lonely")
    eng.add_entity("host", "other")
    radius = eng.blast_radius("host:lonely", max_hops=4)
    assert list(radius.keys()) == ["host:lonely"]
    assert radius["host:lonely"]["distance"] == 0
    assert radius["host:lonely"]["risk_score"] == pytest.approx(100.0)


def test_blast_radius_zero_hops_returns_source_only():
    eng = _chain_graph(4)
    radius = eng.blast_radius("host:h1", max_hops=0)
    assert list(radius.keys()) == ["host:h1"]
    assert radius["host:h1"]["distance"] == 0


# ---------------------------------------------------------------------------
# 8. Edge cases: hunt query boundaries (QA specialist additions)
# ---------------------------------------------------------------------------

def test_hunt_beaconing_ignores_rfc1918_even_when_suspicious():
    eng = GraphEngine()
    eng.add_entity("host", "h1")
    eng.add_entity("ip", "192.168.1.5")
    eng.add_entity("ip", "203.0.113.9")
    eng.add_event("host:h1", "ip:192.168.1.5", "network", 1.0,
                  attrs={"suspicious": True})
    eng.add_event("host:h1", "ip:203.0.113.9", "network", 2.0,
                  attrs={"suspicious": True})
    findings = hunt_beaconing(eng)
    hit = {n for f in findings for n in f["nodes"]}
    assert "ip:203.0.113.9" in hit, "external suspicious IP must be flagged"
    assert "ip:192.168.1.5" not in hit, "RFC-1918 IP must never be flagged"


def _travel_graph(events) -> GraphEngine:
    """events: list of (ip_eid, geo, ts)."""
    eng = GraphEngine()
    eng.add_entity("user", "u1")
    for eid, geo, ts in events:
        eng.add_entity("ip", eid, attrs={"geo": geo})
        eng.add_event("user:u1", f"ip:{eid}", "auth", ts)
    return eng


def test_hunt_impossible_travel_same_geo_no_finding():
    eng = _travel_graph([("1.1.1.1", "US", 1000.0), ("2.2.2.2", "US", 1100.0)])
    assert hunt_impossible_travel(eng) == []


def test_hunt_impossible_travel_outside_window_no_finding():
    # 8000s apart > 3600s window -> no finding even with distinct geos
    eng = _travel_graph([("1.1.1.1", "US", 1000.0), ("2.2.2.2", "EU", 9000.0)])
    assert hunt_impossible_travel(eng) == []


def test_hunt_impossible_travel_positive_control():
    eng = _travel_graph([("1.1.1.1", "US", 1000.0), ("2.2.2.2", "EU", 1500.0)])
    findings = hunt_impossible_travel(eng)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"  # dt=500s < 900s
    assert "user:u1" in findings[0]["nodes"]


# ---------------------------------------------------------------------------
# 9. Edge cases: containment caps + API input validation (QA additions)
# ---------------------------------------------------------------------------

def test_containment_actions_capped_at_max_actions():
    from graphops.response.contain import MAX_ACTIONS
    eng = GraphEngine()
    eng.add_entity("host", "c0")
    for i in range(40):
        eng.add_entity("host", f"w{i}")
        eng.add_event("host:c0", f"host:w{i}", "smb", float(i),
                      attrs={"suspicious": True})
    result = recommend_containment(eng, "host:c0")
    assert len(result["actions"]) <= MAX_ACTIONS
    assert len(result["actions"]) == MAX_ACTIONS  # 41 candidates, capped at 25


def test_api_blast_radius_malformed_body_is_422(client):
    r = client.post("/blast-radius", json={})
    assert r.status_code == 422  # node_id is required


def test_api_blast_radius_empty_string_node_is_422(client):
    # 2026-10-08 input-validation hardening: empty node_id is a 422;
    # unknown-but-wellformed ids still 404 (contract preserved)
    r = client.post("/blast-radius", json={"node_id": ""})
    assert r.status_code == 422
    r = client.post("/blast-radius", json={"node_id": "host:ghost-zzz"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# 9. New hunts: privilege escalation + data staging
# ---------------------------------------------------------------------------

def _finding_shape_ok(f):
    assert isinstance(f, dict)
    assert isinstance(f.get("title"), str) and f["title"]
    assert f.get("severity") in ("low", "medium", "high", "critical")
    assert isinstance(f.get("evidence"), list) and f["evidence"]
    assert isinstance(f.get("nodes"), list) and f["nodes"]


def test_hunt_privilege_escalation_traces_attack_chain():
    from graphops.hunt.queries import hunt_privilege_escalation
    engine, _ = generate(seed=42)
    findings = hunt_privilege_escalation(engine)
    assert len(findings) == 1
    f = findings[0]
    _finding_shape_ok(f)
    assert f["severity"] == "critical"
    assert "user:u-0042" in f["nodes"]
    assert "process:lsass.exe" in f["nodes"]
    assert any("u-0042" in e and "lsass" in e for e in f["evidence"])


def test_hunt_privilege_escalation_group_nesting():
    from graphops.hunt.queries import hunt_privilege_escalation
    eng = GraphEngine()
    eng.add_entity("user", "alice")
    eng.add_entity("group", "team-a")
    eng.add_entity("group", "domain-admins", {"admin": True})
    eng.add_event("user:alice", "group:team-a", "member_of", 1.0)
    eng.add_event("group:team-a", "group:domain-admins", "member_of", 2.0)
    findings = hunt_privilege_escalation(eng)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "user:alice" in findings[0]["nodes"]
    assert "group:domain-admins" in findings[0]["nodes"]


def test_hunt_data_staging_correlates_exfiltration():
    from graphops.hunt.queries import hunt_data_staging
    engine, _ = generate(seed=42)
    findings = hunt_data_staging(engine)
    # exactly one: the 7z staging on ws-031 (powershell noise excluded)
    assert len(findings) == 1
    f = findings[0]
    _finding_shape_ok(f)
    assert f["severity"] == "critical"
    assert "host:ws-031" in f["nodes"]
    assert "process:7z.exe" in f["nodes"]
    assert "ip:203.0.113.9" in f["nodes"]
    assert any("exfiltration" in e for e in f["evidence"])


def test_new_hunts_defensive_on_empty_engine():
    from graphops.hunt.queries import hunt_privilege_escalation, hunt_data_staging
    eng = GraphEngine()
    assert hunt_privilege_escalation(eng) == []
    assert hunt_data_staging(eng) == []
    assert hunt_privilege_escalation(None) == []
    assert hunt_data_staging(None) == []


# ---------------------------------------------------------------------------
# 10. Red-team replay harness
# ---------------------------------------------------------------------------

def test_redteam_replay_report_shape():
    import json
    from graphops.redteam.replay import replay
    report = replay(seed=42)
    json.dumps(report)  # must be JSON-serializable
    assert report["campaign"] == "GRAPHOPS-DEMO-001"
    assert len(report["stages"]) == 7
    assert report["coverage"] == "5/7"
    assert report["detected"] == 5 and report["missed"] == 2
    assert report["mttd_seconds"] == 0.0
    missed = {s["stage"] for s in report["stages"] if s["status"] == "missed"}
    assert missed == {"phishing", "foothold"}
    by_stage = {s["stage"]: s for s in report["stages"]}
    assert by_stage["privilege-escalation"]["detected_by"] == ["privilege_escalation"]
    assert "beaconing" in by_stage["exfiltration"]["detected_by"]


def test_redteam_replay_degrades_without_generator():
    import graphops.redteam.replay as rp
    orig = rp.generate
    rp.generate = None
    try:
        report = rp.replay(seed=42)
        assert report["detected"] == 0
        assert "error" in report
    finally:
        rp.generate = orig


# ---------------------------------------------------------------------------
# 11. Neo4j Aura client
# ---------------------------------------------------------------------------

def test_neo4j_client_configured_and_roundtrip():
    from graphops.store import neo4j_client as n4
    pytest.importorskip("urllib.request")
    if not n4.is_configured():
        pytest.skip("Neo4j credentials not available")
    rows = n4.run_cypher("RETURN 1 AS ok")
    if rows is None:
        pytest.skip("Neo4j Aura unreachable from here")
    assert rows == [{"ok": 1}]
    # sync a tiny graph and read it back
    eng = GraphEngine()
    eng.add_entity("host", "n4-test-01", {"os": "test"})
    eng.add_entity("user", "n4-tester", {"role": "test"})
    eng.add_event("user:n4-tester", "host:n4-test-01", "auth", 1.0,
                  {"suspicious": False})
    res = n4.sync_graph(eng)
    assert res is not None and res["nodes"] == 2 and res["edges"] == 1
    back = n4.run_cypher(
        "MATCH (n:GraphOpsEntity {id: 'host:n4-test-01'}) "
        "RETURN n.etype AS etype")
    assert back and back[0]["etype"] == "host"
    assert n4.clear_graph() is True
    assert n4.run_cypher(
        "MATCH (n:GraphOpsEntity {id: 'host:n4-test-01'}) RETURN n") == []


def test_neo4j_client_never_raises_without_config(monkeypatch):
    from graphops.store import neo4j_client as n4
    monkeypatch.setattr(n4, "_cfg", lambda: None)
    assert n4.is_configured() is False
    assert n4.run_cypher("RETURN 1") is None
    assert n4.sync_graph(GraphEngine()) is None
    assert n4.clear_graph() is False


# ---------------------------------------------------------------------------
# 12. New API endpoints
# ---------------------------------------------------------------------------

def test_api_hunt_privilege_escalation(client):
    r = client.post("/hunt/privilege-escalation")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_api_hunt_data_staging(client):
    r = client.post("/hunt/data-staging")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_api_redteam_replay(client):
    r = client.post("/redteam/replay", json={"seed": 42})
    assert r.status_code == 200
    report = r.json()
    assert report["campaign"] == "GRAPHOPS-DEMO-001"
    assert report["coverage"] == "5/7"
    assert len(report["stages"]) == 7
