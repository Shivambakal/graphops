"""QA suite 2026-10-07: blast-radius boundaries, /contain validation, gate
invariants, neo4j fallback, redteam metrics shape, evidence-chain
completeness on every /hunt finding.

Independent verification only: asserts on real module + API behaviour,
no mocks of the system under test.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import graphops.api.server as srv
from graphops.api.server import app
from graphops.graph.engine import GraphEngine
from graphops.response.contain import recommend_containment
from graphops.response.gate import (
    ACTION_CATALOG,
    AUTO_APPROVE_MIN_REVERSIBILITY,
    STATUS_QUEUED,
    STATUS_RECOMMENDED,
    evaluate_action,
)
from graphops.hunt import queries as q


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Blast-radius boundary cases
# ---------------------------------------------------------------------------

def test_blast_radius_empty_graph_is_empty():
    eng = GraphEngine()
    assert eng.graph.number_of_nodes() == 0
    assert eng.blast_radius("host:ghost") == {}
    res = recommend_containment(eng, "host:ghost")
    assert res == {"blast_radius": {}, "actions": []}


def test_blast_radius_api_unknown_node_is_404(client):
    r = client.post("/blast-radius", json={"node_id": "host:ghost-zzz"})
    assert r.status_code == 404, r.text


def test_blast_radius_single_node_only_itself():
    eng = GraphEngine()
    nid = eng.add_entity("host", "solo")
    radius = eng.blast_radius(nid, max_hops=4)
    assert list(radius.keys()) == [nid]
    assert radius[nid]["distance"] == 0
    assert radius[nid]["risk_score"] == 100.0


def test_blast_radius_zero_hops_terminates_at_source():
    eng = GraphEngine()
    a = eng.add_entity("host", "a")
    b = eng.add_entity("host", "b")
    eng.add_event(a, b, "network", 1.0)
    assert list(eng.blast_radius(a, max_hops=0).keys()) == [a]


def test_blast_radius_disconnected_components_stay_separate():
    eng = GraphEngine()
    a1 = eng.add_entity("host", "a1")
    a2 = eng.add_entity("host", "a2")
    b1 = eng.add_entity("host", "b1")  # island: no edges at all
    eng.add_event(a1, a2, "network", 1.0)
    radius = eng.blast_radius(a1, max_hops=10)
    assert set(radius) == {a1, a2}, f"island {b1} leaked into blast radius"


def test_blast_radius_unknown_node_on_real_engine_is_empty():
    eng, _gt = pytest.importorskip("graphops.intel.generator").generate(seed=42)
    assert eng.blast_radius("host:definitely-not-here") == {}


# ---------------------------------------------------------------------------
# 2. Hunt query limits / validation
# ---------------------------------------------------------------------------

_HUNT_FNS = (
    q.hunt_lateral_movement,
    q.hunt_beaconing,
    q.hunt_impossible_travel,
    q.hunt_privilege_escalation,
    q.hunt_data_staging,
    q.hunt_oauth_scope_creep,
)


def test_hunt_functions_degrade_on_empty_engine():
    eng = GraphEngine()
    for fn in _HUNT_FNS:
        out = fn(eng)
        assert isinstance(out, list), fn.__name__
        assert out == [], f"{fn.__name__} must return [] on an empty graph"


def test_hunt_api_findings_bounded_and_well_formed(client):
    r = client.post("/hunt")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert isinstance(findings, list)
    assert len(findings) < 1000, "unbounded finding list is a DoS-shaped bug"
    for f in findings:
        assert isinstance(f.get("title"), str) and f["title"]
        assert f.get("severity") in {"low", "medium", "high", "critical"}


def test_hunt_api_tolerates_unexpected_body(client):
    # /hunt takes no params; a stray body must not 500
    r = client.post("/hunt", json={"limit": 5, "zzz": [1, 2, 3]})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# 3. /contain validation: malformed payloads
# ---------------------------------------------------------------------------

def test_contain_unknown_action_is_422(client):
    r = client.post("/contain", json={"node_id": "host:a", "action": "launch_missiles"})
    assert r.status_code == 422, r.text
    assert "unknown containment action" in r.json()["detail"]
    assert "isolate_host" in r.json()["detail"], "422 must name the known actions"


def test_contain_missing_fields_is_422(client):
    assert client.post("/contain", json={}).status_code == 422
    assert client.post("/contain", json={"node_id": "host:a"}).status_code == 422
    assert client.post("/contain", json={"action": "observe"}).status_code == 422


def test_contain_action_name_normalization(client):
    r = client.post("/contain", json={"node_id": "host:a", "action": "Isolate Host"})
    assert r.status_code == 200, r.text
    assert r.json()["gate"]["action"] == "isolate_host"
    assert r.json()["gate"]["status"] == STATUS_QUEUED


# ---------------------------------------------------------------------------
# 4. Evidence-chain completeness on EVERY /hunt finding
# ---------------------------------------------------------------------------

def test_every_hunt_finding_has_complete_evidence_chain(client):
    r = client.post("/hunt")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert findings, "expected findings"
    required = {"detection_method", "signals", "signal_count",
                "subgraph", "recommended_action", "synthetic"}
    for f in findings:
        chain = f.get("evidence_chain")
        assert isinstance(chain, dict), f"missing evidence_chain: {f.get('title')}"
        missing = required - set(chain.keys())
        assert not missing, f"{f.get('title')}: missing {missing}"
        assert isinstance(chain["signals"], list) and chain["signals"], \
            f"{f.get('title')}: empty signals"
        assert chain["signal_count"] == len(chain["signals"])
        assert chain["synthetic"] is True


# ---------------------------------------------------------------------------
# 5. Reversibility-gate invariants
# ---------------------------------------------------------------------------

def test_gate_invariant_no_sub_090_action_is_auto_approved():
    for name, entry in ACTION_CATALOG.items():
        score = float(entry["reversibility"])
        d = evaluate_action(name, "host:a")
        assert d["executed"] is False, name
        assert d["reversibility_score"] == score
        assert d["impact_tier"] == entry["impact_tier"]
        if score < AUTO_APPROVE_MIN_REVERSIBILITY:
            assert d["status"] == STATUS_QUEUED, name
        else:
            assert d["status"] == STATUS_RECOMMENDED, name
    # and the threshold is exactly what we think it is
    assert AUTO_APPROVE_MIN_REVERSIBILITY == 0.90


def test_reversible_action_is_never_queued(client, tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH", str(tmp_path / "q.json"))
    r = client.post("/contain", json={"node_id": "host:a", "action": "observe"})
    assert r.status_code == 200
    body = r.json()
    assert body["gate"]["status"] == STATUS_RECOMMENDED
    assert body["queued"] is None, "reversible actions must not enter the queue"
    assert not (tmp_path / "q.json").exists()


def test_irreversible_action_queued_with_score_and_tier(client, tmp_path, monkeypatch):
    qpath = tmp_path / "q.json"
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH", str(qpath))
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    r = client.post("/contain", json={"node_id": "host:a", "action": "isolate_host"})
    assert r.status_code == 200
    body = r.json()
    gate, queued = body["gate"], body["queued"]
    assert gate["status"] == STATUS_QUEUED
    assert gate["executed"] is False
    assert queued is not None
    for key in ("reversibility_score", "impact_tier"):
        assert key in queued and queued[key] is not None, key
    assert queued["reversibility_score"] == 0.70
    assert queued["impact_tier"] == "high"
    # the queued record is visible to the analyst via /decisions
    dq = client.get("/decisions", params={"limit": 5}).json()["queue"]
    ids = {rec.get("id") for rec in dq}
    assert queued["id"] in ids
    rec = next(rec for rec in dq if rec.get("id") == queued["id"])
    assert rec["reversibility_score"] == 0.70
    assert rec["impact_tier"] == "high"
    assert rec["status"] == STATUS_QUEUED


# ---------------------------------------------------------------------------
# 6. Neo4j sync fallback when credentials are absent
# ---------------------------------------------------------------------------

def test_neo4j_fallback_when_creds_absent(tmp_path, monkeypatch):
    from graphops.store import neo4j_client as neo
    for var in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD", "NEO4J_DATABASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(neo, "_CREDS_FILE", tmp_path / "no-creds.txt")
    assert neo.is_configured() is False
    eng = GraphEngine()
    eng.add_entity("host", "h0")
    # every public entry point must degrade gracefully, never raise
    assert neo.sync_graph(eng) is None
    assert neo.run_cypher("MATCH (n) RETURN n") is None
    assert neo.clear_graph() is False
    assert neo.count_by_etype() is None
    p = neo.ping(timeout=1.0)
    assert p["reachable"] is False
    assert p["error"] == "neo4j not configured"


# ---------------------------------------------------------------------------
# 7. Redteam scenario endpoints (contract as built 2026-10-07)
# ---------------------------------------------------------------------------

def test_redteam_replay_endpoint_shape(client):
    r = client.post("/redteam/replay", json={"seed": 42})
    assert r.status_code == 200
    body = r.json()
    assert "mttd_seconds" in body, f"mttd missing: {sorted(body)}"


def test_redteam_scenarios_catalog_shape(client):
    # GET /redteam/scenarios is the catalog (no metrics keys by design);
    # per-scenario metrics live at POST /redteam/run/{id}.
    r = client.get("/redteam/scenarios")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 5
    assert len(body["scenarios"]) == 5
    assert body["synthetic"] is True


def test_redteam_run_endpoint_returns_metrics(client):
    r = client.post("/redteam/run/token-theft-to-exfil")
    assert r.status_code == 200
    body = r.json()
    assert "mttd_seconds" in body and "mttc_seconds" in body
    assert "precision" in body["blast_radius"]
    assert body["detections_fired_total"] >= 1


def test_redteam_run_unknown_scenario_is_404(client):
    assert client.post("/redteam/run/nope").status_code == 404


def test_redteam_metrics_path_still_unbuilt(client):
    # GET /redteam/metrics was never built: 404 proves it, no silent 200.
    assert client.get("/redteam/metrics").status_code == 404
