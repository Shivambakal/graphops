"""GraphOps identity-trust layer, evidence chains, and reversibility-gated
containment tests. Runs against the REAL modules — no mocks of the system
under test. The local containment queue is redirected to a tmp path via
GRAPHOPS_QUEUE_PATH so tests never touch the repo's store.
"""

from __future__ import annotations

import json
import os

import pytest

from graphops.graph.engine import GraphEngine
from graphops.graph.identity import (
    identity_edge_weight,
    seed_identity_layer,
)
from graphops.hunt.queries import hunt_impossible_travel, hunt_oauth_scope_creep
from graphops.hunt.evidence import attach_evidence_chains, build_evidence_chain
from graphops.response.gate import (
    ACTION_CATALOG,
    evaluate_action,
    list_queued,
    queue_action,
)
from graphops.intel.generator import generate


# ---------------------------------------------------------------------------
# 1. Identity-trust layer
# ---------------------------------------------------------------------------

def test_identity_layer_seed_adds_nodes_and_edges():
    eng = GraphEngine()
    for u in ("alice", "bob"):
        eng.add_entity("user", u)
    stats = seed_identity_layer(eng, user_ids=["user:alice", "user:bob"])
    assert stats["apps"] == 4
    assert stats["datasets"] == 3
    assert stats["tokens"] == 2
    etypes = {str(n).split(":", 1)[0] for n in eng.graph.nodes()}
    assert {"oauth_token", "oauth_app", "oauth_scope", "dataset"} <= etypes
    # all identity nodes tagged synthetic
    for n in eng.graph.nodes():
        if str(n).split(":", 1)[0] in ("oauth_token", "oauth_app", "oauth_scope", "dataset"):
            assert eng.graph.nodes[n].get("synthetic") is True, n


def test_identity_edge_weight_bounds_and_anomaly_bump():
    base = identity_edge_weight("user", "oauth_token",
                                {"etype": "grants", "scopes": ["repo:read"]})
    creep = identity_edge_weight("user", "oauth_token",
                                 {"etype": "grants", "scopes": ["admin:users:write"],
                                  "scope_creep": True})
    for w in (base, creep):
        assert 0.0 <= w <= 1.0
    assert creep > base, "scope-creep + admin scope must raise the edge weight"
    regulated = identity_edge_weight("oauth_scope", "dataset",
                                     {"etype": "accesses", "regulated": True})
    assert 0.0 <= regulated <= 1.0


def test_identity_layer_on_generator_seed_42():
    engine, _gt = generate(seed=42)
    tokens = [n for n in engine.graph.nodes()
              if str(n).startswith("oauth_token:")]
    assert len(tokens) == 41  # 40 baseline + 1 campaign anomaly
    apps = [n for n in engine.graph.nodes() if str(n).startswith("oauth_app:")]
    assert len(apps) == 4
    assert "oauth_token:tok-campaign-01" in engine.graph.nodes()


# ---------------------------------------------------------------------------
# 2. OAuth scope-creep hunt
# ---------------------------------------------------------------------------

def test_hunt_oauth_scope_creep_finds_embedded_anomaly():
    engine, _gt = generate(seed=42)
    findings = hunt_oauth_scope_creep(engine)
    assert findings, "expected the embedded scope-creep anomaly to be found"
    hit = {n for f in findings for n in f["nodes"]}
    assert "oauth_token:tok-campaign-01" in hit
    assert "user:u-0042" in hit
    f = next(f for f in findings if "oauth_token:tok-campaign-01" in f["nodes"])
    assert f["severity"] == "critical"  # admin scope + regulated dataset
    assert any("admin:users:write" in e for e in f["evidence"])
    assert any("customer-pii" in e for e in f["evidence"])


def test_hunt_oauth_scope_creep_quiet_on_baseline_tokens():
    eng = GraphEngine()
    eng.add_entity("user", "carol")
    stats = seed_identity_layer(eng, user_ids=["user:carol"])
    assert stats["tokens"] == 1
    assert hunt_oauth_scope_creep(eng) == [], \
        "baseline-scoped tokens must not fire"


def test_hunt_oauth_scope_creep_defensive_on_empty_engine():
    assert hunt_oauth_scope_creep(GraphEngine()) == []
    assert hunt_oauth_scope_creep(None) == []


def test_identity_sync_degrades_gracefully_without_config(monkeypatch):
    from graphops.graph import identity as ident
    from graphops.store import neo4j_client as n4
    monkeypatch.setattr(n4, "_cfg", lambda: None)
    engine, _ = generate(seed=42)
    assert ident.sync_identity_layer(engine) is None


# ---------------------------------------------------------------------------
# 3. Impossible travel now fires on the synthetic campaign
# ---------------------------------------------------------------------------

def test_impossible_travel_fires_on_synthetic_campaign():
    engine, _gt = generate(seed=42)
    findings = hunt_impossible_travel(engine)
    assert findings, "expected impossible-travel on the seeded campaign pair"
    hit = {n for f in findings for n in f["nodes"]}
    assert "user:u-0042" in hit
    f = next(f for f in findings if "user:u-0042" in f["nodes"])
    assert f["severity"] == "high"  # 500 s apart < 900 s


# ---------------------------------------------------------------------------
# 4. Evidence chains
# ---------------------------------------------------------------------------

def test_evidence_chain_structure():
    engine, _gt = generate(seed=42)
    findings = hunt_oauth_scope_creep(engine)
    assert findings
    chain = build_evidence_chain(engine, findings[0])
    assert chain["signal_count"] == len(findings[0]["evidence"]) > 0
    assert chain["detection_method"] == "oauth_scope_creep"
    assert chain["subgraph"]["nodes"], "subgraph must be non-empty"
    assert chain["subgraph"]["edges"], "subgraph must include edges"
    ra = chain["recommended_action"]
    assert ra["executed"] is False
    assert isinstance(ra["requires_approval"], bool)
    assert chain["synthetic"] is True


def test_attach_evidence_chains_never_drops_findings():
    engine, _gt = generate(seed=42)
    findings = hunt_impossible_travel(engine)
    enriched = attach_evidence_chains(engine, findings)
    assert len(enriched) == len(findings)
    for f in enriched:
        assert "evidence_chain" in f
        assert f["evidence_chain"]["signal_count"] >= 1


# ---------------------------------------------------------------------------
# 5. Reversibility gate (unit)
# ---------------------------------------------------------------------------

def test_gate_reversible_action_auto_recommended():
    d = evaluate_action("observe", "host:ws-007")
    assert d["status"] == "recommended"
    assert d["reversible"] is True
    assert d["reversibility_score"] == 1.0
    assert d["executed"] is False


def test_gate_irreversible_action_queued():
    d = evaluate_action("isolate_host", "host:ws-007")
    assert d["status"] == "queued_for_approval"
    assert d["reversible"] is False
    assert d["reversibility_score"] == 0.70
    assert d["impact_tier"] == "high"
    assert d["est_cost_usd"] == 500.0
    assert d["executed"] is False


def test_gate_unknown_action_raises():
    with pytest.raises(ValueError):
        evaluate_action("nuke_everything", "host:ws-007")


def test_gate_catalog_covers_expected_actions():
    for a in ("observe", "enrich_alert", "flag_account", "revoke_token",
              "isolate_host", "block_ip", "quarantine_account"):
        assert a in ACTION_CATALOG
        entry = ACTION_CATALOG[a]
        assert 0.0 <= entry["reversibility"] <= 1.0
        assert entry["impact_tier"] in ("low", "medium", "high")


def test_queue_roundtrip_local_store(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH", str(tmp_path / "q.json"))
    assert list_queued() == []
    d = evaluate_action("block_ip", "host:ws-007", target="ip:203.0.113.9")
    record, store = queue_action(d, requested_by="test")
    assert store == "local"  # no Supabase configured in test env
    assert record["status"] == "queued_for_approval"
    assert record["reversibility_score"] == 0.60
    queued = list_queued()
    assert len(queued) == 1
    assert queued[0]["action"] == "block_ip"
    assert queued[0]["est_cost_usd"] == 50.0
    # file exists on disk as JSON
    with open(tmp_path / "q.json") as f:
        assert isinstance(json.load(f), list)


# ---------------------------------------------------------------------------
# 6. API: /contain + /decisions queue + /contain/actions
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient
from graphops.api.server import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_api_contain_observe_recommended(client):
    r = client.post("/contain", json={"node_id": "host:ws-007", "action": "observe"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["gate"]["status"] == "recommended"
    assert body["gate"]["reversibility_score"] == 1.0
    assert body["queued"] is None  # reversible: nothing queued


def test_api_contain_isolate_queued(client, tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH", str(tmp_path / "q2.json"))
    r = client.post("/contain", json={"node_id": "host:ws-007",
                                      "action": "isolate_host"})
    assert r.status_code == 200
    body = r.json()
    assert body["gate"]["status"] == "queued_for_approval"
    assert body["gate"]["executed"] is False
    assert body["queued"] is not None
    assert body["queued"]["reversibility_score"] == 0.70
    assert body["queued"]["impact_tier"] == "high"
    assert body["store"] == "local"


def test_api_contain_unknown_action_is_422(client):
    r = client.post("/contain", json={"node_id": "host:ws-007",
                                      "action": "delete_everything"})
    assert r.status_code == 422


def test_api_decisions_includes_queue_with_scores(client, tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH", str(tmp_path / "q3.json"))
    r = client.post("/contain", json={"node_id": "host:ws-031",
                                      "action": "revoke_token"})
    assert r.status_code == 200
    r = client.get("/decisions")
    assert r.status_code == 200
    body = r.json()
    assert "decisions" in body and "queue" in body  # backward compatible
    item = next(q for q in body["queue"] if q["action"] == "revoke_token")
    assert item["reversibility_score"] == 0.85
    assert item["impact_tier"] == "medium"
    assert item["est_cost_usd"] == 50.0
    assert item["status"] == "queued_for_approval"


def test_api_contain_actions_catalog(client):
    r = client.get("/contain/actions")
    assert r.status_code == 200
    body = r.json()
    assert "isolate_host" in body["actions"]
    assert body["auto_approve_min_reversibility"] == 0.90


def test_api_hunt_includes_scope_creep_and_evidence_chains(client):
    r = client.post("/hunt")
    assert r.status_code == 200
    findings = r.json()["findings"]
    methods = {f["evidence_chain"]["detection_method"] for f in findings}
    assert "oauth_scope_creep" in methods
    assert "impossible_travel" in methods
    for f in findings:
        chain = f["evidence_chain"]
        assert chain["signal_count"] >= 1
        assert chain["recommended_action"]["executed"] is False
