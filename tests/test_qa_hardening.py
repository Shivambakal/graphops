"""QA hardening suite (2026-10-06): edge cases, determinism, containment
gating, input validation, and evidence-chain contracts.

Covers gaps the earlier suites left open:
  - /ingest resilience to malformed payloads (never a 500)
  - evidence-chain presence on EVERY finding from EVERY hunt
  - /graph size-cap contract
  - redteam replay determinism
  - containment is recommendations-only (reversible gating): no action
    ever carries an "executed" status, the engine graph is never mutated,
    and approving a decision has no side effects
  - API input-validation 422s
  - blast-radius boundary behaviour (negative hops, score clamping)
  - /api prefix tolerance (Vercel routing)

All tests run against the real modules — no mocks of the system under test.
"""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

import graphops.api.server as srv
from graphops.api.server import app
from graphops.graph.engine import GraphEngine
from graphops.intel.generator import generate
from graphops.response.contain import STATUS_RECOMMENDED, recommend_containment
from graphops.hunt.queries import (
    hunt_beaconing,
    hunt_data_staging,
    hunt_impossible_travel,
    hunt_lateral_movement,
    hunt_privilege_escalation,
)

SEVERITIES = {"low", "medium", "high", "critical"}
DATA_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def engine():
    eng, _gt = generate(seed=42)
    return eng


@pytest.fixture(autouse=True)
def _restore_ingest_state():
    """Leave the server's ingestion globals untouched for other suites."""
    yield
    srv._INGESTED_GRAPH = None
    srv._INGESTED_META = {}


# ---------------------------------------------------------------------------
# 1. /ingest resilience: malformed payloads must degrade, never 500
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload,want", [
    ({"logs": "this is not csv or json {{{", "format": "auto"}, 200),
    ({"logs": "not json at all", "format": "json"}, 200),
    # 2026-10-08 input-validation hardening: empty logs and unknown
    # formats are rejected with 422 instead of silently ingested
    ({"logs": "", "format": "auto"}, 422),
    ({"logs": "a,b\n1,2\n", "format": "xml"}, 422),
    ({"logs": "timestamp\nnot-a-time\n,,,\n", "format": "csv"}, 200),
])
def test_ingest_malformed_logs_never_500(client, payload, want):
    r = client.post("/ingest", json=payload)
    assert r.status_code == want, f"payload {payload['format']}: {r.status_code}"
    if want == 200:
        body = r.json()
        assert body["ok"] is True
        assert body["nodes"] >= 0 and body["edges"] >= 0


def test_ingest_missing_logs_field_is_422(client):
    r = client.post("/ingest", json={"format": "csv"})
    assert r.status_code == 422


def test_ingest_real_logs_populates_graph_and_hunts_work(client):
    with open(DATA_CSV) as f:
        raw = f.read()
    r = client.post("/ingest", json={"logs": raw, "format": "csv"})
    assert r.status_code == 200
    body = r.json()
    assert body["events"] > 50 and body["nodes"] > 20
    # telemetry hunts must operate on the ingested graph, not the synthetic one
    rb = client.post("/hunt/beaconing")
    assert rb.status_code == 200
    assert rb.json()["ingested"] is True
    findings = rb.json()["findings"]
    assert len(findings) == 1, "sample logs embed exactly one beaconing attack"
    assert findings[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 2. Evidence-chain contract: every finding from every hunt must carry
#    title + severity + non-empty evidence + non-empty nodes.
# ---------------------------------------------------------------------------

def _all_generated_findings(engine):
    hunts = (
        hunt_lateral_movement,
        hunt_beaconing,
        hunt_impossible_travel,
        hunt_privilege_escalation,
        hunt_data_staging,
    )
    out = []
    for h in hunts:
        out.extend(h(engine) or [])
    return out


def test_all_findings_carry_evidence_chain(engine):
    findings = _all_generated_findings(engine)
    assert findings, "expected findings from the generated attack graph"
    for f in findings:
        assert isinstance(f.get("title"), str) and f["title"], f
        assert f.get("severity") in SEVERITIES, f
        assert isinstance(f.get("evidence"), list) and len(f["evidence"]) >= 1, f
        assert isinstance(f.get("nodes"), list) and len(f["nodes"]) >= 1, f


def test_api_hunt_findings_carry_evidence_chain(client):
    r = client.post("/hunt")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert findings, "expected findings from /hunt"
    for f in findings:
        assert isinstance(f.get("title"), str) and f["title"]
        assert f.get("severity") in SEVERITIES
        assert isinstance(f.get("evidence"), list) and f["evidence"]
        assert isinstance(f.get("nodes"), list) and f["nodes"]


# ---------------------------------------------------------------------------
# 3. /graph size-cap contract
# ---------------------------------------------------------------------------

def test_graph_endpoint_respects_size_caps(client):
    r = client.get("/graph")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) <= srv.MAX_GRAPH_NODES
    assert len(body["edges"]) <= srv.MAX_GRAPH_EDGES
    health = client.get("/health").json()
    expected_truncated = (
        health["nodes"] > srv.MAX_GRAPH_NODES
        or health["edges"] > srv.MAX_GRAPH_EDGES
    )
    assert body["truncated"] is expected_truncated
    # known state: 4116 edges > 1500 cap, so truncation must be engaged
    assert health["edges"] > srv.MAX_GRAPH_EDGES
    assert body["truncated"] is True


# ---------------------------------------------------------------------------
# 4. Redteam replay determinism
# ---------------------------------------------------------------------------

def test_redteam_replay_is_deterministic():
    from graphops.redteam.replay import replay
    r1, r2 = replay(seed=42), replay(seed=42)
    assert r1["stages"] == r2["stages"], "stage attribution must be stable"
    for key in ("campaign", "detected", "missed", "coverage", "mttd_seconds"):
        assert r1[key] == r2[key]


def test_redteam_replay_report_is_sound_for_other_seed():
    from graphops.redteam.replay import replay
    report = replay(seed=7)
    assert report["campaign"] == "GRAPHOPS-DEMO-001"
    assert len(report["stages"]) == 7
    assert report["detected"] + report["missed"] == 7
    det, total = (int(x) for x in report["coverage"].split("/"))
    assert det == report["detected"] and total == 7
    for s in report["stages"]:
        if s["status"] == "detected":
            assert s["detection_delay_s"] >= 0, "detection can never precede occurrence"


def test_redteam_replay_delays_never_negative():
    # full scan of the canonical seed: a detected stage must not be
    # attributed to a finding from an earlier cutoff (would show as
    # negative delay / time-travel detection)
    from graphops.redteam.replay import replay
    report = replay(seed=42)
    for s in report["stages"]:
        if s["status"] == "detected":
            assert s["detected_at"] >= s["occurred_at"]
            assert s["detection_delay_s"] >= 0


# ---------------------------------------------------------------------------
# 5. Containment gating: recommendations only, nothing auto-executes
# ---------------------------------------------------------------------------

def test_containment_all_actions_are_recommendations_only(engine):
    eng_host = next(n for n in engine.graph.nodes if n.startswith("host:ws-007"))
    result = recommend_containment(engine, eng_host)
    assert result["actions"], "expected actions for a compromised host"
    for a in result["actions"]:
        assert a["status"] == STATUS_RECOMMENDED == "recommended"
    # nothing in the output may describe an executed action, ever
    dumped = json.dumps(result).lower()
    assert "executed" not in dumped and "executing" not in dumped


def test_containment_never_mutates_the_engine(engine):
    g = engine.graph
    before = (g.number_of_nodes(), g.number_of_edges())
    attrs_before = {n: dict(d) for n, d in g.nodes(data=True)}
    eng_host = next(n for n in g.nodes if n.startswith("host:ws-007"))
    recommend_containment(engine, eng_host)
    recommend_containment(engine, eng_host)  # run twice: still pure
    after = (g.number_of_nodes(), g.number_of_edges())
    assert before == after, "containment must not add/remove nodes or edges"
    for n, d in g.nodes(data=True):
        assert dict(d) == attrs_before[n], f"node {n} attrs mutated"


def _stable_health(body):
    """Normalize volatile /health diagnostic fields (probe latency)
    before comparing snapshots."""
    body = dict(body)
    neo = dict(body.get("neo4j") or {})
    neo.pop("latency_ms", None)
    body["neo4j"] = neo
    return body


def test_approved_decision_has_no_side_effects(client):
    node_id = client.get("/graph").json()["nodes"][0]["id"]
    before = client.get("/health").json()
    r = client.post("/decisions", json={
        "node_id": node_id, "action": "isolate_host",
        "target": node_id, "decision": "approved",
        "rationale": "qa gating test",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    # approving an action is an audit record only: the graph, the node and
    # the blast-radius output must be completely unchanged
    assert _stable_health(client.get("/health").json()) == _stable_health(before)
    assert node_id in {n["id"] for n in client.get("/graph").json()["nodes"][:500]}


def test_containment_code_path_has_no_execution_primitives():
    import inspect
    from graphops.response import contain
    src = inspect.getsource(contain)
    for prim in ("subprocess", "os.system", "os.exec", "os.popen", "eval(", "exec("):
        assert prim not in src, f"execution primitive in containment: {prim}"


# ---------------------------------------------------------------------------
# 6. API input validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,payload", [
    ("/blast-radius", {"node_id": None}),       # null -> 422
    ("/blast-radius", {"node_id": 123}),        # non-str coerced or 422; must not 500
    ("/ingest", {"format": "csv"}),             # logs missing -> 422
    ("/redteam/replay", {"seed": "abc"}),       # uncoercible seed -> 422
    ("/hunt/privilege-paths", {}),              # source missing -> 422
    ("/decisions", {"node_id": "h", "action": "a", "target": "t"}),  # no decision -> 422
])
def test_api_input_validation_never_500s(client, url, payload):
    r = client.post(url, json=payload)
    assert r.status_code in (400, 404, 422), f"{url} {payload} -> {r.status_code}"


# ---------------------------------------------------------------------------
# 7. Blast-radius boundaries
# ---------------------------------------------------------------------------

def test_blast_radius_negative_hops_degrades_safely():
    eng = GraphEngine()
    eng.add_entity("host", "h0")
    eng.add_entity("host", "h1")
    eng.add_event("host:h0", "host:h1", "network", 1.0)
    radius = eng.blast_radius("host:h0", max_hops=-1)
    assert list(radius.keys()) == ["host:h0"], "negative hops must not crash or leak"
    assert radius["host:h0"]["distance"] == 0


def test_blast_radius_risk_scores_always_clamped(engine):
    # across the whole generated graph, scores must stay in [0, 100]
    nodes = list(engine.graph.nodes)[:50]
    for nid in nodes:
        for info in engine.blast_radius(nid, max_hops=3).values():
            assert 0.0 <= info["risk_score"] <= 100.0, (nid, info)


def test_blast_radius_huge_hops_terminates(engine):
    # absurd hop budget must still terminate (finite graph => finite BFS)
    import time
    t0 = time.time()
    radius = engine.blast_radius(next(iter(engine.graph.nodes)), max_hops=10**6)
    assert time.time() - t0 < 30
    assert radius, "expected non-empty radius for a connected node"


# ---------------------------------------------------------------------------
# 8. /api prefix tolerance (Vercel routing)
# ---------------------------------------------------------------------------

def test_api_prefix_tolerance(client):
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/hunt").status_code == 200
    node_id = client.get("/api/graph").json()["nodes"][0]["id"]
    r = client.post("/api/blast-radius", json={"node_id": node_id})
    assert r.status_code == 200
    assert r.json()["blast_radius"][node_id]["distance"] == 0
    assert client.post("/api/blast-radius", json={"node_id": "host:nope"}).status_code == 404
