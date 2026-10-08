"""QA suite 2026-10-08: boundary conditions, gate edge cases, queue lifecycle,
evidence-chain contract on ALL hunt endpoints, error-leakage, secrets hygiene.

Verifies fixes shipped today:
  - /hunt/privilege-escalation, /hunt/data-staging, /hunt/beaconing,
    /hunt/lateral now attach evidence chains (was: contract violated).
  - gate.queue_action dedups identical pending actions (was: duplicates).
  - POST /decisions resolves the matching queue record (was: approved
    actions stayed "queued_for_approval" forever).

Independent verification only: asserts on real module + API behaviour,
no mocks of the system under test.
"""
from __future__ import annotations

import inspect
import os

import pytest
from fastapi.testclient import TestClient

import graphops.api.server as srv
from graphops.api.server import app
from graphops.graph.engine import GraphEngine
from graphops.hunt import evidence as ev
from graphops.hunt import queries as q
from graphops.response import gate
from graphops.response.gate import (
    ACTION_CATALOG,
    STATUS_QUEUED,
    STATUS_RECOMMENDED,
    evaluate_action,
)

DATA_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture()
def isolated_queue(tmp_path, monkeypatch):
    """Point the local queue/decisions stores at throwaway files."""
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH", str(tmp_path / "q.json"))
    monkeypatch.setenv("GRAPHOPS_DECISIONS_PATH", str(tmp_path / "d.json"))
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)


@pytest.fixture(autouse=True)
def _restore_ingest_state():
    yield
    srv._INGESTED_GRAPH = None
    srv._INGESTED_META = {}


# ---------------------------------------------------------------------------
# 1. Blast-radius depth caps + decay behaviour
# ---------------------------------------------------------------------------

def _chain_engine(n_links=5):
    eng = GraphEngine()
    ids = [eng.add_entity("host", f"c{i}") for i in range(n_links + 1)]
    for a, b in zip(ids, ids[1:]):
        eng.add_event(a, b, "network", 1.0)
    return eng, ids


def test_blast_radius_depth_cap_excludes_beyond_hops():
    eng, ids = _chain_engine(5)
    r2 = eng.blast_radius(ids[0], max_hops=2)
    assert set(r2) == set(ids[:3]), f"nodes beyond 2 hops leaked: {set(r2)}"
    assert all(info["distance"] <= 2 for info in r2.values())
    r5 = eng.blast_radius(ids[0], max_hops=5)
    assert set(r5) == set(ids), "full chain must be covered at 5 hops"


def test_blast_radius_decay_monotonic_with_distance():
    eng, ids = _chain_engine(4)
    radius = eng.blast_radius(ids[0], max_hops=4)
    scores = [radius[n]["risk_score"] for n in ids]
    for deeper, shallower in zip(scores, scores[1:]):
        assert deeper > shallower, "risk must decay with distance"
    for n, info in radius.items():
        d = info["distance"]
        assert info["risk_score"] == pytest.approx(100.0 * (0.6 ** d)), n


def test_blast_radius_severity_bonus_then_clamp():
    eng, ids = _chain_engine(3)
    eng.graph.nodes[ids[2]]["severity"] = "high"
    radius = eng.blast_radius(ids[0], max_hops=3)
    # distance 2: 36.0 + 25.0 = 61.0 (under the clamp)
    assert radius[ids[2]]["risk_score"] == pytest.approx(61.0)
    # distance 0: 100.0 + 25.0 clamps to 100.0, never above
    eng.graph.nodes[ids[0]]["severity"] = "critical"
    r0 = eng.blast_radius(ids[0], max_hops=0)
    assert r0[ids[0]]["risk_score"] == 100.0


# ---------------------------------------------------------------------------
# 2. Hunt empty-engine safety (incl. telemetry variants)
# ---------------------------------------------------------------------------

def test_hunt_functions_safe_on_empty_engine():
    eng = GraphEngine()
    for fn in (q.hunt_lateral_movement, q.hunt_beaconing,
               q.hunt_impossible_travel, q.hunt_privilege_escalation,
               q.hunt_data_staging, q.hunt_oauth_scope_creep):
        assert fn(eng) == [], f"{fn.__name__} must return [] on empty engine"
    import networkx as nx
    g = nx.DiGraph()
    from graphops.engine.beaconing import detect_beaconing
    assert detect_beaconing(g) == []
    assert q.hunt_lateral_movement_telemetry(g) == []


def test_attach_evidence_chains_never_drops_findings_on_empty_engine():
    eng = GraphEngine()
    findings = [{"title": "odd finding", "severity": "high",
                 "evidence": ["sig-1"], "nodes": ["host:nowhere"]}]
    out = ev.attach_evidence_chains(eng, findings)
    assert len(out) == 1
    chain = out[0]["evidence_chain"]
    for key in ("detection_method", "signals", "signal_count", "subgraph",
                "recommended_action", "synthetic"):
        assert key in chain
    assert chain["subgraph"] == {"nodes": ["host:nowhere"], "edges": []}


# ---------------------------------------------------------------------------
# 3. /contain gate edge cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action,expected", [
    ("observe", STATUS_RECOMMENDED),        # 1.00 — top of the borderline
    ("flag_account", STATUS_RECOMMENDED),   # 0.95 — just above 0.90
    ("revoke_token", STATUS_QUEUED),        # 0.85 — just below 0.90
    ("isolate_host", STATUS_QUEUED),
    ("wipe_device", STATUS_QUEUED),         # 0.20 — bottom of the catalog
])
def test_gate_borderline_reversibility(action, expected):
    d = evaluate_action(action, "host:a")
    assert d["status"] == expected, (action, d)
    assert d["executed"] is False
    assert d["reversibility_score"] == ACTION_CATALOG[action]["reversibility"]


def test_contain_empty_action_is_422(client):
    r = client.post("/contain", json={"node_id": "host:a", "action": ""})
    assert r.status_code == 422


def test_contain_whitespace_action_normalizes(client, isolated_queue):
    r = client.post("/contain",
                    json={"node_id": "host:a", "action": "  block_ip  "})
    assert r.status_code == 200
    assert r.json()["gate"]["action"] == "block_ip"
    assert r.json()["gate"]["status"] == STATUS_QUEUED


def test_contain_duplicate_queue_dedupes(client, isolated_queue):
    payload = {"node_id": "host:dup1", "action": "isolate_host"}
    r1 = client.post("/contain", json=payload)
    r2 = client.post("/contain", json=payload)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["queued"]["id"] == r2.json()["queued"]["id"], \
        "identical pending action must not queue twice"
    queue = client.get("/decisions", params={"limit": 20}).json()["queue"]
    dupes = [rec for rec in queue if rec["node_id"] == "host:dup1"]
    assert len(dupes) == 1, f"queue shows the same action {len(dupes)}x"


# ---------------------------------------------------------------------------
# 4. Decision-queue lifecycle: queue -> decide -> resolved
# ---------------------------------------------------------------------------

def test_approval_resolves_queue_item(client, isolated_queue):
    r = client.post("/contain",
                    json={"node_id": "host:res1", "action": "isolate_host"})
    assert r.json()["gate"]["status"] == STATUS_QUEUED
    r = client.post("/decisions", json={
        "node_id": "host:res1", "action": "isolate_host",
        "target": "host:res1", "decision": "approved",
        "rationale": "qa lifecycle test",
    })
    assert r.status_code == 200
    body = client.get("/decisions", params={"limit": 20}).json()
    pending_ids = {rec["id"] for rec in body["queue"]}
    full = gate.list_queued(limit=20, only_pending=False)
    rec = next(x for x in full if x["node_id"] == "host:res1")
    assert rec["id"] not in pending_ids, \
        "approved action must leave the pending queue"
    assert rec["status"] == gate.STATUS_RESOLVED_APPROVED
    # the audit record itself is still there, and it never claims execution
    audit = next(d for d in body["decisions"]
                 if d["node_id"] == "host:res1")
    assert audit["decision"] == "approved"
    assert audit["executed"] is False


def test_rejection_resolves_queue_item(client, isolated_queue):
    client.post("/contain",
                json={"node_id": "host:res2", "action": "wipe_device"})
    client.post("/decisions", json={
        "node_id": "host:res2", "action": "wipe_device",
        "target": "host:res2", "decision": "rejected",
        "rationale": "too destructive",
    })
    body = client.get("/decisions", params={"limit": 20}).json()
    assert not [rec for rec in body["queue"]
                if rec["node_id"] == "host:res2"], \
        "rejected action must leave the pending queue"
    full = gate.list_queued(limit=20, only_pending=False)
    rec = next(x for x in full if x["node_id"] == "host:res2")
    assert rec["status"] == gate.STATUS_RESOLVED_REJECTED


def test_health_queue_depth_tracks_pending_only(client, isolated_queue):
    before = client.get("/health").json()["queue_depth"]
    client.post("/contain",
                json={"node_id": "host:qd1", "action": "block_ip"})
    assert client.get("/health").json()["queue_depth"] == before + 1
    client.post("/decisions", json={
        "node_id": "host:qd1", "action": "block_ip", "target": "host:qd1",
        "decision": "approved", "rationale": "qa",
    })
    assert client.get("/health").json()["queue_depth"] == before


# ---------------------------------------------------------------------------
# 5. Evidence-chain completeness on EVERY hunt endpoint
# ---------------------------------------------------------------------------

def _assert_complete_chain(finding):
    chain = finding.get("evidence_chain")
    assert isinstance(chain, dict), f"missing chain: {finding.get('title')}"
    for key in ("detection_method", "signals", "signal_count", "subgraph",
                "recommended_action", "synthetic"):
        assert key in chain, f"{finding.get('title')}: missing {key}"
    ra = chain["recommended_action"]
    assert ra["executed"] is False
    # severity -> approval-requirement mapping must stay consistent
    needs_approval = finding.get("severity") == "critical"
    assert ra["requires_approval"] is needs_approval, \
        f"{finding.get('title')}: severity/approval mismatch"


@pytest.mark.parametrize("url", [
    "/hunt", "/hunt/privilege-escalation", "/hunt/data-staging",
])
def test_all_hunt_endpoints_ship_complete_chains(client, url):
    r = client.post(url)
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert findings, f"{url} returned no findings to check"
    for f in findings:
        _assert_complete_chain(f)


def test_telemetry_hunts_carry_chains_when_ingested(client):
    with open(DATA_CSV) as fh:
        raw = fh.read()
    r = client.post("/ingest", json={"logs": raw, "format": "csv"})
    assert r.status_code == 200
    rb = client.post("/hunt/beaconing")
    assert rb.status_code == 200
    findings = rb.json()["findings"]
    assert findings, "sample logs embed one beaconing attack"
    for f in findings:
        _assert_complete_chain(f)


# ---------------------------------------------------------------------------
# 6. API smoke: the core contract, real outputs
# ---------------------------------------------------------------------------

def test_blast_radius_api_source_distance_zero_and_classified(client):
    node_id = client.get("/graph").json()["nodes"][0]["id"]
    r = client.post("/blast-radius", json={"node_id": node_id})
    assert r.status_code == 200
    body = r.json()
    assert body["blast_radius"][node_id]["distance"] == 0
    assert body["blast_radius"][node_id]["risk_score"] == 100.0
    assert body["blast_radius"][node_id]["data_classification"] in {
        "regulated", "personal", "internal", "public"}
    assert isinstance(body["actions"], list)


def test_redteam_run_oauth_scenario_metrics(client):
    r = client.post("/redteam/run/oauth-scope-creep-exfil")
    assert r.status_code == 200
    body = r.json()
    for key in ("mttd_seconds", "mttc_seconds", "blast_radius"):
        assert key in body, f"missing {key}"
    assert "precision" in body["blast_radius"]
    assert 0.0 <= body["blast_radius"]["precision"] <= 1.0


def test_error_bodies_leak_no_tracebacks(client):
    cases = [
        ("post", "/contain",
         {"node_id": "host:a", "action": "launch_missiles"}, 422),
        ("post", "/blast-radius", {"node_id": "host:ghost-zzz"}, 404),
        ("post", "/redteam/run/no-such-scenario", {}, 404),
        ("post", "/decisions",
         {"node_id": "h", "action": "a", "target": "t",
          "decision": "maybe"}, 400),
    ]
    for method, url, payload, want in cases:
        r = getattr(client, method)(url, json=payload)
        assert r.status_code == want, (url, r.status_code)
        text = r.text
        for leak in ("Traceback", "File \"", "graphops/", ".py\", line"):
            assert leak not in text, f"{url}: error body leaks internals"


# ---------------------------------------------------------------------------
# 7. Security review: secrets hygiene + no execution primitives
# ---------------------------------------------------------------------------

def test_gitignore_covers_local_state():
    import subprocess as sp
    out = sp.run(
        ["git", "check-ignore", "-v",
         ".containment-queue.json", ".containment-decisions.json",
         ".neo4j-credentials.txt", ".env"],
        capture_output=True, text=True,
        cwd=os.path.join(os.path.dirname(__file__), "..")).stdout
    for name in (".containment-queue.json", ".containment-decisions.json",
                 ".neo4j-credentials.txt", ".env"):
        assert name in out, f"{name} is NOT git-ignored"


def test_neo4j_credentials_not_tracked():
    import subprocess as sp
    out = sp.run(["git", "ls-files"],
                 capture_output=True, text=True,
                 cwd=os.path.join(os.path.dirname(__file__), "..")).stdout
    for line in out.splitlines():
        low = line.lower()
        assert ".neo4j" not in low and low != ".env", \
            f"secret-bearing file is tracked: {line}"


def test_no_execution_primitives_in_response_store_and_api_code():
    from graphops.response import contain
    from graphops.store import neo4j_client, supabase_client
    for mod in (gate, contain, srv, supabase_client, neo4j_client):
        src = inspect.getsource(mod)
        for prim in ("subprocess", "os.system", "os.popen", "os.exec",
                     "eval(", "exec("):
            assert prim not in src, \
                f"execution primitive {prim!r} in {mod.__name__}"


def test_gate_persistence_files_are_mode_600_if_present():
    # defense-in-depth: local queue/decisions files must not be world-readable
    import stat
    for name in (".containment-queue.json", ".containment-decisions.json",
                 ".neo4j-credentials.txt"):
        p = os.path.join(os.path.dirname(__file__), "..", name)
        if os.path.exists(p):
            mode = stat.S_IMODE(os.stat(p).st_mode)
            assert mode & 0o077 == 0, f"{name} is readable by group/other"
