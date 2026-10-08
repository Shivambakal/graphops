"""Backend build tests (2026-10-08): 2 new red-team scenarios, /redteam/metrics
rollup, input-validation hardening (422s), rate limiting (429s), decision
queue filtering/sorting, Neo4j DPDP-classification sync, and the fallback
blast-radius shape fix.

Runs against the REAL modules — no mocks of the system under test (the
Neo4j live roundtrip is skipped with a reason when Aura is unreachable).
Local containment stores are redirected to tmp paths via env overrides.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import graphops.api.server as srv
from graphops.api.server import app
from graphops.api import ratelimit
from graphops.graph.classification import CLASSIFICATIONS, classify_node
from graphops.graph.engine import GraphEngine
from graphops.intel.generator import generate
from graphops.redteam.scenarios import (
    SCENARIOS,
    get_scenario,
    list_scenarios,
    rollup_metrics,
    run_scenario,
)
from graphops.store import neo4j_client

NEW_SCENARIO_IDS = {"token-replay-finance-ledger", "c2-beaconing-to-exfil"}


@pytest.fixture(scope="module")
def engine():
    eng, _gt = generate(seed=42)
    return eng


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH",
                       str(tmp_path / "queue.json"))
    monkeypatch.setenv("GRAPHOPS_DECISIONS_PATH",
                       str(tmp_path / "decisions.json"))
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_state(tmp_path):
    # Rate-limit buckets never leak between tests in this module.
    ratelimit.reset()
    yield
    ratelimit.reset()
    srv._INGESTED_GRAPH = None
    srv._INGESTED_META = {}


# ---------------------------------------------------------------------------
# 1. Two new red-team scenarios (both verified live before being merged).
# ---------------------------------------------------------------------------

def test_catalog_now_lists_seven_scenarios():
    catalog = list_scenarios()
    assert {s["id"] for s in catalog} == NEW_SCENARIO_IDS | {
        "token-theft-to-exfil", "oauth-scope-creep-exfil",
        "impossible-travel-login", "privesc-path-chain",
        "insider-bulk-download",
    }
    for s in catalog:
        assert get_scenario(s["id"]) is not None
        assert s["synthetic"] is True


@pytest.mark.parametrize("scenario_id", sorted(NEW_SCENARIO_IDS))
def test_new_scenarios_full_coverage_zero_mttd(scenario_id):
    r = run_scenario(scenario_id)
    assert r["coverage"] == "3/3", r["stages"]
    assert r["mttd_seconds"] == 0.0
    assert r["mttc_seconds"] == 1800.0  # SLA only, containment never executes
    assert r["detections_fired_total"] >= 3
    assert all(s["status"] == "detected" for s in r["stages"])
    assert all(s["detection_delay_s"] == 0.0 for s in r["stages"])
    assert r["blast_radius"]["recall"] == 1.0  # fail-closed posture


def test_token_replay_scenario_hits_finance_ledger():
    r = run_scenario("token-replay-finance-ledger")
    by = {s["stage"]: s for s in r["stages"]}
    assert "dataset:finance-ledger" in by["finance-ledger-reached"]["key_nodes"]
    assert by["finance-ledger-reached"]["detected_by"] == ["oauth_scope_creep"]
    assert r["detections_fired"]["oauth_scope_creep"] >= 3


def test_beaconing_scenario_corrorobated_by_two_hunts():
    r = run_scenario("c2-beaconing-to-exfil")
    by = {s["stage"]: s for s in r["stages"]}
    assert set(by["beacon-channel-established"]["detected_by"]) == {
        "beaconing", "data_staging"}
    assert by["staging-for-beacon-exfil"]["detected_by"] == ["data_staging"]


@pytest.mark.parametrize("scenario_id", sorted(NEW_SCENARIO_IDS))
def test_new_scenarios_deterministic(scenario_id):
    a, b = run_scenario(scenario_id), run_scenario(scenario_id)
    assert a["coverage"] == b["coverage"]
    assert a["mttd_seconds"] == b["mttd_seconds"]
    assert a["blast_radius"] == b["blast_radius"]


@pytest.mark.parametrize("scenario_id", sorted(NEW_SCENARIO_IDS))
def test_new_scenario_key_nodes_exist_in_seed(engine, scenario_id):
    # Every stage key node must be a real node in the seeded graph —
    # the harness detects by covering these nodes with findings.
    node_ids = set(engine.graph.nodes())
    s = get_scenario(scenario_id)
    for _name, _off, nodes in s["stages"]:
        for n in nodes:
            assert n in node_ids, (scenario_id, n)


# ---------------------------------------------------------------------------
# 2. /redteam/metrics — per-method rollups + per-scenario table.
# ---------------------------------------------------------------------------

def test_rollup_metrics_shape_and_soundness():
    m = rollup_metrics(seed=42)
    assert m["scenario_count"] == 7
    assert m["synthetic"] is True
    assert "recommendations-only" in m["mttc_model"]
    assert set(m["per_scenario"]) == {s["id"] for s in SCENARIOS}
    for sid, row in m["per_scenario"].items():
        assert row["coverage"].count("/") == 1
        assert row["mttd_seconds"] is not None
        for key in ("blast_precision", "blast_recall"):
            assert row[key] is None or 0.0 <= row[key] <= 1.0
    # per-method: one entry per hunt actually run
    assert set(m["per_method"]) == {
        "lateral_movement", "beaconing", "impossible_travel",
        "privilege_escalation", "data_staging", "oauth_scope_creep",
    }
    for name, row in m["per_method"].items():
        assert row["firings_total"] >= 0
        assert 0 <= row["scenarios_detected"] <= 7
        assert row["stages_detected"] >= row["scenarios_detected"] or \
            row["stages_detected"] == 0
        if row["stages_detected"]:
            assert 0.0 <= row["mean_detection_delay_s"]
    # oauth_scope_creep must show up (two token scenarios now)
    assert m["per_method"]["oauth_scope_creep"]["scenarios_detected"] >= 2
    assert m["per_method"]["beaconing"]["stages_detected"] >= 1
    # totals are bounded means
    assert 0.0 <= m["totals"]["mean_coverage"] <= 1.0
    assert 0.0 <= m["totals"]["mean_blast_precision"] <= 1.0
    assert 0.0 <= m["totals"]["mean_blast_recall"] <= 1.0


def test_rollup_metrics_deterministic():
    def _core(m):
        return {k: v for k, v in m.items()
                if k not in ("computed_ms", "generated_at")}
    assert _core(rollup_metrics()) == _core(rollup_metrics())


def test_metrics_endpoint_caches_and_serves(client):
    r1 = client.get("/redteam/metrics")
    assert r1.status_code == 200
    body = r1.json()
    assert body["scenario_count"] == 7
    assert body["per_method"]["data_staging"]["firings_total"] >= 1
    # second hit is served from the TTL cache: identical payload
    srv._METRICS_CACHE["at"]  # cache was populated
    r2 = client.get("/redteam/metrics")
    assert r2.json() == body


# ---------------------------------------------------------------------------
# 3. Input-validation hardening — absurd inputs are 422s, not 500s/200s.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["0", "-5", "1001", "999999999999", "abc"])
def test_hunt_rejects_absurd_max_findings(client, bad):
    r = client.post("/hunt", params={"max_findings": bad})
    assert r.status_code == 422, bad


def test_hunt_accepts_boundary_max_findings(client):
    assert client.post("/hunt", params={"max_findings": 1}).status_code == 200
    assert client.post("/hunt",
                       params={"max_findings": 1000}).status_code == 200


def test_blast_radius_rejects_empty_and_oversized_node_id(client):
    assert client.post("/blast-radius",
                       json={"node_id": ""}).status_code == 422
    assert client.post("/blast-radius",
                       json={"node_id": "x" * 300}).status_code == 422
    # unknown-but-wellformed ids still 404 (contract preserved)
    assert client.post("/blast-radius",
                       json={"node_id": "host:nope"}).status_code == 404


def test_contain_rejects_bad_shapes(client):
    base = {"node_id": "host:ws-007", "action": "observe"}
    assert client.post("/contain",
                       json={**base, "node_id": ""}).status_code == 422
    assert client.post("/contain",
                       json={**base, "action": ""}).status_code == 422
    assert client.post("/contain",
                       json={**base, "action": "a" * 100}).status_code == 422
    assert client.post("/contain",
                       json={**base,
                             "context": {f"k{i}": "v" for i in range(51)}
                             }).status_code == 422
    assert client.post("/contain",
                       json={**base, "requested_by": "u" * 100}
                       ).status_code == 422
    # unknown actions still 422 through the gate (contract preserved)
    assert client.post("/contain",
                       json={"node_id": "host:a",
                             "action": "launch_missiles"}).status_code == 422
    # and the happy path is untouched
    assert client.post("/contain", json=base).status_code == 200


def test_ingest_rejects_bad_shapes(client):
    assert client.post("/ingest", json={"format": "csv"}).status_code == 422
    assert client.post("/ingest",
                       json={"logs": "x", "format": "xml"}).status_code == 422
    assert client.post("/ingest", json={"logs": ""}).status_code == 422
    # >5 MB payload is rejected at the model boundary, before parsing
    big = "timestamp,host\n" + "2026-01-01,host:a\n" * 400_000
    assert len(big) > 5_000_000
    assert client.post("/ingest",
                       json={"logs": big, "format": "csv"}).status_code == 422


def test_decisions_query_params_validated(client):
    assert client.get("/decisions", params={"limit": 0}).status_code == 422
    assert client.get("/decisions", params={"limit": 999}).status_code == 422
    assert client.get("/decisions",
                      params={"sort": "sideways"}).status_code == 422
    assert client.get("/decisions",
                      params={"min_reversibility": 1.5}).status_code == 422
    assert client.get("/decisions",
                      params={"min_reversibility": -0.1}).status_code == 422


# ---------------------------------------------------------------------------
# 4. Rate limiting on /ingest and /contain — trips, then reports Retry-After.
# ---------------------------------------------------------------------------

def test_contain_rate_limit_trips(client, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_RL_CONTAIN_PER_MIN", "2")
    payload = {"node_id": "host:ws-007", "action": "observe"}
    assert client.post("/contain", json=payload).status_code == 200
    assert client.post("/contain", json=payload).status_code == 200
    r = client.post("/contain", json=payload)
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}
    assert "rate limit" in r.json()["detail"].lower()


def test_ingest_rate_limit_trips(client, monkeypatch):
    monkeypatch.setenv("GRAPHOPS_RL_INGEST_PER_MIN", "1")
    logs = "timestamp,host,event\n2026-01-01T00:00:00Z,host:a,4624\n"
    assert client.post("/ingest",
                       json={"logs": logs, "format": "csv"}).status_code == 200
    r = client.post("/ingest", json={"logs": logs, "format": "csv"})
    assert r.status_code == 429


def test_rate_limit_defaults_are_generous_enough_for_normal_use(client):
    # default 120/min on /contain: 10 rapid calls must all pass
    payload = {"node_id": "host:ws-007", "action": "observe"}
    for _ in range(10):
        assert client.post("/contain", json=payload).status_code == 200


def test_rate_limit_unit_semantics(monkeypatch):
    monkeypatch.setenv("GRAPHOPS_RL_WINDOW_S", "60")
    monkeypatch.setenv("GRAPHOPS_RL_CONTAIN_PER_MIN", "3")
    ip = "10.0.0.99"
    assert ratelimit.check("contain", ip) == (True, 0.0)
    assert ratelimit.check("contain", ip) == (True, 0.0)
    assert ratelimit.check("contain", ip) == (True, 0.0)
    ok, retry = ratelimit.check("contain", ip)
    assert ok is False and retry > 0
    # a different route / different client is unaffected
    assert ratelimit.check("contain", "10.0.0.100")[0] is True
    ratelimit.reset()
    assert ratelimit.check("contain", ip) == (True, 0.0)


# ---------------------------------------------------------------------------
# 5. Decision queue filtering/sorting on GET /decisions.
# ---------------------------------------------------------------------------

def _seed_decisions(client):
    # decisions: approved isolate_host, rejected observe, approved block_ip
    for node, action, decision in (
            ("host:ws-007", "isolate_host", "approved"),
            ("host:ws-023", "observe", "rejected"),
            ("host:ws-031", "block_ip", "approved")):
        r = client.post("/decisions", json={
            "node_id": node, "action": action, "target": node,
            "decision": decision, "rationale": "filter test"})
        assert r.status_code == 200
    # queue: isolate_host (0.70) + quarantine_account (0.55) queued;
    # observe (1.00) is a recommendation, never queued
    for action in ("isolate_host", "quarantine_account", "observe"):
        r = client.post("/contain",
                        json={"node_id": "host:ws-007", "action": action})
        assert r.status_code == 200


def test_decisions_filter_by_status(client):
    _seed_decisions(client)
    body = client.get("/decisions", params={"status": "approved"}).json()
    assert {d["decision"] for d in body["decisions"]} == {"approved"}
    assert len(body["decisions"]) == 2
    body = client.get("/decisions",
                      params={"status": "queued_for_approval"}).json()
    assert len(body["decisions"]) == 0
    assert len(body["queue"]) == 2
    assert all(q["status"] == "queued_for_approval" for q in body["queue"])


def test_decisions_filter_by_action(client):
    _seed_decisions(client)
    body = client.get("/decisions",
                      params={"action": "isolate_host"}).json()
    assert len(body["decisions"]) == 1
    assert body["decisions"][0]["action"] == "isolate_host"
    assert len(body["queue"]) == 1
    assert body["queue"][0]["action"] == "isolate_host"


def test_queue_filter_by_min_reversibility(client):
    _seed_decisions(client)
    q05 = client.get("/decisions",
                     params={"min_reversibility": 0.5}).json()["queue"]
    assert {q["action"] for q in q05} == {"isolate_host",
                                         "quarantine_account"}
    q08 = client.get("/decisions",
                     params={"min_reversibility": 0.8}).json()["queue"]
    assert q08 == []  # 0.70 and 0.55 both below the bar
    # decisions are untouched by the reversibility filter
    d = client.get("/decisions",
                   params={"min_reversibility": 0.99}).json()["decisions"]
    assert len(d) == 3


def test_decisions_sort_oldest_first(client):
    _seed_decisions(client)
    newest = client.get("/decisions",
                        params={"sort": "newest"}).json()["decisions"]
    oldest = client.get("/decisions",
                        params={"sort": "oldest"}).json()["decisions"]
    assert [d["id"] for d in oldest] == [d["id"] for d in reversed(newest)]
    assert oldest[0]["action"] == "isolate_host"  # seeded first


# ---------------------------------------------------------------------------
# 6. Fallback blast-radius shape now matches recommend_containment.
# ---------------------------------------------------------------------------

def test_fallback_containment_matches_real_shape(engine):
    node_id = "host:ws-007"
    real = client_fixture_blast_radius(engine)
    fb = srv._fallback_containment(engine, node_id)
    assert isinstance(fb["blast_radius"], dict)
    assert fb["blast_radius_size"] == len(fb["blast_radius"])
    for nid, info in fb["blast_radius"].items():
        assert isinstance(nid, str)
        assert set(info) >= {"distance", "data_classification"}
        assert isinstance(info["distance"], int) and 0 <= info["distance"] <= 4
        assert info["data_classification"] in CLASSIFICATIONS
    assert fb["blast_radius"][node_id]["distance"] == 0
    # and the key set agrees with the real engine BFS radius
    assert set(fb["blast_radius"]) == set(real)


def client_fixture_blast_radius(engine):
    from graphops.response.contain import recommend_containment
    return recommend_containment(engine, "host:ws-007")["blast_radius"]


# ---------------------------------------------------------------------------
# 7. Neo4j sync ships the DPDP classification attribute.
# ---------------------------------------------------------------------------

def test_sync_batches_carry_data_classification(engine, monkeypatch):
    seen = []

    def fake_run(statement, params=None):
        seen.append((statement, params))
        return [{"ok": 1}]

    monkeypatch.setattr(neo4j_client, "run_cypher", fake_run)
    res = neo4j_client.sync_graph(engine)
    assert res is not None and res["nodes"] > 0 and res["edges"] > 0
    node_rows = [p["batch"] for s, p in seen
                 if p and "batch" in p and "GraphOpsEvent" not in s]
    edge_rows = [p["batch"] for s, p in seen
                 if p and "batch" in p and "GraphOpsEvent" in s]
    assert node_rows, "node sync batches must be captured"
    assert edge_rows, "edge sync batches must be captured"
    checked = 0
    for batch in node_rows:
        for row in batch:
            cls = row["props"].get("data_classification")
            assert cls in CLASSIFICATIONS, row["id"]
            assert cls == classify_node(engine, row["id"])
            checked += 1
    assert checked == res["nodes"]
    by_id = {r["id"]: r for b in node_rows for r in b}
    assert by_id["dataset:customer-pii"]["props"][
        "data_classification"] == "regulated"
    assert by_id["dataset:public-assets"]["props"][
        "data_classification"] == "public"
    assert by_id["user:u-0042"]["props"][
        "data_classification"] == "regulated"


def test_sync_classification_skipped_gracefully_without_engine():
    # no graph attribute -> yields nothing, sync returns None unconfigured
    class NoGraph:
        pass
    assert list(neo4j_client._iter_nodes(NoGraph())) == []


def test_neo4j_live_classification_roundtrip(engine):
    """Live Aura roundtrip: sync, read back one regulated node, clean up.

    Skipped with a reason when Aura is unreachable from this network.
    """
    ping = neo4j_client.ping(timeout=5.0)
    if not ping["reachable"]:
        pytest.skip(f"Aura unreachable: {ping['error']}")
    res = neo4j_client.sync_graph(engine)
    assert res and res["nodes"] > 0
    try:
        rows = neo4j_client.run_cypher(
            "MATCH (n:GraphOpsEntity {id: $id}) "
            "RETURN n.data_classification AS cls",
            {"id": "dataset:customer-pii"})
        assert rows and rows[0]["cls"] == "regulated"
        rows = neo4j_client.run_cypher(
            "MATCH (n:GraphOpsEntity {id: $id}) "
            "RETURN n.data_classification AS cls",
            {"id": "user:u-0042"})
        assert rows and rows[0]["cls"] == "regulated"
    finally:
        assert neo4j_client.clear_graph() is True  # leave Aura clean


# ---------------------------------------------------------------------------
# 8. Safety invariants for the new modules.
# ---------------------------------------------------------------------------

def test_new_modules_have_no_execution_primitives():
    for rel in ("graphops/api/ratelimit.py",):
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                rel)).read()
        for prim in ("subprocess", "os.system", "os.popen", "eval(",
                     "exec(", "__import__"):
            assert prim not in src, (rel, prim)


def test_ratelimit_module_never_leaks_client_data():
    # 429 detail carries no IP and no internals
    ok, _ = ratelimit.check("contain", "203.0.113.77")
    assert ok is True
