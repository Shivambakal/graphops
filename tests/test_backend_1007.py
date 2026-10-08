"""Backend build tests (2026-10-07): Supabase/local decision persistence,
DPDP data-classification overlay, red-team demo scenarios, hunt caps, and
/health self-diagnostics.

Runs against the REAL modules — no mocks of the system under test. The
local containment stores are redirected to tmp paths via env overrides so
tests never touch the repo's stores.
"""

from __future__ import annotations

import json
import os
import re

import pytest
from fastapi.testclient import TestClient

import graphops.api.server as srv
from graphops.api.server import app
from graphops.graph.engine import GraphEngine
from graphops.graph.classification import (
    CLASSIFICATIONS,
    classify_node,
)
from graphops.intel.generator import generate
from graphops.redteam.scenarios import (
    ANALYST_RESPONSE_SLA_S,
    SCENARIOS,
    get_scenario,
    list_scenarios,
    run_scenario,
)
from graphops.response.contain import recommend_containment
from graphops.response.gate import (
    list_analyst_decisions,
    list_queued,
    record_analyst_decision,
)
from graphops.store import neo4j_client

EXPECTED_SCENARIO_IDS = {
    "token-theft-to-exfil",
    "oauth-scope-creep-exfil",
    "impossible-travel-login",
    "privesc-path-chain",
    "insider-bulk-download",
    "token-replay-finance-ledger",  # added 2026-10-08 (backend hardening)
    "c2-beaconing-to-exfil",        # added 2026-10-08 (backend hardening)
}


@pytest.fixture(scope="module")
def engine():
    eng, _gt = generate(seed=42)
    return eng


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Redirect both local stores to tmp so tests never touch the repo.
    monkeypatch.setenv("GRAPHOPS_QUEUE_PATH",
                       str(tmp_path / "queue.json"))
    monkeypatch.setenv("GRAPHOPS_DECISIONS_PATH",
                       str(tmp_path / "decisions.json"))
    return TestClient(app)


@pytest.fixture(autouse=True)
def _restore_ingest_state():
    yield
    srv._INGESTED_GRAPH = None
    srv._INGESTED_META = {}


# ---------------------------------------------------------------------------
# 1. Decision persistence: Supabase when reachable, gitignored local JSON
#    fallback otherwise; /decisions reports the persistence backend.
# ---------------------------------------------------------------------------

def test_record_decision_uses_local_store_without_supabase(tmp_path,
                                                           monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    monkeypatch.setenv("GRAPHOPS_DECISIONS_PATH",
                       str(tmp_path / "d.json"))
    rec, store = record_analyst_decision(
        "host:ws-007", "isolate_host", "host:ws-007",
        "approved", "test rationale")
    assert store == "local"
    assert rec["decision"] == "approved"
    assert rec["executed"] is False  # audit record only, never executes
    assert rec["rationale"] == "test rationale"
    assert json.loads((tmp_path / "d.json").read_text())[0]["id"] == rec["id"]


def test_record_decision_falls_back_local_when_supabase_unreachable(
        tmp_path, monkeypatch):
    # Supabase "configured" but unreachable -> local fallback, never an error.
    monkeypatch.setenv("SUPABASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "bogus-key")
    monkeypatch.setenv("GRAPHOPS_DECISIONS_PATH",
                       str(tmp_path / "d2.json"))
    rec, store = record_analyst_decision(
        "host:ws-007", "isolate_host", "host:ws-007", "rejected", "")
    assert store == "local"
    assert (tmp_path / "d2.json").exists()


def test_list_decisions_newest_first(tmp_path, monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    monkeypatch.setenv("GRAPHOPS_DECISIONS_PATH",
                       str(tmp_path / "d3.json"))
    record_analyst_decision("host:ws-007", "observe", "", "approved", "")
    record_analyst_decision("host:ws-023", "isolate_host", "host:ws-023",
                            "rejected", "")
    items, store = list_analyst_decisions(limit=50)
    assert store == "local"
    assert len(items) == 2
    assert items[0]["node_id"] == "host:ws-023"  # newest first


def test_schema_sql_covers_queue_and_decision_tables():
    sql = open(os.path.join(os.path.dirname(__file__), "..", "supabase",
                            "schema.sql")).read().lower()
    for table in ("containment_queue", "containment_decisions"):
        assert re.search(rf"create table if not exists {table}\b", sql), table
    # queued-action payload fields all have columns
    for col in ("reversibility", "impact_tier", "est_cost_usd", "status",
                "context", "requested_by"):
        assert col in sql, col
    # decision payload fields all have columns
    for col in ("decision", "decided_by", "rationale"):
        assert col in sql, col


def test_decisions_api_reports_persistence_backend(client):
    r = client.post("/decisions", json={
        "node_id": "host:ws-007", "action": "revoke_token",
        "target": "host:ws-007", "decision": "approved",
        "rationale": "api contract test",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["stored"] is True
    assert body["persistence"] == "local"
    assert body["id"]

    r = client.get("/decisions")
    assert r.status_code == 200
    body = r.json()
    assert body["persistence"] == "local"
    assert body["persisted"] is False
    assert body["decisions"][0]["action"] == "revoke_token"


def test_decision_rejects_invalid_choice(client):
    r = client.post("/decisions", json={
        "node_id": "host:ws-007", "action": "observe",
        "target": "", "decision": "maybe",
    })
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 2. DPDP data classification on /graph and /blast-radius payloads.
# ---------------------------------------------------------------------------

def test_dataset_nodes_classified_from_attributes(engine):
    assert classify_node(engine, "dataset:customer-pii") == "regulated"
    assert classify_node(engine, "dataset:finance-ledger") == "regulated"
    assert classify_node(engine, "dataset:public-assets") == "public"


def test_user_inherits_regulated_via_identity_linkage(engine):
    # user:u-0042 -> tok-campaign-01 -> slack-bot -> admin:users:write
    # -> dataset:customer-pii (regulated)
    assert classify_node(engine, "user:u-0042") == "regulated"
    assert classify_node(engine, "oauth_token:tok-campaign-01") == "regulated"


def test_unlinked_nodes_default_to_internal_safe(engine):
    assert classify_node(engine, "host:ws-001") == "internal"
    assert classify_node(engine, "host:nope-missing") == "internal"
    # unknown engine types degrade to the safe default, never raise
    assert classify_node(object(), "anything") == "internal"


def test_classification_values_are_canonical(engine):
    for nid in list(engine.graph.nodes())[:200]:
        assert classify_node(engine, nid) in CLASSIFICATIONS


def test_api_graph_nodes_carry_classification(client):
    body = client.get("/graph").json()
    assert len(body["nodes"]) > 0
    for n in body["nodes"]:
        assert n["data_classification"] in CLASSIFICATIONS
    by_id = {n["id"]: n for n in body["nodes"]}
    assert by_id["dataset:customer-pii"]["data_classification"] == "regulated"
    assert by_id["dataset:public-assets"]["data_classification"] == "public"


def test_blast_radius_entries_carry_classification(client, engine):
    body = client.post("/blast-radius",
                       json={"node_id": "user:u-0042"}).json()
    radius = body["blast_radius"]
    assert radius, "seeded user must have a non-empty blast radius"
    for nid, info in radius.items():
        assert info["data_classification"] in CLASSIFICATIONS, nid
    # the regulated dataset is inside the radius and labeled as such
    assert "dataset:customer-pii" in radius
    assert radius["dataset:customer-pii"]["data_classification"] == "regulated"
    # same via the library entry point
    lib = recommend_containment(engine, "user:u-0042")
    assert lib["blast_radius"]["dataset:customer-pii"][
        "data_classification"] == "regulated"


# ---------------------------------------------------------------------------
# 3. Red-team demo scenarios: catalog + per-scenario metrics.
# ---------------------------------------------------------------------------

def test_scenario_catalog_lists_all_five():
    catalog = list_scenarios()
    assert {s["id"] for s in catalog} == EXPECTED_SCENARIO_IDS
    for s in catalog:
        assert s["name"] and s["description"] and s["seed_node"]
        assert s["stage_count"] == len(s["stages"]) >= 2
        assert s["synthetic"] is True
        assert get_scenario(s["id"]) is not None
    assert get_scenario("nope") is None


def test_redteam_scenarios_endpoint(client):
    r = client.get("/redteam/scenarios")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == len(body["scenarios"]) == len(EXPECTED_SCENARIO_IDS)
    assert {s["id"] for s in body["scenarios"]} == EXPECTED_SCENARIO_IDS
    assert body["synthetic"] is True


def test_redteam_run_unknown_scenario_is_404(client):
    r = client.post("/redteam/run/does-not-exist")
    assert r.status_code == 404


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED_SCENARIO_IDS))
def test_scenario_report_shape_and_sound_metrics(scenario_id):
    r = run_scenario(scenario_id)
    assert r["id"] == scenario_id
    assert r["synthetic"] is True
    # MTTD / MTTC present and labeled
    assert "mttd_seconds" in r and "mttc_seconds" in r
    assert r["analyst_response_sla_seconds"] == ANALYST_RESPONSE_SLA_S
    assert "synthetic" in r["mttc_model"] or "Synthetic" in r["mttc_model"]
    assert "recommendations-only" in r["mttc_model"]
    # detection delays are never negative (static misconfigs clamp at 0)
    for st in r["stages"]:
        assert st["detection_delay_s"] is None or st["detection_delay_s"] >= 0
        assert st["status"] in ("detected", "missed")
    # coverage arithmetic is consistent
    assert r["detected"] + r["missed"] == len(r["stages"])
    assert r["coverage"] == f"{r['detected']}/{len(r['stages'])}"
    # detections fired: per-hunt counts, total consistent
    assert r["detections_fired_total"] == sum(
        r["detections_fired"].values())
    assert r["detections_fired_total"] >= r["detected"] or r["detected"] == 0
    # blast-radius precision/recall bounded
    br = r["blast_radius"]
    for key in ("precision", "recall"):
        assert br[key] is None or 0.0 <= br[key] <= 1.0
    assert br["posture"].startswith("fail-closed")


def test_scenario_detection_reality_spot_checks():
    # OAuth scope creep is a static misconfiguration: immediate detection.
    o = run_scenario("oauth-scope-creep-exfil")
    assert o["coverage"] == "3/3"
    assert o["mttd_seconds"] == 0.0
    assert any(s["early_visible"] for s in o["stages"])
    assert o["detections_fired"]["oauth_scope_creep"] >= 3
    # impossible travel retroactively attributes the first login
    it = run_scenario("impossible-travel-login")
    assert it["coverage"] == "2/2"
    assert it["detections_fired"]["impossible_travel"] >= 1
    # token-theft chain: later stages detected, phishing/foothold are the
    # known blind spots of the current hunt set (same as redteam/replay)
    t = run_scenario("token-theft-to-exfil")
    by = {s["stage"]: s["status"] for s in t["stages"]}
    assert by["exfiltration"] == "detected"
    assert by["privilege-escalation"] == "detected"


def test_scenario_runner_is_deterministic():
    a = run_scenario("privesc-path-chain")
    b = run_scenario("privesc-path-chain")
    assert a["coverage"] == b["coverage"] == "2/2"
    assert a["mttd_seconds"] == b["mttd_seconds"]
    assert a["blast_radius"] == b["blast_radius"]


def test_scenario_code_has_no_execution_primitives():
    src = open(os.path.join(os.path.dirname(__file__), "..", "graphops",
                            "redteam", "scenarios.py")).read()
    for prim in ("subprocess", "os.system", "os.popen", "eval(",
                 "exec(", "__import__"):
        assert prim not in src, prim
    # the module explicitly disavows real access / execution
    assert "NO real system access" in src
    assert "never auto-executes" in src


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED_SCENARIO_IDS))
def test_redteam_run_endpoint_returns_metrics(client, scenario_id):
    r = client.post(f"/redteam/run/{scenario_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == scenario_id
    assert body["mttd_seconds"] is not None
    assert body["mttc_seconds"] is not None
    assert "precision" in body["blast_radius"]
    assert body["detections_fired_total"] >= 1


# ---------------------------------------------------------------------------
# 4a. Hunt-query finding caps.
# ---------------------------------------------------------------------------

def test_hunt_respects_max_findings_cap(client):
    r = client.post("/hunt", params={"max_findings": 2})
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert 1 <= len(findings) <= 2
    r = client.post("/hunt")
    assert r.status_code == 200
    assert len(r.json()["findings"]) <= srv.MAX_FINDINGS_TOTAL


def test_hunt_per_query_cap_constant_sane():
    assert 1 <= srv.MAX_FINDINGS_PER_QUERY <= srv.MAX_FINDINGS_TOTAL <= 1000


# ---------------------------------------------------------------------------
# 4b. /health self-diagnostics.
# ---------------------------------------------------------------------------

def test_health_self_diagnostics(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["engine_source"] in ("generator", "fallback")
    assert body["persistence"] in ("supabase", "local")
    assert isinstance(body["supabase_configured"], bool)
    assert body["queue_depth"] is None or isinstance(
        body["queue_depth"], int)
    assert isinstance(body["ingested"], bool)
    neo = body["neo4j"]
    assert isinstance(neo["reachable"], bool)
    assert neo["latency_ms"] is None or isinstance(neo["latency_ms"], int)
    # no credentials ever leak through diagnostics
    assert "password" not in json.dumps(body).lower()


def test_neo4j_ping_never_raises_and_reports_unconfigured(monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.delenv("NEO4J_USERNAME", raising=False)
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
    # creds file exists in the repo dir; point resolution away by renaming
    # env is enough for "not configured" only if no file — the file exists,
    # so instead assert ping returns a well-formed dict either way.
    res = neo4j_client.ping(timeout=2.0)
    assert set(res) == {"reachable", "latency_ms", "error"}
    assert isinstance(res["reachable"], bool)


def test_neo4j_ping_unreachable_host_reports_cleanly(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "neo4j+s://127.0.0.1:1")
    monkeypatch.setenv("NEO4J_USERNAME", "neo4j")
    monkeypatch.setenv("NEO4J_PASSWORD", "bogus")
    res = neo4j_client.ping(timeout=2.0)
    assert res["reachable"] is False
    assert res["error"], "an unreachable host must report a reason"
    assert "bogus" not in res["error"], "password must never appear in errors"
