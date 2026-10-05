"""Tests for the real detection engine: parser, beaconing math,
privilege-weighted traversal, and the end-to-end unlabeled-attack demo.

The sample CSV embeds an attack that is NOT labeled anywhere in the file.
Detectors must find it from timing/structure math alone — the tests assert
on the *properties* of the findings, never on hardcoded fixture secrets.
"""
import csv
import os

import pytest

from graphops.engine.parser import ingest, build_graph, parse_csv
from graphops.engine.beaconing import (
    detect_beaconing,
    inter_arrival_stats,
    is_periodic,
)
from graphops.engine.privilege import (
    asset_tier,
    privilege_edge_cost,
    privilege_weighted_paths,
    tier0_targets,
)
from graphops.hunt.queries import hunt_lateral_movement_telemetry

DATA_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")


def _load_graph():
    with open(DATA_CSV) as f:
        raw = f.read()
    return build_graph(ingest(raw, fmt="csv"))


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def test_parser_builds_nodes_only_from_logs():
    G = _load_graph()
    assert G.number_of_nodes() > 20
    assert G.number_of_edges() > 50
    # node ids derive from log fields
    for n in G.nodes():
        assert ":" in n
        assert n.split(":", 1)[0] in ("host", "user", "ip", "process")


def test_parser_folds_parallel_connections_into_timestamps():
    G = _load_graph()
    multi = [e for e in G.edges(data=True) if len(e[2].get("timestamps", [])) > 5]
    assert multi, "expected at least one edge with folded parallel connections"


def test_parser_handles_json_input():
    events = ingest('[{"timestamp": "2026-10-01 10:00:00", "event_id": "3", '
                    '"computer": "ws-1", "dst_ip": "8.8.8.8"}]', fmt="json")
    G = build_graph(events)
    assert G.has_edge("host:ws-1", "ip:8.8.8.8")


def test_parser_survives_malformed_rows():
    events = parse_csv("timestamp,event_id,computer\nnot-a-time,xx,\n,,,\n")
    G = build_graph(events)  # must not raise
    assert G.number_of_nodes() >= 0


# ---------------------------------------------------------------------------
# beaconing math
# ---------------------------------------------------------------------------

def test_inter_arrival_stats_periodic():
    tss = [float(60 * k) for k in range(12)]
    stats = inter_arrival_stats(tss)
    assert stats["mean_interval"] == pytest.approx(60.0)
    assert stats["stdev"] == pytest.approx(0.0)
    assert stats["cv"] == pytest.approx(0.0)
    assert is_periodic(stats)


def test_inter_arrival_stats_human_like_not_periodic():
    import random
    random.seed(1)
    t = 0.0
    tss = []
    for _ in range(20):  # irregular human browsing
        t += random.uniform(5, 900)
        tss.append(t)
    stats = inter_arrival_stats(tss)
    assert not is_periodic(stats), f"human-like traffic flagged periodic: {stats}"


def test_beaconing_finds_unlabeled_attack():
    G = _load_graph()
    findings = detect_beaconing(G)
    assert len(findings) >= 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert "T1071" in f["title"]
    # the math must show near-zero variance — the actual proof
    assert f["stats"]["cv"] < 0.35
    assert f["stats"]["count"] >= 6


def test_beaconing_ignores_benign_irregular_egress():
    G = _load_graph()
    findings = detect_beaconing(G)
    # only the periodic attacker may be flagged; benign irregular
    # egress to well-known IPs must stay silent
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# lateral movement on telemetry
# ---------------------------------------------------------------------------

def test_lateral_flags_type3_workstation_hops_and_admin_shares():
    G = _load_graph()
    findings = hunt_lateral_movement_telemetry(G)
    assert len(findings) >= 1
    titles = " ".join(f["title"] for f in findings)
    assert "T1021.002" in titles
    # admin-share access must be among the evidence
    evidence = " ".join(e for f in findings for e in f["evidence"])
    assert "C$" in evidence


def test_lateral_accepts_raw_networkx_graph():
    G = _load_graph()
    # must not require the engine wrapper object
    assert isinstance(hunt_lateral_movement_telemetry(G), list)


# ---------------------------------------------------------------------------
# privilege-weighted traversal
# ---------------------------------------------------------------------------

def test_asset_tier_detects_dc_by_pattern():
    G = _load_graph()
    assert asset_tier(G, "host:dc01") == 0
    assert asset_tier(G, "host:srv-file01") == 1
    assert asset_tier(G, "host:ws-107") == 2


def test_escalation_is_cheaper_than_lateral():
    G = _load_graph()
    up = privilege_edge_cost(G, "host:ws-107", "host:srv-file01")    # T2 -> T1
    flat = privilege_edge_cost(G, "host:ws-107", "host:ws-109")      # T2 -> T2
    assert up < flat


def test_privilege_paths_reach_tier0_with_climbs():
    G = _load_graph()
    paths = privilege_weighted_paths(G, "host:ws-107")
    assert paths, "expected an escalation path to the domain controller"
    best = paths[0]
    assert best["target"] == "host:dc01"
    assert best["privilege_climbs"], "expected T1134 climb annotations"
    assert "T1134" in best["mitre"]


def test_tier0_targets_found():
    G = _load_graph()
    assert "host:dc01" in tier0_targets(G)
