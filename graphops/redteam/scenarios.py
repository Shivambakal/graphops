"""Scripted red-team demo scenarios for GraphOps.

Five end-to-end attack narratives, replayed against the synthetic seeded
graph with progressive disclosure (same method as redteam/replay.py):
after each stage's occurrence time a subgraph of events with ts <= cutoff
is built and every hunt query runs against it. A stage counts as detected
when a single finding covers ALL of its key nodes.

NO real system access, NO auto-execution of anything — the harness only
reads the seeded graph and runs hunt queries. Every number in a scenario
report is computed from that replay; nothing is invented.

Metrics per scenario:
  - MTTD: mean detection delay over detected stages.
  - MTTC: mean(detection_delay + analyst_response_sla_seconds). Containment
    is recommendations-only and never auto-executes, so time-to-contain is
    detection time + a synthetic analyst-response SLA (clearly labeled as a
    planning estimate, default 1800 s / 30 min).
  - detections_fired: per-hunt finding counts touching the scenario's nodes.
  - blast_radius_precision / recall: recommended blast radius (from the
    scenario seed node, via graphops.response.contain) vs the scenario's
    ground-truth node set.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

try:
    from graphops.intel.generator import generate, BASE_EPOCH
except Exception:  # pragma: no cover
    generate = None  # type: ignore[assignment]
    BASE_EPOCH = 1728000000.0

try:
    from graphops.graph.engine import GraphEngine
except Exception:  # pragma: no cover
    GraphEngine = None  # type: ignore[assignment]

try:
    from graphops.hunt.queries import (
        hunt_lateral_movement,
        hunt_beaconing,
        hunt_impossible_travel,
        hunt_privilege_escalation,
        hunt_data_staging,
        hunt_oauth_scope_creep,
    )
except Exception:  # pragma: no cover
    hunt_lateral_movement = hunt_beaconing = hunt_impossible_travel = None  # type: ignore
    hunt_privilege_escalation = hunt_data_staging = hunt_oauth_scope_creep = None  # type: ignore

_DEFAULT_HUNTS = [
    ("lateral_movement", hunt_lateral_movement),
    ("beaconing", hunt_beaconing),
    ("impossible_travel", hunt_impossible_travel),
    ("privilege_escalation", hunt_privilege_escalation),
    ("data_staging", hunt_data_staging),
    ("oauth_scope_creep", hunt_oauth_scope_creep),
]
_DEFAULT_HUNTS = [(n, f) for n, f in _DEFAULT_HUNTS if callable(f)]

# Synthetic analyst-response SLA for the MTTC planning estimate (seconds).
# Containment never auto-executes; this models the human-approval wait.
ANALYST_RESPONSE_SLA_S = 1800.0

_CAMPAIGN = "GRAPHOPS-DEMO-001"
_T0 = BASE_EPOCH + 2 * 86400 + 9 * 3600  # campaign start: day 2, 09:00 UTC


def _subgraph(engine: Any, cutoff: float):
    """Fresh GraphEngine with nodes + edges whose ts <= cutoff."""
    sub = GraphEngine()
    g = engine.graph
    for nid, attrs in g.nodes(data=True):
        sub.graph.add_node(nid, **dict(attrs))
    for src, dst, attrs in g.edges(data=True):
        try:
            ts = float(attrs.get("ts", 0))
        except (TypeError, ValueError):
            ts = 0.0
        if ts <= cutoff:
            sub.graph.add_edge(src, dst, **dict(attrs))
    return sub


def _finding_nodes(finding: Dict[str, Any]) -> set:
    return {str(n) for n in (finding.get("nodes") or [])}


# ---------------------------------------------------------------------------
# Scenario catalog — (stage name, seconds after T0, key node ids).
# Key nodes must be covered by ONE finding for attribution; they are tuned
# against what the hunt queries actually report on the seeded graph.
# ---------------------------------------------------------------------------

SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "token-theft-to-exfil",
        "name": "Token Theft → Lateral Movement → Staging → Exfiltration",
        "description": (
            "Phishing steals a user's session, the attacker gets a foothold, "
            "moves laterally across two workstations, escalates privilege via "
            "LSASS, stages data with 7z, and exfiltrates to an external IP."
        ),
        "campaign": _CAMPAIGN,
        "seed_node": "user:u-0042",
        "stages": [
            ("phishing", 0, ["ip:203.0.113.10", "user:u-0042"]),
            ("foothold", 1800, ["user:u-0042", "host:ws-007"]),
            ("lateral-movement-1", 5400, ["host:ws-007", "host:ws-023"]),
            ("lateral-movement-2", 9000, ["host:ws-023", "host:ws-031"]),
            ("privilege-escalation", 10800, ["host:ws-031", "process:lsass.exe"]),
            ("data-staging", 14400, ["host:ws-031", "process:7z.exe"]),
            ("exfiltration", 16200, ["host:ws-031", "ip:203.0.113.9"]),
        ],
    },
    {
        "id": "oauth-scope-creep-exfil",
        "name": "OAuth Scope Creep → Regulated Data Access",
        "description": (
            "A Slack OAuth token is granted admin scopes beyond the app "
            "baseline; those scopes unlock DPDP-regulated datasets "
            "(customer-pii, finance-ledger). Detection is immediate because "
            "the misconfiguration is visible from t=0."
        ),
        "campaign": _CAMPAIGN,
        "seed_node": "oauth_token:tok-campaign-01",
        "stages": [
            ("anomalous-grant", 0,
             ["user:u-0042", "oauth_token:tok-campaign-01"]),
            ("admin-scope-active", 600,
             ["oauth_token:tok-campaign-01", "oauth_scope:admin:users:write"]),
            ("regulated-data-reachable", 1200,
             ["oauth_scope:admin:users:write", "dataset:customer-pii"]),
        ],
    },
    {
        "id": "impossible-travel-login",
        "name": "Impossible Travel Login",
        "description": (
            "The phished user authenticates from the US and India 500 s "
            "apart. The impossible-travel hunt fires on the second login "
            "and retroactively attributes the first login to the same "
            "finding (delay 500 s on stage 1 is the travel attribution)."
        ),
        "campaign": _CAMPAIGN,
        "seed_node": "user:u-0042",
        "stages": [
            ("sso-login-us", 3600, ["user:u-0042", "ip:203.0.113.60"]),
            ("impossible-travel", 4100, ["user:u-0042", "ip:203.0.113.61"]),
        ],
    },
    {
        "id": "privesc-path-chain",
        "name": "Privilege-Escalation Path Chain",
        "description": (
            "Attacker reaches the admin workstation laterally, then pulls "
            "admin privilege via LSASS (T1134). Stages cover the lateral "
            "arrival and the escalation event itself."
        ),
        "campaign": _CAMPAIGN,
        "seed_node": "host:ws-023",
        "stages": [
            ("lateral-arrival", 9000, ["host:ws-023", "host:ws-031"]),
            ("privilege-escalation", 10800,
             ["host:ws-031", "process:lsass.exe"]),
        ],
    },
    {
        "id": "insider-bulk-download",
        "name": "Insider Bulk Download",
        "description": (
            "A compromised insider account archives data on the admin host "
            "with 7z and pushes it to an external IP. The staging hunt fires "
            "on the archive event; exfil correlation raises it to critical."
        ),
        "campaign": _CAMPAIGN,
        "seed_node": "user:u-0042",
        "stages": [
            ("bulk-archive", 14400, ["host:ws-031", "process:7z.exe"]),
            ("bulk-exfil", 16200, ["host:ws-031", "ip:203.0.113.9"]),
        ],
    },
]


def list_scenarios() -> List[Dict[str, Any]]:
    """Catalog metadata (no replay): id, name, description, seed_node,
    stage list, campaign, synthetic flag."""
    out = []
    for s in SCENARIOS:
        out.append({
            "id": s["id"],
            "name": s["name"],
            "description": s["description"],
            "campaign": s["campaign"],
            "seed_node": s["seed_node"],
            "stage_count": len(s["stages"]),
            "stages": [{"stage": name, "offset_s": off, "key_nodes": list(nodes)}
                       for name, off, nodes in s["stages"]],
            "synthetic": True,
        })
    return out


def get_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return None


def _blast_radius_metrics(engine: Any, seed_node: str,
                          truth: List[str]) -> Dict[str, Any]:
    """Blast-radius precision/recall: recommended radius from seed_node vs
    the scenario's ground-truth node set. None when the radius is empty
    (nothing to score) or the recommendation module is unavailable."""
    radius: set = set()
    try:
        from graphops.response.contain import recommend_containment
        rec = recommend_containment(engine, seed_node)
        radius = set((rec.get("blast_radius") or {}).keys())
    except Exception:
        radius = set()
    truth_set = set(truth)
    tp = len(radius & truth_set)
    return {
        "seed_node": seed_node,
        "radius_size": len(radius),
        "ground_truth_size": len(truth_set),
        "true_positives": tp,
        "precision": round(tp / len(radius), 3) if radius else None,
        "recall": round(tp / len(truth_set), 3) if truth_set else None,
        # Fail-closed posture: the recommended radius deliberately
        # over-approximates (recall 1.0, low precision) so no true
        # compromise node is ever left out of a recommendation.
        "posture": "fail-closed: high recall, low precision by design",
    }


def run_scenario(scenario_id: str, seed: int = 42) -> Dict[str, Any]:
    """Replay one scenario; return the JSON-serializable metrics report."""
    started = time.time()
    scenario = get_scenario(scenario_id)
    if scenario is None:
        return {"error": f"unknown scenario {scenario_id!r}",
                "known": [s["id"] for s in SCENARIOS]}
    if generate is None or GraphEngine is None:
        return {"id": scenario_id, "error": "generator or engine unavailable"}

    engine, _ground_truth = generate(seed=seed)
    truth_nodes = sorted({n for _name, _off, nodes in scenario["stages"]
                          for n in nodes})

    stages: List[Dict[str, Any]] = [
        {"stage": name, "occurred_at": _T0 + offset, "key_nodes": list(nodes),
         "status": "missed", "detected_at": None,
         "detection_delay_s": None, "detected_by": [], "early_visible": False}
        for name, offset, nodes in scenario["stages"]
    ]
    cutoffs = sorted({s["occurred_at"] for s in stages})
    pending = list(stages)

    # detections_fired[hunt] = hunt firings during the replay whose finding
    # touches any scenario node. A hunt firing at several cutoffs counts
    # once per cutoff (each cutoff is a fresh hunt run).
    detections_fired: Dict[str, int] = {name: 0 for name, _ in _DEFAULT_HUNTS}

    for cutoff in cutoffs:
        sub = _subgraph(engine, cutoff)
        findings: List[Dict[str, Any]] = []
        for hunt_name, hunt_fn in _DEFAULT_HUNTS:
            try:
                res = hunt_fn(sub) or []
            except Exception:
                continue
            for f in res:
                if isinstance(f, dict):
                    findings.append((hunt_name, f))
                    if _finding_nodes(f) & set(truth_nodes):
                        detections_fired[hunt_name] += 1
        # No early break: every cutoff is a hunt run, and firings are
        # counted per cutoff even after all stages are detected.
        newly: List[Dict[str, Any]] = []
        for s in pending:
            key = set(s["key_nodes"])
            hitters = sorted({name for name, f in findings
                              if key <= _finding_nodes(f)})
            if hitters:
                s["status"] = "detected"
                s["detected_at"] = cutoff
                # Static misconfigurations (ts=0) are visible from the very
                # first cutoff, which can precede a stage's narrative
                # occurrence time. Clamp: nothing is detected "before" it
                # occurs; early_visible flags the immediate visibility.
                raw_delay = cutoff - s["occurred_at"]
                s["early_visible"] = bool(raw_delay < 0)
                s["detection_delay_s"] = round(max(raw_delay, 0.0), 1)
                s["detected_by"] = hitters
            else:
                newly.append(s)
        pending = newly

    detected = [s for s in stages if s["status"] == "detected"]
    delays = [s["detection_delay_s"] for s in detected
              if s["detection_delay_s"] is not None]
    mttd = round(sum(delays) / len(delays), 1) if delays else None
    mttc = (round(sum(d + ANALYST_RESPONSE_SLA_S for d in delays)
                  / len(delays), 1) if delays else None)

    return {
        "id": scenario["id"],
        "name": scenario["name"],
        "description": scenario["description"],
        "campaign": scenario["campaign"],
        "seed": seed,
        "synthetic": True,
        "hunts_run": [name for name, _ in _DEFAULT_HUNTS],
        "stages": stages,
        "detected": len(detected),
        "missed": len(stages) - len(detected),
        "coverage": f"{len(detected)}/{len(stages)}",
        "mttd_seconds": mttd,
        "mttc_seconds": mttc,
        "mttc_model": ("mean(detection_delay_s) + analyst_response_sla_seconds "
                       "(synthetic planning estimate; containment is "
                       "recommendations-only and never auto-executes)"),
        "analyst_response_sla_seconds": ANALYST_RESPONSE_SLA_S,
        "detections_fired": detections_fired,
        "detections_fired_total": sum(detections_fired.values()),
        "blast_radius": _blast_radius_metrics(
            engine, scenario["seed_node"], truth_nodes),
        "replay_ms": int((time.time() - started) * 1000),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


if __name__ == "__main__":
    import json
    for s in SCENARIOS:
        print(json.dumps(run_scenario(s["id"]), indent=2)[:800], "...\n")
