"""Red-team replay harness: replays the embedded attack campaign and measures
detection performance.

Method (progressive disclosure): the 7 campaign stages are replayed in
chronological order. After each stage's occurrence time, a subgraph containing
only events with ts <= that cutoff is built and every hunt query is executed
against it. A stage counts as detected at the first cutoff whose findings
touch one of the stage's key nodes.

Metrics:
  - detection delay per stage = first_detection_cutoff - occurred_at (>= 0)
  - MTTD = mean delay over detected stages
  - coverage = detected / total stages (missed stages are blind spots)

Output is a JSON-serializable report dict (see replay()).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

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
    )
    _HUNTS = [
        ("lateral_movement", hunt_lateral_movement),
        ("beaconing", hunt_beaconing),
        ("impossible_travel", hunt_impossible_travel),
        ("privilege_escalation", hunt_privilege_escalation),
        ("data_staging", hunt_data_staging),
    ]
except Exception:  # pragma: no cover
    _HUNTS = []

_CAMPAIGN = "GRAPHOPS-DEMO-001"
_T0 = BASE_EPOCH + 2 * 86400 + 9 * 3600  # campaign start: day 2, 09:00 UTC

# (stage name, seconds after T0, key node ids for attribution)
_STAGES = [
    ("phishing", 0, ["ip:203.0.113.10", "user:u-0042"]),
    ("foothold", 1800, ["user:u-0042", "host:ws-007"]),
    ("lateral-movement-1", 5400, ["host:ws-007", "host:ws-023"]),
    ("lateral-movement-2", 9000, ["host:ws-023", "host:ws-031"]),
    ("privilege-escalation", 10800, ["host:ws-031", "process:lsass.exe"]),
    ("data-staging", 14400, ["host:ws-031", "process:7z.exe"]),
    ("exfiltration", 16200, ["host:ws-031", "ip:203.0.113.9"]),
]


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
    nodes = finding.get("nodes") or []
    return {str(n) for n in nodes}


def replay(seed: int = 42) -> Dict[str, Any]:
    """Replay the campaign; return the JSON-serializable detection report."""
    started = time.time()
    if generate is None or GraphEngine is None:
        return {
            "campaign": _CAMPAIGN, "seed": seed, "stages": [],
            "mttd_seconds": None, "detected": 0, "missed": len(_STAGES),
            "coverage": f"0/{len(_STAGES)}", "hunts_run": [],
            "error": "generator or engine unavailable",
        }
    engine, _ground_truth = generate(seed=seed)

    stages: List[Dict[str, Any]] = [
        {"stage": name, "occurred_at": _T0 + offset, "key_nodes": list(nodes),
         "status": "missed", "detected_at": None,
         "detection_delay_s": None, "detected_by": []}
        for name, offset, nodes in _STAGES
    ]
    cutoffs = sorted({s["occurred_at"] for s in stages})
    pending = list(stages)

    for cutoff in cutoffs:
        if not pending:
            break
        sub = _subgraph(engine, cutoff)
        findings: List[Dict[str, Any]] = []
        for hunt_name, hunt_fn in _HUNTS:
            try:
                res = hunt_fn(sub) or []
            except Exception:
                continue
            for f in res:
                if isinstance(f, dict):
                    findings.append((hunt_name, f))
        newly: List[Dict[str, Any]] = []
        for s in pending:
            # A stage is attributed only when a single finding covers ALL of
            # its key nodes. Plain intersection is too loose: consecutive
            # stages share nodes (it is one chain), which would attribute a
            # stage to a finding about its neighbour (even a later stage,
            # producing negative delays).
            key = set(s["key_nodes"])
            hitters = sorted({name for name, f in findings
                              if key <= _finding_nodes(f)})
            if hitters:
                s["status"] = "detected"
                s["detected_at"] = cutoff
                s["detection_delay_s"] = round(cutoff - s["occurred_at"], 1)
                s["detected_by"] = hitters
            else:
                newly.append(s)
        pending = newly

    detected = [s for s in stages if s["status"] == "detected"]
    delays = [s["detection_delay_s"] for s in detected
              if s["detection_delay_s"] is not None]
    mttd = round(sum(delays) / len(delays), 1) if delays else None
    return {
        "campaign": _CAMPAIGN,
        "seed": seed,
        "hunts_run": [name for name, _ in _HUNTS],
        "stages": stages,
        "detected": len(detected),
        "missed": len(stages) - len(detected),
        "coverage": f"{len(detected)}/{len(stages)}",
        "mttd_seconds": mttd,
        "replay_ms": int((time.time() - started) * 1000),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(replay(), indent=2))
