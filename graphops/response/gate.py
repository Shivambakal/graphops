"""Reversibility-gated containment for GraphOps.

RECOMMENDATIONS ONLY — this module never executes anything. Every proposed
containment action carries a reversibility score (0..1) and a business-impact
cost. Reversible actions (score >= 0.90: observe / enrich / flag) are
auto-approved *as recommendations*; irreversible actions (revoke, reset,
block, wipe) are QUEUED behind the analyst approval gate and persisted to
Supabase (``containment_queue`` table) when configured, else to a local
gitignored JSON store. Nothing auto-executes, ever.

Cost model: est_cost_usd values are synthetic placeholder estimates for the
demo (labeled as such) — real deployments would wire their own cost model.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

_BUILD_DIR = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Action catalog: reversibility + business impact (synthetic cost model)
# ---------------------------------------------------------------------------

ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    "observe": {
        "reversibility": 1.00, "impact_tier": "low", "est_cost_usd": 0.0,
        "description": "Watch-only telemetry enrichment; nothing changes.",
    },
    "enrich_alert": {
        "reversibility": 1.00, "impact_tier": "low", "est_cost_usd": 0.0,
        "description": "Add context to the alert record.",
    },
    "flag_account": {
        "reversibility": 0.95, "impact_tier": "low", "est_cost_usd": 0.0,
        "description": "Flag account for review; unflag is one click.",
    },
    "revoke_token": {
        "reversibility": 0.85, "impact_tier": "medium", "est_cost_usd": 50.0,
        "description": "Revoke OAuth token; user re-authenticates. Queued for approval.",
    },
    "reset_credentials": {
        "reversibility": 0.80, "impact_tier": "medium", "est_cost_usd": 100.0,
        "description": "Force password reset; disruptive but recoverable. Queued for approval.",
    },
    "kill_process": {
        "reversibility": 0.75, "impact_tier": "medium", "est_cost_usd": 150.0,
        "description": "Terminate a suspicious process; may lose work. Queued for approval.",
    },
    "isolate_host": {
        "reversibility": 0.70, "impact_tier": "high", "est_cost_usd": 500.0,
        "description": "Network-quarantine the host; downtime for its user. Queued for approval.",
    },
    "block_ip": {
        "reversibility": 0.60, "impact_tier": "medium", "est_cost_usd": 50.0,
        "description": "Block IP at the firewall; may break legit traffic. Queued for approval.",
    },
    "quarantine_account": {
        "reversibility": 0.55, "impact_tier": "high", "est_cost_usd": 1000.0,
        "description": "Disable the account; business process stops. Queued for approval.",
    },
    "wipe_device": {
        "reversibility": 0.20, "impact_tier": "high", "est_cost_usd": 5000.0,
        "description": "Destructive reimage; data loss risk. Queued for approval.",
    },
}

# Reversibility >= this is auto-approved *as a recommendation* (never executed).
# Set so that only observe / enrich / flag pass: revoke, reset, kill,
# isolate, block, quarantine, wipe all queue behind the analyst gate.
AUTO_APPROVE_MIN_REVERSIBILITY = 0.90

STATUS_RECOMMENDED = "recommended"
STATUS_QUEUED = "queued_for_approval"


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate_action(action: str, node_id: str, target: str = "",
                   context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Evaluate a containment action through the reversibility gate.

    Returns the gate decision dict. Raises ValueError for unknown actions.
    Never executes anything.
    """
    name = str(action or "").strip().lower().replace(" ", "_")
    entry = ACTION_CATALOG.get(name)
    if entry is None:
        raise ValueError(
            f"unknown containment action {action!r}; known: "
            f"{', '.join(sorted(ACTION_CATALOG))}"
        )
    reversible = float(entry["reversibility"]) >= AUTO_APPROVE_MIN_REVERSIBILITY
    status = STATUS_RECOMMENDED if reversible else STATUS_QUEUED
    return {
        "action": name,
        "node_id": str(node_id),
        "target": str(target) if target else str(node_id),
        "reversibility_score": float(entry["reversibility"]),
        "impact_tier": entry["impact_tier"],
        "est_cost_usd": float(entry["est_cost_usd"]),
        "cost_model": "synthetic estimate (demo placeholder)",
        "reversible": reversible,
        "status": status,
        "executed": False,
        "description": entry["description"],
        "context": dict(context or {}),
        "reason": ("reversible: auto-approved as recommendation"
                   if reversible else
                   "irreversible: queued behind analyst approval"),
    }


# ---------------------------------------------------------------------------
# Persistence: Supabase when configured, else local gitignored JSON store
# ---------------------------------------------------------------------------

def _queue_path() -> Path:
    override = os.environ.get("GRAPHOPS_QUEUE_PATH", "").strip()
    if override:
        return Path(override)
    return _BUILD_DIR / ".containment-queue.json"


def _local_read() -> List[Dict[str, Any]]:
    try:
        with open(_queue_path()) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _local_append(record: Dict[str, Any]) -> None:
    records = _local_read()
    records.append(record)
    try:
        p = _queue_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(records, f, indent=2)
        tmp.replace(p)
    except OSError:
        pass


def queue_action(decision: Dict[str, Any],
                 requested_by: str = "analyst") -> Tuple[Dict[str, Any], str]:
    """Persist an irreversible action behind the analyst gate.

    Returns (queued_record, store) where store is "supabase" or "local".
    The record is NOT executed — it waits for an analyst approve/reject.
    """
    record = {
        "id": uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "node_id": decision.get("node_id", ""),
        "action": decision.get("action", ""),
        "target": decision.get("target", ""),
        "reversibility_score": decision.get("reversibility_score"),
        "impact_tier": decision.get("impact_tier"),
        "est_cost_usd": decision.get("est_cost_usd"),
        "status": STATUS_QUEUED,
        "context": dict(decision.get("context") or {}),
        "requested_by": requested_by,
    }
    try:
        from graphops.store import supabase_client as _store
        if _store is not None and _store.is_configured():
            rid = _store.record_queued_action(record)
            if rid:
                record["id"] = rid
                return record, "supabase"
    except Exception:
        pass
    _local_append(record)
    return record, "local"


def list_queued(limit: int = 100) -> List[Dict[str, Any]]:
    """List queued (pending-approval) containment actions, newest first."""
    try:
        from graphops.store import supabase_client as _store
        if _store is not None and _store.is_configured():
            return _store.list_queued_actions(limit=limit)
    except Exception:
        pass
    records = _local_read()
    records.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
    return records[: max(int(limit), 1)]
