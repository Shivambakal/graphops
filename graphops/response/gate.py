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
STATUS_RESOLVED_APPROVED = "resolved_approved"
STATUS_RESOLVED_REJECTED = "resolved_rejected"


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
        os.chmod(tmp, 0o600)  # queue may hold attacker IOCs — owner-only
        tmp.replace(p)
    except OSError:
        pass


def _local_write_all(records: List[Dict[str, Any]]) -> None:
    try:
        p = _queue_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(records, f, indent=2)
        os.chmod(tmp, 0o600)  # queue may hold attacker IOCs — owner-only
        tmp.replace(p)
    except OSError:
        pass


def queue_action(decision: Dict[str, Any],
                 requested_by: str = "analyst") -> Tuple[Dict[str, Any], str]:
    """Persist an irreversible action behind the analyst gate.

    Returns (queued_record, store) where store is "supabase" or "local".
    The record is NOT executed — it waits for an analyst approve/reject.

    Local-store dedup: an identical (node_id, action, target) that is still
    pending is returned as-is instead of queuing a second copy — the analyst
    should never see the same irreversible action twice in the queue.
    """
    try:
        from graphops.store import supabase_client as _store
        if _store is not None and _store.is_configured():
            rid = _store.record_queued_action({
                "node_id": decision.get("node_id", ""),
                "action": decision.get("action", ""),
                "target": decision.get("target", ""),
                "reversibility_score": decision.get("reversibility_score"),
                "impact_tier": decision.get("impact_tier"),
                "est_cost_usd": decision.get("est_cost_usd"),
                "status": STATUS_QUEUED,
                "context": dict(decision.get("context") or {}),
                "requested_by": requested_by,
            })
            if rid:
                return {
                    "id": rid,
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
                }, "supabase"
    except Exception:
        pass
    # local dedup: same pending action must not queue twice
    node_id = str(decision.get("node_id", ""))
    action = str(decision.get("action", ""))
    target = str(decision.get("target", ""))
    for rec in _local_read():
        if (rec.get("status") == STATUS_QUEUED
                and str(rec.get("node_id")) == node_id
                and str(rec.get("action")) == action
                and str(rec.get("target")) == target):
            return rec, "local"
    record = {
        "id": uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "node_id": node_id,
        "action": action,
        "target": target,
        "reversibility_score": decision.get("reversibility_score"),
        "impact_tier": decision.get("impact_tier"),
        "est_cost_usd": decision.get("est_cost_usd"),
        "status": STATUS_QUEUED,
        "context": dict(decision.get("context") or {}),
        "requested_by": requested_by,
    }
    _local_append(record)
    return record, "local"


def list_queued(limit: int = 100,
              only_pending: bool = True) -> List[Dict[str, Any]]:
    """List containment actions waiting on analyst approval, newest first.

    only_pending=True (default) hides records already resolved by an analyst
    decision (resolved_approved / resolved_rejected) — the queue is the
    pending work list, not the audit trail.
    """
    try:
        from graphops.store import supabase_client as _store
        if _store is not None and _store.is_configured():
            rows = _store.list_queued_actions(limit=limit)
            if only_pending:
                rows = [r for r in rows
                        if str(r.get("status")) == STATUS_QUEUED]
            return rows
    except Exception:
        pass
    records = _local_read()
    if only_pending:
        records = [r for r in records
                   if str(r.get("status")) == STATUS_QUEUED]
    records.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
    return records[: max(int(limit), 1)]


def resolve_queued_action(node_id: str, action: str, target: str,
                          decision: str) -> int:
    """Mark pending queue records resolved after an analyst decision.

    Matches on (node_id, action, target); approved decisions mark
    resolved_approved, rejected ones resolved_rejected. Returns the number
    of records transitioned. Local store only — the Supabase client has no
    update endpoint. Never raises; a resolution failure must never break
    the /decisions audit write.
    """
    status = (STATUS_RESOLVED_APPROVED if decision == "approved"
              else STATUS_RESOLVED_REJECTED)
    try:
        records = _local_read()
        changed = 0
        now = datetime.now(timezone.utc).isoformat()
        for r in records:
            if (str(r.get("status")) == STATUS_QUEUED
                    and str(r.get("node_id")) == str(node_id)
                    and str(r.get("action")) == str(action)
                    and str(r.get("target")) == str(target)):
                r["status"] = status
                r["resolution"] = decision
                r["resolved_at"] = now
                changed += 1
        if changed:
            _local_write_all(records)
        return changed
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Analyst decisions: Supabase when configured, else local gitignored JSON.
# ---------------------------------------------------------------------------

def _decisions_path() -> Path:
    override = os.environ.get("GRAPHOPS_DECISIONS_PATH", "").strip()
    if override:
        return Path(override)
    return _BUILD_DIR / ".containment-decisions.json"


def _decisions_local_read() -> List[Dict[str, Any]]:
    try:
        with open(_decisions_path()) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _decisions_local_append(record: Dict[str, Any]) -> None:
    records = _decisions_local_read()
    records.append(record)
    try:
        p = _decisions_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(records, f, indent=2)
        os.chmod(tmp, 0o600)  # audit trail — owner-only
        tmp.replace(p)
    except OSError:
        pass


def record_analyst_decision(node_id: str, action: str, target: str = "",
                            decision: str = "", rationale: str = "",
                            decided_by: str = "analyst"
                            ) -> Tuple[Dict[str, Any], str]:
    """Persist an analyst approve/reject decision on a containment action.

    Returns (record, store) where store is "supabase" or "local".
    Supabase is tried first; when it is unconfigured or unreachable the
    decision lands in the gitignored local JSON store. The decision is an
    audit record only — it never triggers execution of anything.
    """
    record = {
        "id": uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "node_id": str(node_id),
        "action": str(action),
        "target": str(target),
        "decision": str(decision),
        "decided_by": str(decided_by),
        "rationale": str(rationale),
        "executed": False,  # audit trail only; approving never executes
    }
    try:
        from graphops.store import supabase_client as _store
        if _store is not None and _store.is_configured():
            rid = _store.record_decision(
                record["node_id"], record["action"], record["target"],
                record["decision"], record["rationale"], record["decided_by"])
            if rid:
                record["id"] = rid
                return record, "supabase"
    except Exception:
        pass
    _decisions_local_append(record)
    return record, "local"


def list_analyst_decisions(limit: int = 50) -> Tuple[List[Dict[str, Any]], str]:
    """List analyst decisions, newest first. Returns (decisions, store)."""
    try:
        from graphops.store import supabase_client as _store
        if _store is not None and _store.is_configured():
            return _store.list_decisions(limit=limit), "supabase"
    except Exception:
        pass
    records = _decisions_local_read()
    records.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
    return records[: max(int(limit), 1)], "local"
