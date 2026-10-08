"""In-process rate limiting for GraphOps write endpoints.

Sliding-window limiter keyed on (route, client_ip): each route keeps a
deque of request timestamps per client; a request is allowed when fewer
than ``limit`` timestamps fall inside the trailing ``window_s``.

Limits are read from the environment on every call (so tests can tune
them without reloading the module):
  GRAPHOPS_RL_INGEST_PER_MIN  (default 30)
  GRAPHOPS_RL_CONTAIN_PER_MIN (default 120)
  GRAPHOPS_RL_WINDOW_S        (default 60)

``reset()`` clears all buckets (used by tests). Exceeding the limit
raises nothing here — the caller returns HTTP 429 with a Retry-After.
"""

from __future__ import annotations

import os
import time
from collections import deque
from typing import Deque, Dict, Tuple

_BUCKETS: Dict[Tuple[str, str], Deque[float]] = {}

_ROUTE_ENV = {
    "ingest": "GRAPHOPS_RL_INGEST_PER_MIN",
    "contain": "GRAPHOPS_RL_CONTAIN_PER_MIN",
}

_DEFAULTS = {"ingest": 30, "contain": 120}


def _limit(route: str) -> int:
    env_key = _ROUTE_ENV.get(route)
    if env_key:
        try:
            return max(1, int(os.environ.get(env_key, "") or _DEFAULTS[route]))
        except (TypeError, ValueError):
            pass
    return _DEFAULTS[route]


def _window_s() -> float:
    try:
        return max(1.0, float(os.environ.get("GRAPHOPS_RL_WINDOW_S", "") or 60))
    except (TypeError, ValueError):
        return 60.0


def check(route: str, client_ip: str) -> Tuple[bool, float]:
    """Return (allowed, retry_after_s). Never raises."""
    now = time.monotonic()
    window = _window_s()
    limit = _limit(route)
    key = (route, client_ip or "unknown")
    bucket = _BUCKETS.setdefault(key, deque())
    cutoff = now - window
    while bucket and bucket[0] <= cutoff:
        bucket.popleft()
    if len(bucket) >= limit:
        oldest = bucket[0]
        return False, max(0.1, round(oldest + window - now, 1))
    bucket.append(now)
    return True, 0.0


def reset() -> None:
    """Clear all rate-limit buckets (tests, or after config changes)."""
    _BUCKETS.clear()
