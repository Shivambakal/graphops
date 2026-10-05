"""Containment recommendation responses (recommendations only — never executes)."""

from .contain import MAX_ACTIONS, STATUS_RECOMMENDED, recommend_containment

__all__ = ["recommend_containment", "MAX_ACTIONS", "STATUS_RECOMMENDED"]
