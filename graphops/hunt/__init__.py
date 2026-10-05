"""GraphOps hunt queries: threat-hunting detections over the security graph."""

from graphops.hunt.queries import (
    hunt_lateral_movement,
    hunt_beaconing,
    hunt_impossible_travel,
)

__all__ = [
    "hunt_lateral_movement",
    "hunt_beaconing",
    "hunt_impossible_travel",
]
