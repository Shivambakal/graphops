"""GraphOps intel package — synthetic SOC telemetry generation.

SYNTHETIC DATA — generated, not real. Everything in this package is
deterministically fabricated telemetry for demo/eval use only. It does not
represent any real users, hosts, IPs, or incidents.
"""

from .generator import generate, ground_truth_attack_path

__all__ = ["generate", "ground_truth_attack_path"]
