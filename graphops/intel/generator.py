"""GraphOps synthetic SOC intel generator.

SYNTHETIC DATA — generated, not real. All hosts, users, IPs, processes,
timestamps, and attack stages below are deterministically fabricated for
demo/evaluation purposes. Nothing here represents a real environment or
incident. External IPs use the TEST-NET documentation ranges (203.0.113.0/24
et al.) so they can never be mistaken for real infrastructure.

Determinism: every random choice flows through ``random.Random(seed)``;
``generate(42)`` twice yields byte-identical graphs.

Contract (against graphops.graph.engine.GraphEngine):
    add_entity(etype, eid, attrs)        # creates node id f"{etype}:{eid}"
    add_event(src, dst, etype, ts, attrs)  # creates a directed edge

Embedded scenario: a deterministic multi-stage attack campaign —
phishing -> foothold -> lateral x2 -> privesc -> staging -> exfiltration —
woven into ~7 days of realistic background telemetry.
"""

from __future__ import annotations

import random

try:  # pragma: no cover - real sibling module may not exist yet at test time
    from graphops.graph.engine import GraphEngine
except ImportError:  # pragma: no cover
    GraphEngine = None  # type: ignore[assignment]

# Fixed base epoch for all synthetic timestamps (deterministic).
BASE_EPOCH = 1728000000.0  # 2024-10-04 00:00:00 UTC
SEVEN_DAYS = 7 * 86400.0

# Fixed attack facts (deterministic by design, not drawn from the RNG).
PHISH_IP = "ip:203.0.113.10"
PHISH_USER = "user:u-0042"
FOOTHOLD_HOST = "host:ws-007"
LAT1_HOST = "host:ws-023"
LAT2_HOST = "host:ws-031"
PRIVESc_PROC = "process:lsass.exe"
STAGING_PROC = "process:7z.exe"
EXFIL_IP = "ip:203.0.113.9"


def ground_truth_attack_path() -> list:
    """Canonical attack path (node ids in execution order)."""
    return [
        PHISH_IP,
        PHISH_USER,
        FOOTHOLD_HOST,
        LAT1_HOST,
        LAT2_HOST,
        STAGING_PROC,
        EXFIL_IP,
    ]


# ---------------------------------------------------------------------------
# Background telemetry builders
# ---------------------------------------------------------------------------

_PROCESS_POOL = [
    "svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe", "msedge.exe",
    "teams.exe", "winlogon.exe", "powershell.exe", "cmd.exe", "python.exe",
    "vscode.exe", "zoom.exe", "slack.exe", "notepad++.exe", "onedrive.exe",
    "wmiprvse.exe", "dwm.exe", "lsass.exe", "spoolsv.exe", "msmpeng.exe",
]

_EXT_IP_POOL = [
    "203.0.113.20", "203.0.113.21", "203.0.113.22",
    "203.0.113.31", "198.51.100.44", "198.51.100.45",
    "192.0.2.10", "203.0.113.50",
]

_HOST_NAMES = [f"ws-{i:03d}" for i in range(1, 51)]
_USER_NAMES = [f"u-{i:04d}" for i in range(1, 201)]


def _build_entities(engine, rng):
    # Hosts.
    for name in _HOST_NAMES:
        engine.add_entity(
            "host", name,
            {"hostname": f"{name}.corp.local",
             "os": rng.choice(["Windows 11", "Windows 11", "Windows 10", "Ubuntu 22.04"]),
             "dept": rng.choice(["eng", "sales", "fin", "it", "hr"]),
             "synthetic": True},
        )
    # Users.
    first = ["alex", "priya", "raj", "mia", "chen", "ana", "omar", "sara",
             "vik", "lena", "diego", "nora", "arjun", "kate", "sam"]
    for name in _USER_NAMES:
        engine.add_entity(
            "user", name,
            {"username": f"{rng.choice(first)}.{name}",
             "role": rng.choice(["employee"] * 8 + ["admin", "dev", "exec"]),
             "synthetic": True},
        )
    # Processes.
    for proc in _PROCESS_POOL:
        engine.add_entity("process", proc, {"name": proc, "synthetic": True})
    # Staging process entity (also added here so background-only runs have it).
    engine.add_entity("process", "7z.exe", {"name": "7z.exe", "synthetic": True})
    # External IPs (TEST-NET ranges).
    for ip_id in _EXT_IP_POOL + ["203.0.113.10", "203.0.113.9"]:
        engine.add_entity(
            "ip", ip_id,
            {"reputation": "unknown", "test_net": True, "synthetic": True},
        )


def _background_events(engine, rng):
    hosts = [f"host:{h}" for h in _HOST_NAMES]
    users = [f"user:{u}" for u in _USER_NAMES]
    procs = [f"process:{p}" for p in _PROCESS_POOL]
    ext_ips = [f"ip:{p}" for p in _EXT_IP_POOL]

    # auth: user -> host (logons spread across 7 days, 8am-8pm workday bias)
    for i in range(3200):
        u = rng.choice(users)
        h = rng.choice(hosts)
        day = rng.randrange(7)
        hour = rng.choice(list(range(8, 20)) * 6 + list(range(20, 24)) + list(range(0, 8)))
        ts = BASE_EPOCH + day * 86400 + hour * 3600 + rng.randrange(3600)
        engine.add_event(u, h, "auth", ts, {
            "logon_type": rng.choice([2, 3, 10, 11]),
            "success": rng.random() > 0.02,
            "suspicious": False,
            "synthetic": True,
        })

    # network: host -> external ip (outbound web/api traffic)
    for i in range(2600):
        h = rng.choice(hosts)
        ip = rng.choice(ext_ips)
        day = rng.randrange(7)
        ts = BASE_EPOCH + day * 86400 + rng.randrange(86400)
        engine.add_event(h, ip, "network", ts, {
            "proto": rng.choice(["https", "https", "https", "http", "dns"]),
            "port": rng.choice([443, 443, 443, 80, 53]),
            "bytes": rng.randint(200, 5_000_000),
            "suspicious": False,
            "synthetic": True,
        })

    # process: host -> process (executions)
    for i in range(3400):
        h = rng.choice(hosts)
        p = rng.choice(procs)
        day = rng.randrange(7)
        ts = BASE_EPOCH + day * 86400 + rng.randrange(86400)
        engine.add_event(h, p, "process", ts, {
            "ppid": rng.randint(100, 9000),
            "cmdline": f"{p} --bg-task",
            "suspicious": False,
            "synthetic": True,
        })


# ---------------------------------------------------------------------------
# Embedded deterministic attack campaign
# ---------------------------------------------------------------------------

def _embed_attack(engine):
    """Multi-stage campaign; fixed facts + timestamps (no RNG)."""
    T0 = BASE_EPOCH + 2 * 86400 + 9 * 3600  # day 2, 09:00 UTC — phishing
    dt = 0.0
    edge_attrs = lambda **kw: dict({"suspicious": True, "synthetic": True,
                                    "campaign": "GRAPHOPS-DEMO-001"}, **kw)

    # Stage 1: phishing — external TEST-NET ip -> user (malicious mail/link)
    engine.add_event(PHISH_IP, PHISH_USER, "phishing", T0, edge_attrs(
        vector="email-link", subject="Q3 bonus payout — action required"))
    # Stage 2: foothold — user -> host:ws-007 (credential use / session)
    engine.add_event(PHISH_USER, FOOTHOLD_HOST, "auth", T0 + 1800,
                     edge_attrs(logon_type=10, note="remote-desktop-logon"))
    # Stage 3a: lateral — ws-007 -> ws-023
    engine.add_event(FOOTHOLD_HOST, LAT1_HOST, "network", T0 + 5400,
                     edge_attrs(proto="smb", port=445, note="lateral-move"))
    # Stage 3b: lateral — ws-023 -> ws-031
    engine.add_event(LAT1_HOST, LAT2_HOST, "network", T0 + 9000,
                     edge_attrs(proto="smb", port=445, note="lateral-move"))
    # Stage 4: privilege escalation — process event on ws-031
    engine.add_event(LAT2_HOST, PRIVESc_PROC, "process", T0 + 10800,
                     edge_attrs(priv="admin", note="privilege-escalation",
                                technique="T1134"))
    # Stage 5: data staging — ws-031 -> 7z.exe (archiving)
    engine.add_event(LAT2_HOST, STAGING_PROC, "process", T0 + 14400,
                     edge_attrs(note="data-staging", cmdline="7z.exe a loot.7z C:\\data"))
    # Stage 6: exfiltration — ws-031 -> ip:203.0.113.9
    engine.add_event(LAT2_HOST, EXFIL_IP, "network", T0 + 16200,
                     edge_attrs(proto="https", port=443, bytes=873_412_352,
                                note="exfiltration"))

    # Alert entities pinned to each compromised host.
    alerts = [
        ("alt-phish-01", FOOTHOLD_HOST, "high", "phishing-click"),
        ("alt-lat-01", LAT1_HOST, "high", "lateral-movement"),
        ("alt-priv-01", LAT2_HOST, "critical", "privilege-escalation"),
        ("alt-exfil-01", LAT2_HOST, "critical", "data-exfiltration"),
    ]
    for aid, host_id, sev, kind in alerts:
        engine.add_entity("alert", aid, {
            "severity": sev, "kind": kind, "status": "open",
            "campaign": "GRAPHOPS-DEMO-001", "synthetic": True})
        engine.add_event(f"alert:{aid}", host_id, "raised_on", T0 + 20000,
                         {"suspicious": True, "synthetic": True,
                          "campaign": "GRAPHOPS-DEMO-001"})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(seed: int = 42):
    """Build the synthetic SOC graph.

    Returns (engine, ground_truth) where ground_truth is:
      {"compromised_hosts": [...], "compromised_users": [...],
       "attack_path": [node ids in order], "seed": seed}
    """
    if GraphEngine is None:
        raise ImportError(
            "graphops.graph.engine.GraphEngine is not available. "
            "Ensure the sibling graph module is installed.")
    rng = random.Random(seed)
    engine = GraphEngine()
    _build_entities(engine, rng)
    _background_events(engine, rng)
    _embed_attack(engine)

    # Mark the whole engine as synthetic (duck-typed for the contract).
    try:
        engine.synthetic = True
    except AttributeError:
        pass

    ground_truth = {
        "compromised_hosts": [FOOTHOLD_HOST, LAT1_HOST, LAT2_HOST],
        "compromised_users": [PHISH_USER],
        "attack_path": ground_truth_attack_path(),
        "seed": seed,
    }
    return engine, ground_truth
