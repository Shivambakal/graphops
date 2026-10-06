---
title: GraphOps
emoji: 🛡️
colorFrom: red
colorTo: indigo
sdk: docker
app_port: 8000
pinned: false
---

# GraphOps

Graph analytics for proactive threat hunting and blast-radius containment in security operations centers.
Built for **HackFront India 2026** (Cybersecurity problem statement).

## What it does
- **Entity graph** — hosts, users, IPs, processes, alerts + auth/network/process events (Neo4j-ready core, NetworkX local engine)
- **Threat hunting** — lateral-movement, beaconing, and impossible-travel queries with human-readable evidence chains
- **Blast radius** — distance-decayed risk scoring from any compromised node
- **Containment (recommendations only)** — prioritized actions (isolate host, revoke sessions, block IP). Nothing auto-executes; a human reviews and acts.
- **SOC dashboard** — dark interactive UI with live graph visualization
- **Self-test harness** — scripted attack replay → detection metrics (in progress)

## Run it
```bash
pip install -r requirements.txt
uvicorn graphops.api.server:app --port 8000
# open dashboard/index.html
```

## Test
```bash
python -m pytest tests/ -q
```

## Data honesty
All demo data is **synthetic, seeded, and labeled** (`graphops/intel/generator.py`, `seed=42`).
No real telemetry, no invented findings.

## Work log
- League work starts 2026-10-05 (this repo's first commits). Prior fraud-defense tooling (ScamShield/AEGIS)
  informed the design; the GraphOps engine, generator, hunt queries, and containment module were built
  during the league window.
