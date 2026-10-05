# Copilot instructions — GraphOps

HackFront India 2026 · Cybersecurity: "Graph analytics for proactive threat hunting and blast radius containment in SOCs."

## Hard rules (never violate)
- **Containment is recommendations-only.** `graphops/response/contain.py` returns actions with `status: "recommended"` — nothing in this repo may ever auto-execute isolation, revocation, blocking, or reporting. A human reviews and acts.
- **No invented data.** Demo data comes only from the seeded generator (`graphops/intel/generator.py`, `seed=42`) and is labeled synthetic. Never fabricate findings, metrics, or telemetry.
- **Every feature must be tested.** New code needs pytest coverage in `tests/`; run the suite before calling anything done.

## Architecture
- `graphops/graph/engine.py` — `GraphEngine` over networkx.DiGraph (entities: host/user/ip/process/alert; events as edges)
- `graphops/intel/generator.py` — deterministic synthetic SOC + embedded attack campaign + `ground_truth`
- `graphops/hunt/queries.py` — hunt functions → findings `{title, severity, evidence[], nodes[]}`
- `graphops/response/contain.py` — blast radius + prioritized containment recommendations
- `graphops/api/server.py` — FastAPI (`/health`, `/hunt`, `/blast-radius`, `/graph`); also serves `dashboard/` statically at `/`
- `api/index.py` — Vercel serverless entry (strips `/api` prefix)
- `dashboard/` — vanilla JS + canvas force-directed graph; zero hardcoded data, everything from the API

## Conventions
- Python 3.11, FastAPI, Pydantic v2, NetworkX. Keep modules duck-typed and defensive (the API has fallbacks).
- Frontend: no build step, no framework — plain HTML/CSS/JS served statically.
- Keep the demo honest: offline/error states must be explicit, never faked.
