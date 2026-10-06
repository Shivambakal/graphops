# GraphOps — Deploy map

One repo, every platform. Pick any; the app is a single FastAPI process that also
serves the dashboard UI at `/` (API at `/health`, `/hunt`, `/blast-radius`, `/graph`).

## The daily loop (what Shivam opens every day)
1. Code is pushed to GitHub (`graphops` repo).
2. **Vercel** auto-deploys on every push → the live URL always shows the latest build.
3. Dashboard API base resolves automatically: same-origin `/api` on Vercel,
   `?api=https://<backend-url>` override to point at any other backend,
   `http://localhost:8000` for local dev.

## One-click / one-command targets
| Platform | How | Notes |
|---|---|---|
| **Vercel** (frontend + API) | Import the GitHub repo on vercel.com | `vercel.json` routes `/api/*` → Python serverless, `/` → dashboard. Auto-deploys per push. |
| **Render** | New → Blueprint → point at repo | `render.yaml` builds the Dockerfile (free tier). |
| **Railway** | New project → deploy from repo | `railway.toml` uses the Dockerfile. |
| **Fly.io** | `fly launch` in repo dir | `fly.toml` (region `bom`, shared CPU). |
| **Koyeb** | Create service → GitHub → Dockerfile | No config needed; autodetects. |
| **Hugging Face Spaces** | New Space → Docker SDK → point at repo | README frontmatter sets `sdk: docker`, port 8000. |

## GPU note
GraphOps needs **no GPU** — graph traversal, hunt queries, and blast-radius scoring
are CPU work (NetworkX today, Neo4j Aura for the production graph). Deploying GPU
would be theater. If a future ML scoring model needs it, that's a Phase-2 call.

## Local
```bash
pip install -r requirements.txt
uvicorn graphops.api.server:app --port 8000   # then open http://localhost:8000/
```
`http://localhost:8000/` serves the dashboard; `/health` proves the API is up.

## Env
No secrets required for the demo build. Neo4j Aura credentials (Phase 2) go in a
gitignored `.env` — never committed.
