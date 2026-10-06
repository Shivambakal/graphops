# GraphOps — Master Plan
**HackFront India 2026 · Cybersecurity · Problem statement:** "Graph analytics for proactive threat hunting and blast radius containment in security operations centers"
**Status:** planned 2026-10-05 · direction = judge-intel combo (identity-trust graph + reversibility-gated containment + self-test harness) · pending Shivam's final greenlight
**Deadline:** prototype submit by Oct 25, 6:29 PM IST (safe target)

## 1. The bet
Every other team will build a SIEM-alert graph. We build what the actual jury obsesses over:
identity-first trust graphs (Parihar: "OAuth is a legal weapon"; Ganapathy: non-human identity blind spot),
containment with human gates at irreversible actions (Parihar's observe→prepare→act→commit; Agarwal: humans supervise critical decisions),
and proof it works (Agarwal: "Implement, Don't Fuss"; Ganapathy: "tested by execution, not intent").
Full judge reasoning: JUDGE-INTEL.md. Reconstructed rubric: JUDGING-ALGO.md. Dashboard facts: DASHBOARD-EXTRACTION-2026-10-05.md.

## 2. Architecture
- **Identity-trust graph (Neo4j):** users → OAuth tokens → third-party apps → SaaS scopes → regulated datasets; hosts/devices as second layer. Edges weighted by behavioral anomaly + privilege depth.
- **Signal layer:** ScamShield's account-takeover risk engine becomes edge-weighting; hunt queries: lateral movement, beaconing, impossible travel, privilege-escalation paths.
- **Blast radius:** BFS from compromised node with risk decay → ranked impacted assets, DPDP-regulated-data overlay (which personal datasets exposed, notification scope).
- **Containment (reversibility-gated):** every action carries reversibility score + business-impact cost. Reversible (observe/enrich/flag) runs autonomous; irreversible (isolate, revoke, block) queues behind analyst approval + one-click rollback. NEVER auto-executes.
- **Explainability:** every finding ships its evidence chain (which signals fired, the subgraph, recommended action).
- **Self-test harness:** replays scripted attack scenarios (token theft → lateral movement → staging → exfiltration) → reports MTTD, MTTC, false-positive rate, blast-radius precision. Doubles as the demo script.
- **API:** FastAPI — /health, /hunt, /blast-radius, /graph.
- **Dashboard:** dark SOC aesthetic, 3D interactive graph (Three.js), findings feed, blast-radius panel, containment queue. Awwwards-level motion; everything from the API, nothing hardcoded.

## 3. Tech stack
- Backend: Python 3.11, FastAPI, Pydantic, networkx (local/test), neo4j-driver (prod)
- Frontend: Vite + React + Three.js
- Data: seeded synthetic SOC generator (labeled synthetic) + real-telemetry adapter interface
- Infra: Neo4j Aura free tier; backend Render/Fly or laptop; frontend Vercel; repo GitHub (public at submit)

## 4. Accounts & tools checklist
- [x] GitHub account (his) — repo creation + push needs his PAT (transient, like the Jarvis flow)
- [x] Neo4j Aura free tier — LIVE (2026-10-05): instance `graphops-hackfront` (badf36f3), status RUNNING, no card used.
  URI `neo4j+s://badf36f3.databases.neo4j.io`, creds in gitignored `build/.neo4j-credentials.txt` (chmod 600).
  Sandbox note: bolt driver fails here (DNS shimmed) — use the HTTPS Query API (`/db/badf36f3/query/v2`), verified working. Bolt is fine on his laptop / deployed backends.
- [x] Vercel (his)
- [x] Python/Node toolchains (sandbox + his laptop)
- [x] Google SSO vault login for attacksurface.alerts@gmail.com (saved, do not delete)

## 5. Phase plan
- **Now → Oct 7:** foundation — graph engine, synthetic SOC generator (embedded attack campaign), hunt queries, blast-radius, API, tests (coordinator building now)
- **Oct 8 → Oct 12:** identity-trust graph layer (OAuth/token/SaaS modeling), dashboard 3D graph viz
- **Oct 13 → Oct 16:** reversibility-gated containment, self-test harness, DPDP overlay
- **Oct 17 → Oct 20:** demo scenarios (5+), measurements (precision/recall/latency), hardening
- **Oct 21 → Oct 22:** PPT, demo video, GitHub polish, README with AI/OSS disclosure + dated old-vs-new split
- **Oct 23 → Oct 24:** buffer, submission dry-run, SUBMIT (safe target Oct 25 6:29 PM)
- Daily: cron `hackfront-daily-build` — min 5 verified features/day, zero fake progress

## 6. Submission assembly (dashboard-verbatim)
PPT pdf/pptx ≤25MB · source zip/rar/7z ≤50MB · video mp4/mov ≤25MB · public GitHub URL · free-text problem statement · Cybersecurity → Problem Selection → GraphOps statement. Multiple submissions allowed, latest counts.

## 7. Risks & mitigations
- Judge lineup changes when announced → re-run intel deep dive before Nov 21 finale
- Neo4j Aura free-tier limits → NetworkX fallback kept working
- HACK8UF5 (real team) incomplete → hard eligibility gate; his action: recruit via Discord (top priority, independent of build)
- Pre-existing vs league work → dated commits + README split from day one
