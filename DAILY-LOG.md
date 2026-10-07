# HackFront GraphOps Build — Daily Log

Project: HackFront India 2026, Cybersecurity — "GraphOps: Graph analytics for proactive threat hunting and blast radius containment in security operations centers".
Direction: evolve ScamShield/AEGIS into a SOC-side graph threat-hunting tool (Neo4j blast-radius graph, account-takeover risk engine, explainable evidence, human-in-the-loop reporting).
Spec: BUILD-SPEC.md (written when Shivam finalizes direction — until then, Phase 1: market scans + verified research spikes + scaffolding).

Rule: every feature listed as DONE must be verified working end-to-end. Blocked items say exactly why. No theater.

---

## 2026-10-07 — DPDP classification overlay + Supabase persistence + 5 red-team demo scenarios + dashboard scenarios panel
**Commit:** (below; push + Vercel deploy to follow).

**Backend (6 features, verified — 160/160 tests green):**
1. Decision persistence: `POST /decisions` / `GET /decisions` return `"persistence": "supabase"|"local"`; Supabase `containment_queue`+`containment_decisions` first, gitignored local JSON fallback (never errors; `.containment-decisions.json` gitignored). Records carry `"executed": false` — audit only.
2. DPDP classification overlay `graphops/graph/classification.py`: `data_classification` on all 344 `/graph` nodes and every `/blast-radius` row — dataset attrs (customer-pii→regulated, public-assets→public), identity-BFS inheritance (`user:u-0042`→regulated via creep token), safe `internal` default. Live: 339-row radius of `user:u-0042` = 69 regulated / 270 internal.
3. Red-team demo scenarios `graphops/redteam/scenarios.py` — `GET /redteam/scenarios` (5) + `POST /redteam/run/{id}` → MTTD, MTTC, detections fired, blast precision/recall; deterministic; unknown id → 404. Live runs: oauth-scope-creep-exfil 3/3 MTTD 0.0; token-theft-to-exfil 5/7 (phishing/foothold = known blind spots).
4. Hunt caps: `/hunt?max_findings=N` (per-query 100, total default 500, hard max 1000); `max_findings=2` → exactly 2.
5. `/health` self-diagnostics: engine_source, persistence, supabase_configured, queue_depth, neo4j {reachable, latency_ms, error} — Aura reachable from sandbox.
6. Neo4j `ping()` liveness (never raises, creds redacted); containment paths still zero exec primitives.

**Frontend (verified — harness 39/39 + 12/12, node --check clean):** demo-scenario runner panel (list → run → animated MTTD/MTTC card, loading + offline states); decision-queue persistence badge (Supabase/local, error surfaced); blast-radius data-classification color toggle (regulated/personal/internal/public from real attrs); designed empty/offline states on every panel; SOC polish pass. Zero hardcoded data.

**Intel:** 11 dated entries appended to MARKET-SCAN.md (2026-10-07 scan: Vercel OAuth session-token breach → 2nd real-world demo scenario; DPDP 72h breach clock + ₹250cr exposure; Exabeam Agentic SOC + RiskProfiler MCP → human-approval market alignment; Keycloak 26.8.0 NHI token-exchange; PathSphere 3D BloodHound blueprint; Setu identity-trust graph; NETSCOUT copilot sequence; NHI hunt presets). **No HackFront/WUE rule, judging, or timeline changes in ~90 days — standing facts hold.**

**QA:** 21 new tests `tests/test_qa_1007.py` (blast-radius boundaries, hunt limits, /contain 422s, evidence-chain completeness, gate invariants ≥0.90, neo4j fallback); suite **160/160 green**; coordinator re-ran full smoke (TestClient): `/` 200, `/api/health` 200, `POST /api/hunt` 200, `POST /api/blast-radius` 200, `/api/decisions` 200, `/contain` isolate_host → queued_for_approval/executed=False/store=local, `/redteam/run/oauth-scope-creep-exfil` → MTTD 0.0. Security review all PASS (no hardcoded secrets, no exec in containment, no error leakage, .gitignore clean).

**Deploy:** Vercel production deployment `graphops-ijhn208jj-shivam8668bakal-7211.vercel.app` (dpl_AX6tyZrbatsVydVJGgyZpTecxvV6) → **READY** (file-based API, 66 files, today's verified tree). ⚠️ BLOCKER: GitHub push FAILED — GITHUB_TOKEN in deploy.env returns 401 (invalid/expired); worked yesterday, rejected today. Commit `c50a0c5` stays local-only until he refreshes the token (his PAT flow). Vercel deployment is the live demo of today's build, but the repo on GitHub lags behind. ⚠️ SSO wall persists: project's `ssoProtection` (`all_except_custom_domains`) 302s anonymous `/api/health` to vercel.com/sso-api — needs his call (disable SSO protection / custom domain / bypass secret).

**Next up:** wire new endpoints into dashboard fully; PPT draft; video plan; 2 more demo measurements.

## 2026-10-06 — identity-trust layer + reversibility gating + dashboard containment UI
**Commit:** 7ef145f (pushed to github.com/Shivambakal/graphops master — PUSH-CONFIRMED, local SHA == remote SHA).

**Backend (6 features, verified):**
1. Identity-trust graph layer `graphops/graph/identity.py`: oauth_token/oauth_app/oauth_scope/dataset nodes, `grants→authorizes→has_scope→accesses` edges, privilege-depth + anomaly edge weights; seed = 4 apps, 9 scopes, 3 datasets (customer-pii + finance-ledger flagged DPDP-regulated), 40 baseline tokens + 1 over-scoped anomaly token (`user:u-0042`), all `synthetic=True`. Live Aura HTTPS roundtrip: synced 57 nodes/60 edges, read back, deleted (instance clean).
2. OAuth scope-creep hunt `hunt_oauth_scope_creep()`: flags admin-level creep reaching regulated datasets — seed-42 finds `tok-campaign-01` (critical, evidence names `admin:users:write` + `customer-pii`); quiet on baseline; safe on empty engine.
3. Evidence-chain builder `graphops/hunt/evidence.py`: every `/hunt` finding carries detection_method + signals + capped 1-hop subgraph + recommended_action (`requires_approval`, `executed: False`). Smoke: 5 findings across 4 methods, all chains non-empty.
4. Reversibility-gated `POST /contain` (`graphops/response/gate.py`): 10-action catalog with reversibility scores + synthetic-estimate impact costs; observe/enrich/flag (≥0.90) → `recommended`; revoke/reset/kill/isolate/block/quarantine/wipe → `queued_for_approval`. Queue → Supabase `containment_queue` when configured else gitignored local JSON. Unknown action → 422. NOTHING executes, ever. Smoke: isolate_host → queued, score 0.70, high, $500.
5. `GET /decisions` extended: adds `queue` with reversibility_score / impact_tier / est_cost_usd / status + `persisted`/`queue_persisted`. Backward-compatible.
6. Impossible-travel campaign data: `_embed_attack` adds geo-annotated TEST-NET IPs (US/IN, 500s apart) for `user:u-0042`; existing query fires high severity on seed-42; privesc/staging counts unchanged, determinism byte-identical.

**Frontend (6 features, verified):** live findings feed (auto-refresh toggle, 45s silent, skeletons, offline halt); containment decision queue (Approve/Reject → real POST /decisions, reversible/fast-lane/audit badges); evidence-chain drawer (signals + BFS path over real /graph edges, click-through to blast radius); exfil-risk overlay on blast radius (external IPs ≤1 hop: badges + amber pulse rings, 8 flagged on 341-row radius); 3D upgrades (GSAP camera fly-to + shockwave, edge coloring by etype, alert emissive) + fixed pre-existing OrbitControls import break; SOC polish (toasts, H/D/E/C shortcuts, Cmd+K additions). Verified via headless DOM harness 26/26 and THREE-stub harness 7/7; `node --check` clean; zero hardcoded data.

**Intel:** 9 dated entries appended to MARKET-SCAN.md (2026-10-06 scan: 3d-force-graph declutter, graph-engine capacity table, Memgraph blast-radius viz patterns, analyst-handoff UX, threat-hunting MCP pivot points, Cypher attack-pattern library, Klue/Salesforce OAuth breach (Icarus), EvilTokens PhaaS). No HackFront/WUE judging/rule/timeline updates surfaced in ~90 days — standing facts unchanged.

**QA:** 27 new tests (`tests/test_qa_hardening.py`); suite **105/105 green**. Security review: no hardcoded secrets; containment path has no subprocess/os.system/eval/exec; error paths leak nothing; .gitignore covers `.env`/`.neo4j*`/`.containment-queue.json`. Full API smoke (TestClient, incl. new `/contain`, `/api/decisions`, `/hunt-runs`) all 200; coordinator re-ran: `/`, `/api/health`, `/hunt` (5 findings), `/blast-radius` (200), `/api/decisions` (200), `/contain` (isolate_host → queued 0.70) all OK.

**Deploy:** Vercel production deployment `graphops-gug46gpzk-shivam8668bakal-7211.vercel.app` → **READY** (also auto-deploy `graphops-er8t5v1r9-...` for same commit). ⚠️ BLOCKER: project's own `ssoProtection` (`all_except_custom_domains`) SSO-wall blocks anonymous `/api/health` — 302s to vercel.com/sso-api. Deployment is live in production but publicly gated by HIS project setting; anonymous health check cannot return ok. Fix options for him: disable SSO protection on the project, add a custom domain (exempt), or set a protection-bypass secret. Not changing his security setting without his word.

**Next up:** DPDP-overlay node attributes (`data_classification` on nodes) for the frontend blast-radius panel; persist decision queue to Supabase (SUPABASE_* creds now in deploy.env); 5+ demo scenarios + MTTD/MTTC measurements; PPT draft.
