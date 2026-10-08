# Market & Element Scan

New tech, UI elements, and market updates hunted for the HackFront GraphOps build.
Each entry: date, what it is, source link, how we could use it.

---

## 2026-10-06 — Daily scan

### 1. Graph visualization — OpenChart ships 3D via 3d-force-graph with a 2000-node gate (Sep 2026)
- **Date:** PR landed ~Sep 8, 2026 (RFC 27).
- **What:** tryopendata/openchart added `dimensions: 3` rendering with 3d-force-graph on WebGL, but gated: >2000 nodes warns and falls back to 2D. Notable implementation details: custom three.js node/link objects for per-object opacity, emphasis composition shared between 2D/3D, label budget re-ranked by camera distance with screen-space declutter, staggered entrance with camera pull-in, forced WebGL context disposal on remount.
- **Source:** https://github.com/tryopendata/openchart/pull/118
- **Use in GraphOps:** Steal the gating pattern — cap the 3D blast-radius view at ~2000 nodes with a 2D fallback (our demo graphs are smaller, so 3D stays default). Label declutter by camera distance + per-object opacity are exactly what we need for dimming unaffected subgraphs when an analyst selects a blast-radius origin node.

### 2. Graph engine capacity table (May 2026, doc refreshed ~Oct 1, 2026)
- **Date:** Post published May 27, 2026; comparison table actively maintained (updated ~Oct 1, 2026).
- **What:** Benchmark-backed engine comparison: 3D Force (WebGL/Three.js) holds 500–5,000 nodes at 60 FPS via 3D force-directed sphere; sigma.js (WebGL 2.0, ForceAtlas2 in Web Worker) handles 1,000–50,000+ for massive networks; Cytoscape/D3/Vis.js for 2D/hierarchical. Includes runtime code-splitting trick — Three.js only loaded when the 3D engine is selected.
- **Source:** https://github.com/ghackenberg/ghackenberg.github.io/blob/HEAD/src/content/posts/2026_05_27_interactive_graph_visualizations_update/index.md
- **Use in GraphOps:** Validates our 3d-force-graph choice for the demo scale; adopt the code-splitting pattern (lazy-load three.js only when the 3D tab opens) to keep the Vercel bundle small. Cite the capacity numbers in the PPT "why 3D" slide.

### 3. Blast-radius viz with Memgraph + React — shared-entity bridging + 48h temporal window (Mar 2026)
- **Date:** March 2026.
- **What:** A graph-powered threat detection build where the blast-radius Cypher runs in six steps: focal detection → 1-hop entities → parallel shared-host/shared-user/shared-IP/shared-technique queries (each returning the *bridging entity* so the UI shows *why* two detections are related, not just that they are) → 2nd ring → hop extension (technique→tactic, host→IP, process ancestry) → metadata enrichment. Critical design choice: related detections filtered to a **48-hour window** around the focal alert — temporal scoping kills noise from unrelated historical false positives.
- **Source:** https://medium.com/@th3machin3/graph-powered-threat-detection-visualizing-blast-radius-with-memgraph-and-react-c9a1ce0f9a2e
- **Use in GraphOps:** Copy the bridging-entity pattern into our /api/blast-radius response — return `via` (shared host/user/IP/technique) on every related node so the frontend can render "connected via…" labels. Adopt the 48h default temporal window as a tunable parameter in hunt queries; it's the exact "proactive threat hunting" rigor judges look for.

### 4. Analyst-handoff UX: facts vs inferences vs unknowns (updated ~Oct 1, 2026)
- **Date:** Architecture guide updated ~Oct 1, 2026 (6 days ago).
- **What:** 2026 agentic-SOC UX pattern: never present a bare confidence percentage. Split every finding into supported facts (cited telemetry), inferences (derived), assumptions (accepted due to missing data), unknowns (unresolved), contradictions. Prescribes a strict analyst-handoff block: one-sentence disposition + compact timeline + entities & blast-radius + evidence citations + queries run with negative results + missing telemetry + alternative hypotheses + recommended action with approval requirement.
- **Source:** https://threatcrush.com/blog/ai-agents-threat-detection-architecture-guide
- **Use in GraphOps:** Redesign our decision/containment cards to this format — it maps 1:1 onto our reversibility-gated containment (recommendation + evidence + reversibility score + explicit approval requirement). Negative results ("queried X, found nothing") are a strong demo differentiator for judges.

### 5. Threat-hunting MCP server: Brandes betweenness pivot points + edge tagging at build time (2026)
- **Date:** Repo active 2026 (curated May 2026).
- **What:** Graph-based threat detection stack: attack-path analysis from initial compromise to crown jewels, **pivot-point identification via Brandes betweenness centrality (NetworkX)** over the attack graph with BFS shortest-path fallback, provenance/ancestry tracking, and — key trick — **lateral-movement & credential-access edges (SMB/RDP/WinRM, lsass access) tagged at graph-build time** so MITRE TTP extraction works on real path traversals. Also honeytoken/deception helpers.
- **Source:** https://github.com/anhdung28888/threat-hunting-mcp-server
- **Use in GraphOps:** Implement Brandes betweenness as a backend endpoint (`/api/pivot-points`) — ranks which hosts/sessions are chokepoints in an attack path, a killer 3D demo (highlight pivot nodes in the blast radius). Adopt build-time edge tagging for lateral-movement edges; it makes hunt queries simpler and faster than post-hoc classification.

### 6. Cypher attack-pattern library with temporal edges for lateral movement (Oct 1, 2026)
- **Date:** Doc updated Oct 1, 2026 (5 days ago).
- **What:** A graph-analytics detection roadmap with a ready-to-copy pattern library for threat hunting: e.g. lateral movement as `MATCH (p1:Process)-[:SPAWNS*1..3]->(p2:Process)-[:CONNECTS]->(e:External)`, fan-out fraud patterns, and PPR (personalized PageRank) scoring of suspicious paths from known IOCs, plus KNN anomaly search against baseline graph embeddings.
- **Source:** https://github.com/intersystems-community/iris-vector-graph/blob/HEAD/docs/graph-analytics-detection-roadmap.md
- **Use in GraphOps:** Feed our hunt-query catalog — translate 3–4 of these Cypher patterns to our FastAPI backend as preset hunt buttons ("Lateral movement hunt", "Fan-out anomaly", "Beaconing"). PPR-from-IOCs gives us a principled risk-score we can surface in the self-test harness as real metrics.

### 7. Klue/Salesforce OAuth breach — the third OAuth-supply-chain breach in a year (Sep 29, 2026)
- **Date:** Published Sep 29, 2026 (breach began mid-June 2026).
- **What:** Threat actor Icarus compromised Klue (market-intelligence SaaS), generated OAuth tokens via a compromised integration service account, and pulled CRM data from hundreds of customer Salesforce environments — including security vendors Huntress and LastPass, who were in the blast radius. Third instance of the identical playbook in under a year (Salesloft Drift Aug 2025 → Gainsight Nov 2025 → Klue 2026). CSA data cited: 46% of organizations lack adequate visibility into non-human identities; prescription = living OAuth inventories, automated expiration/re-authorization, OAuth supply-chain controls.
- **Source:** https://securityboulevard.com/2026/09/the-fourth-oauth-breach-is-already-being-written/
- **Use in GraphOps:** This IS our identity-trust-graph demo scenario — model it end-to-end: SaaS app nodes → OAuth grant edges → tenant blast radius when one grant is compromised. "Even Huntress and LastPass were in the blast radius" is a devastating one-liner for the PPT/video. Also justifies our NHI inventory view as the remediation UI.

### 8. EvilTokens PhaaS — OAuth consent as the new phishing click, device-code abuse (May 19, 2026)
- **Date:** Published May 19, 2026 (PhaaS went live Feb 2026; 340+ M365 orgs in 5 weeks).
- **What:** EvilTokens phishing-as-a-service: victims enter a device code at microsoft.com/devicelogin, complete MFA, and hand over a **refresh token scoped to mailbox/drive/calendar/contacts with tenant-policy lifetime** — no password needed, no MFA tripped, no sign-in event looking like intrusion. Push Security: 3,750% increase in OAuth phishing/device-code abuse from 2025→2026. The key insight: the consent layer sits *below* the identity controls most orgs treat as the perimeter.
- **Source:** http://thehackernews.com/2026/05/the-new-phishing-click-how-oauth.html
- **Use in GraphOps:** Add OAuth grant edges (user→app, scopes, lifetime) as first-class citizens in the identity graph; a "suspicious grant" detector (broad scopes + recent consent + device-code flow) becomes a preset hunt. Refresh-token lifetime is a natural reversibility input: revoking a grant is low-risk, reversible containment — exactly our gating model.

### 9. HackFront India 2026 — no new organizer/judging updates found (checked Oct 6, 2026)
- **Date:** Last public coverage: June 13–21, 2026 (Leadership Forum launch at Constitution Club of India, New Delhi).
- **What:** Web search surfaced no new Where U Elevate judging, rule, or timeline announcements in the last ~90 days. Standing dashboard-authoritative facts: prototype submission Sep 22–Oct 25 (11:59 PM IST; safe target 6:29 PM), finale Nov 21–22 (30-hr, Delhi-NCR), GTM cohorts Dec 1–27; Cybersecurity has exactly one problem statement ("GraphOps: Graph analytics for proactive threat hunting and blast radius containment in SOCs"). Framing from launch coverage to echo in submission: ideas → enterprises, employability, "innovation decade."
- **Source:** https://bloggersalliance.medium.com/hackfront-india-ignites-bharats-innovation-decade-with-nationwide-innovation-league-5d4e1c8120c1 (Jun 21, 2026)
- **Use in GraphOps:** No action — keep the countdown assumptions as-is; continue the portal-watch cron. Echo the "creators not consumers / innovation decade" framing in the pitch video narration.

---

## 2026-10-07 — Daily scan

### 1. HackFront India 2026 — still no rule/judge/timeline updates in the last ~90 days
- **Date:** Checked Oct 7, 2026 (last public coverage: June 2026 launch; Where U Elevate Medium post Sep 4, 2026 is SIH-rejection advice, not HackFront changes).
- **What:** No new announcements from Where U Elevate on rules, judging criteria, named judges/mentors, or timeline shifts across web search, launch press, and their Medium channel. (Note: unstop listing "Hack in Hills '26" is a separate Galgotias event in Manali, not HackFront.) Standing dashboard facts unchanged: prototype submission Sep 22–Oct 25, safe target Oct 25 6:29 PM IST; 30-hr finale Nov 21–22 Delhi-NCR; GTM cohorts Dec 1–27; one Cybersecurity problem statement = GraphOps.
- **Source:** https://medium.com/@whereuelevate/didnt-make-it-through-smart-india-hackathon-your-hackathon-journey-isn-t-over-1b344cb31495
- **Use in GraphOps:** No changes needed — hold all assumptions, keep the build + countdown cadence. Keep watching the portal cron.

### 2. Vercel breach — stolen Google OAuth session token via Lumma stealer, $2M ransom (surfaced again May–Oct 2026)
- **Date:** Breach reported ~May 26, 2026; analysis recirculating Oct 2026.
- **What:** Attackers harvested a Google OAuth session token from a Lumma-stealer-infected personal device, replayed the session to bypass MFA into Vercel internal systems, exposed ~580 employee records, and issued a $2M ransom demand tied to customer environment variables. Key pattern: token replay gives friction-free access without re-authentication; "attackers are targeting identity trust chains between vendors, not just credentials." Mandiant cited 1,000+ SaaS environments hit in this supply-chain campaign class.
- **Source:** http://news.eastcoastsentinel.com/story/549821/how-did-a-stolen-oauth-token-bypass-mfa-in-the-2m-supply-chain-attack.html
- **Use in GraphOps:** New named demo scenario for the identity-trust graph: personal device → stolen session token → internal workspace, with MFA bypassed *without a login event*. Model it as: Employee node → personal Device node → OAuth session edge (Vercel/Google) → internal systems blast radius. Pairs perfectly with the Klue/Icarus scenario (Oct 6 scan) — two 2026 real breaches where the graph would have shown the trust chain before it broke. Both belong on the PPT.

### 3. PathSphere 3D — BloodHound-style attack-path viz architecture blueprint (Sep 2026)
- **Date:** Architecture doc updated ~Sep 27, 2026.
- **What:** Design blueprint for a web-based 3D BloodHound viewer: GPU WebGL rendering with a 250K-node-at-60-FPS design target, AD/Entra ID/cloud posture graphs, hash-chained append-only audit ledger with Ed25519-signed reports, ABAC re-authorization on every request (OPA, deny-by-default), mapped to ISO 27001:2022 / NIST CSF 2.0 / MITRE ATT&CK. Treat the 250K number as a design target, not a benchmark.
- **Source:** https://github.com/mohsin539/cybersecurity-projects/blob/HEAD/70.%20Interactive%203D%20network%20attack-path%20visualizer%20(web-based%20BloodHound%20viewer)/ARCHITECTURE.md
- **Use in GraphOps:** Steal the hash-chained audit-ledger idea for our analyst-handoff/decisions view — every containment recommendation gets an evidence-chain entry (who/what/when, cited telemetry). That's a strong differentiator vs dashboards that just log text. Also note their compliance-mapping: we can mirror control→evidence traceability for our DPDP breach-clock panel.

### 4. Setu — identity trust graph with GNN risk scoring + attack-simulation timeline (Bank of Baroda Hackathon 2026)
- **Date:** Repo active ~July 2026.
- **What:** Production-style identity-fraud platform: Neo4j graph schema, FastAPI ingestion with parameterized Cypher, synthetic SIM-swap attack *executed programmatically* with live GNN risk recomputation and hard-blocking responses, cross-entity correlation (employee account access → customer recovery attempt within 2 hours = insider-assisted ATO), per-case risk-score sparkline history, compliance mapping doc.
- **Source:** https://github.com/tejaspatel2255/bob-identity-trust-2026
- **Use in GraphOps:** Copy the 5-step attack simulation timeline pattern into our demo harness — scripted Klue/Vercel scenarios that *execute* step-by-step while the graph re-scores risk live. The "insider-assisted ATO in a 2h window" pattern is a ready-made hunt preset (temporal correlation between two entity types). The risk-score sparkline per case is a cheap, high-impact UI win.

### 5. Exabeam "Agentic SOC" launch — Claude Enterprise timeline, Executive Digest, on-prem MCP server (Oct 1, 2026)
- **Date:** Announced Oct 1, 2026.
- **What:** Exabeam's new platform release: deeper Claude Enterprise integration normalizing prompts/tool calls/actions into one timeline with behavior-based detection of rogue agents and drift; Executive Digest (boardroom metrics) + Outcomes Navigator (custom risk scoring); LogRhythm SIEM platform ships a **community MCP server** so teams can query/triage security data with *local* LLMs without data leaving the environment (on-prem agentic SOC).
- **Source:** https://www.businesswire.com/news/home/20261001892002/en/The-Agentic-SOC-Delivered-Exabeam-Accelerates-AI-Powered-Security-Operations-to-Machine-Speed
- **Use in GraphOps:** Market validation for our direction, and framing material for the PPT: the industry's "agentic SOC" converged on *assistant-as-investigator + human keeps approval* — exactly our reversibility-gated containment. The on-prem MCP-server pattern is worth mirroring: offer an MCP-style query endpoint over our graph so an analyst's local LLM can ask "show the blast radius of X" — cheap to demo, strong signal of "advanced."

### 6. RiskProfiler launches MCP connector for AI-assisted threat hunts (Oct 7, 2026 — today)
- **Date:** Announced Oct 7, 2026.
- **What:** RiskProfiler shipped an MCP Connector giving authorized users natural-language access to its external threat-intel platform via compatible AI assistants — the connector translates questions into permitted queries in the customer's environment, and **the platform remains the system of record enforcing access controls** while the assistant is just the interface layer.
- **Source:** https://itbrief.co.nz/story/riskprofiler-launches-mcp-connector-for-ai-threat-hunts
- **Use in GraphOps:** Second 2026 vendor in the same week converging on "MCP interface, platform stays the record" — cite both in the PPT "market alignment" slide. Concrete build takeaway: expose our hunt/blast-radius endpoints as a small MCP server so any assistant can call them; our API keeps enforcing reversibility gating, the agent never executes.

### 7. NETSCOUT nGenius Copilot — data-first, MCP second, conversational layer last (Sep 29, 2026)
- **Date:** Three-release sequence Sept 3 → 22 → 29, 2026; analyst take published Oct 6, 2026.
- **What:** NETSCOUT added MCP connectivity (Sep 22) then a copilot (Sep 29) *on top of* its data platform (Sep 3). Analyst read: durable value is forming in "the trustworthiness of the evidence a system reasons over," not in the copilot surface — natural-language access is baseline by late 2026.
- **Source:** https://futurumgroup.com/insights/netscout-ngenius-copilot-caps-a-three-release-data-first-strategy/
- **Use in GraphOps:** Confirms our build order: verified evidence layer (hunt queries, blast radius, audit ledger) before copilot gloss. A one-line PPT argument: "everyone has a copilot in 2026; almost nobody has an evidence layer the copilot can reason over — that's GraphOps."

### 8. Identity visibility in 2026 — build the unified NHI inventory first (Sep 2026)
- **Date:** Published ~Sep 19, 2026.
- **What:** IR-casework-backed prescription: enumerate every identity source (AD/Entra/Okta/cloud IAM/SaaS/CI-CD) into one continuously refreshed inventory *before* buying detection; treat NHIs as first-class risk; close the telemetry gap by ingesting auth logs from *all* identity planes; operationalize hunts for dormant-account reactivation, MFA-method changes, consent grants to unknown OAuth apps, and cross-platform correlation — mapped to T1078/T1098/T1550. Also: GitGuardian shipped Developer Endpoint Protection (June 2026) — treats developer laptops as credential stores, inventories secrets + discovered MCP servers/agents per machine.
- **Source:** https://securityarsenal.com/blog/identity-visibility-in-2026-why-stolen-credentials-still-beat-your-perimeter-and-how-to-fix-the-blind-spots
- **Use in GraphOps:** Adds two hunt presets we don't have: "consent grant to unknown OAuth app" and "dormant account reactivation." Also consider a "credential store" node type in the graph (laptop → secrets found → production systems they unlock), mirroring the GitGuardian endpoint model — it would make our Vercel/Lumma demo scenario literally graphable.

### 9. Keycloak 26.8.0 — AI agents as NHIs via OAuth token exchange (Oct 1, 2026)
- **Date:** Tagged Oct 1, 2026.
- **What:** Keycloak 26.8.0 implements the token-exchange delegation pattern (RFC 8693): an AI agent acting with its own credentials is an NHI; when acting for a user, the token carries both the `act` (actor = agent) and `sub` (subject = user) claims. Guidance: one shared service account per agent fleet erases attribution — inventory each agent with owner, scope, and blast radius ("what breaks if you revoke it").
- **Source:** https://skycloak.io/blog/non-human-identity-ai-agents-keycloak/
- **Use in GraphOps:** Direct schema input for our identity graph: model agent nodes with `act`/`sub` dual-claim edges (Agent —acts-for→ User), and add an "attribution gap" detector (actions whose actor claim is a shared service account = non-attributable). Also gives the PPT a fresh citation: "even our own security agents must be in the identity inventory."

### 10. DPDP Act — Board still unstaffed, penalty schedule + phase dates locked (checked Oct 7, 2026)
- **Date:** Rules notified Nov 13, 2025; status as of Sep–Oct 2026 reporting.
- **What:** The Data Protection Board of India exists in law but had **no Chairperson or Members appointed as of Sep 2026** (LiveLaw; Cabinet may clear 5 posts — chairperson + 4 members). Courts are already treating it as an available remedy, which creates a compliance-architecture gap. Phase dates: Nov 13, 2026 = Consent Manager registration goes live; May 13, 2027 = full obligations (notice, consent, breach notification, data-principal rights) with no grace period. Penalty schedule: up to ₹250 crore (security safeguards), ₹200 crore (breach-notification failure), ₹150 crore (Significant Data Fiduciary obligations), ₹50 crore (other breaches). DPDP Rules 2025 set breach notification at 72 hours to the Board + affected data principals; CERT-In's 6-hour incident-reporting rule still runs in parallel.
- **Source:** https://www.livelaw.in/articles/india-data-protection-board-established-law-543751 · https://www.saptashwatv.com/news/national-news/india-data-protection-board-five-key-posts-dpdp-act-27048.html
- **Use in GraphOps:** Add a **"DPDP 72h breach clock"** to the containment/decision card: breach discovered → countdown to 72h Board notification + data-principal notification, with penalty ceilings shown as stakes. "The Board doesn't even have a chairperson yet — the compliance burden falls on tooling, not humans" is a strong PPT one-liner. Note the ambiguity (unstaffed Board) honestly in the handoff UX: recommend notification preparation, don't pretend filing works.

### 11. Graph viz libraries — no new WebGL successor to 3d-force-graph in 2026 (checked Oct 7, 2026)
- **Date:** Checked Oct 7, 2026 (3d-force-graph v1.73.1, commits within last 7 days).
- **What:** Web search for 2026 graph-viz releases surfaced no new library dethroning 3d-force-graph for 3D SOC dashboards — recent builds (e.g., CodeGraph Galaxy, Sep 2026) still use 3D force-directed + WebGL; three.js remains actively maintained (mid-2026 commits, WebGL + WebGPU renderers). No new dedicated WebGPU graph library has emerged as a standard.
- **Use in GraphOps:** Stay with 3d-force-graph + three.js; no migration needed. Continue the LOD/declutter work from the Oct 6 scan.


---

---

## 2026-10-08 — Daily scan

### 1. CrowdSec breach — departing engineer's GitHub access kept alive, harvested via Shai-Hulud, source code stolen, found 4 months later (Oct 6, 2026)
- **Date:** Published Oct 6, 2026.
- **What:** A departing CrowdSec engineer got a routine exception to keep GitHub access for extra wrap-up time. The engineer's personal laptop was later infected by malicious TanStack NPM packages carrying Shai-Hulud malware, which harvested developer credentials and tokens; attackers used the still-live GitHub access to download private CrowdSec repositories. CrowdSec only discovered it ~4 months later when stolen source code surfaced on a public forum. Core lesson: offboarding is a credential-state problem, not a calendar date — developer access lives in personal access tokens, SSH keys, and third-party SaaS, not just the corporate account.
- **Source:** https://www.techtarget.com/cybersecurity/news/366651571/CrowdSec-breach-exposes-security-blind-spots-in-developer-access
- **Use in GraphOps:** Third named 2026 demo scenario (after Klue/Icarus, Vercel/OAuth). Model: Employee node → GitHub OAuth/PAT edge → exception-flagged grant (no platform-enforced expiry) → stolen token via endpoint malware → private repo exfiltration, with a 4-month dwell. Add an "orphaned exception" hunt preset: grants/tokens surviving past the offboarding date with no expiry — exactly the graph query judges will ask about.

### 2. AWS Loom flaws — OAuth2 token theft via MCP/A2A scopes + SageMaker credential disclosure (fixed Aug 2026, reported ~Oct 4, 2026)
- **Date:** Flaws fixed in Loom 1.6.1 (Aug 4, 2026) and 1.7.0; reported Oct 4, 2026.
- **What:** AWS patched four issues: CVE-2026-103957 (unsafe OAuth2 discovery-URL handling — an authenticated user with `mcp:write` or `a2a:write` scope could point the Loom backend at an attacker-controlled discovery endpoint, sending OAuth2 client secrets or another user's access token to it); CVE-2026-103958 (SSRF in Loom's MCP tool server/Agent2Agent connection logic, able to reach container credential-vending endpoints and expose temporary AWS credentials); plus an auth bypass and a SageMaker Space startup-script command injection (CVE-2026-104019) that could yield another member's Trusted Identity Propagation credentials.
- **Source:** https://completeaitraining.com/news/aws-fixes-authentication-bypass-and-token-theft-flaws-in/
- **Use in GraphOps:** This is the NHI/agentic-identity blast radius made concrete: OAuth scopes (`mcp:write`, `a2a:write`) become attack edges. Add MCP/A2A servers and agent tool scopes as node types in the identity graph with a "scope-grant abuse path" hunt. Also a framing gem for Judge Ganapathy: agents themselves are NHIs with token-bearing edges — they must be inventoried like any other identity, not trusted by default.

### 3. ClearVector 2026 Identity Intelligence Report — NHIs are 91% of active production identities (report cited Aug 2026)
- **Date:** Reported Aug 6, 2026 (ClearVector 2026 Identity Intelligence Report, drawn from AWS/Google Cloud environments).
- **What:** 91% of active identities in production belong to machines (service accounts, execution roles, managed identities, vendor credentials). Only 20% of non-human activity falls inside business hours — time-of-day tells defenders almost nothing. June 2026: stolen credentials + trusted publishing workflows pushed malicious packages through Red Hat's legitimate channels ("Miasma"); April 2026: LiteLLM compromise fed the Mercor breach; May 2026: researchers watched an LLM-driven workflow use harvested cloud credentials to pull secrets from AWS Secrets Manager.
- **Source:** https://www.helpnetsecurity.com/2026/08/06/non-human-identities-active-in-production/
- **Use in GraphOps:** Two things. (a) PPT stats for the NHI blind-spot slide: "91% of production identities are machines; only 20% of their activity happens during business hours." (b) A new hunt preset: "off-hours NHI anomaly" is weak — instead detect *attribution-less* privileged NHI actions, since time-of-day is admitted noise. Pairs with the Oct 7 Keycloak `act`/`sub` entry: flag actions missing an attributable actor.

### 4. SpyCloud 2026 Identity Threat Report — compromised NHIs now the #1 enterprise entry point (Sep 9, 2026)
- **Date:** Published Sep 9, 2026.
- **What:** Survey-based study: compromised non-human identities (31%) are now ~2x as likely to be the primary entry point as phishing/social engineering (17%), the #2 answer. NHI misuse was the most commonly reported identity event type (42%). Yet 95% of organizations believe they have visibility into AI/machine identity exposures while only 36% actually monitor them — the least-watched identity risk category. 68% of orgs experienced an identity-based event, averaging 8 each.
- **Source:** https://www.csoonline.com/article/4220209/spycloud-2026-identity-threat-report-finds-non-human-identities-are-now-the-leading-path-into-the-enterprise.html
- **Use in GraphOps:** The single strongest authority citation for the entire GraphOps premise: NHIs outrank phishing as the entry point and almost nobody watches them. Put the "31% vs 17% / 95% believe, 36% monitor" pair on the problem statement slide verbatim. Also validates the NHI inventory view as the hero screen of the dashboard, not an add-on.

### 5. OCC launches Bedrock SOC Agent — agentic investigation with human-in-the-loop control, interpretable and auditable (Sep 29, 2026)
- **Date:** Announced Sep 29, 2026.
- **What:** The Options Clearing Corporation (world's largest equity derivatives clearing org) launched a Bedrock-built SOC agent that automates alert investigation — forming lines of inquiry, retrieving evidence, evaluating findings — while delivering interpretable, auditable results and keeping human experts firmly in control of the process and outcomes, with a human-in-the-loop feedback system for continuous improvement. AWS framed it as preserving "the critical human judgment that security requires."
- **Source:** https://press.aboutamazon.com/aws/2026/9/occ-strengthens-security-operations-with-an-agentic-ai-investigation-solution-built-on-aws
- **Use in GraphOps:** Market-validation gold for Judge Agarwal's "humans supervise critical decisions" bar: even a systemically important clearing corp ships agentic investigation but keeps humans in control — exactly our reversibility-gated containment thesis. Cite on the "why human approval" slide. Also mirror their pattern: investigation lines of inquiry as an auditable sequence we log into our evidence-chain ledger.

### 6. Zscaler Agentic SOC — "data-rich context graph" at the core of detect/investigate/respond (Sep 9, 2026)
- **Date:** Announced Sep 9, 2026.
- **What:** Zscaler's new platform centers on a "data-rich context graph" correlating real-time zero-trust telemetry with third-party data to map, prioritize, and investigate complex incident chains; specialized AI agents handle triage, root-cause investigation, verdicts, and response workflows; closed-loop inline remediation isolates users, blocks C2, and cuts lateral movement at machine speed. Built on 750 billion daily zero-trust transactions and the world's largest decoy mesh network.
- **Source:** https://www.globenewswire.com/news-release/2026/09/09/3358327/0/en/zscaler-launches-agentic-soc-to-contain-ai-driven-threats.html
- **Use in GraphOps:** A global security vendor independently converged on "context graph at the center of the SOC" — our architecture thesis, named on a launch press release a month before submission. Use the phrase "data-rich context graph" in the PPT to signal category alignment, then differentiate: Zscaler's remediation is closed-loop/auto; GraphOps is reversibility-gated/human-approved. That contrast is the moat slide.

### 7. DPDP — Board still not set up with 5 weeks to the Nov 13 enforcement milestone (Oct 5, 2026)
- **Date:** Published Oct 5, 2026.
- **What:** With the Consent Manager registration window opening Nov 13, 2026, privacy-tech firms are holding back from registering: the key adjudicating authority (Data Protection Board of India) is yet to be set up and the Board's detailed guidelines on the Consent Manager regime are unpublished. Meanwhile a companion compliance explainer notes enforcement powers (inquiries + penalties up to ₹250 crore per instance for security-safeguard failures) arrive Nov 13, 2026, six months before substantive obligations bite (May 13, 2027) — 2026 is deliberate "soft enforcement" (guidance, warnings, inquiries), not the punitive phase.
- **Source:** https://www.thehindubusinessline.com/info-tech/dpdp-privacy-tech-firms-weigh-consent-manager-role-await-regulatory-uncertainty-and-board-formation/article71544123.ece/amp/ · https://myprivacy.blog/india-dpdp-november-2026-enforcement-clock/
- **Use in GraphOps:** Freshens the Oct 7 DPDP entry: the Nov 13, 2026 countdown is now ~5 weeks away with an unstaffed Board — sharpen the 72h breach-clock panel to show "soft enforcement now, ₹250cr exposure from May 2027." Also honest note for the handoff UX: filing recommendations are advisory until the Board publishes procedures — don't overclaim in the containment card.

### 8. HackFront India 2026 — no new organizer/judging/timeline updates in the last ~90 days (checked Oct 8, 2026)
- **Date:** Checked Oct 8, 2026; last public coverage remains June 13–21, 2026 launch press (Leadership Forum, Constitution Club of India).
- **What:** Web search surfaced no new Where U Elevate announcements on rules, judging criteria, named judges/mentors, or timeline shifts. Standing dashboard facts unchanged: prototype submission Sep 22–Oct 25 (11:59 PM IST; safe target 6:29 PM), 30-hr finale Nov 21–22 Delhi-NCR, GTM cohorts Dec 1–27; Cybersecurity's single problem statement = GraphOps. Launch framing to echo: "innovation decade," creators-not-consumers.
- **Source:** https://www.europeansuntimes.com/news/as-bharat-innovates-goes-global-hackfront-india-launches-to-power-the-next-million-innovators20260616153820//
- **Use in GraphOps:** No action — hold all assumptions, keep the countdown cadence and portal-watch cron. The standing absence finding persists for the fourth consecutive scan.
