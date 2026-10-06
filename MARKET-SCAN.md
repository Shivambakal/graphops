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
